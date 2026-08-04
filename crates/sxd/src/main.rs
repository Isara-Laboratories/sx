//! `sxd` — the secrets daemon.
//!
//! Runs *outside* the agent's sandbox. It is the only component that reads
//! secret material: it captures `.env` files on demand (TouchID-gated),
//! holds the values in memory under a TTL, and injects them into child
//! processes it spawns on the client's behalf — gating each use and redacting
//! the values out of the child's output before returning it.
//!
//! The caller is authenticated via socket peer credentials: only the owning
//! uid may connect, and the `.env` path / child cwd are resolved against the
//! caller's *verified* working directory (derived from its pid), never a field
//! the client supplies.
//!
//! v1 simplifications (see DESIGN.md):
//!   * the spawned child is NOT yet re-sandboxed — it inherits the daemon's
//!     (unsandboxed) context. Production must re-apply the agent's sandbox to
//!     the child so `run` is not an escape hatch.

mod config;
mod gate;
mod peer;
mod service;
mod state;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use sx_proto::{humanize_secs, socket_path, Request, Response, GRANT_TTL_MAX_SECS, GRANT_TTL_SECS};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use gate::{AllowAllGate, ApprovalGate, CliGate};
use peer::Peer;
use state::State;

struct Daemon {
    state: Mutex<State>,
    // Only one human approval prompt can be active at a time. Connection
    // workers that do not need approval do not take this lock.
    gate: Mutex<Box<dyn ApprovalGate>>,
    /// Serialize refreshes per AWS profile. A command that reaches the refresh
    /// boundary rechecks the stored values after it acquires this lock, so
    /// concurrent commands share one AWS CLI invocation.
    aws_refresh_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    aws_minter: Arc<AwsMinter>,
}

type AwsMinter = dyn Fn(&str) -> Result<HashMap<String, String>, Response> + Send + Sync;

fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    // Service-management subcommands run and exit; they don't start the daemon.
    match raw.first().map(String::as_str) {
        Some("install") => {
            let dry_run = raw.iter().any(|a| a == "--print" || a == "--dry-run");
            service::install(dry_run)?;
            // A single `sxd install` should leave the daemon fully ready, so
            // also resolve + persist the aws CLI path here (this runs with the
            // user's real shell PATH). Discovery failure is non-fatal: warn and
            // point at `sxd setup` rather than aborting the service install.
            if !dry_run {
                match store_aws_cli_path() {
                    Ok(Some(path)) => {
                        println!("Resolved aws CLI: {}", path.display());
                    }
                    Ok(None) => eprintln!(
                        "warning: could not find the `aws` CLI on PATH; AWS minting will not \
                         work until you install it and run `sxd setup`."
                    ),
                    Err(e) => eprintln!(
                        "warning: failed to record the aws CLI path ({e}); run `sxd setup`."
                    ),
                }
            }
            return Ok(());
        }
        Some("setup") => {
            let dry_run = raw.iter().any(|a| a == "--print" || a == "--dry-run");
            return cmd_setup(dry_run);
        }
        Some("uninstall") => return service::uninstall().map_err(Into::into),
        _ => {}
    }

    let mut socket = socket_path();
    let mut gate: Box<dyn ApprovalGate> = default_gate();

    let mut args = raw.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = PathBuf::from(args.next().context("--socket needs a value")?);
            }
            "--no-gate" => gate = Box::new(AllowAllGate),
            "--cli-gate" => gate = Box::new(CliGate),
            "-h" | "--help" => {
                println!(
                    "usage: sxd [--socket PATH] [--cli-gate] [--no-gate]\n       \
                     sxd install [--print]   # register a login auto-start agent (macOS); also runs setup\n       \
                     sxd setup [--print]     # resolve the aws CLI path and store it in ~/.sx/config\n       \
                     sxd uninstall"
                );
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {}", parent.display()))?;
    }
    // Clear any stale socket from a previous run.
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding socket {}", socket.display()))?;

    eprintln!("sxd listening on {}", socket.display());

    let daemon = Arc::new(Daemon::new(gate));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // A wait for human approval can take any amount of time.
                // Keep accepting connections so status, clear, and requests
                // covered by an allow-all grant can continue meanwhile.
                drop(spawn_connection(&daemon, stream));
            }
            Err(e) => eprintln!("sxd: accept error: {e}"),
        }
    }

    Ok(())
}

/// Handle one client on an independent worker.
///
/// The accept loop drops the returned handle and does not wait for the worker.
/// Tests keep the handle so they can wait for the worker to finish.
fn spawn_connection(daemon: &Arc<Daemon>, stream: UnixStream) -> thread::JoinHandle<()> {
    let daemon = Arc::clone(daemon);
    thread::spawn(move || {
        if let Err(e) = daemon.handle(stream) {
            eprintln!("sxd: connection error: {e:#}");
        }
    })
}

/// Discover the `aws` CLI on the current PATH and persist its absolute path to
/// `~/.sx/config` under `aws_cli_path`. Returns the resolved path, or `None`
/// when `aws` could not be found anywhere. Shared by `sxd install` and
/// `sxd setup` so both leave identical config behind.
fn store_aws_cli_path() -> Result<Option<PathBuf>> {
    match config::discover_aws_cli() {
        Some(path) => {
            config::set(config::AWS_CLI_PATH, &path.to_string_lossy())
                .context("writing ~/.sx/config")?;
            Ok(Some(path))
        }
        None => Ok(None),
    }
}

/// `sxd setup`: resolve the `aws` CLI in the user's real shell environment and
/// store it in `~/.sx/config`, so the daemon — which launchd starts with a
/// minimal PATH — can spawn it by absolute path without ever searching PATH.
///
/// With `--print`/`--dry-run`, report what would be written without touching
/// the config file. A missing `aws` is a hard error here (unlike during
/// `install`), telling the user how to fix it.
fn cmd_setup(dry_run: bool) -> Result<()> {
    let cfg = config::config_path()?;
    match config::discover_aws_cli() {
        Some(path) => {
            if dry_run {
                println!(
                    "# would write {}={} to {}",
                    config::AWS_CLI_PATH,
                    path.display(),
                    cfg.display()
                );
            } else {
                config::set(config::AWS_CLI_PATH, &path.to_string_lossy())
                    .context("writing ~/.sx/config")?;
                println!("Found aws CLI: {}", path.display());
                println!(
                    "Saved {}={} to {}",
                    config::AWS_CLI_PATH,
                    path.display(),
                    cfg.display()
                );
            }
            Ok(())
        }
        None => anyhow::bail!(
            "could not find the `aws` CLI on your PATH. Install the AWS CLI \
             (https://aws.amazon.com/cli/), or set `{}=<absolute path>` manually in {}.",
            config::AWS_CLI_PATH,
            cfg.display()
        ),
    }
}

/// The gate used unless overridden by a flag: TouchID on macOS (falling back
/// to a terminal prompt when biometrics/passcode can't be evaluated), and a
/// terminal prompt elsewhere.
#[cfg(target_os = "macos")]
fn default_gate() -> Box<dyn ApprovalGate> {
    Box::new(gate::TouchIdGate::new(Box::new(CliGate)))
}

#[cfg(not(target_os = "macos"))]
fn default_gate() -> Box<dyn ApprovalGate> {
    Box::new(CliGate)
}

impl Daemon {
    fn new(gate: Box<dyn ApprovalGate>) -> Self {
        Self::with_aws_minter(gate, Arc::new(mint_aws))
    }

    fn with_aws_minter(gate: Box<dyn ApprovalGate>, aws_minter: Arc<AwsMinter>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            gate: Mutex::new(gate),
            aws_refresh_locks: Mutex::new(HashMap::new()),
            aws_minter,
        }
    }

    /// Authenticate the peer, read one request, dispatch it, write one response.
    fn handle(&self, stream: UnixStream) -> Result<()> {
        let response = self.authenticate_and_dispatch(&stream);

        let mut out = stream;
        let mut buf = serde_json::to_vec(&response)?;
        buf.push(b'\n');
        out.write_all(&buf)?;
        out.flush()?;
        Ok(())
    }

    /// Verify the caller, then read and dispatch the request.
    /// Every failure path returns a `Response` so the client always hears back.
    ///
    /// The caller's cwd is derived lazily by the handlers that need it (only
    /// `capture`, and `clear` when given a path), not here — a transient
    /// `proc_pidinfo` failure must not break `status`/`clear`/`run`.
    fn authenticate_and_dispatch(&self, stream: &UnixStream) -> Response {
        let peer = match Peer::from_stream(stream) {
            Ok(p) => p,
            Err(e) => {
                return Response::Error {
                    message: format!("cannot read peer credentials: {e}"),
                }
            }
        };

        // Only the owning user may reach their own secrets.
        if peer.uid != peer::own_uid() {
            return Response::Denied {
                reason: format!("connection from uid {} refused", peer.uid),
            };
        }

        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    message: format!("socket error: {e}"),
                }
            }
        });
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Response::Error {
                    message: "client closed without sending a request".to_string(),
                }
            }
            Ok(_) => {}
            Err(e) => {
                return Response::Error {
                    message: format!("read error: {e}"),
                }
            }
        }

        match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => self.dispatch(req, &peer),
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        }
    }

    fn dispatch(&self, req: Request, peer: &Peer) -> Response {
        match req {
            Request::Clear { path } => self.clear(path, peer),
            Request::Status => Response::Status {
                captures: self.state.lock().unwrap().info(),
            },
            Request::GrantAll {
                env,
                aws_profiles,
                lease_secs,
                renew,
            } => self.grant_all(env, aws_profiles, lease_secs, renew, peer),
            Request::Run {
                env,
                aws_profiles,
                argv,
                grant_all,
                renew,
            } => self.run(env, aws_profiles, argv, grant_all, renew, peer),
        }
    }

    /// Drop captures. A `path` is resolved the same way `capture` resolves it
    /// (relative to the caller's verified cwd, then canonicalized) so that the
    /// argument matches the canonical key the capture is stored under — without
    /// this, `sx clear .env` would never match and the secret would not revoke.
    fn clear(&self, path: Option<String>, peer: &Peer) -> Response {
        let target = path.map(|p| {
            // AWS source keys (`aws:<profile>`) are synthetic identities, not
            // filesystem paths — match them verbatim, never canonicalize.
            if p.starts_with(AWS_SOURCE_PREFIX) {
                return p;
            }
            match peer.cwd() {
                Ok(cwd) => resolve(&cwd, &p)
                    .map(|r| r.display().to_string())
                    .unwrap_or(p),
                Err(_) => p,
            }
        });
        let n = self.state.lock().unwrap().clear(target.as_deref());
        Response::Ok {
            message: format!("cleared {n} grant(s)"),
        }
    }

    /// Pre-authorize sources in allow-all mode (no command). Prompts once per
    /// source to grant it for the window with the per-command prompt suppressed.
    ///
    /// A source that already has a live allow-all window is reused silently;
    /// `renew` overrides that and starts a fresh window (re-prompt, re-read/mint,
    /// reset the lease).
    fn grant_all(
        &self,
        env: Vec<String>,
        aws_profiles: Vec<String>,
        lease_secs: Option<u64>,
        renew: bool,
        peer: &Peer,
    ) -> Response {
        if env.is_empty() && aws_profiles.is_empty() {
            return Response::Error {
                message: "grant-all requires at least one --env <path> or --aws-profile <profile>"
                    .to_string(),
            };
        }

        // Validate the requested lease against the hard maximum; reject rather
        // than silently clamp. `None` falls back to the default 1h.
        let ttl_secs = lease_secs.unwrap_or(GRANT_TTL_SECS);
        if ttl_secs > GRANT_TTL_MAX_SECS {
            return Response::Denied {
                reason: format!(
                    "lease {} exceeds maximum of {}",
                    humanize_secs(ttl_secs),
                    humanize_secs(GRANT_TTL_MAX_SECS)
                ),
            };
        }
        let ttl = Duration::from_secs(ttl_secs);

        let sources = match build_sources(&env, &aws_profiles, peer) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let count = sources.len();

        if count > 1 {
            if let Err(resp) = self.authorize_allow_all_batch(&sources, ttl, renew) {
                return resp;
            }
        } else {
            for src in &sources {
                if let Err(resp) = self.authorize(src, None, true, ttl, renew) {
                    return resp;
                }
            }
        }

        Response::Ok {
            message: format!(
                "allow-all granted for {count} source(s) ({})",
                humanize_secs(ttl_secs)
            ),
        }
    }

    /// Resolve each source, run both gates, then return the merged values for
    /// the client to inject and exec `argv`.
    fn run(
        &self,
        env: Vec<String>,
        aws_profiles: Vec<String>,
        argv: Vec<String>,
        grant_all: bool,
        renew: bool,
        peer: &Peer,
    ) -> Response {
        if argv.is_empty() {
            return Response::Error {
                message: "run requires a command".to_string(),
            };
        }
        if env.is_empty() && aws_profiles.is_empty() {
            return Response::Error {
                message: "run requires at least one --env <path> or --aws-profile <profile>"
                    .to_string(),
            };
        }

        let sources = match build_sources(&env, &aws_profiles, peer) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        // Merge the values of every requested source, in order (later sources
        // win), running both gates per source along the way. `run` always uses
        // the fixed default lease; only `grant_all --lease` varies it.
        let ttl = Duration::from_secs(GRANT_TTL_SECS);
        let mut merged: Vec<(String, String)> = Vec::new();
        for src in &sources {
            let values = match self.authorize(src, Some(&argv), grant_all, ttl, renew) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            for (k, v) in values {
                merged.retain(|(ek, _)| ek != &k);
                merged.push((k, v));
            }
        }

        Response::Granted { secrets: merged }
    }

    /// The two gates for one already-resolved source.
    ///
    /// * **File grant** — if no live grant exists, prompt a 1h grant and read
    ///   (or mint) its values. `make_allow_all` decides whether the new grant
    ///   is allow-all.
    /// * **Per-command** — when the grant is *not* allow-all and `argv` is
    ///   `Some`, prompt to approve this specific command. `make_allow_all`
    ///   upgrades a live confirm-mode grant to allow-all (prompted) instead.
    ///
    /// A live allow-all window is *reused silently*: re-requesting `grant-all`
    /// against it is a no-op, not a re-prompt. `renew` overrides that and forces
    /// a fresh window — re-prompting, re-reading/minting the values, and
    /// resetting the lease even when one is live (only meaningful with
    /// `make_allow_all`).
    ///
    /// `argv == None` means "pre-authorize only" (no command to confirm).
    /// `Err(Response)` carries a denial/error to return verbatim.
    ///
    /// `ttl` is the lease applied to any grant established or upgraded here.
    /// `run` callers always pass [`GRANT_TTL_SECS`]; only `grant_all` varies it
    /// (via `--lease`).
    fn authorize(
        &self,
        src: &Source,
        argv: Option<&[String]>,
        make_allow_all: bool,
        ttl: Duration,
        renew: bool,
    ) -> Result<Vec<(String, String)>, Response> {
        let source = src.key();
        let is_run = argv.is_some();
        let live = self.state.lock().unwrap().live(source);

        // First use of this source → file-grant gate (reads/mints fresh).
        let Some(live) = live else {
            let values = self.establish_grant(src, argv, make_allow_all, ttl)?;
            return self.finish_authorization(src, values, is_run);
        };

        // `--renew` on an allow-all request starts over: re-prompt, re-read/mint,
        // and reset the lease, discarding the live window. Establishing fresh
        // keeps a single, well-tested grant path.
        if renew && make_allow_all {
            let values = self.establish_grant(src, argv, true, ttl)?;
            return self.finish_authorization(src, values, is_run);
        }

        // A live allow-all window is reused without prompting — including a
        // repeated `grant-all`/`--grant-all` against it (matching the window
        // that already exists is a no-op, not a re-prompt).
        let values = if live.allow_all {
            live.values
        } else if make_allow_all {
            // Live grant is confirm-mode. Asked to upgrade it to allow-all →
            // prompt because this is a genuine escalation.
            if !self.approve(&allow_all_prompt(src, ttl)) {
                return Err(Response::Denied {
                    reason: format!("allow-all not approved for {source}"),
                });
            }
            self.state.lock().unwrap().set_allow_all(source, ttl);
            live.values
        } else {
            // Confirm-mode grant + a command → per-command gate.
            let argv = argv.expect("confirm-mode path always has a command");
            if !self.approve(&per_command_prompt(src, argv)) {
                return Err(Response::Denied {
                    reason: "command not approved".to_string(),
                });
            }
            // Re-resolve after approval: the grant may have expired at the prompt.
            match self.state.lock().unwrap().live(source) {
                Some(g) => g.values,
                None => {
                    return Err(Response::Denied {
                        reason: format!("grant for {source} expired during approval"),
                    })
                }
            }
        };

        self.finish_authorization(src, values, is_run)
    }

    /// First-use grant: prompt, read/mint the source's values, store them.
    fn establish_grant(
        &self,
        src: &Source,
        argv: Option<&[String]>,
        allow_all: bool,
        ttl: Duration,
    ) -> Result<Vec<(String, String)>, Response> {
        let prompt = if allow_all {
            allow_all_prompt(src, ttl)
        } else {
            first_run_prompt(src, argv, ttl)
        };
        if !self.approve(&prompt) {
            return Err(Response::Denied {
                reason: format!("grant not approved for {}", src.key()),
            });
        }

        // Read/mint values only AFTER approval. On failure return the carried
        // Response verbatim so any CLI stderr never enters a successful grant.
        let values = self.source_values(src)?;

        self.state
            .lock()
            .unwrap()
            .add(src.key().to_string(), values.clone(), ttl, allow_all);

        let mut out: Vec<(String, String)> = values.into_iter().collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Multi-source allow-all grant: one approval covers every listed source,
    /// then each source is upgraded or established under the same lease.
    ///
    /// A source that already has a live allow-all window is reused untouched, so
    /// if *every* source is already allow-all (and `renew` is false) this is a
    /// silent no-op with no prompt. `renew` forces a fresh window for all of
    /// them — re-prompting, re-reading/minting, and resetting the lease.
    fn authorize_allow_all_batch(
        &self,
        sources: &[Source],
        ttl: Duration,
        renew: bool,
    ) -> Result<(), Response> {
        // A source needs (re)granting unless it already has a live allow-all
        // window we can reuse as-is. `--renew` forces every source to re-grant.
        let needs_grant = |src: &Source| {
            renew
                || !self
                    .state
                    .lock()
                    .unwrap()
                    .live(src.key())
                    .map(|g| g.allow_all)
                    .unwrap_or(false)
        };
        if !sources.iter().any(needs_grant) {
            return Ok(());
        }

        if !self.approve(&allow_all_sources_prompt(sources, ttl)) {
            return Err(Response::Denied {
                reason: format!("allow-all not approved for {} source(s)", sources.len()),
            });
        }

        for src in sources {
            let source = src.key();
            let live = self.state.lock().unwrap().live(source);
            match live {
                // Reuse an existing allow-all window untouched (unless renewing).
                Some(g) if g.allow_all && !renew => continue,
                // Upgrade a live confirm-mode grant in place, keeping its values.
                Some(_) if !renew => {
                    self.state.lock().unwrap().set_allow_all(source, ttl);
                }
                // Fresh or renewed: (re-)read/mint and store under the new lease.
                _ => {
                    let values = self.source_values(src)?;
                    self.state
                        .lock()
                        .unwrap()
                        .add(source.to_string(), values, ttl, true);
                }
            }
        }

        Ok(())
    }

    /// Run one human approval prompt at a time.
    fn approve(&self, prompt: &str) -> bool {
        self.gate.lock().unwrap().approve(prompt)
    }

    fn source_values(&self, src: &Source) -> Result<HashMap<String, String>, Response> {
        match src {
            Source::Env { path, key } => parse_env(path).map_err(|e| Response::Error {
                message: format!("reading {key}: {e:#}"),
            }),
            Source::Aws { profile, .. } => (self.aws_minter)(profile),
        }
    }

    fn finish_authorization(
        &self,
        src: &Source,
        values: Vec<(String, String)>,
        is_run: bool,
    ) -> Result<Vec<(String, String)>, Response> {
        if is_run {
            self.refresh_aws_if_needed(src, values)
        } else {
            Ok(values)
        }
    }

    /// Refresh temporary AWS credentials near their provider-reported expiry.
    /// This changes only the cached values; it never extends the human grant.
    fn refresh_aws_if_needed(
        &self,
        src: &Source,
        values: Vec<(String, String)>,
    ) -> Result<Vec<(String, String)>, Response> {
        let Source::Aws { profile, .. } = src else {
            return Ok(values);
        };
        if !aws_credentials_need_refresh(&values, OffsetDateTime::now_utc())? {
            return Ok(values);
        }

        let source = src.key();
        let refresh_lock = {
            let mut locks = self.aws_refresh_locks.lock().unwrap();
            Arc::clone(
                locks
                    .entry(source.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _refresh_guard = refresh_lock.lock().unwrap();

        // Another command may have refreshed this profile while this command
        // waited for the lock. Re-read the grant before starting the AWS CLI.
        let current = self
            .state
            .lock()
            .unwrap()
            .live(source)
            .ok_or_else(|| Response::Denied {
                reason: format!("grant for {source} expired before credential refresh"),
            })?;
        if !aws_credentials_need_refresh(&current.values, OffsetDateTime::now_utc())? {
            return Ok(current.values);
        }

        let refreshed = (self.aws_minter)(profile)?;
        let refreshed_values = sorted_values(&refreshed);
        if aws_credentials_need_refresh(&refreshed_values, OffsetDateTime::now_utc())? {
            return Err(Response::Error {
                message: format!(
                    "AWS CLI returned credentials for profile {profile} that expire within {} minutes",
                    AWS_REFRESH_WINDOW_SECS / 60
                ),
            });
        }

        if !self.state.lock().unwrap().replace_values(source, refreshed) {
            return Err(Response::Denied {
                reason: format!("grant for {source} expired during credential refresh"),
            });
        }
        Ok(refreshed_values)
    }
}

/// Synthetic source-key prefix for AWS-profile grants (`aws:<profile>`). These
/// keys are never filesystem paths and must bypass `resolve`/`canonicalize`.
const AWS_SOURCE_PREFIX: &str = "aws:";
const AWS_CREDENTIAL_EXPIRATION: &str = "AWS_CREDENTIAL_EXPIRATION";
const AWS_REFRESH_WINDOW_SECS: i64 = 5 * 60;

fn sorted_values(values: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut values: Vec<(String, String)> = values
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    values.sort_by(|a, b| a.0.cmp(&b.0));
    values
}

/// Return true when temporary AWS credentials expire within the refresh
/// window. Credentials without an expiration are static and need no refresh.
fn aws_credentials_need_refresh(
    values: &[(String, String)],
    now: OffsetDateTime,
) -> Result<bool, Response> {
    let Some((_, expiration)) = values
        .iter()
        .find(|(name, _)| name == AWS_CREDENTIAL_EXPIRATION)
    else {
        return Ok(false);
    };
    let expiration = OffsetDateTime::parse(expiration, &Rfc3339).map_err(|e| Response::Error {
        message: format!("AWS CLI returned an invalid {AWS_CREDENTIAL_EXPIRATION}: {e}"),
    })?;
    Ok(expiration <= now + time::Duration::seconds(AWS_REFRESH_WINDOW_SECS))
}

/// A resolved secret source: a canonical `.env` file path, or a named AWS
/// profile. This is the one place that differs between backends — the State
/// key it is stored under, the subject shown at the human gate, and how its
/// values are produced ("minted"). Everything else (TTL, grant/allow-all
/// machinery, status, redaction) is identical across sources.
enum Source {
    /// A `.env` file: `key` is its canonical path (also the display identity).
    Env { key: String, path: PathBuf },
    /// An AWS profile: `key` is `aws:<profile>`, `profile` the bare name.
    Aws { key: String, profile: String },
}

impl Source {
    /// The State key this source is stored under (also shown by `status`).
    fn key(&self) -> &str {
        match self {
            Source::Env { key, .. } | Source::Aws { key, .. } => key,
        }
    }

    /// Subject phrase for the grant / allow-all prompts ("...access to X").
    fn subject(&self) -> String {
        match self {
            Source::Env { path, .. } => format!("secrets in:\n  {}", path.display()),
            Source::Aws { profile, .. } => format!("AWS credentials for profile:\n  {profile}"),
        }
    }

    /// Subject phrase for the per-command prompt ("...with X").
    fn subject_from(&self) -> String {
        match self {
            Source::Env { path, .. } => format!("secrets from:\n  {}", path.display()),
            Source::Aws { profile, .. } => format!("AWS credentials for profile:\n  {profile}"),
        }
    }

    /// Compact single-line label for multi-source approval prompts.
    fn batch_label(&self) -> String {
        match self {
            Source::Env { path, .. } => format!("secrets in {}", path.display()),
            Source::Aws { profile, .. } => format!("AWS profile {profile}"),
        }
    }
}

fn first_run_prompt(src: &Source, argv: Option<&[String]>, ttl: Duration) -> String {
    let mut p = format!(
        "Grant access to {}\nfor {}.",
        src.subject(),
        humanize_secs(ttl.as_secs())
    );
    if let Some(argv) = argv {
        p.push_str(&format!("\nThis command will run:\n  {}", argv.join(" ")));
    }
    p
}

fn per_command_prompt(src: &Source, argv: &[String]) -> String {
    format!(
        "Run command:\n  {}\nwith {}",
        argv.join(" "),
        src.subject_from()
    )
}

fn allow_all_prompt(src: &Source, ttl: Duration) -> String {
    format!(
        "Allow ALL commands to use {}\nfor {}, without confirming each one.",
        src.subject(),
        humanize_secs(ttl.as_secs())
    )
}

fn allow_all_sources_prompt(sources: &[Source], ttl: Duration) -> String {
    let mut prompt = format!(
        "Allow ALL commands to use {} sources\nfor {}, without confirming each one.\nSources:",
        sources.len(),
        humanize_secs(ttl.as_secs())
    );
    for src in sources {
        prompt.push_str("\n  - ");
        prompt.push_str(&src.batch_label());
    }
    prompt
}

/// Turn the client's `--env` paths and `--aws-profile` names into resolved
/// [`Source`]s, preserving order (env first, then AWS).
///
/// The caller's verified cwd is only derived when there is at least one `.env`
/// path to resolve, so an AWS-only request never fails on a transient
/// `proc_pidinfo` hiccup. AWS profiles are NOT touched by filesystem
/// resolution — they are keyed under a synthetic `aws:<profile>`.
fn build_sources(
    env: &[String],
    aws_profiles: &[String],
    peer: &Peer,
) -> Result<Vec<Source>, Response> {
    let mut sources = Vec::with_capacity(env.len() + aws_profiles.len());
    if !env.is_empty() {
        let cwd = match peer.cwd() {
            Ok(c) => c,
            Err(e) => {
                return Err(Response::Error {
                    message: format!("cannot determine caller cwd (pid {}): {e}", peer.pid),
                })
            }
        };
        for path in env {
            let resolved = match resolve(&cwd, path) {
                Ok(p) => p,
                Err(e) => {
                    return Err(Response::Error {
                        message: format!("cannot resolve {path}: {e}"),
                    })
                }
            };
            sources.push(Source::Env {
                key: resolved.display().to_string(),
                path: resolved,
            });
        }
    }
    for profile in aws_profiles {
        sources.push(Source::Aws {
            key: format!("{AWS_SOURCE_PREFIX}{profile}"),
            profile: profile.clone(),
        });
    }
    Ok(sources)
}

/// Resolve `path` relative to `cwd` and canonicalize it (file must exist).
fn resolve(cwd: &Path, path: &str) -> std::io::Result<PathBuf> {
    let p = Path::new(path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    joined.canonicalize()
}

/// Parse a `.env` file into name→value pairs.
fn parse_env(path: &Path) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in dotenvy::from_path_iter(path)? {
        let (k, v) = item?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Environment override for the configured `aws` CLI path, taking precedence
/// over `~/.sx/config`. Handy for tests/CI. Even with this set, the daemon
/// still NEVER does a bare `$PATH` search for `aws`.
const AWS_PATH_ENV: &str = "SX_AWS_PATH";

/// Resolve the absolute path to the `aws` CLI the daemon must spawn — WITHOUT
/// searching `$PATH`.
///
/// The path comes from `$SX_AWS_PATH` if set, otherwise from `aws_cli_path` in
/// `~/.sx/config` (written by `sxd setup` / `sxd install`). Read fresh on every
/// mint so a freshly-written config is picked up by an already-running daemon
/// with no launchd reload. Every failure path returns a `Response` for the
/// client, never folding error text into a grant.
fn resolve_aws_cli() -> Result<PathBuf, Response> {
    let configured = match std::env::var_os(AWS_PATH_ENV) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => match config::get(config::AWS_CLI_PATH) {
            Ok(Some(p)) => PathBuf::from(p),
            Ok(None) => {
                return Err(Response::Error {
                    message: "AWS CLI path is not configured; run `sxd setup` \
                              (or `sxd install`) to record it in ~/.sx/config."
                        .to_string(),
                })
            }
            Err(e) => {
                return Err(Response::Error {
                    message: format!("cannot read ~/.sx/config: {e}; run `sxd setup`."),
                })
            }
        },
    };

    if !config::is_executable_file(&configured) {
        return Err(Response::Error {
            message: format!(
                "configured aws CLI path {} does not exist or isn't executable; \
                 re-run `sxd setup` (the CLI may have moved).",
                configured.display()
            ),
        });
    }
    Ok(configured)
}

/// Mint temporary AWS credentials for `profile` by shelling out to the AWS CLI.
///
/// Runs `aws configure export-credentials --profile <profile> --format
/// env-no-export`, which resolves SSO, assume-role, and static profiles
/// uniformly and prints `KEY=VALUE` lines (`AWS_ACCESS_KEY_ID`,
/// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and usually
/// `AWS_CREDENTIAL_EXPIRATION` / `AWS_REGION`).
///
/// We do NOT add an AWS SDK dependency: the CLI is the source of truth for the
/// user's profile config and credential providers. On any failure (missing
/// CLI, non-zero exit) this returns a `Response` carrying the CLI's stderr so
/// the caller surfaces it as a denial/error — the stderr is NEVER folded into a
/// successful grant.
///
/// Crucially, the daemon spawns `aws` by the **absolute path resolved at setup
/// time** (see [`resolve_aws_cli`]), never by searching `$PATH`. launchd starts
/// `sxd` with a minimal `$PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`), so a bare
/// `Command::new("aws")` would fail to find `/usr/local/bin/aws`. The config is
/// read fresh on every mint, so writing it via `sxd setup` takes effect on the
/// next mint with no launchd reload.
fn mint_aws(profile: &str) -> Result<HashMap<String, String>, Response> {
    let aws = resolve_aws_cli()?;
    let output = match Command::new(&aws)
        .args([
            "configure",
            "export-credentials",
            "--profile",
            profile,
            "--format",
            "env-no-export",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Err(Response::Error {
                message: format!(
                    "cannot run `{}` to mint credentials for profile {profile}: {e} \
                     (re-run `sxd setup` — the AWS CLI may have moved)",
                    aws.display()
                ),
            })
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Response::Denied {
            reason: format!(
                "aws could not export credentials for profile {profile}: {}",
                stderr.trim()
            ),
        });
    }

    Ok(parse_env_no_export(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Parse the `KEY=VALUE` lines printed by
/// `aws configure export-credentials --format env-no-export` into a map.
///
/// Each non-empty line is `NAME=VALUE`; values are taken verbatim (this AWS
/// format emits no quoting or escaping). Blank lines are ignored, and a line
/// without `=` is skipped defensively rather than panicking.
fn parse_env_no_export(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Barrier,
    };

    #[test]
    fn parses_env_no_export_lines() {
        let out = "AWS_ACCESS_KEY_ID=AKIA123\n\
                   AWS_SECRET_ACCESS_KEY=secret/with+slashes\n\
                   AWS_SESSION_TOKEN=tok==\n\
                   AWS_CREDENTIAL_EXPIRATION=2026-01-01T00:00:00Z\n";
        let map = parse_env_no_export(out);
        assert_eq!(map["AWS_ACCESS_KEY_ID"], "AKIA123");
        assert_eq!(map["AWS_SECRET_ACCESS_KEY"], "secret/with+slashes");
        // A value containing `=` is preserved after the first split.
        assert_eq!(map["AWS_SESSION_TOKEN"], "tok==");
        assert_eq!(map["AWS_CREDENTIAL_EXPIRATION"], "2026-01-01T00:00:00Z");
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn skips_blank_and_malformed_lines() {
        let map = parse_env_no_export("\n  \nNOEQUALS\nA=1\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map["A"], "1");
    }

    fn aws_test_values(expiration: Option<&str>, access_key: &str) -> HashMap<String, String> {
        let mut values = HashMap::from([
            ("AWS_ACCESS_KEY_ID".to_string(), access_key.to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "dummy-not-a-secret".to_string(),
            ),
        ]);
        if let Some(expiration) = expiration {
            values.insert(
                AWS_CREDENTIAL_EXPIRATION.to_string(),
                expiration.to_string(),
            );
        }
        values
    }

    #[test]
    fn aws_refresh_uses_provider_expiration_and_safety_window() {
        let now = OffsetDateTime::parse("2026-08-04T12:00:00Z", &Rfc3339).unwrap();
        let static_values = sorted_values(&aws_test_values(None, "static"));
        let outside_window = sorted_values(&aws_test_values(
            Some("2026-08-04T12:05:01+00:00"),
            "temporary",
        ));
        let at_window = sorted_values(&aws_test_values(
            Some("2026-08-04T12:05:00.000Z"),
            "temporary",
        ));

        assert!(!aws_credentials_need_refresh(&static_values, now).unwrap());
        assert!(!aws_credentials_need_refresh(&outside_window, now).unwrap());
        assert!(aws_credentials_need_refresh(&at_window, now).unwrap());
    }

    #[test]
    fn invalid_aws_expiration_is_an_error() {
        let values = sorted_values(&aws_test_values(Some("not-a-time"), "temporary"));
        let result = aws_credentials_need_refresh(&values, OffsetDateTime::now_utc());
        assert!(matches!(result, Err(Response::Error { .. })));
    }

    #[test]
    fn concurrent_runs_share_one_aws_refresh_without_extending_grant() {
        const WORKERS: usize = 8;
        let source_key = format!("{AWS_SOURCE_PREFIX}benchmark");
        let old = aws_test_values(Some("2000-01-01T00:00:00Z"), "old");
        let fresh = aws_test_values(Some("2099-01-01T00:00:00Z"), "fresh");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_minter = Arc::clone(&calls);
        let minter: Arc<AwsMinter> = Arc::new(move |_profile| {
            calls_for_minter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            Ok(fresh.clone())
        });
        let daemon = Arc::new(Daemon::with_aws_minter(Box::new(AllowAllGate), minter));
        daemon.state.lock().unwrap().add(
            source_key.clone(),
            old.clone(),
            Duration::from_secs(3600),
            true,
        );
        let expires_before = daemon.state.lock().unwrap().info()[0].expires_in_secs;

        let barrier = Arc::new(Barrier::new(WORKERS + 1));
        let mut workers = Vec::new();
        for _ in 0..WORKERS {
            let daemon = Arc::clone(&daemon);
            let barrier = Arc::clone(&barrier);
            let old_values = sorted_values(&old);
            workers.push(std::thread::spawn(move || {
                let src = Source::Aws {
                    key: format!("{AWS_SOURCE_PREFIX}benchmark"),
                    profile: "benchmark".to_string(),
                };
                barrier.wait();
                daemon.refresh_aws_if_needed(&src, old_values).unwrap()
            }));
        }
        barrier.wait();
        for worker in workers {
            let values = worker.join().unwrap();
            assert!(values
                .iter()
                .any(|(name, value)| name == "AWS_ACCESS_KEY_ID" && value == "fresh"));
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let info = daemon.state.lock().unwrap().info();
        assert!(info[0].allow_all);
        assert!(info[0].expires_in_secs <= expires_before);
    }

    #[test]
    fn aws_source_uses_profile_in_prompts_and_key() {
        let src = Source::Aws {
            key: format!("{AWS_SOURCE_PREFIX}prod"),
            profile: "prod".to_string(),
        };
        assert_eq!(src.key(), "aws:prod");
        let ttl = Duration::from_secs(GRANT_TTL_SECS);
        let first = first_run_prompt(&src, Some(&["cmd".to_string()]), ttl);
        assert!(first.contains("AWS credentials for profile:\n  prod"));
        assert!(first.contains("This command will run:\n  cmd"));
        assert!(allow_all_prompt(&src, ttl).contains("AWS credentials for profile:\n  prod"));
        assert!(per_command_prompt(&src, &["cmd".to_string()])
            .contains("with AWS credentials for profile:\n  prod"));
    }

    #[test]
    fn env_source_keeps_existing_prompt_wording() {
        let src = Source::Env {
            key: "/tmp/.env".to_string(),
            path: PathBuf::from("/tmp/.env"),
        };
        assert_eq!(src.key(), "/tmp/.env");
        let ttl = Duration::from_secs(GRANT_TTL_SECS);
        assert!(first_run_prompt(&src, None, ttl).contains("secrets in:\n  /tmp/.env"));
        assert!(per_command_prompt(&src, &["x".to_string()])
            .contains("with secrets from:\n  /tmp/.env"));
    }

    fn allow_all_daemon() -> Daemon {
        Daemon::new(Box::new(AllowAllGate))
    }

    struct RecordingGate {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    impl ApprovalGate for RecordingGate {
        fn approve(&self, prompt: &str) -> bool {
            self.prompts.lock().unwrap().push(prompt.to_string());
            true
        }
    }

    struct BlockingGate {
        started: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl ApprovalGate for BlockingGate {
        fn approve(&self, _prompt: &str) -> bool {
            self.started.send(()).unwrap();
            self.release.lock().unwrap().recv().is_ok()
        }
    }

    fn write_request(stream: &mut UnixStream, request: &Request) {
        serde_json::to_writer(&mut *stream, request).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    fn read_response(stream: &mut UnixStream) -> Result<Response> {
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(line.trim())?)
    }

    fn recording_daemon() -> (Daemon, Arc<Mutex<Vec<String>>>) {
        let prompts = Arc::new(Mutex::new(Vec::new()));
        (
            Daemon::new(Box::new(RecordingGate {
                prompts: prompts.clone(),
            })),
            prompts,
        )
    }

    /// A peer whose pid is this test process, so `cwd()` resolves successfully.
    /// (`grant_all` itself performs no uid check.)
    fn self_peer() -> Peer {
        Peer {
            uid: 0,
            pid: std::process::id() as i32,
        }
    }

    #[test]
    fn pending_approval_does_not_block_other_requests() {
        let dir =
            std::env::temp_dir().join(format!("sx-concurrent-approval-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "FOO=bar\n").unwrap();
        let approved_env_path = dir.join("approved.env");
        std::fs::write(&approved_env_path, "READY=yes\n").unwrap();
        let approved_source = approved_env_path
            .canonicalize()
            .unwrap()
            .display()
            .to_string();

        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let daemon = Arc::new(Daemon::new(Box::new(BlockingGate {
            started: started_tx,
            release: Mutex::new(release_rx),
        })));
        daemon.state.lock().unwrap().add(
            approved_source,
            HashMap::from([("READY".to_string(), "yes".to_string())]),
            Duration::from_secs(GRANT_TTL_SECS),
            true,
        );

        let (mut approval_client, approval_server) = UnixStream::pair().unwrap();
        let approval_worker = spawn_connection(&daemon, approval_server);
        write_request(
            &mut approval_client,
            &Request::GrantAll {
                env: vec![env_path.to_string_lossy().into_owned()],
                aws_profiles: vec![],
                lease_secs: None,
                renew: false,
            },
        );
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("approval did not start");

        let (mut status_client, status_server) = UnixStream::pair().unwrap();
        status_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let status_worker = spawn_connection(&daemon, status_server);
        write_request(&mut status_client, &Request::Status);
        let status_response = read_response(&mut status_client);

        let (mut run_client, run_server) = UnixStream::pair().unwrap();
        run_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let run_worker = spawn_connection(&daemon, run_server);
        write_request(
            &mut run_client,
            &Request::Run {
                env: vec![approved_env_path.to_string_lossy().into_owned()],
                aws_profiles: vec![],
                argv: vec!["true".to_string()],
                grant_all: false,
                renew: false,
            },
        );
        let run_response = read_response(&mut run_client);

        release_tx.send(()).unwrap();
        let approval_response = read_response(&mut approval_client).unwrap();
        approval_worker.join().unwrap();
        status_worker.join().unwrap();
        run_worker.join().unwrap();

        assert!(matches!(status_response.unwrap(), Response::Status { .. }));
        assert!(matches!(run_response.unwrap(), Response::Granted { .. }));
        assert!(matches!(approval_response, Response::Ok { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_all_with_custom_lease_uses_it() {
        let dir = std::env::temp_dir().join(format!("sx-lease-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "FOO=bar\n").unwrap();

        let daemon = allow_all_daemon();
        let resp = daemon.grant_all(
            vec![env_path.to_string_lossy().into_owned()],
            vec![],
            Some(1800),
            false,
            &self_peer(),
        );
        match resp {
            Response::Ok { message } => assert!(
                message.contains("30 minutes"),
                "message should reflect the lease: {message}"
            ),
            other => panic!("expected Ok, got {other:?}"),
        }

        // The stored grant is allow-all and carries (about) the chosen TTL.
        let info = daemon.state.lock().unwrap().info();
        assert_eq!(info.len(), 1);
        assert!(info[0].allow_all);
        assert!(
            info[0].expires_in_secs > 1700 && info[0].expires_in_secs <= 1800,
            "unexpected ttl: {}",
            info[0].expires_in_secs
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_all_multiple_sources_uses_one_prompt() {
        let dir = std::env::temp_dir().join(format!("sx-batch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_one = dir.join("one.env");
        let env_two = dir.join("two.env");
        std::fs::write(&env_one, "ONE=1\n").unwrap();
        std::fs::write(&env_two, "TWO=2\n").unwrap();

        let (daemon, prompts) = recording_daemon();
        let resp = daemon.grant_all(
            vec![
                env_one.to_string_lossy().into_owned(),
                env_two.to_string_lossy().into_owned(),
            ],
            vec![],
            Some(1800),
            false,
            &self_peer(),
        );

        match resp {
            Response::Ok { message } => assert!(
                message.contains("2 source(s)"),
                "message should reflect the source count: {message}"
            ),
            other => panic!("expected Ok, got {other:?}"),
        }

        let prompts = prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1, "expected one batch approval prompt");
        assert!(prompts[0].contains("Allow ALL commands to use 2 sources"));
        assert!(prompts[0].contains(&env_one.display().to_string()));
        assert!(prompts[0].contains(&env_two.display().to_string()));
        drop(prompts);

        let info = daemon.state.lock().unwrap().info();
        assert_eq!(info.len(), 2);
        assert!(info.iter().all(|g| g.allow_all));
        assert!(info
            .iter()
            .all(|g| g.expires_in_secs > 1700 && g.expires_in_secs <= 1800));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_all_rejects_lease_over_max() {
        let daemon = allow_all_daemon();
        // The lease check fires before any source resolution or minting, so an
        // AWS source (never reached) is fine and needs no AWS CLI.
        let resp = daemon.grant_all(
            vec![],
            vec!["prod".to_string()],
            Some(GRANT_TTL_MAX_SECS + 1),
            false,
            &self_peer(),
        );
        match resp {
            Response::Denied { reason } => assert!(
                reason.contains("exceeds maximum"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected Denied, got {other:?}"),
        }
        // Nothing was granted.
        assert!(daemon.state.lock().unwrap().info().is_empty());
    }

    #[test]
    fn prompts_reflect_the_chosen_lease() {
        let src = Source::Env {
            key: "/tmp/.env".to_string(),
            path: PathBuf::from("/tmp/.env"),
        };
        // Default 1h reads as "1 hour".
        assert!(
            first_run_prompt(&src, None, Duration::from_secs(GRANT_TTL_SECS))
                .contains("for 1 hour.")
        );
        // A custom lease is rendered human-readably in both prompts.
        assert!(allow_all_prompt(&src, Duration::from_secs(86_400)).contains("for 1 day,"));
        assert!(allow_all_prompt(&src, Duration::from_secs(1800)).contains("for 30 minutes,"));
    }

    #[test]
    fn batch_allow_all_prompt_lists_aws_profiles() {
        let sources = vec![
            Source::Aws {
                key: format!("{AWS_SOURCE_PREFIX}dev/readonly-no-secrets"),
                profile: "dev/readonly-no-secrets".to_string(),
            },
            Source::Aws {
                key: format!("{AWS_SOURCE_PREFIX}prod/readonly-no-secrets"),
                profile: "prod/readonly-no-secrets".to_string(),
            },
        ];

        let prompt = allow_all_sources_prompt(&sources, Duration::from_secs(43_200));
        assert!(prompt.contains("Allow ALL commands to use 2 sources"));
        assert!(prompt.contains("for 12 hours"));
        assert!(prompt.contains("AWS profile dev/readonly-no-secrets"));
        assert!(prompt.contains("AWS profile prod/readonly-no-secrets"));
    }

    #[test]
    fn grant_all_reuses_live_window_without_reprompting() {
        let dir = std::env::temp_dir().join(format!("sx-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "FOO=bar\n").unwrap();
        let arg = env_path.to_string_lossy().into_owned();

        let (daemon, prompts) = recording_daemon();

        // First grant-all establishes the window: one prompt.
        daemon.grant_all(vec![arg.clone()], vec![], None, false, &self_peer());
        assert_eq!(prompts.lock().unwrap().len(), 1, "first grant-all prompts");

        // Re-issuing grant-all against the live window reuses it — no new prompt.
        daemon.grant_all(vec![arg.clone()], vec![], None, false, &self_peer());
        daemon.grant_all(vec![arg], vec![], None, false, &self_peer());
        assert_eq!(
            prompts.lock().unwrap().len(),
            1,
            "reusing a live allow-all window must not re-prompt"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_all_renew_reprompts_and_rereads_values() {
        let dir = std::env::temp_dir().join(format!("sx-renew-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "FOO=one\n").unwrap();
        let arg = env_path.to_string_lossy().into_owned();
        let key = env_path.canonicalize().unwrap().display().to_string();

        let (daemon, prompts) = recording_daemon();

        daemon.grant_all(vec![arg.clone()], vec![], None, false, &self_peer());
        assert_eq!(prompts.lock().unwrap().len(), 1);

        // --renew re-prompts and re-reads the source even though a window is live.
        std::fs::write(&env_path, "FOO=two\n").unwrap();
        daemon.grant_all(vec![arg], vec![], None, true, &self_peer());
        assert_eq!(prompts.lock().unwrap().len(), 2, "--renew must re-prompt");

        let live = daemon.state.lock().unwrap().live(&key).unwrap();
        assert_eq!(
            live.values,
            vec![("FOO".to_string(), "two".to_string())],
            "--renew must re-read the source's values"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn grant_all_batch_reuses_when_all_live_then_renews() {
        let dir = std::env::temp_dir().join(format!("sx-batch-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let one = dir.join("one.env");
        let two = dir.join("two.env");
        std::fs::write(&one, "ONE=1\n").unwrap();
        std::fs::write(&two, "TWO=2\n").unwrap();
        let args = || {
            vec![
                one.to_string_lossy().into_owned(),
                two.to_string_lossy().into_owned(),
            ]
        };

        let (daemon, prompts) = recording_daemon();

        // First batch grant-all: one approval for both sources.
        daemon.grant_all(args(), vec![], None, false, &self_peer());
        assert_eq!(prompts.lock().unwrap().len(), 1);

        // Both windows already live → re-issuing is a silent no-op (no prompt).
        daemon.grant_all(args(), vec![], None, false, &self_peer());
        assert_eq!(
            prompts.lock().unwrap().len(),
            1,
            "reusing live windows in a batch must not re-prompt"
        );

        // --renew forces a fresh batch approval.
        daemon.grant_all(args(), vec![], None, true, &self_peer());
        assert_eq!(
            prompts.lock().unwrap().len(),
            2,
            "--renew re-prompts the batch"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
