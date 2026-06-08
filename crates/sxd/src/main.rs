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

mod gate;
mod peer;
mod state;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use sx_proto::{socket_path, Request, Response, DEFAULT_TTL_SECS};

use gate::{AllowAllGate, ApprovalGate, CliGate};
use peer::Peer;
use state::State;

struct Daemon {
    state: Mutex<State>,
    gate: Box<dyn ApprovalGate>,
}

fn main() -> Result<()> {
    let mut socket = socket_path();
    let mut gate: Box<dyn ApprovalGate> = default_gate();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = PathBuf::from(args.next().context("--socket needs a value")?);
            }
            "--no-gate" => gate = Box::new(AllowAllGate),
            "--cli-gate" => gate = Box::new(CliGate),
            "-h" | "--help" => {
                println!("usage: sxd [--socket PATH] [--cli-gate] [--no-gate]");
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

    let daemon = Daemon {
        state: Mutex::new(State::default()),
        gate,
    };

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = daemon.handle(stream) {
                    eprintln!("sxd: connection error: {e:#}");
                }
            }
            Err(e) => eprintln!("sxd: accept error: {e}"),
        }
    }

    Ok(())
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

    /// Verify the caller, derive its cwd, then read and dispatch the request.
    /// Every failure path returns a `Response` so the client always hears back.
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

        let cwd = match peer.cwd() {
            Ok(c) => c,
            Err(e) => {
                return Response::Error {
                    message: format!("cannot determine caller cwd (pid {}): {e}", peer.pid),
                }
            }
        };

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
            Ok(req) => self.dispatch(req, &cwd),
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        }
    }

    fn dispatch(&self, req: Request, cwd: &Path) -> Response {
        match req {
            Request::Capture { path, ttl_secs } => {
                self.capture(path, cwd, ttl_secs.unwrap_or(DEFAULT_TTL_SECS))
            }
            Request::Clear { path } => {
                let n = self.state.lock().unwrap().clear(path.as_deref());
                Response::Ok {
                    message: format!("cleared {n} capture(s)"),
                }
            }
            Request::Status => Response::Status {
                captures: self.state.lock().unwrap().info(),
            },
            Request::Run { secrets, argv } => self.run(secrets, argv, cwd),
        }
    }

    /// Capture gate: resolve + canonicalize the path, ask the user, read it.
    fn capture(&self, path: String, cwd: &Path, ttl_secs: u64) -> Response {
        let resolved = match resolve(cwd, &path) {
            Ok(p) => p,
            Err(e) => {
                return Response::Error {
                    message: format!("cannot resolve {path}: {e}"),
                }
            }
        };

        let prompt = format!(
            "Capture secrets from:\n  {}\nHold for {} minute(s).",
            resolved.display(),
            ttl_secs / 60
        );
        if !self.gate.approve(&prompt) {
            return Response::Denied {
                reason: "capture not approved".to_string(),
            };
        }

        let values = match parse_env(&resolved) {
            Ok(v) => v,
            Err(e) => {
                return Response::Error {
                    message: format!("reading {}: {e:#}", resolved.display()),
                }
            }
        };

        let source = resolved.display().to_string();
        let mut names: Vec<String> = values.keys().cloned().collect();
        names.sort();
        self.state
            .lock()
            .unwrap()
            .add(source.clone(), values, Duration::from_secs(ttl_secs));

        Response::Captured {
            source,
            names,
            expires_in_secs: ttl_secs,
        }
    }

    /// Per-use gate: resolve names from active captures, confirm, spawn child.
    fn run(&self, secrets: Vec<String>, argv: Vec<String>, cwd: &Path) -> Response {
        if argv.is_empty() {
            return Response::Error {
                message: "run requires a command".to_string(),
            };
        }

        // Resolve every requested name against active captures.
        let mut injected: Vec<(String, String)> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let mut st = self.state.lock().unwrap();
            for name in &secrets {
                match st.lookup(name) {
                    Some(v) => injected.push((name.clone(), v)),
                    None => missing.push(name.clone()),
                }
            }
        }
        if !missing.is_empty() {
            return Response::Denied {
                reason: format!("no active capture provides: {}", missing.join(", ")),
            };
        }

        let prompt = format!(
            "Agent requests secret(s): {}\nfor command:\n  {}",
            if secrets.is_empty() {
                "(none)".to_string()
            } else {
                secrets.join(", ")
            },
            argv.join(" ")
        );
        if !self.gate.approve(&prompt) {
            return Response::Denied {
                reason: "command not approved".to_string(),
            };
        }

        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).current_dir(cwd);
        for (k, v) in &injected {
            cmd.env(k, v);
        }

        match cmd.output() {
            Ok(out) => {
                let values: Vec<String> = injected.into_iter().map(|(_, v)| v).collect();
                Response::Ran {
                    code: out.status.code().unwrap_or(-1),
                    stdout: redact(String::from_utf8_lossy(&out.stdout).into_owned(), &values),
                    stderr: redact(String::from_utf8_lossy(&out.stderr).into_owned(), &values),
                }
            }
            Err(e) => Response::Error {
                message: format!("spawning {}: {e}", argv[0]),
            },
        }
    }
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

/// Replace every (non-empty) secret value in `text` with a placeholder.
fn redact(mut text: String, values: &[String]) -> String {
    for v in values {
        if v.is_empty() {
            continue;
        }
        text = text.replace(v.as_str(), "‹redacted›");
    }
    text
}
