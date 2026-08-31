//! `sx` — the in-sandbox client.
//!
//! `sx` runs *inside* the agent's sandbox. For `run`, it asks the daemon for
//! the named secrets (the daemon gates that on the user), receives the values,
//! injects them, and execs the command as its own subprocess — so the child
//! inherits this process's sandbox confinement and the daemon never executes
//! anything. `sx` is therefore the single point that briefly holds plaintext
//! inside the sandbox; it is trusted (and, in a follow-up, code-sign-attested
//! by the daemon) to use the values only to launch the requested command and
//! to redact them from that command's output.

mod skill;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sx_proto::{parse_duration, socket_path, Request, Response};

#[derive(Parser)]
#[command(
    name = "sx",
    about = "Conditioned secret access for sandboxed agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Drop granted sources — a single source, or all of them.
    ///
    /// Pass a `.env` path positionally, or `--aws-profile <name>` to revoke a
    /// single AWS-profile grant. With no argument, clears everything.
    Clear {
        /// Source path to clear; omit to clear everything.
        path: Option<String>,
        /// AWS profile to clear (maps to the `aws:<profile>` grant).
        #[arg(long = "aws-profile", conflicts_with = "path")]
        aws_profile: Option<String>,
    },
    /// Show active grants and the secret names they expose (never values).
    Status,
    /// List configured AWS profile names (never credentials; no approval).
    Inventory,
    /// Alias for `status`, framed as "what secrets can I use right now".
    List,
    /// Install or remove the sx usage skill for AI coding agents.
    Skill {
        #[command(subcommand)]
        action: SkillAction,
    },
    /// Grant a .env file AND allow all its commands without per-command
    /// prompts. Runs nothing — use this to opt a file out of confirmation.
    ///
    /// The grant lasts one hour by default; pass --lease <DURATION> to choose a
    /// different window, up to a maximum of 7 days (7d). A duration is an
    /// integer with an optional unit suffix s/m/h/d (no suffix = seconds), e.g.
    /// 30m, 2h, 1d, or 5400.
    ///
    /// Re-running this while the window is still live just reuses it (no second
    /// prompt). Pass --renew to start a fresh window early (re-prompt, reload
    /// credentials, and reset the lease).
    ///
    /// Example: sx grant-all --env .env --lease 1d
    GrantAll {
        /// Path to a .env file to allow-all (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// AWS profile to allow-all (repeatable).
        #[arg(long = "aws-profile")]
        aws_profile: Vec<String>,
        /// How long the grant lasts: 30m, 2h, 7d, or plain seconds (default 1h,
        /// max 7d).
        #[arg(long = "lease", value_parser = parse_duration)]
        lease: Option<u64>,
        /// Start a fresh allow-all window even if one is still live: re-prompt,
        /// reload credentials, and reset the lease.
        #[arg(long)]
        renew: bool,
        /// Re-read env files without changing a live grant's expiry or mode.
        #[arg(long, requires = "env")]
        refresh: bool,
    },
    /// Run a command with the secrets from one or more sources injected.
    ///
    /// Sources are `.env` files (`--env`) and/or AWS profiles (`--aws-profile`);
    /// at least one of either is required. The first use of a given source
    /// prompts for a 1-hour grant; by default every command is then confirmed
    /// individually. Pass --grant-all to opt the source(s) out of per-command
    /// confirmation for the window; re-running with --grant-all while that
    /// window is live just reuses it (no second prompt) unless --renew is given.
    /// The source(s) must be given each call.
    ///
    /// Example: sx run --env .env --aws-profile prod -- gh pr create
    Run {
        /// Path to a .env file whose secrets to inject (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// AWS profile to mint temporary credentials from (repeatable).
        #[arg(long = "aws-profile")]
        aws_profile: Vec<String>,
        /// Skip per-command confirmation for these source(s) for the grant window.
        #[arg(long = "grant-all")]
        grant_all: bool,
        /// With --grant-all, start a fresh allow-all window even if one is live:
        /// re-prompt, reload credentials, and reset the lease.
        #[arg(long, requires = "grant_all")]
        renew: bool,
        /// Re-read env files without changing a live grant's expiry or mode.
        #[arg(long, requires = "env")]
        refresh: bool,
        /// Long-lived AWS session mode: inject no static AWS credentials.
        /// The command instead reads a private AWS config whose
        /// `credential_process` redeems fresh credentials from the daemon, so
        /// its SDKs refresh in place for as long as the grant lease lives
        /// (keep an allow-all lease alive, e.g. `sx grant-all --aws-profile
        /// <p> --lease 7d`). Requires exactly one --aws-profile.
        #[arg(long = "aws-session")]
        aws_session: bool,
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Print AWS credentials for a profile in the AWS `credential_process`
    /// JSON format. Machine plumbing behind `sx run --aws-session`: AWS SDKs
    /// inside the launched command invoke this near credential expiry. The
    /// daemon serves it only to descendants of a live `--aws-session` run
    /// with a live allow-all grant, and never prompts — invoked anywhere
    /// else it prints a denial, not credentials. Hidden from help because it
    /// is not an operator command.
    #[command(hide = true)]
    CredentialProcess {
        /// AWS profile to mint fresh credentials from.
        #[arg(long = "aws-profile")]
        aws_profile: String,
    },
}

#[derive(Subcommand)]
enum SkillAction {
    /// Write the skill into agent config dirs. With no target flag, all three.
    Install {
        /// Install for Claude Code (~/.claude/skills/sx).
        #[arg(long)]
        claude: bool,
        /// Install for Codex (managed block in ~/.codex/AGENTS.md).
        #[arg(long)]
        codex: bool,
        /// Install for Pi (~/.pi/agent/skills/sx).
        #[arg(long)]
        pi: bool,
        /// Print what would change without writing anything.
        #[arg(long)]
        print: bool,
    },
    /// Remove the installed skill. With no target flag, all three.
    Uninstall {
        #[arg(long)]
        claude: bool,
        #[arg(long)]
        codex: bool,
        #[arg(long)]
        pi: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sx: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    // `run` is special: the daemon returns the secret values and *we* execute,
    // so the child stays inside our sandbox. Everything else is a simple
    // request/response we just render.
    //
    // Note: we deliberately do NOT send our cwd. The daemon derives the caller's
    // working directory from the verified peer pid to resolve the --env paths,
    // so a compromised client cannot fake where the files live.
    match cli.command {
        Cmd::Run {
            env,
            aws_profile,
            grant_all,
            renew,
            refresh,
            aws_session,
            argv,
        } => {
            if env.is_empty() && aws_profile.is_empty() {
                anyhow::bail!("run requires at least one --env <path> or --aws-profile <profile>");
            }
            if aws_session && aws_profile.len() != 1 {
                anyhow::bail!("--aws-session requires exactly one --aws-profile");
            }
            exec_with_secrets(
                env,
                aws_profile,
                argv,
                RunFlags {
                    grant_all,
                    renew,
                    refresh,
                    aws_session,
                },
            )
        }
        Cmd::CredentialProcess { aws_profile } => credential_process(aws_profile),
        Cmd::GrantAll {
            env,
            aws_profile,
            lease,
            renew,
            refresh,
        } => {
            if env.is_empty() && aws_profile.is_empty() {
                anyhow::bail!(
                    "grant-all requires at least one --env <path> or --aws-profile <profile>"
                );
            }
            Ok(render(send(&Request::GrantAll {
                env,
                aws_profiles: aws_profile,
                lease_secs: lease,
                renew,
                refresh,
            })?))
        }
        Cmd::Clear { path, aws_profile } => {
            // `--aws-profile p` clears the synthetic `aws:p` grant; a positional
            // path clears that source; neither clears everything.
            let path = aws_profile.map(|p| format!("aws:{p}")).or(path);
            Ok(render(send(&Request::Clear { path })?))
        }
        Cmd::Status | Cmd::List => Ok(render(send(&Request::Status)?)),
        Cmd::Inventory => Ok(render(send(&Request::Inventory)?)),
        Cmd::Skill { action } => run_skill(action),
    }
}

/// Skill (un)installation runs locally; it never contacts the daemon.
fn run_skill(action: SkillAction) -> Result<ExitCode> {
    match action {
        SkillAction::Install {
            claude,
            codex,
            pi,
            print,
        } => skill::install(skill::Targets { claude, codex, pi }, print)?,
        SkillAction::Uninstall { claude, codex, pi } => {
            skill::uninstall(skill::Targets { claude, codex, pi })?
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Ask the daemon (gated) for the secrets from `env` files and `aws_profiles`,
/// then inject and exec `argv` as our own child, redacting the secret values
/// from its output.
/// The run-mode flags forwarded from the CLI into one daemon `Run` request.
struct RunFlags {
    grant_all: bool,
    renew: bool,
    refresh: bool,
    aws_session: bool,
}

fn exec_with_secrets(
    env: Vec<String>,
    aws_profiles: Vec<String>,
    argv: Vec<String>,
    flags: RunFlags,
) -> Result<ExitCode> {
    let response = send(&Request::Run {
        env,
        aws_profiles: aws_profiles.clone(),
        argv: argv.clone(),
        grant_all: flags.grant_all,
        renew: flags.renew,
        refresh: flags.refresh,
        aws_session: flags.aws_session,
    })?;

    let granted = match response {
        Response::Granted { secrets } => secrets,
        other => return Ok(render(other)),
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    configure_child_environment(&mut cmd, &granted, !aws_profiles.is_empty());
    if flags.aws_session {
        // An older daemon ignores `aws_session` and returns the static
        // credentials; refuse rather than silently launching a child whose
        // credentials would freeze at exec.
        if granted
            .iter()
            .any(|(name, _)| name == "AWS_SECRET_ACCESS_KEY")
        {
            anyhow::bail!("sxd predates --aws-session; rebuild and restart the daemon");
        }
        configure_aws_session(&mut cmd, &aws_profiles[0], &granted)?;
    }
    // Inherit stdin so commands that read input (pipes, prompts) work. Drain
    // stdout and stderr concurrently, redacting and flushing each chunk as it
    // arrives so long-running commands report progress live.
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("running {}", argv[0]))?;
    let stdout = child.stdout.take().context("capturing child stdout")?;
    let stderr = child.stderr.take().context("capturing child stderr")?;
    let values = Arc::new(
        granted
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(_, value)| value.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    );
    let stdout_values = Arc::clone(&values);
    let stdout_thread = thread::spawn(move || relay_redacted(stdout, io::stdout(), &stdout_values));
    let stderr_thread = thread::spawn(move || relay_redacted(stderr, io::stderr(), &values));

    let status = child
        .wait()
        .with_context(|| format!("waiting for {}", argv[0]))?;
    stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stdout relay thread panicked"))??;
    stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stderr relay thread panicked"))??;

    Ok(ExitCode::from(
        u8::try_from(status.code().unwrap_or(1)).unwrap_or(1),
    ))
}

/// Inject granted values into a child while preventing an ambient or
/// file-sourced profile from overriding credentials minted by `--aws-profile`.
fn configure_child_environment(
    cmd: &mut Command,
    granted: &[(String, String)],
    aws_profile_requested: bool,
) {
    for (name, value) in granted {
        cmd.env(name, value);
    }
    if aws_profile_requested {
        cmd.env_remove("AWS_PROFILE");
    }
}

/// Point a child at a private AWS config whose `credential_process` redeems
/// fresh credentials from the daemon, instead of injecting a frozen snapshot.
///
/// Ambient static AWS credentials are removed from the child environment
/// because SDK provider chains prefer them over the config file; region hints
/// returned by the daemon are injected normally by the caller.
fn configure_aws_session(
    cmd: &mut Command,
    profile: &str,
    granted: &[(String, String)],
) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the sx binary path")?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set")?;
    let region = granted
        .iter()
        .find(|(name, _)| name == "AWS_REGION" || name == "AWS_DEFAULT_REGION")
        .map(|(_, value)| value.as_str());

    let config_path = aws_session_config_path(&home, profile);
    let config_dir = config_path
        .parent()
        .context("AWS session config path has no parent directory")?;
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("creating {}", config_dir.display()))?;
    std::fs::write(&config_path, aws_session_config(&exe, profile, region))
        .with_context(|| format!("writing {}", config_path.display()))?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", config_path.display()))?;

    cmd.env("AWS_CONFIG_FILE", &config_path);
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CREDENTIAL_EXPIRATION",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
    ] {
        cmd.env_remove(name);
    }
    Ok(())
}

/// Render the private AWS config for an `--aws-session` child: one default
/// profile whose `credential_process` calls back into this same binary. The
/// config file itself contains no secrets.
fn aws_session_config(exe: &Path, profile: &str, region: Option<&str>) -> String {
    let mut config = format!(
        "[default]\ncredential_process = \"{}\" credential-process --aws-profile \"{}\"\n",
        exe.display(),
        profile
    );
    if let Some(region) = region {
        config.push_str(&format!("region = {region}\n"));
    }
    config
}

/// Deterministic per-profile config path under `~/.sx/aws-session/`, so
/// repeated runs reuse one file and the child can outlive this process.
fn aws_session_config_path(home: &Path, profile: &str) -> PathBuf {
    let sanitized: String = profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    home.join(".sx")
        .join("aws-session")
        .join(format!("{sanitized}.config"))
}

/// Redeem one AWS `credential_process` refresh from the daemon and print it
/// in the AWS credential_process JSON contract. Machine-facing plumbing: the
/// output feeds an SDK, so it is intentionally not redacted.
fn credential_process(profile: String) -> Result<ExitCode> {
    let response = send(&Request::CredentialProcess { profile })?;
    let granted = match response {
        Response::Granted { secrets } => secrets,
        other => return Ok(render(other)),
    };
    println!("{}", credential_process_json(&granted)?);
    Ok(ExitCode::SUCCESS)
}

/// Render granted AWS values as credential_process JSON: Version 1 plus
/// AccessKeyId/SecretAccessKey and optional SessionToken/Expiration. The
/// daemon's `AWS_CREDENTIAL_EXPIRATION` passes through verbatim so the SDK
/// schedules its own refresh.
fn credential_process_json(secrets: &[(String, String)]) -> Result<String> {
    let get = |name: &str| {
        secrets
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let access = get("AWS_ACCESS_KEY_ID").context("daemon returned no AWS_ACCESS_KEY_ID")?;
    let secret =
        get("AWS_SECRET_ACCESS_KEY").context("daemon returned no AWS_SECRET_ACCESS_KEY")?;
    let mut json = serde_json::json!({
        "Version": 1,
        "AccessKeyId": access,
        "SecretAccessKey": secret,
    });
    if let Some(token) = get("AWS_SESSION_TOKEN") {
        json["SessionToken"] = token.into();
    }
    if let Some(expiration) = get("AWS_CREDENTIAL_EXPIRATION") {
        json["Expiration"] = expiration.into();
    }
    Ok(json.to_string())
}

/// Relay one output stream live, redacting each read chunk independently.
fn relay_redacted<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    values: &[Vec<u8>],
) -> io::Result<()> {
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let chunk = redact_chunk(&buf[..n], values);
        writer.write_all(&chunk)?;
        writer.flush()?;
    }
}

fn redact_chunk(chunk: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    const REDACTED: &[u8] = "‹redacted›".as_bytes();
    let mut output = chunk.to_vec();
    for value in values {
        let mut redacted = Vec::with_capacity(output.len());
        let mut rest = output.as_slice();
        while let Some(index) = rest.windows(value.len()).position(|window| window == value) {
            redacted.extend_from_slice(&rest[..index]);
            redacted.extend_from_slice(REDACTED);
            rest = &rest[index + value.len()..];
        }
        redacted.extend_from_slice(rest);
        output = redacted;
    }
    output
}

/// Send one request and read one response over the daemon socket.
fn send(request: &Request) -> Result<Response> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).with_context(|| {
        format!(
            "cannot reach daemon at {} (is sxd running?)",
            path.display()
        )
    })?;

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    (&stream).write_all(&line)?;

    let mut reader = BufReader::new(&stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    let response = serde_json::from_str::<Response>(buf.trim())
        .with_context(|| format!("bad response from daemon: {buf:?}"))?;
    Ok(response)
}

/// Print a response and map it to a process exit code.
fn render(response: Response) -> ExitCode {
    match response {
        Response::Ok { message } => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Response::Status { captures } => {
            if captures.is_empty() {
                println!("no active grants");
            } else {
                for c in captures {
                    let mode = if c.allow_all {
                        " [allow-all]"
                    } else {
                        " [confirm each command]"
                    };
                    println!(
                        "{} (expires in {}m){mode}",
                        c.source,
                        c.expires_in_secs / 60
                    );
                    for n in c.names {
                        println!("  {n}");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Response::Inventory { aws_profiles } => {
            println!("AWS profiles:");
            if aws_profiles.is_empty() {
                println!("  (none configured)");
            } else {
                for profile in aws_profiles {
                    println!("  {profile}");
                }
            }
            ExitCode::SUCCESS
        }
        Response::Granted { .. } => {
            // Handled by exec_with_secrets; reaching render means a logic error.
            eprintln!("error: unexpected grant outside of run");
            ExitCode::FAILURE
        }
        Response::Denied { reason } => {
            eprintln!("denied: {reason}");
            ExitCode::FAILURE
        }
        Response::Timeout { reason } => {
            eprintln!("timeout: {reason}");
            ExitCode::FAILURE
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    struct ChunkReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(0);
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn redacts_complete_secrets_within_a_chunk() {
        let values = vec![b"top-secret".to_vec()];
        assert_eq!(
            redact_chunk(b"before top-secret after", &values),
            "before ‹redacted› after".as_bytes()
        );
    }

    #[test]
    fn relay_preserves_non_utf8_output() {
        let input = [0xff, b' ', b's', b'e', b'c', b'r', b'e', b't'];
        let mut output = Vec::new();
        relay_redacted(&input[..], &mut output, &[b"secret".to_vec()]).unwrap();
        assert_eq!(
            output,
            [vec![0xff, b' '], "‹redacted›".as_bytes().to_vec()].concat()
        );
    }

    #[test]
    fn relay_flushes_each_chunk_immediately() {
        let reader = ChunkReader {
            chunks: [b"first\n".to_vec(), b"second\n".to_vec()].into(),
        };
        let mut writer = RecordingWriter::default();
        relay_redacted(reader, &mut writer, &[]).unwrap();
        assert_eq!(writer.bytes, b"first\nsecond\n");
        assert_eq!(writer.flushes, 2);
    }

    #[test]
    fn credential_process_json_carries_the_full_contract() {
        let grant = vec![
            ("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string()),
            (
                "AWS_CREDENTIAL_EXPIRATION".to_string(),
                "2026-01-01T00:00:00Z".to_string(),
            ),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "sekrit".to_string()),
            ("AWS_SESSION_TOKEN".to_string(), "tok==".to_string()),
        ];
        let json: serde_json::Value =
            serde_json::from_str(&credential_process_json(&grant).unwrap()).unwrap();
        assert_eq!(json["Version"], 1);
        assert_eq!(json["AccessKeyId"], "AKIA123");
        assert_eq!(json["SecretAccessKey"], "sekrit");
        assert_eq!(json["SessionToken"], "tok==");
        assert_eq!(json["Expiration"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn credential_process_json_omits_absent_optionals_and_requires_keys() {
        let minimal = vec![
            ("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "sekrit".to_string()),
        ];
        let json: serde_json::Value =
            serde_json::from_str(&credential_process_json(&minimal).unwrap()).unwrap();
        assert!(json.get("SessionToken").is_none());
        assert!(json.get("Expiration").is_none());

        let missing = vec![("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string())];
        assert!(credential_process_json(&missing).is_err());
    }

    #[test]
    fn aws_profile_source_removes_aws_profile_from_child_environment() {
        let granted = vec![
            ("AWS_PROFILE".to_string(), "from-env-file".to_string()),
            ("OTHER".to_string(), "preserved".to_string()),
        ];
        let mut cmd = Command::new("true");

        configure_child_environment(&mut cmd, &granted, true);

        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();
        assert_eq!(env.get(OsStr::new("AWS_PROFILE")), Some(&None));
        assert_eq!(
            env.get(OsStr::new("OTHER")).and_then(|value| *value),
            Some(OsStr::new("preserved"))
        );
    }

    #[test]
    fn aws_session_config_points_credential_process_at_this_binary() {
        let config = aws_session_config(
            Path::new("/Users/u/.cargo/bin/sx"),
            "asi-dev/admin",
            Some("us-west-2"),
        );
        assert_eq!(
            config,
            "[default]\n\
             credential_process = \"/Users/u/.cargo/bin/sx\" credential-process --aws-profile \"asi-dev/admin\"\n\
             region = us-west-2\n"
        );
        let without_region = aws_session_config(Path::new("/bin/sx"), "prod", None);
        assert!(!without_region.contains("region"));
    }

    #[test]
    fn aws_session_config_path_sanitizes_profile_names() {
        let path = aws_session_config_path(Path::new("/Users/u"), "asi-dev/admin");
        assert_eq!(
            path,
            PathBuf::from("/Users/u/.sx/aws-session/asi-dev-admin.config")
        );
    }
}
