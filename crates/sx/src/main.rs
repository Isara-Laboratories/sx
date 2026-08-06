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
use std::os::unix::net::UnixStream;
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
    /// different window, up to a maximum of 24 hours (1d). A duration is an
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
        /// How long the grant lasts: 30m, 2h, 1d, or plain seconds (default 1h,
        /// max 24h).
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
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
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
            argv,
        } => {
            if env.is_empty() && aws_profile.is_empty() {
                anyhow::bail!("run requires at least one --env <path> or --aws-profile <profile>");
            }
            exec_with_secrets(env, aws_profile, argv, grant_all, renew, refresh)
        }
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
fn exec_with_secrets(
    env: Vec<String>,
    aws_profiles: Vec<String>,
    argv: Vec<String>,
    grant_all: bool,
    renew: bool,
    refresh: bool,
) -> Result<ExitCode> {
    let response = send(&Request::Run {
        env,
        aws_profiles,
        argv: argv.clone(),
        grant_all,
        renew,
        refresh,
    })?;

    let granted = match response {
        Response::Granted { secrets } => secrets,
        other => return Ok(render(other)),
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (name, value) in &granted {
        cmd.env(name, value);
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
}
