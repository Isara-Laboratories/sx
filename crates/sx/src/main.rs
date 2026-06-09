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

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sx_proto::{socket_path, Request, Response};

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
    /// Capture the secrets in a .env file (TouchID-gated, time-boxed).
    Capture {
        /// Path to the .env file (resolved by the daemon, relative to cwd).
        path: String,
        /// How long the capture stays live, in minutes.
        #[arg(long, default_value_t = 60)]
        ttl: u64,
    },
    /// Drop captured secrets — a single source path, or all of them.
    Clear {
        /// Source path to clear; omit to clear everything.
        path: Option<String>,
    },
    /// Show active captures and the secret names they expose (never values).
    Status,
    /// Alias for `status`, framed as "what secrets can I use right now".
    List,
    /// Run a command with named secrets injected into the child only.
    ///
    /// Example: sx run -s GITHUB_TOKEN -- gh pr create
    Run {
        /// Secret name to inject (repeatable).
        #[arg(short = 's', long = "secret")]
        secrets: Vec<String>,
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
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
    // Note: we deliberately do NOT send our cwd. For `capture`, the daemon
    // derives the caller's working directory from the verified peer pid, so a
    // compromised client cannot point it at an arbitrary `.env`. For `run`, the
    // child simply inherits our own cwd.
    match cli.command {
        Cmd::Run { secrets, argv } => exec_with_secrets(secrets, argv),
        Cmd::Capture { path, ttl } => Ok(render(send(&Request::Capture {
            path,
            ttl_secs: Some(ttl * 60),
        })?)),
        Cmd::Clear { path } => Ok(render(send(&Request::Clear { path })?)),
        Cmd::Status | Cmd::List => Ok(render(send(&Request::Status)?)),
    }
}

/// Ask the daemon (gated) for the named secrets, then inject and exec `argv`
/// as our own child, redacting the secret values from its output.
fn exec_with_secrets(secrets: Vec<String>, argv: Vec<String>) -> Result<ExitCode> {
    let response = send(&Request::Run {
        secrets,
        argv: argv.clone(),
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

    let output = cmd
        .output()
        .with_context(|| format!("running {}", argv[0]))?;

    // Redact the injected values from whatever the command emitted before it
    // reaches our stdout/stderr (which the agent sees).
    let values: Vec<&str> = granted.iter().map(|(_, v)| v.as_str()).collect();
    print!("{}", redact(String::from_utf8_lossy(&output.stdout), &values));
    eprint!("{}", redact(String::from_utf8_lossy(&output.stderr), &values));

    Ok(ExitCode::from(
        u8::try_from(output.status.code().unwrap_or(1)).unwrap_or(1),
    ))
}

/// Replace every (non-empty) secret value in `text` with a placeholder.
fn redact(text: std::borrow::Cow<'_, str>, values: &[&str]) -> String {
    let mut text = text.into_owned();
    for v in values {
        if v.is_empty() {
            continue;
        }
        text = text.replace(v, "‹redacted›");
    }
    text
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
        Response::Captured {
            source,
            names,
            expires_in_secs,
        } => {
            println!(
                "captured {} secret(s) from {source} (expires in {}m):",
                names.len(),
                expires_in_secs / 60
            );
            for n in names {
                println!("  {n}");
            }
            ExitCode::SUCCESS
        }
        Response::Status { captures } => {
            if captures.is_empty() {
                println!("no active captures");
            } else {
                for c in captures {
                    println!("{} (expires in {}m)", c.source, c.expires_in_secs / 60);
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
        Response::Error { message } => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
