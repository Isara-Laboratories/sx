//! `sx` — the in-sandbox client.
//!
//! Deliberately powerless: it never reads `.env` files or secret values. It
//! only forwards paths, secret *names*, and argv to the daemon over the unix
//! socket and prints the (already redacted) result. Even if the agent fully
//! controls this process, the most it can do is *ask* the daemon — which
//! gates every request behind the user.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

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
    let cwd = std::env::current_dir()
        .context("getting current directory")?
        .to_string_lossy()
        .into_owned();

    let request = match cli.command {
        Cmd::Capture { path, ttl } => Request::Capture {
            path,
            cwd,
            ttl_secs: Some(ttl * 60),
        },
        Cmd::Clear { path } => Request::Clear { path },
        Cmd::Status | Cmd::List => Request::Status,
        Cmd::Run { secrets, argv } => Request::Run { secrets, argv, cwd },
    };

    let response = send(&request)?;
    Ok(render(response))
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
        Response::Ran {
            code,
            stdout,
            stderr,
        } => {
            print!("{stdout}");
            eprint!("{stderr}");
            ExitCode::from(u8::try_from(code).unwrap_or(1))
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
