//! Wire protocol shared between the `sx` client and the `sxd` daemon.
//!
//! Transport is newline-delimited JSON over a unix domain socket: the client
//! writes exactly one [`Request`] followed by `\n`, the daemon replies with
//! exactly one [`Response`] followed by `\n`.
//!
//! The client is the *in-sandbox* half and is deliberately incapable of
//! reading secret material: it only ever passes paths, names, and argv. The
//! daemon is the *out-of-sandbox* half that actually touches secrets.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Environment variable that overrides the default socket path.
pub const SOCKET_ENV: &str = "SX_SOCKET";

/// Default capture lifetime if the client does not specify one.
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Resolve the unix socket path both halves agree on.
///
/// Honors `$SX_SOCKET`, otherwise falls back to `$HOME/.sx/sxd.sock`.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var(SOCKET_ENV) {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".sx").join("sxd.sock")
}

/// A request from the client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Capture the secrets defined in a `.env` file into the daemon.
    ///
    /// This is the time-boxed outer envelope ("capture security"): it is
    /// TouchID-gated and the captured values live only in daemon memory until
    /// `ttl_secs` elapses or they are explicitly cleared. The client never
    /// reads the file — `path` is resolved (relative to `cwd`) by the daemon.
    Capture {
        path: String,
        cwd: String,
        ttl_secs: Option<u64>,
    },

    /// Drop captured secrets — a single source path, or all of them.
    Clear { path: Option<String> },

    /// Report active captures and the secret names they expose (never values).
    Status,

    /// Run `argv` with `secrets` injected into the child process only.
    ///
    /// Requires (a) an active capture providing every requested name, and
    /// (b) a per-use approval — the inner gate. The child's output is
    /// redacted of the injected values before being returned.
    Run {
        secrets: Vec<String>,
        argv: Vec<String>,
        cwd: String,
    },
}

/// A response from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Generic success with a human-readable message.
    Ok { message: String },

    /// A capture succeeded; reports the names made available (no values).
    Captured {
        source: String,
        names: Vec<String>,
        expires_in_secs: u64,
    },

    /// Current daemon state.
    Status { captures: Vec<CaptureInfo> },

    /// A command finished. Output is already redacted.
    Ran {
        code: i32,
        stdout: String,
        stderr: String,
    },

    /// A gate (capture or per-use) refused, or a precondition failed.
    Denied { reason: String },

    /// The daemon hit an internal error handling the request.
    Error { message: String },
}

/// Summary of one active capture, safe to show the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInfo {
    pub source: String,
    pub names: Vec<String>,
    pub expires_in_secs: u64,
}
