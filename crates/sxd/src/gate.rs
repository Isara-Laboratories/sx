//! Human-approval gates.
//!
//! Two gates exist conceptually:
//!   * the *capture* gate — TouchID before a `.env` is read into memory;
//!   * the *per-use* gate — confirmation before each `run` releases a secret.
//!
//! Both share this trait so a single implementation (terminal confirm today,
//! TouchID/`LocalAuthentication` next) backs them. The daemon runs on a TTY
//! the user controls, *outside* the agent's sandbox, so prompting here is a
//! real out-of-band checkpoint the agent cannot answer on the user's behalf.

use std::io::{self, BufRead, Write};

/// Anything that can ask the user to approve an action.
pub trait ApprovalGate: Send + Sync {
    /// Show `prompt` and return whether the user approved.
    fn approve(&self, prompt: &str) -> bool;
}

/// Approve by reading a yes/no answer on the daemon's own stdin.
///
/// Portable default. On macOS this is where a `TouchIdGate` backed by
/// `LAContext` / `kSecAccessControl` will slot in (TODO).
pub struct CliGate;

impl ApprovalGate for CliGate {
    fn approve(&self, prompt: &str) -> bool {
        let stderr = io::stderr();
        let mut err = stderr.lock();
        let _ = writeln!(err, "\n┌─ sx approval ─────────────────────────────");
        for line in prompt.lines() {
            let _ = writeln!(err, "│ {line}");
        }
        let _ = write!(err, "└─ approve? [y/N] ");
        let _ = err.flush();

        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

/// Approve everything without prompting. For tests and `--no-gate` only.
pub struct AllowAllGate;

impl ApprovalGate for AllowAllGate {
    fn approve(&self, _prompt: &str) -> bool {
        true
    }
}
