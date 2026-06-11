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

/// Lifetime of a grant: how long a `.env` stays usable after its first run
/// before the next run re-prompts. One hour.
///
/// This is the default for every grant, and the fixed lease for `sx run` and
/// allow-all upgrades reached from `run`. Only `sx grant-all --lease` can pick
/// a different value, up to [`GRANT_TTL_MAX_SECS`].
pub const GRANT_TTL_SECS: u64 = 3600;

/// Hard ceiling on a grant lease: 24 hours. `sx grant-all --lease` may request
/// any duration up to (and including) this; a longer lease is rejected rather
/// than silently clamped.
pub const GRANT_TTL_MAX_SECS: u64 = 86_400;

/// Parse a human-friendly duration into whole seconds.
///
/// Accepts an unsigned integer with an optional unit suffix:
/// `s` (seconds, the default when omitted), `m` (minutes), `h` (hours), or
/// `d` (days). Examples: `45` → 45s, `30m` → 1800s, `2h` → 7200s, `1d` →
/// 86400s.
///
/// Rejects empty input, zero, negative or non-numeric values, unknown unit
/// suffixes, and any duration exceeding [`GRANT_TTL_MAX_SECS`]. The `Err` is a
/// human-readable message suitable for surfacing directly to the user (e.g. as
/// a clap `value_parser` error).
pub fn parse_duration(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration; use e.g. 30m, 2h, 1d, or 45".to_string());
    }

    let (digits, multiplier) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let mult = match c {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                _ => {
                    return Err(format!(
                        "invalid duration unit '{c}' in {s:?}; use s, m, h, or d"
                    ))
                }
            };
            (&s[..s.len() - c.len_utf8()], mult)
        }
        _ => (s, 1),
    };

    let n: u64 = digits.parse().map_err(|_| {
        format!("invalid duration {s:?}; expected a number optionally followed by s, m, h, or d")
    })?;

    let secs = n
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration {s:?} is too large"))?;

    if secs == 0 {
        return Err("duration must be greater than zero".to_string());
    }
    if secs > GRANT_TTL_MAX_SECS {
        return Err(format!(
            "lease {} exceeds maximum of {}",
            humanize_secs(secs),
            humanize_secs(GRANT_TTL_MAX_SECS)
        ));
    }
    Ok(secs)
}

/// Render a whole-second duration as a short human-readable string, choosing
/// the largest unit that divides it evenly (`86400` → "1 day", `7200` → "2
/// hours", `1800` → "30 minutes", `45` → "45 seconds"). Used in prompts and
/// error messages.
pub fn humanize_secs(secs: u64) -> String {
    let (n, unit) = if secs.is_multiple_of(86_400) {
        (secs / 86_400, "day")
    } else if secs.is_multiple_of(3600) {
        (secs / 3600, "hour")
    } else if secs.is_multiple_of(60) {
        (secs / 60, "minute")
    } else {
        (secs, "second")
    };
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{plural}")
}

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
    /// Drop granted sources — a single source (an `.env` path or an
    /// `aws:<profile>` key), or all of them when `path` is `None`.
    Clear { path: Option<String> },

    /// Report active grants and the secret names they expose (never values).
    Status,

    /// Pre-authorize one or more secret sources in *allow-all* mode: grant the
    /// source for an hour AND suppress the per-command prompt for that window.
    /// Runs no command — `sx grant-all --env <path> --aws-profile <name>`.
    ///
    /// Sources are either `.env` file paths (`env`) or named AWS profiles
    /// (`aws_profiles`); both kinds are gated and TTL'd identically.
    GrantAll {
        env: Vec<String>,
        /// AWS profile names to mint temporary credentials from.
        #[serde(default)]
        aws_profiles: Vec<String>,
        /// Optional lease for the grant, in seconds. `None` (older clients or an
        /// omitted `--lease`) falls back to [`GRANT_TTL_SECS`]; the daemon
        /// rejects anything over [`GRANT_TTL_MAX_SECS`].
        #[serde(default)]
        lease_secs: Option<u64>,
    },

    /// Request the secrets from one or more sources in order to run `argv`.
    ///
    /// The daemon does NOT execute anything. Sources come in two flavors:
    ///
    /// * `env` — `.env` file paths, resolved against the caller's *verified*
    ///   cwd (derived from the peer pid, not sent here) and canonicalized.
    /// * `aws_profiles` — named AWS profiles; the daemon mints temporary
    ///   credentials by shelling out to `aws configure export-credentials` and
    ///   injects the resulting `AWS_*` env vars. Keyed under `aws:<profile>`,
    ///   never touched by filesystem resolution.
    ///
    /// Two independent gates apply to every source:
    ///
    /// * **file grant** — on first use of a source, a 1h TouchID grant reads
    ///   (or mints) its values into memory; later runs reuse them.
    /// * **per-command** — by default *every* run prompts to approve this
    ///   specific command. A source in allow-all mode (via [`Request::GrantAll`]
    ///   or `grant_all` here) skips this prompt for its window.
    ///
    /// It returns the merged values via [`Response::Granted`]; the client (`sx`)
    /// injects them and execs `argv` itself. `argv` is sent so the daemon can
    /// show it at the per-command prompt; the daemon does not run it.
    Run {
        env: Vec<String>,
        /// AWS profile names to mint temporary credentials from.
        #[serde(default)]
        aws_profiles: Vec<String>,
        argv: Vec<String>,
        /// Upgrade the sources used here to allow-all for the rest of their grant.
        grant_all: bool,
    },
}

/// A response from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Generic success with a human-readable message.
    Ok { message: String },

    /// Current daemon state.
    Status { captures: Vec<CaptureInfo> },

    /// The per-use gate approved: here are the requested secret values for the
    /// client to inject into the child it is about to exec. This is the only
    /// message that carries plaintext, and only to an (eventually attested)
    /// in-sandbox `sx`. `secrets` preserves request order as (name, value).
    Granted { secrets: Vec<(String, String)> },

    /// A gate (capture or per-use) refused, or a precondition failed.
    Denied { reason: String },

    /// The daemon hit an internal error handling the request.
    Error { message: String },
}

/// Summary of one active grant, safe to show the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInfo {
    /// Source identity: a canonical `.env` path, or `aws:<profile>` for an
    /// AWS-profile grant.
    pub source: String,
    pub names: Vec<String>,
    pub expires_in_secs: u64,
    /// True when this source is in allow-all mode (no per-command prompt).
    pub allow_all: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_seconds_and_units() {
        assert_eq!(parse_duration("45").unwrap(), 45);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86_400);
        assert_eq!(parse_duration("90s").unwrap(), 90);
    }

    #[test]
    fn parses_at_the_maximum() {
        assert_eq!(parse_duration("24h").unwrap(), GRANT_TTL_MAX_SECS);
        assert_eq!(parse_duration("1440m").unwrap(), GRANT_TTL_MAX_SECS);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_duration("  2h  ").unwrap(), 7200);
    }

    #[test]
    fn rejects_empty_zero_and_negative() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("-5").is_err());
    }

    #[test]
    fn rejects_unknown_units_and_garbage() {
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("1.5h").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn rejects_over_maximum() {
        let err = parse_duration("2d").unwrap_err();
        assert!(err.contains("exceeds maximum"), "got: {err}");
        assert!(parse_duration("25h").is_err());
        assert!(parse_duration("86401").is_err());
    }

    #[test]
    fn humanizes_largest_even_unit() {
        assert_eq!(humanize_secs(86_400), "1 day");
        assert_eq!(humanize_secs(172_800), "2 days");
        assert_eq!(humanize_secs(3600), "1 hour");
        assert_eq!(humanize_secs(7200), "2 hours");
        assert_eq!(humanize_secs(1800), "30 minutes");
        assert_eq!(humanize_secs(60), "1 minute");
        assert_eq!(humanize_secs(45), "45 seconds");
    }
}
