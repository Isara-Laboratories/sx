//! Persistent `sxd` configuration in `$HOME/.sx/config`.
//!
//! This is a tiny `KEY=VALUE` file (the same `~/.sx` directory that already
//! holds the socket and the log). It exists so that values which must be
//! resolved in the *user's real shell environment* can be captured ONCE at an
//! install/setup step and then read back by the daemon — which runs under a
//! deliberately minimal environment.
//!
//! ## Why this file exists at all: launchd's minimal `$PATH`
//!
//! `sxd` is started by a per-user **LaunchAgent**. launchd does NOT inherit the
//! user's login shell environment; it hands the daemon a bare `$PATH` of
//! roughly `/usr/bin:/bin:/usr/sbin:/sbin`. So a `Command::new("aws")` inside
//! the daemon fails with "No such file or directory" even though `aws` is
//! sitting in `/usr/local/bin` or `/opt/homebrew/bin` on the user's interactive
//! `$PATH`. Augmenting the daemon's `$PATH` with guessed directories is brittle
//! (every machine differs). Instead we resolve the absolute path to `aws`
//! exactly once, at `sxd setup` / `sxd install` time — which DOES run with the
//! user's full shell `$PATH` — and persist it here. The daemon then spawns that
//! stored absolute path verbatim and never searches `$PATH` at runtime.
//!
//! The format is intentionally minimal: `KEY=VALUE`, one per line. We reuse the
//! existing `dotenvy` parser for reads and write the file back ourselves,
//! preserving any keys we don't recognize so the file stays forward-compatible.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

/// Config key holding the absolute path to the `aws` CLI executable, resolved
/// at setup time. Read verbatim by the daemon when minting AWS credentials.
pub const AWS_CLI_PATH: &str = "aws_cli_path";

/// `$HOME`, or an error if it is unset (the daemon always runs as the user).
fn home_dir() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))
}

/// The `~/.sx` directory (socket + log + this config live here).
pub fn sx_dir() -> io::Result<PathBuf> {
    Ok(home_dir()?.join(".sx"))
}

/// Absolute path to the config file (`~/.sx/config`).
pub fn config_path() -> io::Result<PathBuf> {
    Ok(sx_dir()?.join("config"))
}

/// Read a single config key from `~/.sx/config`.
///
/// Returns `Ok(None)` when the file is absent or the key is unset — a missing
/// config is "not configured", never an error.
pub fn get(key: &str) -> io::Result<Option<String>> {
    read_value(&config_path()?, key)
}

/// Set a single config key in `~/.sx/config`, creating `~/.sx/` if needed and
/// preserving every other key already present in the file.
pub fn set(key: &str, value: &str) -> io::Result<()> {
    std::fs::create_dir_all(sx_dir()?)?;
    write_value(&config_path()?, key, value)
}

/// Read every `KEY=VALUE` pair from `path`. A missing file yields an empty map.
fn read_all(path: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    if !path.exists() {
        return Ok(map);
    }
    for item in dotenvy::from_path_iter(path).map_err(to_io)? {
        let (k, v) = item.map_err(to_io)?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Read one key from the file at `path` (testable core of [`get`]).
fn read_value(path: &Path, key: &str) -> io::Result<Option<String>> {
    Ok(read_all(path)?.remove(key))
}

/// Insert/update `key` in the file at `path`, preserving other keys (testable
/// core of [`set`]). The caller is responsible for creating the directory.
fn write_value(path: &Path, key: &str, value: &str) -> io::Result<()> {
    let mut map = read_all(path)?;
    map.insert(key.to_string(), value.to_string());
    let mut out = String::new();
    for (k, v) in &map {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    std::fs::write(path, out)
}

/// Map a `dotenvy` parse error into an `io::Error` so this module's surface is
/// uniformly `io::Result`.
fn to_io(e: dotenvy::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// True if `p` is an existing regular file with at least one execute bit set.
///
/// The daemon uses this to validate the configured `aws` path before spawning
/// it (so a stale config produces a clear "re-run `sxd setup`" error instead of
/// a cryptic exec failure), and discovery uses it to pick PATH entries.
pub fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

/// Locate the `aws` executable for persisting at setup time.
///
/// This runs in the user's real shell environment (full `$PATH`), NOT inside
/// the daemon. We scan the entries of the *current process's* `$PATH` (split on
/// `:`) and return the first one that holds an executable file named `aws`. As
/// a last resort — only when `$PATH` yields nothing — we probe a couple of
/// well-known install locations. The daemon never calls this: it reads the
/// already-resolved absolute path from the config file.
pub fn discover_aws_cli() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(found) = find_on_path(&path, "aws") {
            return Some(found);
        }
    }
    // Last-resort fallback for the (rare) case where the setup step itself ran
    // with a stripped PATH. PATH is always the primary source above.
    for cand in ["/usr/local/bin/aws", "/opt/homebrew/bin/aws"] {
        let p = PathBuf::from(cand);
        if is_executable_file(&p) {
            return Some(p);
        }
    }
    None
}

/// Scan `path_var` (a `$PATH`-style `:`-separated list) for an executable file
/// named `name`, returning the first absolute match. Testable core of
/// [`discover_aws_cli`].
fn find_on_path(path_var: &OsStr, name: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_var) {
        let cand = dir.join(name);
        if is_executable_file(&cand) {
            // Prefer an absolute path so the daemon can spawn it verbatim; fall
            // back to the joined candidate if canonicalization fails.
            return Some(cand.canonicalize().unwrap_or(cand));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A throwaway directory under the system temp dir, unique per call and
    /// removed on drop — avoids adding a `tempfile` dev-dependency.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("sxd-cfg-test-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_file_reads_as_not_configured() {
        let dir = TempDir::new();
        let cfg = dir.path().join("config");
        assert!(read_value(&cfg, AWS_CLI_PATH).unwrap().is_none());
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = TempDir::new();
        let cfg = dir.path().join("config");
        write_value(&cfg, AWS_CLI_PATH, "/usr/local/bin/aws").unwrap();
        assert_eq!(
            read_value(&cfg, AWS_CLI_PATH).unwrap().as_deref(),
            Some("/usr/local/bin/aws")
        );
    }

    #[test]
    fn write_preserves_other_keys() {
        let dir = TempDir::new();
        let cfg = dir.path().join("config");
        std::fs::write(&cfg, "other_key=keep-me\naws_cli_path=/old/aws\n").unwrap();
        write_value(&cfg, AWS_CLI_PATH, "/new/aws").unwrap();
        assert_eq!(
            read_value(&cfg, "other_key").unwrap().as_deref(),
            Some("keep-me")
        );
        assert_eq!(
            read_value(&cfg, AWS_CLI_PATH).unwrap().as_deref(),
            Some("/new/aws")
        );
    }

    #[test]
    fn discovers_executable_aws_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let bin = TempDir::new();
        let aws = bin.path().join("aws");
        std::fs::write(&aws, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();

        // A PATH whose first entry has no `aws`, second entry does.
        let empty = TempDir::new();
        let path_var = std::env::join_paths([empty.path(), bin.path()]).unwrap();
        let found = find_on_path(&path_var, "aws").expect("should find aws");
        assert_eq!(found, aws.canonicalize().unwrap());
    }

    #[test]
    fn non_executable_aws_is_ignored() {
        let bin = TempDir::new();
        // A plain (non-executable) file named `aws` must not match.
        std::fs::write(bin.path().join("aws"), "not executable").unwrap();
        let path_var: OsString = bin.path().as_os_str().to_owned();
        assert!(find_on_path(&path_var, "aws").is_none());
    }
}
