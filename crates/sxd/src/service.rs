//! Self-installation as a per-user auto-start service.
//!
//! On macOS this is a **LaunchAgent** (not a LaunchDaemon): `sxd` presents
//! TouchID/LocalAuthentication prompts, which can only be shown from within the
//! user's GUI session, and it must run as the user so the peer-credential uid
//! check matches. A LaunchAgent in `~/Library/LaunchAgents` satisfies both;
//! with `RunAtLoad` + `KeepAlive` it starts at login and respawns if it dies.

use std::io;
/// launchd / service label (reverse-DNS-ish).
#[cfg(target_os = "macos")]
const LABEL: &str = "dev.sx.sxd";

/// Install and start the auto-start service. `dry_run` prints what would happen
/// without writing files or touching the service manager.
pub fn install(dry_run: bool) -> io::Result<()> {
    platform::install(dry_run)
}

/// Stop and remove the auto-start service.
pub fn uninstall() -> io::Result<()> {
    platform::uninstall()
}

fn home_dir() -> io::Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))
}

/// Minimal XML text escaping for values embedded in the plist.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::process::Command;

    pub fn install(dry_run: bool) -> io::Result<()> {
        let exe = std::env::current_exe()?;
        let home = home_dir()?;
        let agents = home.join("Library/LaunchAgents");
        let sx_dir = home.join(".sx");
        let log = sx_dir.join("sxd.log");
        let plist_path = agents.join(format!("{LABEL}.plist"));
        let plist = plist_contents(&exe, &log);

        let uid = crate::peer::own_uid().to_string();
        let domain = format!("gui/{uid}");
        let service_target = format!("{domain}/{LABEL}");

        if dry_run {
            println!("# would write {}:\n", plist_path.display());
            println!("{plist}");
            println!("# would run:");
            println!("launchctl bootout {service_target}    # (ignore failure)");
            println!("launchctl bootstrap {domain} {}", plist_path.display());
            println!("launchctl enable {service_target}");
            println!("launchctl kickstart -k {service_target}");
            return Ok(());
        }

        std::fs::create_dir_all(&agents)?;
        std::fs::create_dir_all(&sx_dir)?;
        std::fs::write(&plist_path, plist)?;

        // Reload cleanly: tolerate "not currently loaded" on bootout.
        let _ = launchctl(&["bootout", &service_target]);
        require(launchctl(&[
            "bootstrap",
            &domain,
            plist_path.to_str().unwrap(),
        ])?)?;
        let _ = launchctl(&["enable", &service_target]);
        let _ = launchctl(&["kickstart", "-k", &service_target]);

        println!("Installed LaunchAgent {LABEL}");
        println!("  plist: {}", plist_path.display());
        println!("  log:   {}", log.display());
        println!("sxd now starts at login and is running.");
        println!("Check it:  launchctl print {service_target}");
        Ok(())
    }

    pub fn uninstall() -> io::Result<()> {
        let home = home_dir()?;
        let plist_path = home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"));
        let uid = crate::peer::own_uid().to_string();
        let _ = launchctl(&["bootout", &format!("gui/{uid}/{LABEL}")]);
        if plist_path.exists() {
            std::fs::remove_file(&plist_path)?;
        }
        println!("Removed LaunchAgent {LABEL} ({})", plist_path.display());
        Ok(())
    }

    fn plist_contents(exe: &Path, log: &Path) -> String {
        // Carry SX_SOCKET into the agent if the installer set a custom one, so
        // the daemon and clients agree on the socket path.
        let env_block = match std::env::var("SX_SOCKET") {
            Ok(sock) => format!(
                "    <key>EnvironmentVariables</key>\n    \
                 <dict>\n        <key>SX_SOCKET</key>\n        \
                 <string>{}</string>\n    </dict>\n",
                xml_escape(&sock)
            ),
            Err(_) => String::new(),
        };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
{env_block}    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
            label = LABEL,
            exe = xml_escape(&exe.display().to_string()),
            log = xml_escape(&log.display().to_string()),
        )
    }

    fn launchctl(args: &[&str]) -> io::Result<std::process::ExitStatus> {
        Command::new("launchctl").args(args).status()
    }

    fn require(status: std::process::ExitStatus) -> io::Result<()> {
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("launchctl failed: {status}")))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    pub fn install(_dry_run: bool) -> io::Result<()> {
        // Linux auto-start needs a GUI approval gate: a headless systemd unit
        // would run the terminal gate with no TTY and deny every request. Until
        // a GUI gate exists, refuse rather than install something broken.
        let _ = (home_dir(), xml_escape("")); // keep helpers referenced
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "auto-start install is only implemented on macOS so far \
             (Linux needs a GUI approval gate; run `sxd` manually meanwhile)",
        ))
    }

    pub fn uninstall() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "auto-start install is only implemented on macOS so far",
        ))
    }
}
