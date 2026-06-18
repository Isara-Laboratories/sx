//! Peer authentication over the unix socket.
//!
//! The daemon does not trust anything the client *says* about who it is or
//! where it runs. Instead it asks the kernel, via the socket, for the peer's
//! uid and pid, then derives the peer's working directory from that pid. This
//! is what lets us (a) reject connections from other users and (b) resolve
//! `.env` paths against the caller's *real* cwd rather than a spoofable field.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Authenticated identity of the process on the other end of the socket.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub uid: u32,
    pub pid: i32,
}

impl Peer {
    /// Read the peer's credentials from the connected socket.
    pub fn from_stream(stream: &UnixStream) -> io::Result<Peer> {
        let fd = stream.as_raw_fd();
        let uid = peer_uid(fd)?;
        let pid = peer_pid(fd)?;
        Ok(Peer { uid, pid })
    }

    /// The working directory of the peer process (derived from its pid).
    pub fn cwd(&self) -> io::Result<PathBuf> {
        pid_cwd(self.pid)
    }
}

/// The uid the daemon itself runs as. Connections from any other uid are
/// refused — only the owning user may reach their own secrets.
pub fn own_uid() -> u32 {
    // Safety: getuid is always safe and cannot fail.
    unsafe { libc::getuid() }
}

/// Peer effective uid via `getpeereid`.
#[cfg(target_os = "macos")]
fn peer_uid(fd: i32) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // Safety: fd is a valid connected socket; out-params are owned locals.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid as u32)
}

#[cfg(target_os = "linux")]
fn peer_cred(fd: i32) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // Safety: valid socket fd; buffer/len sized to a ucred.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

/// Peer uid via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn peer_uid(fd: i32) -> io::Result<u32> {
    Ok(peer_cred(fd)?.uid as u32)
}

#[cfg(target_os = "macos")]
fn peer_pid(fd: i32) -> io::Result<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // Safety: valid socket fd; buffer/len sized to a pid_t.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn peer_pid(fd: i32) -> io::Result<i32> {
    Ok(peer_cred(fd)?.pid)
}

/// macOS: derive cwd from a pid via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`.
#[cfg(target_os = "macos")]
fn pid_cwd(pid: i32) -> io::Result<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
    // Safety: info is a correctly-sized, zeroed target buffer.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }

    // vip_path is a NUL-terminated path in a fixed 1024-byte buffer
    // (declared as [[c_char; 32]; 32] in libc to satisfy old rustc).
    let raw = &info.pvi_cdir.vip_path;
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(raw.as_ptr() as *const u8, std::mem::size_of_val(raw))
    };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}

/// Linux: cwd is the `/proc/<pid>/cwd` symlink target.
#[cfg(target_os = "linux")]
fn pid_cwd(pid: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pid_cwd(_pid: i32) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer cwd derivation not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_from_stream_reads_linux_socket_credentials() {
        let (_client, server) = UnixStream::pair().unwrap();

        let peer = Peer::from_stream(&server).unwrap();

        assert_eq!(peer.uid, own_uid());
        assert_eq!(peer.pid, std::process::id() as i32);
    }
}
