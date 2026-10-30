//! Process hardening, applied before any key or secret is loaded. Failure is fatal: the server refuses
//! to run in a state where a secret could reach swap or a core dump.

#![allow(unsafe_code)] // setrlimit/prctl/mlockall: no safe wrappers in std

use std::io;

pub fn harden_process() -> Result<(), String> {
    // SAFETY: plain syscalls with valid arguments.
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
            return Err(format!("setrlimit(RLIMIT_CORE): {}", io::Error::last_os_error()));
        }
        #[cfg(target_os = "linux")]
        {
            // Not dumpable: no core dumps, and no ptrace or /proc/<pid>/mem by the same (non-root) user.
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(format!("prctl(PR_SET_DUMPABLE): {}", io::Error::last_os_error()));
            }
            // Never gain privileges through exec (we never exec, but make it impossible).
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(format!("prctl(PR_SET_NO_NEW_PRIVS): {}", io::Error::last_os_error()));
            }
        }
        // All memory, now and future, locked into RAM: nothing can be swapped out. Needs CAP_IPC_LOCK or
        // an unlimited memlock ulimit (the compose files set the ulimit and grant no capability).
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            return Err(format!("mlockall: {} (run with --ulimit memlock=-1)", io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Turns on TCP keepalive (`SO_KEEPALIVE`) for an accepted connection (best effort). A firewall or NAT that silently forgets
/// the flow, leaving the peer unable to send a FIN or RST, is then detected by the kernel and the socket
/// errors out, so the server thread handling it is not pinned forever.
pub fn enable_keepalive<F: std::os::unix::io::AsRawFd>(sock: &F) {
    let on: libc::c_int = 1;
    let len = libc::socklen_t::try_from(std::mem::size_of_val(&on)).unwrap_or(0);
    // SAFETY: a valid fd, a known level/option, and an option value of the size the kernel expects.
    unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE, std::ptr::addr_of!(on).cast(), len);
    }
}

/// Makes a close send a TCP RST instead of a FIN (tests only), to exercise the abrupt-reset path.
#[cfg(test)]
pub fn set_linger_zero<F: std::os::unix::io::AsRawFd>(sock: &F) {
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    let len = libc::socklen_t::try_from(std::mem::size_of_val(&l)).unwrap_or(0);
    // SAFETY: a valid fd, SO_LINGER, and a correctly sized `struct linger`.
    unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, std::ptr::addr_of!(l).cast(), len);
    }
}

/// Reads back `SO_KEEPALIVE` (tests only), to prove `enable_keepalive` took effect.
#[cfg(test)]
pub fn keepalive_enabled<F: std::os::unix::io::AsRawFd>(sock: &F) -> bool {
    let mut on: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&on)).unwrap_or(0);
    // SAFETY: a valid fd, a known level/option, and out-params of the matching size.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            std::ptr::addr_of_mut!(on).cast(),
            &mut len,
        )
    };
    rc == 0 && on != 0
}
