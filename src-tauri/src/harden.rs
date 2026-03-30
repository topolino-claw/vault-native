/// Apply platform-specific process hardening.
/// Best-effort: logs warnings on failure but doesn't crash the app.
pub fn apply() {
    #[cfg(target_os = "macos")]
    harden_macos();

    #[cfg(target_os = "linux")]
    harden_linux();

    // Windows: no direct equivalent. WER crash dump settings are registry-level.
}

#[cfg(target_os = "macos")]
fn harden_macos() {
    // PT_DENY_ATTACH: prevent debuggers from attaching to this process.
    // This blocks casual `lldb -p <pid>` attachment.
    // Root or SIP-disabled systems can bypass this, but it raises the bar.
    unsafe {
        let pt_deny_attach: libc::c_int = 31; // PT_DENY_ATTACH
        let ret = libc::ptrace(pt_deny_attach, 0, std::ptr::null_mut(), 0);
        if ret != 0 {
            eprintln!(
                "[harden] PT_DENY_ATTACH failed (errno={}). Debugger attachment not blocked.",
                *libc::__error()
            );
        }
    }

    // Disable core dumps
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            eprintln!("[harden] Failed to disable core dumps on macOS.");
        }
    }
}

#[cfg(target_os = "linux")]
fn harden_linux() {
    // PR_SET_DUMPABLE: prevent core dumps and /proc/pid/mem access by non-root.
    unsafe {
        let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if ret != 0 {
            eprintln!("[harden] PR_SET_DUMPABLE(0) failed. Core dumps not disabled.");
        }
    }

    // Disable core dumps via rlimit
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            eprintln!("[harden] Failed to disable core dumps via RLIMIT_CORE.");
        }
    }
}
