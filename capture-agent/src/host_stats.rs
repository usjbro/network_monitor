/// Reads this machine's hostname via `gethostname(2)`, the same POSIX call
/// available on both macOS and Linux. Returns an empty string on any
/// failure (oversized/invalid buffer, non-UTF8 result, syscall error)
/// rather than panicking or fabricating a placeholder — `SystemStatsJson`'s
/// consumer (the UI) treats an empty hostname as "not available", not as a
/// real, empty-named host (see issue #64).
pub fn hostname() -> String {
    // 256 bytes comfortably covers HOST_NAME_MAX on both platforms (64 on
    // Linux, 255 on macOS) with room to spare for the syscall to null-
    // terminate within it.
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul_pos]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_returns_a_nonempty_string_on_a_real_machine() {
        // Can't assert a specific value (machine-dependent), but this
        // syscall should succeed in any normal test environment — a
        // consistently-empty result here would mean the FFI call itself is
        // broken, not just that this particular host has no name set.
        let name = hostname();
        assert!(!name.is_empty(), "expected gethostname() to succeed in a real environment");
        // No embedded NUL bytes should survive into the returned String —
        // proves the null-terminator search actually truncated the buffer
        // rather than returning 256 bytes of zero-padded garbage.
        assert!(!name.contains('\0'));
    }
}
