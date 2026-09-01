/// Disables core dumps for this process unconditionally, independent of
/// whether Tier B (decrypted TLS content) is ever used in this run. Cheap,
/// no functional downside, closes the gap where a crash while the ring
/// buffer holds live plaintext could otherwise leave a core file on disk
/// (spec Security model summary).
pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_core_dumps_sets_the_soft_and_hard_limit_to_zero() {
        disable_core_dumps().expect("setrlimit should succeed for a self-limit lowering");
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(rc, 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}
