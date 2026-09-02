use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SessionSecret {
    pub client_random: Vec<u8>,
    pub label: String,
    pub secret: Vec<u8>,
}

/// Parses one line of an `SSLKEYLOGFILE`-format file:
/// `<LABEL> <client_random hex> <secret hex>`. Strict about the shape —
/// blank lines and `#`-prefixed comments are expected and silently skipped;
/// anything else that doesn't parse cleanly (wrong number of fields,
/// non-hex data) is also just skipped, never panics, matching this agent's
/// existing tolerance for malformed/attacker-influenced input.
pub fn parse_keylog_line(line: &str) -> Option<SessionSecret> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let label = parts.next()?.to_string();
    let client_random = hex::decode(parts.next()?).ok()?;
    let secret = hex::decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None; // unexpected extra field — be strict, not lenient-to-garbage
    }
    Some(SessionSecret { client_random, label, secret })
}

struct WatchedFile {
    path: PathBuf,
    offset: u64,
}

pub struct KeyLogWatcher {
    eligible: HashMap<u32, WatchedFile>,
    // Keyed by client_random for lookup; multiple labels (handshake vs.
    // application traffic secrets) per client_random are collapsed to "last
    // one wins" deliberately — tls_decrypt.rs is responsible for
    // picking which label it actually needs at decrypt time, not this store.
    secrets: HashMap<Vec<u8>, SessionSecret>,
}

impl Default for KeyLogWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLogWatcher {
    pub fn new() -> Self {
        Self { eligible: HashMap::new(), secrets: HashMap::new() }
    }

    pub fn register_eligible_pid(&mut self, pid: u32, keylog_path: PathBuf) {
        self.eligible.insert(pid, WatchedFile { path: keylog_path, offset: 0 });
    }

    pub fn unregister_pid(&mut self, pid: u32) {
        self.eligible.remove(&pid);
    }

    pub fn is_eligible(&self, pid: u32) -> bool {
        self.eligible.contains_key(&pid)
    }

    /// Reads any bytes appended to each watched file since the last poll.
    /// Missing/unreadable file is treated as "nothing new yet," not an
    /// error — the wrapped process may not have written its first secret
    /// yet, or the file may momentarily not exist between registration and
    /// first write.
    pub fn poll(&mut self) {
        for watched in self.eligible.values_mut() {
            let Ok(mut file) = std::fs::File::open(&watched.path) else { continue };
            if file.seek(SeekFrom::Start(watched.offset)).is_err() {
                continue;
            }
            let mut buf = String::new();
            if file.read_to_string(&mut buf).is_err() {
                continue;
            }
            watched.offset += buf.len() as u64;
            for line in buf.lines() {
                if let Some(secret) = parse_keylog_line(line) {
                    self.secrets.insert(secret.client_random.clone(), secret);
                }
            }
        }
    }

    pub fn secret_for(&self, client_random: &[u8]) -> Option<&SessionSecret> {
        self.secrets.get(client_random)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_a_tls13_labeled_keylog_line() {
        let line = "CLIENT_HANDSHAKE_TRAFFIC_SECRET aabbccdd112233440000000000000000 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344";
        let secret = parse_keylog_line(line).expect("should parse");
        assert_eq!(secret.label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert_eq!(secret.client_random, hex::decode("aabbccdd112233440000000000000000").unwrap());
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        assert!(parse_keylog_line("").is_none());
        assert!(parse_keylog_line("# a comment").is_none());
    }

    #[test]
    fn ignores_malformed_lines_without_panicking() {
        assert!(parse_keylog_line("NOT_ENOUGH_FIELDS").is_none());
        assert!(parse_keylog_line("LABEL not-hex not-hex-either").is_none());
    }

    #[test]
    fn register_unregister_controls_eligibility() {
        let mut watcher = KeyLogWatcher::new();
        assert!(!watcher.is_eligible(1234));
        let dir = tempfile_dir("register-unregister");
        let path = dir.join("test.keylog");
        std::fs::write(&path, "").unwrap();
        watcher.register_eligible_pid(1234, path);
        assert!(watcher.is_eligible(1234));
        watcher.unregister_pid(1234);
        assert!(!watcher.is_eligible(1234));
    }

    #[test]
    fn poll_picks_up_newly_appended_secrets() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("poll-new-secrets");
        let path = dir.join("test.keylog");
        std::fs::write(&path, "").unwrap();
        watcher.register_eligible_pid(999, path.clone());
        watcher.poll();
        assert!(watcher.secret_for(&hex::decode("11".repeat(17)).unwrap()).is_none());

        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}", "11".repeat(17), "22".repeat(48)).unwrap();
        watcher.poll();
        assert!(watcher.secret_for(&hex::decode("11".repeat(17)).unwrap()).is_some());
    }

    fn tempfile_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keylog-test-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
