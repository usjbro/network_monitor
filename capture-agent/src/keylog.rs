use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const MAX_KEYLOG_SESSIONS_PER_PID: usize = 128;
const MAX_KEYLOG_SECRET_BYTES: usize = 1024 * 1024;
const MAX_KEYLOG_READ_BYTES_PER_POLL: usize = 64 * 1024;
const MAX_KEYLOG_LINE_BYTES: usize = 1024;
const UNUSED_SECRET_TTL: Duration = Duration::from_secs(10 * 60);

pub fn secret_label_for_direction(
    client_is_outbound: bool,
    packet_is_outbound: bool,
    handshake: bool,
) -> &'static str {
    let client_to_server = client_is_outbound == packet_is_outbound;
    match (handshake, client_to_server) {
        (true, true) => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        (true, false) => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        (false, true) => "CLIENT_TRAFFIC_SECRET_0",
        (false, false) => "SERVER_TRAFFIC_SECRET_0",
    }
}

#[derive(Clone)]
pub struct SessionSecret {
    pub client_random: Vec<u8>,
    pub label: String,
    pub secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecret")
            .field("client_random", &"[REDACTED]")
            .field("label", &self.label)
            .field("secret", &"[REDACTED]")
            .finish()
    }
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
    let secret = Zeroizing::new(hex::decode(parts.next()?).ok()?);
    if parts.next().is_some() {
        return None; // unexpected extra field — be strict, not lenient-to-garbage
    }
    Some(SessionSecret {
        client_random,
        label,
        secret,
    })
}

struct WatchedFile {
    path: PathBuf,
    offset: u64,
    pending_line: Zeroizing<Vec<u8>>,
    discarding_oversized_line: bool,
}

pub struct KeyLogWatcher {
    eligible: HashMap<u32, WatchedFile>,
    secrets: HashMap<(u32, Vec<u8>, String), StoredSecret>,
    next_order: u64,
    last_polled_pid: u32,
}

struct StoredSecret {
    value: SessionSecret,
    inserted_at: Instant,
    order: u64,
    associated_with_flow: bool,
}

impl Default for KeyLogWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLogWatcher {
    pub fn new() -> Self {
        Self {
            eligible: HashMap::new(),
            secrets: HashMap::new(),
            next_order: 0,
            last_polled_pid: 0,
        }
    }

    pub fn register_eligible_pid(&mut self, pid: u32, keylog_path: PathBuf) {
        self.eligible.insert(
            pid,
            WatchedFile {
                path: keylog_path,
                offset: 0,
                pending_line: Zeroizing::new(Vec::new()),
                discarding_oversized_line: false,
            },
        );
    }

    pub fn unregister_pid(&mut self, pid: u32) {
        self.eligible.remove(&pid);
        self.secrets.retain(|(owner, _, _), _| *owner != pid);
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
        self.poll_at(Instant::now());
    }

    fn poll_at(&mut self, now: Instant) {
        let mut found = Vec::new();
        let mut pids = self.eligible.keys().copied().collect::<Vec<_>>();
        pids.sort_unstable();
        let start = pids.partition_point(|pid| *pid <= self.last_polled_pid);
        let pid_count = pids.len();
        if pid_count > 0 {
            pids.rotate_left(start % pid_count);
        }
        let mut remaining = MAX_KEYLOG_READ_BYTES_PER_POLL;
        for pid in pids {
            if remaining == 0 {
                break;
            }
            let Some(watched) = self.eligible.get_mut(&pid) else {
                continue;
            };
            let Ok(mut file) = std::fs::File::open(&watched.path) else {
                self.last_polled_pid = pid;
                continue;
            };
            if file.seek(SeekFrom::Start(watched.offset)).is_err() {
                self.last_polled_pid = pid;
                continue;
            }
            let mut buf = Zeroizing::new(Vec::new());
            let read_result = file.take(remaining as u64).read_to_end(&mut buf);
            if read_result.is_err() {
                continue;
            }
            watched.offset += buf.len() as u64;
            remaining = remaining.saturating_sub(buf.len());
            self.last_polled_pid = pid;
            for byte in buf.iter().copied() {
                if watched.discarding_oversized_line {
                    if byte == b'\n' {
                        watched.discarding_oversized_line = false;
                    }
                    continue;
                }
                if byte == b'\n' {
                    if let Ok(line) = std::str::from_utf8(&watched.pending_line) {
                        if let Some(secret) = parse_keylog_line(line) {
                            found.push((pid, secret));
                        }
                    }
                    watched.pending_line.zeroize();
                    watched.pending_line.clear();
                } else if watched.pending_line.len() < MAX_KEYLOG_LINE_BYTES {
                    watched.pending_line.push(byte);
                } else {
                    watched.pending_line.zeroize();
                    watched.pending_line.clear();
                    watched.discarding_oversized_line = true;
                }
            }
            buf.zeroize();
        }
        for (pid, secret) in found {
            let key = (pid, secret.client_random.clone(), secret.label.clone());
            self.next_order = self.next_order.wrapping_add(1);
            self.secrets.insert(
                key,
                StoredSecret {
                    value: secret,
                    inserted_at: now,
                    order: self.next_order,
                    associated_with_flow: false,
                },
            );
        }
        self.enforce_caps(now);
    }

    pub fn secret_for(
        &self,
        pid: u32,
        client_random: &[u8],
        label: &str,
    ) -> Option<&SessionSecret> {
        self.secrets
            .get(&(pid, client_random.to_vec(), label.to_owned()))
            .map(|s| &s.value)
    }

    pub fn mark_flow_seen(&mut self, pid: u32, client_random: &[u8]) {
        for ((owner, random, _), stored) in &mut self.secrets {
            if *owner == pid && random.as_slice() == client_random {
                stored.associated_with_flow = true;
            }
        }
    }

    pub fn take_secret(
        &mut self,
        pid: u32,
        client_random: &[u8],
        label: &str,
    ) -> Option<SessionSecret> {
        self.secrets
            .remove(&(pid, client_random.to_vec(), label.to_owned()))
            .map(|s| s.value)
    }

    pub fn remove_flow_secrets(&mut self, pid: u32, client_random: &[u8]) {
        self.secrets
            .retain(|(owner, random, _), _| *owner != pid || random.as_slice() != client_random);
    }

    fn enforce_caps(&mut self, now: Instant) {
        self.secrets.retain(|_, stored| {
            stored.associated_with_flow
                || now.saturating_duration_since(stored.inserted_at) <= UNUSED_SECRET_TTL
        });

        let pids: Vec<u32> = self.eligible.keys().copied().collect();
        for pid in pids {
            loop {
                let mut sessions: HashMap<Vec<u8>, u64> = HashMap::new();
                for ((owner, random, _), stored) in &self.secrets {
                    if *owner == pid {
                        sessions
                            .entry(random.clone())
                            .and_modify(|order| *order = (*order).min(stored.order))
                            .or_insert(stored.order);
                    }
                }
                if sessions.len() <= MAX_KEYLOG_SESSIONS_PER_PID {
                    break;
                }
                if let Some((oldest_random, _)) =
                    sessions.into_iter().min_by_key(|(_, order)| *order)
                {
                    self.secrets
                        .retain(|(owner, random, _), _| *owner != pid || *random != oldest_random);
                } else {
                    break;
                }
            }
        }
        while self.secret_bytes() > MAX_KEYLOG_SECRET_BYTES {
            let oldest = self
                .secrets
                .iter()
                .min_by_key(|(_, stored)| stored.order)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                self.secrets.remove(&key);
            } else {
                break;
            }
        }
    }

    fn secret_bytes(&self) -> usize {
        self.secrets.values().map(|s| s.value.secret.len()).sum()
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
        assert_eq!(
            secret.client_random,
            hex::decode("aabbccdd112233440000000000000000").unwrap()
        );
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
    fn secrets_are_scoped_by_pid_and_label_and_removed_on_unregister() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("pid-label-scope");
        for pid in [101, 202] {
            let path = dir.join(format!("{pid}.keylog"));
            std::fs::write(
                &path,
                format!(
                    "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                    "11".repeat(32),
                    "22".repeat(32)
                ),
            )
            .unwrap();
            watcher.register_eligible_pid(pid, path);
        }
        watcher.poll();
        let random = hex::decode("11".repeat(32)).unwrap();
        assert!(watcher
            .secret_for(101, &random, "CLIENT_TRAFFIC_SECRET_0")
            .is_some());
        assert!(watcher
            .secret_for(101, &random, "SERVER_TRAFFIC_SECRET_0")
            .is_none());
        assert!(watcher
            .secret_for(303, &random, "CLIENT_TRAFFIC_SECRET_0")
            .is_none());
        watcher.unregister_pid(101);
        assert!(watcher
            .secret_for(101, &random, "CLIENT_TRAFFIC_SECRET_0")
            .is_none());
        assert!(watcher
            .secret_for(202, &random, "CLIENT_TRAFFIC_SECRET_0")
            .is_some());
    }

    #[test]
    fn taking_a_secret_transfers_ownership_and_removes_the_stored_copy() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("take-secret");
        let path = dir.join("test.keylog");
        std::fs::write(
            &path,
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                "11".repeat(32),
                "22".repeat(32)
            ),
        )
        .unwrap();
        watcher.register_eligible_pid(88, path);
        watcher.poll();
        let random = hex::decode("11".repeat(32)).unwrap();
        let moved = watcher
            .take_secret(88, &random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
            .unwrap();
        assert_eq!(
            moved.secret.as_slice(),
            hex::decode("22".repeat(32)).unwrap()
        );
        assert!(watcher
            .secret_for(88, &random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
            .is_none());
    }

    #[test]
    fn secret_debug_output_does_not_expose_key_material() {
        let secret = parse_keylog_line(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "11".repeat(32),
            "ab".repeat(32)
        ))
        .unwrap();
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&"ab".repeat(32)));
    }

    #[test]
    fn unused_secrets_expire_and_session_cap_evicts_all_labels_together() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("expiry-session-cap");
        let path = dir.join("test.keylog");
        let mut contents = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\nSERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            "00".repeat(32),
            "22".repeat(32),
            "00".repeat(32),
            "33".repeat(32)
        );
        for i in 1..=MAX_KEYLOG_SESSIONS_PER_PID {
            contents.push_str(&format!(
                "CLIENT_TRAFFIC_SECRET_0 {:064x} {}\n",
                i,
                "44".repeat(32)
            ));
        }
        std::fs::write(&path, contents).unwrap();
        watcher.register_eligible_pid(77, path);
        let start = Instant::now();
        watcher.poll_at(start);
        let oldest_random = [0u8; 32];
        assert!(watcher
            .secret_for(77, &oldest_random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
            .is_none());
        assert!(watcher
            .secret_for(77, &oldest_random, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
            .is_none());
        let newest_random = hex::decode(format!("{:064x}", MAX_KEYLOG_SESSIONS_PER_PID)).unwrap();
        assert!(watcher
            .secret_for(77, &newest_random, "CLIENT_TRAFFIC_SECRET_0")
            .is_some());
        watcher.enforce_caps(start + UNUSED_SECRET_TTL + Duration::from_secs(1));
        assert!(watcher.secrets.is_empty());
    }

    #[test]
    fn poll_picks_up_newly_appended_secrets() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("poll-new-secrets");
        let path = dir.join("test.keylog");
        std::fs::write(&path, "").unwrap();
        watcher.register_eligible_pid(999, path.clone());
        watcher.poll();
        assert!(watcher
            .secret_for(
                999,
                &hex::decode("11".repeat(17)).unwrap(),
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            )
            .is_none());

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(
            f,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}",
            "11".repeat(17),
            "22".repeat(48)
        )
        .unwrap();
        watcher.poll();
        assert!(watcher
            .secret_for(
                999,
                &hex::decode("11".repeat(17)).unwrap(),
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            )
            .is_some());
    }

    #[test]
    fn poll_does_not_consume_an_unterminated_partial_keylog_line() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("partial-line");
        let path = dir.join("test.keylog");
        let random = "11".repeat(32);
        let secret = "22".repeat(32);
        let line = format!("CLIENT_TRAFFIC_SECRET_0 {random} {secret}");
        std::fs::write(&path, &line).unwrap();
        watcher.register_eligible_pid(501, path.clone());
        let start = Instant::now();

        watcher.poll_at(start);
        assert!(watcher
            .secret_for(
                501,
                &hex::decode(&random).unwrap(),
                "CLIENT_TRAFFIC_SECRET_0"
            )
            .is_none());

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        watcher.poll_at(start + Duration::from_millis(1));
        assert!(watcher
            .secret_for(
                501,
                &hex::decode(&random).unwrap(),
                "CLIENT_TRAFFIC_SECRET_0"
            )
            .is_some());
    }

    #[test]
    fn poll_caps_total_bytes_and_skips_oversized_lines_without_losing_later_secrets() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir("bounded-read");
        let path = dir.join("test.keylog");
        let random = "11".repeat(32);
        let secret = "22".repeat(32);
        let line = format!("CLIENT_TRAFFIC_SECRET_0 {random} {secret}\n");
        let mut contents = "#".repeat(MAX_KEYLOG_READ_BYTES_PER_POLL * 2 + 7);
        contents.push('\n');
        contents.push_str(&line);
        std::fs::write(&path, contents).unwrap();
        watcher.register_eligible_pid(502, path);
        let start = Instant::now();

        for poll in 0..4 {
            let previous = watcher.eligible[&502].offset;
            watcher.poll_at(start + Duration::from_millis(poll));
            let read = watcher.eligible[&502].offset - previous;
            assert!(read <= MAX_KEYLOG_READ_BYTES_PER_POLL as u64);
        }
        assert!(watcher
            .secret_for(
                502,
                &hex::decode(&random).unwrap(),
                "CLIENT_TRAFFIC_SECRET_0"
            )
            .is_some());
    }

    fn tempfile_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keylog-test-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
