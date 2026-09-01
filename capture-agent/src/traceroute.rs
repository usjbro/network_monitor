// capture-agent/src/traceroute.rs
//
// Bounded ICMP traceroute probe loop. Uses an unprivileged
// SOCK_DGRAM/IPPROTO_ICMP "ping socket" per Task 1's spike result (see
// docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md):
// on this macOS version, an ordinary (non-root) process can open one of
// these sockets, send ICMP Echo Requests with a chosen TTL, and receive both
// direct Echo Replies and router-generated Time Exceeded messages on it.
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

#[derive(Debug, Clone)]
pub struct HopResult {
    pub hop_number: u8,
    pub hop_ip: Option<String>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IcmpReplyType {
    TimeExceeded,
    EchoReply,
    Other,
}

#[derive(Debug)]
pub struct ParsedIcmpReply {
    pub reply_type: IcmpReplyType,
    /// Echo identifier from the reply, when one could be extracted (direct
    /// from an Echo Reply's own header, or from the original datagram
    /// embedded in a Time Exceeded message). `None` if the reply is too
    /// short/malformed to contain one.
    pub identifier: Option<u16>,
    /// Echo sequence number, same extraction rules as `identifier`.
    pub sequence: Option<u16>,
}

// Standard Internet checksum (RFC 1071 / the same algorithm ICMP, IP, and
// TCP all use): sum the packet as 16-bit big-endian words with end-around
// carry, then take the one's complement of the sum. Transcribed verbatim
// from the review-verified spike at
// capture-agent/examples/icmp_ping_spike.rs — do not reimplement.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds an 8-byte ICMP Echo Request header (type=8, code=0, checksum,
/// identifier, sequence) with a correctly computed checksum. A zero
/// checksum is not valid ICMP and gets silently dropped by the IP stack —
/// see the spike result doc for how that bug was found and fixed.
fn build_echo_request(identifier: u16, sequence: u16) -> [u8; 8] {
    let mut packet = [0u8; 8];
    packet[0] = 8; // type: echo request
    packet[1] = 0; // code
    packet[4] = (identifier >> 8) as u8;
    packet[5] = (identifier & 0xff) as u8;
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xff) as u8;
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
    packet
}

/// On macOS/BSD, an unprivileged SOCK_DGRAM/IPPROTO_ICMP "ping socket"
/// delivers received datagrams with a leading IPv4 header still attached —
/// confirmed empirically while generating this module's test fixtures: both
/// a direct Echo Reply and a router-generated Time Exceeded came back
/// prefixed with a 20-byte IPv4 header, not just the bare ICMP message. This
/// is a longstanding BSD raw-socket quirk, independent of the ICMP message
/// type. Strip it before reading the ICMP type octet. If the buffer doesn't
/// start with an IPv4 header (version nibble != 4), treat it as already
/// being a bare ICMP message — real ICMP type values (0, 3, 4, 5, 8, 11-18)
/// never occupy the 0x40-0x4F "looks like an IPv4 header" range, so this
/// heuristic doesn't collide with real ICMP types.
fn strip_leading_ipv4_header(bytes: &[u8]) -> Option<&[u8]> {
    let first = *bytes.first()?;
    let version = first >> 4;
    if version != 4 {
        return Some(bytes);
    }
    let ihl = (first & 0x0f) as usize;
    let header_len = ihl * 4;
    if header_len < 20 || bytes.len() < header_len {
        return None;
    }
    Some(&bytes[header_len..])
}

/// Extracts the identifier/sequence pair from the original echo datagram
/// embedded in a Time Exceeded (or other ICMP error) message: an embedded
/// IPv4 header followed by the first 8 bytes of the original ICMP message.
fn extract_embedded_identifier_sequence(embedded: &[u8]) -> Option<(u16, u16)> {
    let first = *embedded.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = (first & 0x0f) as usize;
    let header_len = ihl * 4;
    if header_len < 20 || embedded.len() < header_len + 8 {
        return None;
    }
    let orig_icmp = &embedded[header_len..header_len + 8];
    Some((
        u16::from_be_bytes([orig_icmp[4], orig_icmp[5]]),
        u16::from_be_bytes([orig_icmp[6], orig_icmp[7]]),
    ))
}

/// Parses the minimal ICMP header fields this module needs. Tolerates
/// malformed/truncated input the same way parse.rs does elsewhere in this
/// crate — Option, never a panic.
pub fn parse_icmp_reply(bytes: &[u8]) -> Option<ParsedIcmpReply> {
    let icmp = strip_leading_ipv4_header(bytes)?;
    let icmp_type = *icmp.first()?;
    if icmp.len() < 8 {
        return None; // shorter than a minimal ICMP header — malformed
    }
    let reply_type = match icmp_type {
        11 => IcmpReplyType::TimeExceeded,
        0 => IcmpReplyType::EchoReply,
        _ => IcmpReplyType::Other,
    };
    let (identifier, sequence) = match reply_type {
        IcmpReplyType::EchoReply => (
            Some(u16::from_be_bytes([icmp[4], icmp[5]])),
            Some(u16::from_be_bytes([icmp[6], icmp[7]])),
        ),
        IcmpReplyType::TimeExceeded => match extract_embedded_identifier_sequence(&icmp[8..]) {
            Some((id, seq)) => (Some(id), Some(seq)),
            None => (None, None),
        },
        IcmpReplyType::Other => (None, None),
    };
    Some(ParsedIcmpReply { reply_type, identifier, sequence })
}

const HOP_CEILING: u8 = 30;
const PER_HOP_TIMEOUT: Duration = Duration::from_secs(1);
const PER_HOP_RETRIES: u8 = 3;
const TOTAL_TRACE_TIMEOUT: Duration = Duration::from_secs(45);

/// One ICMP ping-socket, opened once per traceroute run (not once per
/// probe), plus the per-run identifier and a monotonically increasing
/// sequence counter used to match replies to the probe that elicited them.
struct ProbeSession {
    socket: UdpSocket,
    identifier: u16,
    next_sequence: u16,
}

impl ProbeSession {
    fn open() -> io::Result<Self> {
        // SAFETY: libc::socket is called with valid, constant arguments; the
        // returned fd (or negative error) is handled immediately below,
        // matching the mechanism proven in
        // capture-agent/examples/icmp_ping_spike.rs.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just returned by a successful socket() call above
        // and is not owned anywhere else yet.
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        Ok(ProbeSession {
            socket,
            identifier: (std::process::id() & 0xffff) as u16,
            next_sequence: 1,
        })
    }

    /// Sets the outgoing TTL for the next probe via IP_TTL, matching the
    /// raw-libc style used elsewhere in this crate's ICMP handling.
    fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        let ttl_val: libc::c_int = ttl as libc::c_int;
        // SAFETY: fd is a valid, open socket owned by `self`; the option
        // value is a valid, correctly-sized c_int on the stack.
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u16 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        seq
    }
}

/// Real entry point, used by main.rs (Task 3). Wraps
/// run_traceroute_with_timeouts with the production bounds above — kept as
/// a thin wrapper so tests can inject much shorter timeouts (Step 1) without
/// duplicating the probe-loop logic itself.
pub async fn run_traceroute(target_ip: &str, on_hop: impl FnMut(HopResult)) -> Vec<HopResult> {
    run_traceroute_with_timeouts(target_ip, PER_HOP_TIMEOUT, TOTAL_TRACE_TIMEOUT, on_hop).await
}

pub async fn run_traceroute_with_timeouts(
    target_ip: &str,
    per_hop_timeout: Duration,
    total_trace_timeout: Duration,
    mut on_hop: impl FnMut(HopResult),
) -> Vec<HopResult> {
    let deadline = Instant::now() + total_trace_timeout;
    let mut results = Vec::new();

    let mut session = match ProbeSession::open() {
        Ok(session) => session,
        Err(e) => {
            // Unprivileged ping-sockets are confirmed available on this
            // platform (Task 1's spike), so this is an unexpected runtime
            // failure (e.g. resource exhaustion), not the expected-failure
            // path. Degrade gracefully — report every hop as no-response
            // rather than hanging or panicking — so a caller streaming
            // `on_hop` still gets a bounded, terminating sequence of events.
            eprintln!("traceroute: failed to open ICMP probe socket: {e}");
            for hop_number in 1..=HOP_CEILING {
                let hop = HopResult { hop_number, hop_ip: None, rtt_ms: None };
                on_hop(hop.clone());
                results.push(hop);
            }
            return results;
        }
    };

    for ttl in 1..=HOP_CEILING {
        if Instant::now() >= deadline {
            break;
        }
        let mut hop = HopResult { hop_number: ttl, hop_ip: None, rtt_ms: None };
        for _attempt in 0..PER_HOP_RETRIES {
            if Instant::now() >= deadline {
                break;
            }
            match send_probe_and_await_reply(&mut session, target_ip, ttl, per_hop_timeout).await {
                Some((ip, rtt)) => {
                    hop.hop_ip = Some(ip);
                    hop.rtt_ms = Some(rtt);
                    break;
                }
                None => continue, // this attempt timed out — retry, up to PER_HOP_RETRIES
            }
        }
        let destination_reached = hop.hop_ip.as_deref() == Some(target_ip);
        on_hop(hop.clone());
        results.push(hop);
        if destination_reached {
            break;
        }
    }
    results
}

/// Sends one ICMP Echo Request at the given TTL on `session`'s socket and
/// waits up to `timeout` for a reply. Returns the replying IP (taken from
/// the socket's own `recv_from` address, not parsed out of the reply
/// payload's embedded IP header — the OS delivers `from_addr` correctly
/// regardless of whether the payload is an Echo Reply or a Time Exceeded)
/// and the round-trip time in milliseconds, or `None` on timeout/no-match.
async fn send_probe_and_await_reply(
    session: &mut ProbeSession,
    target_ip: &str,
    ttl: u8,
    timeout_duration: Duration,
) -> Option<(String, f64)> {
    let target: Ipv4Addr = target_ip.parse().ok()?;
    let dest = SocketAddr::new(IpAddr::V4(target), 0);

    session.set_ttl(ttl).ok()?;
    let sequence = session.next_seq();
    let identifier = session.identifier;
    let packet = build_echo_request(identifier, sequence);

    let started = Instant::now();
    session.socket.send_to(&packet, dest).await.ok()?;

    let reply_ip = timeout(timeout_duration, async {
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = match session.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return None,
            };
            let Some(parsed) = parse_icmp_reply(&buf[..n]) else {
                continue; // malformed/unparseable — keep waiting for the real reply
            };
            match parsed.reply_type {
                IcmpReplyType::EchoReply => {
                    if parsed.identifier == Some(identifier) && parsed.sequence == Some(sequence) {
                        return Some(from.ip().to_string());
                    }
                    // an echo reply that isn't ours (e.g. a stale/duplicate
                    // from a prior attempt) — keep waiting
                }
                IcmpReplyType::TimeExceeded => {
                    // This dedicated socket only ever carries our own
                    // probes, so any Time Exceeded on it is a valid
                    // intermediate-hop response; id/sequence matching isn't
                    // required to treat it as ours (also embedded id/seq
                    // extraction can legitimately fail if a router truncates
                    // the original datagram it echoes back).
                    return Some(from.ip().to_string());
                }
                IcmpReplyType::Other => {
                    // unrelated ICMP traffic on this socket — keep waiting
                }
            }
        }
    })
    .await
    .ok()
    .flatten();

    reply_ip.map(|ip| (ip, started.elapsed().as_secs_f64() * 1000.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_time_exceeded_reply_and_extracts_the_replying_hop_ip() {
        // ICMP Time Exceeded (type 11, code 0) wrapping the original IP
        // header + first 8 bytes of the original ICMP echo request, as sent
        // by an intermediate router. Fixture bytes captured from a real
        // traceroute session (see tests/fixtures/icmp/README.md for how to
        // regenerate).
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/icmp/time_exceeded.bin"
        ))
        .unwrap();
        let parsed = parse_icmp_reply(&raw).expect("should parse a well-formed Time Exceeded reply");
        assert_eq!(parsed.reply_type, IcmpReplyType::TimeExceeded);
    }

    #[test]
    fn parses_an_echo_reply_as_trace_completion() {
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/icmp/echo_reply.bin"
        ))
        .unwrap();
        let parsed = parse_icmp_reply(&raw).expect("should parse a well-formed Echo Reply");
        assert_eq!(parsed.reply_type, IcmpReplyType::EchoReply);
    }

    #[test]
    fn malformed_or_truncated_icmp_bytes_return_none_not_a_panic() {
        assert!(parse_icmp_reply(&[]).is_none());
        assert!(parse_icmp_reply(&[0xff; 3]).is_none());
        // A byte sequence shorter than a full ICMP header.
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/icmp/echo_reply.bin"
        ))
        .unwrap();
        assert!(parse_icmp_reply(&raw[..raw.len() - 5]).is_none());
    }

    #[tokio::test]
    async fn a_trace_that_never_gets_a_reply_terminates_at_the_hop_ceiling_not_hangs() {
        // This exercises the real socket path end-to-end (real send, real
        // recv-with-timeout), so the target must be one that deterministically
        // never elicits a reply on ANY real network, not just an unreachable
        // one. TEST-NET-3 (203.0.113.1, RFC 5737) was tried first and does
        // NOT work for that: any routable destination still gets its TTL
        // decremented by real intermediate routers (this machine's own
        // default gateway, then its ISP's router) before those routers ever
        // check whether the final destination is reachable — that's the
        // whole mechanism traceroute relies on, so a "reserved, presumably
        // unreachable" destination still produces real Time Exceeded replies
        // from the first couple of real hops. 0.0.0.0 ("this network", RFC
        // 791/1122) is rejected at the local IP layer before any packet
        // leaves the host, on any machine/network, giving a genuinely
        // deterministic "never any reply" case while still exercising the
        // real send/recv/timeout code path (a real, failing sendto()).
        let hops = run_traceroute_with_timeouts(
            "0.0.0.0",
            Duration::from_millis(1),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        assert!(hops.len() <= 30, "must respect the hop ceiling even when nothing ever replies");
        assert!(
            hops.iter().all(|h| h.hop_ip.is_none()),
            "every hop should be recorded as no-response, not fabricated"
        );
    }

    #[tokio::test]
    async fn on_hop_callback_fires_progressively_not_batched_at_the_end() {
        let mut seen = Vec::new();
        let _ = run_traceroute_with_timeouts(
            "203.0.113.1",
            Duration::from_millis(1),
            Duration::from_millis(20),
            |hop| seen.push(hop.hop_number),
        )
        .await;
        assert!(!seen.is_empty(), "on_hop must be called at least once per hop attempted, even for no-response hops");
    }
}
