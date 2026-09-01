use crate::l7::L7Info;
use crate::parse::{ParsedPacket, TransportProtocol};
use std::collections::HashMap;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub protocol: TransportProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

impl FlowKey {
    /// The single canonical id format for this flow, shared by
    /// `ConnectionJson.id` and the `ConnectionClosed` event's `id` so the two
    /// can never diverge.
    pub fn connection_id(&self) -> String {
        format!(
            "{:?}-{}:{}-{}:{}",
            self.protocol, self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}

struct FlowState {
    app_layer_protocol: String,
    encryption: String,
    established: bool,
    fin_seen: bool,
    rst_seen: bool,
    syn_sent_at_ms: Option<u64>,
    rtt_ms: Option<f64>,
    rx_bytes_total: u64,
    tx_bytes_total: u64,
    rx_bytes_this_tick: u64,
    tx_bytes_this_tick: u64,
    max_seq_seen: HashMap<bool /* local_is_sender */, u32>,
    retransmits: u64,
    segments: u64,
    last_seen_ms: u64,
    ja3_fingerprint: Option<String>,
    ja3_label: Option<&'static str>,
}

impl Default for FlowState {
    fn default() -> Self {
        FlowState {
            app_layer_protocol: "Unknown".to_string(),
            encryption: "None".to_string(),
            established: false,
            fin_seen: false,
            rst_seen: false,
            syn_sent_at_ms: None,
            rtt_ms: None,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_bytes_this_tick: 0,
            tx_bytes_this_tick: 0,
            max_seq_seen: HashMap::new(),
            retransmits: 0,
            segments: 0,
            last_seen_ms: 0,
            ja3_fingerprint: None,
            ja3_label: None,
        }
    }
}

pub struct FlowSnapshot {
    pub key: FlowKey,
    pub app_layer_protocol: String,
    pub status: String,
    pub encryption: String,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub latency_ms: f64,
    pub packet_loss: f64,
    pub ja3_fingerprint: Option<String>,
    pub ja3_label: Option<&'static str>,
}

/// Default ceiling on the number of tracked flows. Bounds memory under a SYN
/// flood / port scan / spoofed-UDP burst, which would otherwise allocate one
/// `FlowState` (four `String`s + a `HashMap`) per distinct (local, remote)
/// pair and hold each for up to 30 minutes regardless of attacker intent.
const DEFAULT_MAX_FLOWS: usize = 10_000;

pub struct FlowTable {
    local_addrs: Vec<String>,
    flows: HashMap<FlowKey, FlowState>,
    last_snapshot_ms: u64,
    max_flows: usize,
}

fn well_known_protocol(port: u16) -> Option<&'static str> {
    match port {
        80 => Some("HTTP"),
        443 => Some("HTTPS/TLS"),
        53 => Some("DNS"),
        22 => Some("SSH"),
        _ => None,
    }
}

/// Derives the display status for a flow. Shared by `snapshot()` and
/// `evict_stale()` so the two can never drift on what counts as
/// "TIME_WAIT"/"CLOSE_WAIT" vs. still-active.
fn status_for(state: &FlowState, protocol: TransportProtocol) -> &'static str {
    if state.fin_seen || state.rst_seen {
        "TIME_WAIT"
    } else if state.established {
        "ESTABLISHED"
    } else if state.syn_sent_at_ms.is_some() {
        "SYN_SENT"
    } else if protocol != TransportProtocol::Tcp {
        // Non-TCP flows (UDP, ICMP) are connectionless — there is no
        // TCP-style closing state to report for them. An observed
        // non-TCP flow is simply active.
        "ESTABLISHED"
    } else {
        "CLOSE_WAIT"
    }
}

impl FlowTable {
    pub fn new(local_addrs: Vec<String>) -> Self {
        Self::new_with_capacity(local_addrs, DEFAULT_MAX_FLOWS)
    }

    /// Same as `new`, but with an explicit flow-count ceiling instead of
    /// `DEFAULT_MAX_FLOWS` — lets tests exercise capacity eviction without
    /// creating thousands of flows.
    pub fn new_with_capacity(local_addrs: Vec<String>, max_flows: usize) -> Self {
        FlowTable {
            local_addrs,
            flows: HashMap::new(),
            last_snapshot_ms: 0,
            max_flows,
        }
    }

    fn is_local(&self, addr: &str) -> bool {
        self.local_addrs.iter().any(|a| a == addr)
    }

    /// `key_for` always orders (local, remote) so both packet directions of
    /// one connection map to the same FlowKey.
    fn key_for(&self, packet: &ParsedPacket) -> Option<(FlowKey, bool /* is_outbound */)> {
        let (src_port, dst_port) = (packet.src_port?, packet.dst_port?);
        if self.is_local(&packet.src_ip) {
            Some((
                FlowKey {
                    protocol: packet.protocol,
                    local_addr: packet.src_ip.clone(),
                    local_port: src_port,
                    remote_addr: packet.dst_ip.clone(),
                    remote_port: dst_port,
                },
                true,
            ))
        } else if self.is_local(&packet.dst_ip) {
            Some((
                FlowKey {
                    protocol: packet.protocol,
                    local_addr: packet.dst_ip.clone(),
                    local_port: dst_port,
                    remote_addr: packet.src_ip.clone(),
                    remote_port: src_port,
                },
                false,
            ))
        } else {
            None
        }
    }

    pub fn observe(&mut self, packet: &ParsedPacket, l7: &L7Info, now_ms: u64) {
        let Some((key, is_outbound)) = self.key_for(packet) else { return };
        let remote_port = key.remote_port;
        let state = self.flows.entry(key).or_default();
        state.last_seen_ms = now_ms;

        if is_outbound {
            state.tx_bytes_total += packet.total_len as u64;
            state.tx_bytes_this_tick += packet.total_len as u64;
        } else {
            state.rx_bytes_total += packet.total_len as u64;
            state.rx_bytes_this_tick += packet.total_len as u64;
        }

        match l7 {
            L7Info::Http { .. } => state.app_layer_protocol = "HTTP".to_string(),
            L7Info::Dns { .. } => state.app_layer_protocol = "DNS".to_string(),
            L7Info::TlsClientHello { ja3, ja3_label, .. } => {
                state.app_layer_protocol = "HTTPS/TLS".to_string();
                state.encryption = "TLS".to_string();
                // First ClientHello wins: a flow has exactly one handshake,
                // so once a JA3 fingerprint is recorded, later packets on
                // the same flow (which report L7Info::None) must not
                // overwrite it.
                if state.ja3_fingerprint.is_none() {
                    state.ja3_fingerprint = ja3.clone();
                    state.ja3_label = *ja3_label;
                }
            }
            L7Info::None => {
                if state.app_layer_protocol == "Unknown" {
                    if let Some(name) = well_known_protocol(remote_port) {
                        state.app_layer_protocol = name.to_string();
                    }
                }
            }
        }

        if let Some(flags) = packet.tcp_flags {
            if flags.syn && !flags.ack {
                state.syn_sent_at_ms = Some(now_ms);
            }
            if flags.syn && flags.ack && !is_outbound {
                if let Some(sent_at) = state.syn_sent_at_ms {
                    state.rtt_ms = Some((now_ms.saturating_sub(sent_at)) as f64);
                }
            }
            if flags.ack {
                state.established = true;
            }
            if flags.fin {
                state.fin_seen = true;
            }
            if flags.rst {
                state.established = false;
                state.rst_seen = true;
            }

            // Only segments that carry payload participate in retransmit
            // detection. A pure ACK (no payload) legitimately reuses the
            // previous sequence number constantly in healthy TCP flows
            // (delayed ACKs, window updates, ACKing a large inbound
            // response) — counting those as retransmits would flag nearly
            // every ordinary connection as lossy.
            if let Some(seq) = packet.seq {
                if !packet.payload.is_empty() {
                    state.segments += 1;
                    // Per-direction: the first data segment ever seen in a
                    // direction has nothing to compare against, so it is never
                    // a retransmit. Using the flow's combined segment count
                    // here (instead of a per-direction one) would flag the
                    // first segment of the *second* direction as a
                    // false-positive retransmit as soon as any segment had
                    // already been seen in the other direction — this must
                    // stay scoped per-direction.
                    let is_retransmit = match state.max_seq_seen.get(&is_outbound) {
                        Some(&max_seen) => seq <= max_seen,
                        None => false,
                    };
                    if is_retransmit {
                        state.retransmits += 1;
                    } else {
                        state.max_seq_seen.insert(is_outbound, seq);
                    }
                }
            }
        }
    }

    pub fn snapshot(&mut self, now_ms: u64) -> Vec<FlowSnapshot> {
        let elapsed_s = ((now_ms.saturating_sub(self.last_snapshot_ms)).max(1)) as f64 / 1000.0;
        self.last_snapshot_ms = now_ms;

        let mut result = Vec::with_capacity(self.flows.len());
        for (key, state) in self.flows.iter_mut() {
            let status = status_for(state, key.protocol);

            let packet_loss = if state.segments > 0 {
                (state.retransmits as f64 / state.segments as f64) * 100.0
            } else {
                0.0
            };

            result.push(FlowSnapshot {
                key: key.clone(),
                app_layer_protocol: state.app_layer_protocol.clone(),
                status: status.to_string(),
                encryption: state.encryption.clone(),
                rx_speed: state.rx_bytes_this_tick as f64 / elapsed_s,
                tx_speed: state.tx_bytes_this_tick as f64 / elapsed_s,
                rx_bytes_total: state.rx_bytes_total,
                tx_bytes_total: state.tx_bytes_total,
                latency_ms: state.rtt_ms.unwrap_or(0.0),
                packet_loss: packet_loss.min(100.0),
                ja3_fingerprint: state.ja3_fingerprint.clone(),
                ja3_label: state.ja3_label,
            });

            state.rx_bytes_this_tick = 0;
            state.tx_bytes_this_tick = 0;
        }
        result
    }

    /// Removes flows that have gone idle past a status-appropriate threshold
    /// and returns the keys of everything evicted, so the caller can emit an
    /// explicit close event per removed flow. Also enforces `max_flows` by
    /// evicting the least-recently-seen flows once the table is over
    /// capacity, so an unbounded burst of distinct flows (SYN flood, port
    /// scan, spoofed UDP, or just many short-lived DNS queries) is bounded by
    /// entry count as well as by time.
    pub fn evict_stale(&mut self, now_ms: u64) -> Vec<FlowKey> {
        // SYN_SENT: a connection attempt that never completes (e.g. nothing
        // is listening, or the SYN was dropped) shouldn't sit for the full
        // 30-minute ceiling — 30s is generous for even a slow handshake.
        const SYN_SENT_IDLE_MS: u64 = 30_000;
        const CLOSING_IDLE_MS: u64 = 120_000; // TIME_WAIT/CLOSE_WAIT
        // Non-TCP (UDP/ICMP) flows are always reported "ESTABLISHED" since
        // they have no closing handshake — a short idle timeout stands in
        // for that. Otherwise a single DNS query (fresh ephemeral port each
        // time) would occupy a flow slot for the full 30-minute ceiling.
        const UDP_IDLE_MS: u64 = 60_000;
        const MAX_IDLE_MS: u64 = 1_800_000; // ceiling, any status
        let mut evicted = Vec::new();
        self.flows.retain(|key, state| {
            let idle = now_ms.saturating_sub(state.last_seen_ms);
            let status = status_for(state, key.protocol);
            let threshold = if matches!(status, "TIME_WAIT" | "CLOSE_WAIT") {
                CLOSING_IDLE_MS
            } else if status == "SYN_SENT" {
                SYN_SENT_IDLE_MS
            } else if key.protocol != TransportProtocol::Tcp {
                UDP_IDLE_MS
            } else {
                MAX_IDLE_MS
            };
            let stale = idle > threshold;
            if stale {
                evicted.push(key.clone());
            }
            !stale
        });

        if self.flows.len() > self.max_flows {
            let excess = self.flows.len() - self.max_flows;
            let mut by_age: Vec<(FlowKey, u64)> = self
                .flows
                .iter()
                .map(|(key, state)| (key.clone(), state.last_seen_ms))
                .collect();
            by_age.sort_by_key(|(_, last_seen_ms)| *last_seen_ms);
            for (key, _) in by_age.into_iter().take(excess) {
                self.flows.remove(&key);
                evicted.push(key);
            }
        }

        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ParsedPacket, TransportProtocol, TcpFlags};
    use crate::l7::L7Info;

    fn tcp_packet(local_is_src: bool, flags: TcpFlags, len: u16) -> ParsedPacket {
        tcp_packet_with_payload(local_is_src, flags, len, vec![])
    }

    fn tcp_packet_with_payload(
        local_is_src: bool,
        flags: TcpFlags,
        len: u16,
        payload: Vec<u8>,
    ) -> ParsedPacket {
        let (src_ip, dst_ip, src_port, dst_port) = if local_is_src {
            ("192.168.1.10".to_string(), "93.184.216.34".to_string(), 51000u16, 443u16)
        } else {
            ("93.184.216.34".to_string(), "192.168.1.10".to_string(), 443u16, 51000u16)
        };
        ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip,
            dst_ip,
            protocol: TransportProtocol::Tcp,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            tcp_flags: Some(flags),
            seq: Some(1000),
            ttl: 64,
            total_len: len,
            payload,
            ip_version: 4,
            ip_checksum: Some(0),
        }
    }

    #[test]
    fn derives_syn_sent_then_established() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);

        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);
        let snap = table.snapshot(0);
        assert_eq!(snap[0].status, "SYN_SENT");

        let synack = tcp_packet(false, TcpFlags { syn: true, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&synack, &L7Info::None, 20);
        let ack = tcp_packet(true, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&ack, &L7Info::None, 25);

        let snap = table.snapshot(25);
        assert_eq!(snap[0].status, "ESTABLISHED");
        assert!((snap[0].latency_ms - 20.0).abs() < 0.01, "expected ~20ms RTT, got {}", snap[0].latency_ms);
    }

    #[test]
    fn accumulates_byte_totals_by_direction() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let out = tcp_packet(true, TcpFlags::default(), 100);
        let inb = tcp_packet(false, TcpFlags::default(), 250);
        table.observe(&out, &L7Info::None, 0);
        table.observe(&inb, &L7Info::None, 0);

        let snap = table.snapshot(1000);
        assert_eq!(snap[0].tx_bytes_total, 100);
        assert_eq!(snap[0].rx_bytes_total, 250);
    }

    #[test]
    fn first_segment_in_each_direction_is_never_a_false_retransmit() {
        // Regression test: the first inbound segment of a flow must not be
        // flagged as a retransmit just because outbound segments were already
        // observed — retransmission detection is scoped per-direction.
        // Retransmit detection only considers segments with payload (pure
        // ACKs are exempt), so these packets carry a non-empty payload —
        // otherwise none of them would count as a "segment" at all and this
        // test wouldn't exercise the retransmit path.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let out1 = tcp_packet_with_payload(true, TcpFlags::default(), 60, vec![1, 2, 3]);
        let out2 = tcp_packet_with_payload(true, TcpFlags::default(), 60, vec![1, 2, 3]);
        let inb1 = tcp_packet_with_payload(false, TcpFlags::default(), 60, vec![4, 5, 6]);
        table.observe(&out1, &L7Info::None, 0);
        table.observe(&out2, &L7Info::None, 1);
        table.observe(&inb1, &L7Info::None, 2);

        let snap = table.snapshot(1000);
        // All three share seq=1000 in this fixture (tcp_packet always sets seq
        // 1000), so the *outbound* direction legitimately sees a repeat
        // (out2 after out1) — but the inbound direction's first-ever segment
        // must not count as a second retransmit on top of that.
        assert_eq!(snap[0].packet_loss, (1.0 / 3.0) * 100.0);
    }

    #[test]
    fn pure_acks_are_never_counted_as_retransmits() {
        // Regression test for the "misfires on every plain ACK" finding:
        // zero-payload segments reusing the previous sequence number (which
        // is how real ACKs behave) must not inflate packet_loss at all.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        let data = tcp_packet_with_payload(true, TcpFlags::default(), 100, vec![1, 2, 3]);
        let ack1 = tcp_packet(false, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        let ack2 = tcp_packet(false, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);
        table.observe(&data, &L7Info::None, 1);
        table.observe(&ack1, &L7Info::None, 2);
        table.observe(&ack2, &L7Info::None, 3);

        let snap = table.snapshot(1000);
        assert_eq!(snap[0].packet_loss, 0.0);
    }

    /// Builds a bare TCP packet like `tcp_packet`, but lets the caller choose
    /// the remote port so distinct-flow tests can produce two separate
    /// `FlowKey`s instead of colliding on the fixture's hardcoded remote.
    fn tcp_packet_to(local_is_src: bool, flags: TcpFlags, remote_port: u16) -> ParsedPacket {
        let (src_ip, dst_ip, src_port, dst_port) = if local_is_src {
            ("192.168.1.10".to_string(), "93.184.216.34".to_string(), 51000u16, remote_port)
        } else {
            ("93.184.216.34".to_string(), "192.168.1.10".to_string(), remote_port, 51000u16)
        };
        ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip,
            dst_ip,
            protocol: TransportProtocol::Tcp,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            tcp_flags: Some(flags),
            seq: Some(1000),
            ttl: 64,
            total_len: 60,
            payload: vec![],
            ip_version: 4,
            ip_checksum: Some(0),
        }
    }

    #[test]
    fn evicts_time_wait_flow_after_two_minutes_idle() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let fin = tcp_packet(true, TcpFlags { syn: false, ack: false, fin: true, rst: false, ..Default::default() }, 60);
        table.observe(&fin, &L7Info::None, 0);

        // idle = 120_001ms > the 120_000ms TIME_WAIT/CLOSE_WAIT threshold.
        let evicted = table.evict_stale(120_001);
        assert_eq!(evicted.len(), 1);
        assert_eq!(table.snapshot(120_001).len(), 0);
    }

    #[test]
    fn does_not_evict_time_wait_flow_before_threshold() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let fin = tcp_packet(true, TcpFlags { syn: false, ack: false, fin: true, rst: false, ..Default::default() }, 60);
        table.observe(&fin, &L7Info::None, 0);

        // idle = exactly 120_000ms, not yet past the threshold.
        let evicted = table.evict_stale(120_000);
        assert!(evicted.is_empty());
        assert_eq!(table.snapshot(120_000).len(), 1);
    }

    #[test]
    fn evicts_established_flow_past_ceiling_even_though_status_is_active() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        let ack = tcp_packet(true, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);
        table.observe(&ack, &L7Info::None, 5);

        // idle = 1_800_001ms > the 1_800_000ms ceiling — ESTABLISHED isn't
        // exempt from the ceiling just because it's not a closing status.
        let evicted = table.evict_stale(5 + 1_800_001);
        assert_eq!(evicted.len(), 1);
        assert_eq!(table.snapshot(5 + 1_800_001).len(), 0);
    }

    #[test]
    fn does_not_evict_established_flow_under_ceiling() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        let ack = tcp_packet(true, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);
        table.observe(&ack, &L7Info::None, 5);

        // idle = 1_800_000ms, exactly at the ceiling — not yet past it. An
        // idle-but-alive long-lived connection (e.g. an idle SSH session)
        // must survive under the ceiling.
        let evicted = table.evict_stale(5 + 1_800_000);
        assert!(evicted.is_empty());
        assert_eq!(table.snapshot(5 + 1_800_000).len(), 1);
    }

    #[test]
    fn evict_stale_leaves_other_flows_in_table() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);

        // Stale flow: FIN'd long ago on remote port 443.
        let fin = tcp_packet_to(true, TcpFlags { syn: false, ack: false, fin: true, rst: false, ..Default::default() }, 443);
        table.observe(&fin, &L7Info::None, 0);

        // Fresh flow: established just now on a different remote port.
        let syn = tcp_packet_to(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 8443);
        let ack = tcp_packet_to(true, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 8443);
        table.observe(&syn, &L7Info::None, 130_000);
        table.observe(&ack, &L7Info::None, 130_005);

        let now = 130_005 + 1; // stale flow idle ~130_006ms (> 120_000ms), fresh flow idle ~1ms
        let evicted = table.evict_stale(now);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].remote_port, 443);

        let remaining = table.snapshot(now);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key.remote_port, 8443);
    }

    #[test]
    fn rst_after_established_is_treated_as_closing_not_syn_sent() {
        // Regression test for the "RST-closed flows evade the 2-minute path"
        // finding: after SYN -> SYN/ACK -> ACK -> RST, the flow must report a
        // closing status (not fall through to "SYN_SENT" just because
        // syn_sent_at_ms is still set) and must be eligible for the same
        // 120s idle eviction as a FIN-closed flow.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        let synack = tcp_packet(false, TcpFlags { syn: true, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        let ack = tcp_packet(true, TcpFlags { syn: false, ack: true, fin: false, rst: false, ..Default::default() }, 60);
        let rst = tcp_packet(true, TcpFlags { syn: false, ack: false, fin: false, rst: true, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);
        table.observe(&synack, &L7Info::None, 5);
        table.observe(&ack, &L7Info::None, 10);
        table.observe(&rst, &L7Info::None, 15);

        let snap = table.snapshot(15);
        assert_eq!(snap[0].status, "TIME_WAIT");

        // idle = 120_001ms > the 120_000ms TIME_WAIT/CLOSE_WAIT threshold —
        // an RST-closed flow must not wait for the 30-minute ceiling.
        let evicted = table.evict_stale(15 + 120_001);
        assert_eq!(evicted.len(), 1);
    }

    #[test]
    fn evicts_syn_sent_flow_after_thirty_seconds_idle() {
        // Regression test: a connection attempt that never completes (SYN
        // out, nothing back) must not sit for the full 30-minute ceiling.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }, 60);
        table.observe(&syn, &L7Info::None, 0);

        assert!(table.evict_stale(30_000).is_empty(), "not yet past the 30s SYN_SENT threshold");
        let evicted = table.evict_stale(30_001);
        assert_eq!(evicted.len(), 1);
    }

    #[test]
    fn evicts_udp_flow_after_sixty_seconds_idle() {
        // Regression test: UDP flows always report "ESTABLISHED" (no closing
        // handshake exists), so without a dedicated idle timeout they'd sit
        // for the full 30-minute ceiling — turning ordinary DNS traffic into
        // an unbounded-growth vector.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let udp_packet = ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            protocol: TransportProtocol::Udp,
            src_port: Some(60123),
            dst_port: Some(53),
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: 40,
            payload: vec![],
            ip_version: 4,
            ip_checksum: Some(0),
        };
        table.observe(&udp_packet, &L7Info::None, 0);

        assert!(table.evict_stale(60_000).is_empty(), "not yet past the 60s UDP idle threshold");
        let evicted = table.evict_stale(60_001);
        assert_eq!(evicted.len(), 1);
    }

    #[test]
    fn enforces_max_flow_capacity_by_evicting_oldest() {
        // Regression test for the "no size cap" finding: once the table is
        // over `max_flows`, the least-recently-seen flows are evicted to
        // bring it back under the cap, independent of any idle timeout.
        let mut table = FlowTable::new_with_capacity(vec!["192.168.1.10".to_string()], 2);

        let a = tcp_packet_to(true, TcpFlags::default(), 1);
        let b = tcp_packet_to(true, TcpFlags::default(), 2);
        let c = tcp_packet_to(true, TcpFlags::default(), 3);
        table.observe(&a, &L7Info::None, 0);
        table.observe(&b, &L7Info::None, 10);
        table.observe(&c, &L7Info::None, 20);

        // All three flows are fresh (idle=0..20ms), so nothing is stale by
        // time alone — only the capacity cap should trigger an eviction.
        let evicted = table.evict_stale(20);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].remote_port, 1, "oldest (least-recently-seen) flow should be evicted first");

        let remaining = table.snapshot(20);
        assert_eq!(remaining.len(), 2);
        let remaining_ports: Vec<u16> = remaining.iter().map(|s| s.key.remote_port).collect();
        assert!(remaining_ports.contains(&2));
        assert!(remaining_ports.contains(&3));
    }

    #[test]
    fn observe_records_ja3_from_a_tls_client_hello_and_keeps_it_across_later_non_tls_packets() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        // `tcp_packet` (the existing fixture-building helper in this test
        // module) always targets remote 93.184.216.34:443.
        let packet = tcp_packet(true, TcpFlags::default(), 60);
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(),
            ja3: Some("abc123".to_string() + &"0".repeat(26)), // 32-char hex-like JA3 hash
            ja3_label: Some("matches Chrome 12x"),
        };
        table.observe(&packet, &l7, 0);
        table.observe(&packet, &L7Info::None, 100); // a later, non-ClientHello packet on the same flow

        let snaps = table.snapshot(200);
        let snap = snaps.iter().find(|s| s.key.remote_addr == "93.184.216.34").expect("flow present");
        assert!(snap.ja3_fingerprint.is_some());
        assert_eq!(snap.ja3_label, Some("matches Chrome 12x"));
    }

    #[test]
    fn udp_flows_report_established_not_a_tcp_closing_state() {
        // Regression test: a flow with no tcp_flags (UDP, e.g. DNS) must not
        // default to "CLOSE_WAIT" — that names a TCP state it never entered.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let udp_packet = ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            protocol: TransportProtocol::Udp,
            src_port: Some(60123),
            dst_port: Some(53),
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: 40,
            payload: vec![],
            ip_version: 4,
            ip_checksum: Some(0),
        };
        table.observe(&udp_packet, &L7Info::None, 0);

        let snap = table.snapshot(1000);
        assert_eq!(snap[0].status, "ESTABLISHED");
    }
}
