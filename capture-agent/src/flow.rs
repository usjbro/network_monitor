use crate::l7::L7Info;
use crate::parse::{ParsedPacket, TransportProtocol};
use std::collections::hash_map::Entry;
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
    client_random: Option<Vec<u8>>,
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
            client_random: None,
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
    // Server-side-only lookup key for Tier B decrypt eligibility — never
    // serialized onto any wire event (see l7::L7Info::TlsClientHello's
    // client_random field doc comment).
    pub client_random: Option<Vec<u8>>,
}

/// Default ceiling on the number of tracked flows. Bounds memory under a SYN
/// flood / port scan / spoofed-UDP burst, which would otherwise allocate one
/// `FlowState` (four `String`s + a `HashMap`) per distinct (local, remote)
/// pair and hold each for up to 30 minutes regardless of attacker intent.
pub const DEFAULT_MAX_FLOWS: usize = 10_000;

pub struct FlowTable {
    local_addrs: Vec<String>,
    flows: HashMap<FlowKey, FlowState>,
    last_snapshot_ms: u64,
    max_flows: usize,
    /// Cumulative count of distinct flows ever observed (a repeat packet on
    /// an already-tracked flow doesn't count again) — never reset, unlike
    /// `flows.len()` which only reflects what's currently in the table.
    total_flows_observed: u64,
    /// Cumulative count of flows evicted because the table exceeded
    /// `max_flows`, distinct from `idle_evictions` below (see
    /// `EvictedFlows`).
    capacity_evictions: u64,
    /// Cumulative count of flows evicted for going idle past their
    /// status-appropriate threshold, distinct from `capacity_evictions`.
    idle_evictions: u64,
}

/// `evict_stale`'s result, split by eviction reason so a caller (the
/// periodic emitter's `capture_stats` reporting) can tell an operator-facing
/// "this connection just closed" apart from "the table is under memory
/// pressure and dropped a still-idle-but-not-stale flow to make room" — two
/// very different health signals that a single flat `Vec<FlowKey>` couldn't
/// distinguish. Both kinds still get an identical `connection_closed` wire
/// event; only the counting is reason-aware.
#[derive(Default)]
pub struct EvictedFlows {
    pub idle: Vec<FlowKey>,
    pub capacity: Vec<FlowKey>,
}

impl EvictedFlows {
    pub fn len(&self) -> usize {
        self.idle.len() + self.capacity.len()
    }

    pub fn is_empty(&self) -> bool {
        self.idle.is_empty() && self.capacity.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FlowKey> {
        self.idle.iter().chain(self.capacity.iter())
    }
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
            total_flows_observed: 0,
            capacity_evictions: 0,
            idle_evictions: 0,
        }
    }

    fn is_local(&self, addr: &str) -> bool {
        self.local_addrs.iter().any(|a| a == addr)
    }

    /// True exactly when `key_for`'s canonical-endpoint-ordering fallback is
    /// in effect for every packet this table observes right now — i.e.
    /// `local_addrs` is currently empty. Live, not a startup snapshot: a
    /// runtime `set_interface` switch (issue #69) calls `reset`, which can
    /// change this from either state to the other, so callers (the
    /// `agent_status` emitter) must re-read this each tick rather than
    /// caching the value computed at process start.
    pub fn direction_attribution_unavailable(&self) -> bool {
        self.local_addrs.is_empty()
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
        } else if self.local_addrs.is_empty() {
            // No known local address at all (replay with no REPLAY_LOCAL_ADDRS
            // and no IDB address option — see resolve_packet_source in
            // main.rs) — rather than silently dropping this packet from the
            // flow table entirely, fall back to a canonical ordering of the
            // two endpoints (compare (ip, port) pairs) and treat the
            // lexicographically-smaller one as "local" for FlowKey
            // construction. This is explicitly NOT a claim that endpoint
            // actually was the local side — every consumer of this flow's
            // direction is told so via
            // agent_status.directionAttributionUnavailable, sent once per
            // replay session, not silently per-flow. Canonicalizing by
            // endpoint identity (rather than by this packet's own src/dst
            // position) is what makes both directions of one connection map
            // to the same FlowKey, as this function's doc comment requires —
            // a positional convention would instead split a request and its
            // reply into two separate one-directional flows.
            let src_is_canonical_local =
                (&packet.src_ip, src_port) <= (&packet.dst_ip, dst_port);
            if src_is_canonical_local {
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
            } else {
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
            }
        } else {
            // local_addrs is non-empty but matched neither side — e.g. a
            // capture containing third-party-to-third-party traffic captured
            // in promiscuous mode. Unchanged existing behavior: this packet
            // isn't part of any flow this table tracks.
            None
        }
    }

    /// Returns the direction this packet was attributed (`Some(true)` =
    /// outbound/local-to-remote, `Some(false)` = inbound, `None` = the
    /// packet matched no tracked flow) — the single source of truth for
    /// per-packet direction, so callers (e.g. the capture loop's aggregate
    /// throughput counters) don't need their own separate src/dst-vs-
    /// local_addrs check that can drift out of sync with this one.
    pub fn observe(&mut self, packet: &ParsedPacket, l7: &L7Info, now_ms: u64) -> Option<bool> {
        let (key, is_outbound) = self.key_for(packet)?;
        let remote_port = key.remote_port;
        let is_new = matches!(self.flows.entry(key.clone()), Entry::Vacant(_));
        if is_new {
            self.total_flows_observed += 1;
        }
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
            L7Info::Http { .. } | L7Info::HttpResponse { .. } => state.app_layer_protocol = "HTTP".to_string(),
            L7Info::Dns { .. } => state.app_layer_protocol = "DNS".to_string(),
            L7Info::TlsClientHello { ja3, ja3_label, client_random, .. } => {
                state.app_layer_protocol = "HTTPS/TLS".to_string();
                state.encryption = "TLS".to_string();
                // First ClientHello wins: a flow has exactly one handshake,
                // so once a JA3 fingerprint is recorded, later packets on
                // the same flow (which report L7Info::None) must not
                // overwrite it.
                if state.ja3_fingerprint.is_none() {
                    state.ja3_fingerprint = ja3.clone();
                    state.ja3_label = *ja3_label;
                    state.client_random = client_random.clone();
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

        Some(is_outbound)
    }

    /// Looks up the given flow's observed ClientHello `client_random`, if
    /// any — used by the capture loop (Tier B) to find this flow's logged
    /// session secret without needing a full `snapshot()`. Returns `None`
    /// for a flow that hasn't been `observe()`d yet, or one whose
    /// ClientHello (if any) hasn't been seen yet.
    pub fn client_random_for(&self, key: &FlowKey) -> Option<Vec<u8>> {
        self.flows.get(key)?.client_random.clone()
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
                client_random: state.client_random.clone(),
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
    pub fn evict_stale(&mut self, now_ms: u64) -> EvictedFlows {
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
        let mut idle = Vec::new();
        self.flows.retain(|key, state| {
            let idle_ms = now_ms.saturating_sub(state.last_seen_ms);
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
            let stale = idle_ms > threshold;
            if stale {
                idle.push(key.clone());
            }
            !stale
        });
        self.idle_evictions += idle.len() as u64;

        let mut capacity = Vec::new();
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
                capacity.push(key);
            }
        }
        self.capacity_evictions += capacity.len() as u64;

        EvictedFlows { idle, capacity }
    }

    pub fn total_flows_observed(&self) -> u64 {
        self.total_flows_observed
    }

    pub fn capacity_evictions(&self) -> u64 {
        self.capacity_evictions
    }

    pub fn idle_evictions(&self) -> u64 {
        self.idle_evictions
    }

    /// Discards every tracked flow and replaces the local-address list used
    /// to decide packet direction — for a runtime interface switch (issue
    /// #69), not idle eviction. Every existing flow belonged to the
    /// interface that just stopped being captured; leaving it in the table
    /// with a now-wrong `local_addrs` frame of reference is exactly the
    /// silent-direction-flip bug that issue calls out as the error-prone
    /// part of switching interfaces. Returns the keys of everything
    /// discarded, so the caller can emit an explicit close event per
    /// removed flow — same contract as `evict_stale`.
    pub fn reset(&mut self, local_addrs: Vec<String>) -> Vec<FlowKey> {
        self.local_addrs = local_addrs;
        self.flows.drain().map(|(key, _)| key).collect()
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
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
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
    fn merges_both_directions_into_one_flow_when_local_addrs_is_empty() {
        // Regression test: key_for's empty-local_addrs fallback must
        // canonicalize by endpoint identity, not packet-positional src/dst —
        // otherwise a request and its reply (swapped src/dst) hash to two
        // different FlowKeys instead of merging into one flow.
        let mut table = FlowTable::new(vec![]);
        let request = tcp_packet(true, TcpFlags::default(), 100);
        let response = tcp_packet(false, TcpFlags::default(), 250);
        table.observe(&request, &L7Info::None, 0);
        table.observe(&response, &L7Info::None, 1);

        let snap = table.snapshot(1000);
        assert_eq!(snap.len(), 1, "expected request+response to merge into one flow, got {}", snap.len());
        assert_eq!(snap[0].tx_bytes_total + snap[0].rx_bytes_total, 350);
        assert!(
            snap[0].tx_bytes_total > 0 && snap[0].rx_bytes_total > 0,
            "expected both directions to have nonzero bytes, got tx={} rx={}",
            snap[0].tx_bytes_total,
            snap[0].rx_bytes_total
        );
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
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
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
        assert_eq!(evicted.idle[0].remote_port, 443);

        let remaining = table.snapshot(now);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key.remote_port, 8443);
    }

    #[test]
    fn reset_discards_every_flow_and_returns_their_keys() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let syn_a = tcp_packet_to(true, TcpFlags { syn: true, ..Default::default() }, 443);
        let syn_b = tcp_packet_to(true, TcpFlags { syn: true, ..Default::default() }, 8443);
        table.observe(&syn_a, &L7Info::None, 0);
        table.observe(&syn_b, &L7Info::None, 0);
        assert_eq!(table.snapshot(0).len(), 2);

        let closed = table.reset(vec!["10.0.0.5".to_string()]);

        assert_eq!(closed.len(), 2);
        let closed_ports: std::collections::HashSet<u16> = closed.iter().map(|k| k.remote_port).collect();
        assert_eq!(closed_ports, [443, 8443].into_iter().collect());
        assert!(table.snapshot(0).is_empty(), "reset must leave no flows behind");
    }

    #[test]
    fn direction_attribution_unavailable_reflects_a_runtime_reset() {
        // Regression test: a caller (the agent_status emitter) must be able
        // to read this live rather than caching it from startup — a runtime
        // `set_interface` switch (issue #69) to a properly-addressed
        // interface must clear this immediately, and a switch to an
        // addressless one must set it, not leave either state frozen.
        let mut table = FlowTable::new(vec![]); // starts with no known local address
        assert!(table.direction_attribution_unavailable());

        table.reset(vec!["10.0.0.5".to_string()]);
        assert!(!table.direction_attribution_unavailable(), "switching to an addressed interface must clear this immediately");

        table.reset(vec![]);
        assert!(table.direction_attribution_unavailable(), "switching to an addressless interface must set this immediately");
    }

    #[test]
    fn reset_replaces_local_addrs_so_direction_is_correct_for_the_new_interface() {
        // Regression test for issue #69's called-out risk: a stale
        // local_addrs after switching interfaces would make every packet's
        // direction wrong. Old local address (192.168.1.10) must no longer
        // count as local after reset; the new one (10.0.0.5) must.
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        table.reset(vec!["10.0.0.5".to_string()]);

        // A packet whose source is the NEW local address, observed after
        // reset, must be attributed as outbound (i.e. actually recognized
        // as local) — snapshot's local_addr field on the resulting flow
        // confirms which side FlowTable decided was "this machine".
        let outbound = ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip: "10.0.0.5".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            protocol: TransportProtocol::Tcp,
            src_port: Some(51000),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags { syn: true, ack: false, fin: false, rst: false, ..Default::default() }),
            seq: Some(1000),
            ttl: 64,
            total_len: 60,
            payload: vec![],
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
        };
        table.observe(&outbound, &L7Info::None, 0);
        let snap = table.snapshot(0);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].key.local_addr, "10.0.0.5");
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
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 8,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
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
        assert_eq!(evicted.capacity[0].remote_port, 1, "oldest (least-recently-seen) flow should be evicted first");

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
            client_random: Some(vec![0xab; 32]),
            sni_offset: 0,
            sni_len: 0,
        };
        table.observe(&packet, &l7, 0);
        table.observe(&packet, &L7Info::None, 100); // a later, non-ClientHello packet on the same flow

        let snaps = table.snapshot(200);
        let snap = snaps.iter().find(|s| s.key.remote_addr == "93.184.216.34").expect("flow present");
        assert!(snap.ja3_fingerprint.is_some());
        assert_eq!(snap.ja3_label, Some("matches Chrome 12x"));
        assert_eq!(snap.client_random, Some(vec![0xab; 32]));
    }

    #[test]
    fn client_random_for_returns_none_until_a_client_hello_is_observed() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let packet = tcp_packet(true, TcpFlags::default(), 60);
        let key = FlowKey {
            protocol: TransportProtocol::Tcp,
            local_addr: "192.168.1.10".to_string(),
            local_port: 51000,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 443,
        };
        assert!(table.client_random_for(&key).is_none());

        table.observe(&packet, &L7Info::None, 0);
        assert!(table.client_random_for(&key).is_none(), "no ClientHello observed yet");

        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(),
            ja3: Some("x".to_string()),
            ja3_label: None,
            client_random: Some(vec![0x42; 32]),
            sni_offset: 0,
            sni_len: 0,
        };
        table.observe(&packet, &l7, 1);
        assert_eq!(table.client_random_for(&key), Some(vec![0x42; 32]));
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
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 8,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
        };
        table.observe(&udp_packet, &L7Info::None, 0);

        let snap = table.snapshot(1000);
        assert_eq!(snap[0].status, "ESTABLISHED");
    }

    fn packet_between(src_ip: &str, dst_ip: &str) -> ParsedPacket {
        ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            protocol: TransportProtocol::Tcp,
            src_port: Some(51000),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags::default()),
            seq: Some(1000),
            ttl: 64,
            total_len: 60,
            payload: vec![],
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
        }
    }

    #[test]
    fn with_no_local_addrs_a_packet_still_produces_a_flow_using_canonical_endpoint_ordering() {
        let mut table = FlowTable::new(vec![]); // empty — the replay-with-no-hint case
        let packet = packet_between("203.0.113.5", "198.51.100.9");
        table.observe(&packet, &L7Info::None, 0);

        let flows = table.snapshot(0);
        assert_eq!(flows.len(), 1, "an empty local_addrs list must not silently drop every packet");
        // Canonical ordering compares (ip, port) pairs and picks the
        // lexicographically-smaller endpoint as "local" — regardless of
        // which side happens to be this packet's src — so that a reply
        // packet (with src/dst swapped) still maps to the same FlowKey. See
        // merges_both_directions_into_one_flow_when_local_addrs_is_empty.
        assert_eq!(flows[0].key.local_addr, "198.51.100.9", "canonical ordering picks the lexicographically-smaller endpoint as local");
    }

    #[test]
    fn with_local_addrs_set_but_not_matching_either_side_the_packet_is_still_dropped() {
        let mut table = FlowTable::new(vec!["10.0.0.1".to_string()]); // non-empty, but doesn't match this packet
        let packet = packet_between("203.0.113.5", "198.51.100.9");
        table.observe(&packet, &L7Info::None, 0);

        assert_eq!(
            table.snapshot(0).len(),
            0,
            "a non-empty, non-matching local_addrs list keeps its existing drop behavior — only the EMPTY case gets the new fallback"
        );
    }

    #[test]
    fn total_flows_observed_counts_distinct_flows_not_packets() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let packet = tcp_packet(true, TcpFlags::default(), 60);
        table.observe(&packet, &L7Info::None, 0);
        table.observe(&packet, &L7Info::None, 100); // same flow, second packet
        table.observe(&packet, &L7Info::None, 200); // same flow, third packet
        assert_eq!(table.total_flows_observed(), 1, "repeated packets on the same flow must not inflate the observed count");
    }

    #[test]
    fn capacity_and_idle_evictions_are_counted_separately() {
        let mut table = FlowTable::new_with_capacity(vec!["10.0.0.1".to_string()], 1);
        let a = ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            protocol: TransportProtocol::Tcp,
            src_port: Some(51000),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags::default()),
            seq: Some(1000),
            ttl: 64,
            total_len: 60,
            payload: vec![],
            header_bytes: vec![],
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
        };
        let b = ParsedPacket { dst_port: Some(444), ..a.clone() }; // distinct key from a
        table.observe(&a, &L7Info::None, 0);
        table.observe(&b, &L7Info::None, 0); // exceeds capacity 1 — evicts a

        let evicted = table.evict_stale(0);
        assert_eq!(evicted.capacity.len(), 1);
        assert_eq!(evicted.idle.len(), 0);
        assert_eq!(table.capacity_evictions(), 1);
        assert_eq!(table.idle_evictions(), 0);
    }
}
