//! JAM-15: request/response matching and service response time for DNS and
//! HTTP/1.x.
//!
//! The tracker links a response to the request it answers and measures the
//! time between them on the capture clock (the frames' own timestamps), so
//! what it reports is service time as seen at this capture point: how long
//! the server took to answer, plus one network round trip. Requests that
//! never get an answer are reported once each, as `unanswered-request`
//! findings, rather than accumulating.
//!
//! It is owned by the capture thread, like `StreamReassembler`, and keyed on
//! `FlowTable::key_for`'s flow identity so both agree on which connection a
//! packet belongs to. Everything it holds is bounded: see `MAX_PENDING`,
//! `MAX_HTTP_PIPELINE` and the timeouts. See
//! `docs/superpowers/specs/2026-10-04-service-response-time-design.md`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::flow::FlowKey;
use crate::l7::{dns_type_name, L7Info};
use crate::parse::TransportProtocol;
use crate::wire::ServiceTimeSummaryJson;

/// How long a DNS query may wait for its response before it is reported as
/// unanswered. Five seconds is the per-attempt timeout most stub resolvers
/// use (glibc's `timeout:5` default), after which the client itself retries
/// or gives up.
pub const DNS_TIMEOUT_US: u64 = 5_000_000;

/// How long an HTTP/1.x request may wait for its response's status line.
/// Long enough for ordinary slow responses; a long-poll request will exceed
/// it, which is why the finding says "no response seen within" rather than
/// claiming the request failed.
pub const HTTP_TIMEOUT_US: u64 = 30_000_000;

/// Ceiling on pending requests across every flow and protocol, and
/// separately on the remembered answered-DNS set used to recognize duplicate
/// responses. A request arriving at the ceiling is counted as untracked
/// rather than evicting an older one: the older ones expire on their own,
/// and an unbounded set would let a query flood grow memory without limit.
pub const MAX_PENDING: usize = 4_096;

/// Ceiling on outstanding pipelined requests on one HTTP/1.x connection.
pub const MAX_HTTP_PIPELINE: usize = 32;

/// How many recent service times each protocol keeps for its median and
/// 95th percentile. Count, minimum and maximum are exact over the whole
/// capture; the percentiles are over this window only, and the wire event
/// says how many samples they were computed from.
pub const RECENT_SAMPLES: usize = 1_024;

/// The capture-time interval between timeout sweeps. A sweep scans every
/// pending request, so it runs at most this often rather than per frame.
const SWEEP_INTERVAL_US: u64 = 500_000;

/// Longest request description kept for a finding's summary.
const MAX_LABEL_CHARS: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnProtocol {
    Dns,
    Http,
}

impl TxnProtocol {
    pub fn label(self) -> &'static str {
        match self {
            TxnProtocol::Dns => "DNS",
            TxnProtocol::Http => "HTTP",
        }
    }

    fn timeout_us(self) -> u64 {
        match self {
            TxnProtocol::Dns => DNS_TIMEOUT_US,
            TxnProtocol::Http => HTTP_TIMEOUT_US,
        }
    }
}

/// A handle to a request the tracker has just started waiting on, used to
/// attach the request's packet-event id once the capture loop has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestRef {
    Dns(FlowKey, u16),
    Http(FlowKey, u64),
}

/// What one frame meant to the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnEvent {
    /// Not a DNS or HTTP/1.x message the tracker matches.
    None,
    /// A request the tracker is now waiting on.
    Request(RequestRef),
    /// A request the tracker declined to wait on because a bound was
    /// reached. Its response, if one arrives, will be `Unmatched`.
    Untracked,
    /// A DNS query repeated while the original was still pending. The
    /// original's send time is kept: service time is measured from the
    /// first attempt, which is what the client experienced.
    RetransmittedRequest,
    /// A response matched to its request.
    Answered {
        protocol: TxnProtocol,
        service_time_us: u64,
        /// The request's packet-event id, when the request was emitted as a
        /// packet event. `None` when it wasn't (the packet-event rate limit
        /// skipped it), so the UI is never pointed at a frame it never got.
        request_frame_id: Option<String>,
    },
    /// A second response to a DNS transaction that was already answered.
    DuplicateResponse,
    /// An HTTP 1xx informational response. The request stays pending until
    /// its final response.
    Informational,
    /// A response with no pending request: the request predates the
    /// capture, was untracked, or this is not really a response to anything
    /// seen here.
    Unmatched,
}

/// A request that timed out without a response, reported once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unanswered {
    pub protocol: TxnProtocol,
    pub flow_id: String,
    pub request_frame_id: Option<String>,
    /// Display-safe description of the request (see `display_safe`).
    pub description: String,
}

impl Unanswered {
    pub fn summary(&self) -> String {
        format!(
            "no {} response to {} within {} s",
            self.protocol.label(),
            self.description,
            self.protocol.timeout_us() / 1_000_000
        )
    }
}

#[derive(Debug)]
struct PendingRequest {
    sent_at_us: u64,
    request_is_outbound: bool,
    description: String,
    frame_id: Option<String>,
    // DNS only: the question name, lowercased, which a response must echo.
    dns_qname: Option<String>,
    // HTTP only: the request's position in its connection's pipeline.
    http_seq: u64,
}

/// Per-protocol service-time statistics, cumulative since the agent
/// started. Shared with the periodic emitter, which sends a snapshot each
/// tick as a `service_time_update` event.
#[derive(Debug, Default)]
pub struct ProtocolStats {
    answered: u64,
    unanswered: u64,
    untracked: u64,
    min_us: Option<u64>,
    max_us: Option<u64>,
    recent: VecDeque<u64>,
}

impl ProtocolStats {
    fn record(&mut self, service_time_us: u64) {
        self.answered += 1;
        self.min_us = Some(self.min_us.map_or(service_time_us, |m| m.min(service_time_us)));
        self.max_us = Some(self.max_us.map_or(service_time_us, |m| m.max(service_time_us)));
        if self.recent.len() == RECENT_SAMPLES {
            self.recent.pop_front();
        }
        self.recent.push_back(service_time_us);
    }

    fn summary(&self, protocol: TxnProtocol) -> ServiceTimeSummaryJson {
        let mut sorted: Vec<u64> = self.recent.iter().copied().collect();
        sorted.sort_unstable();
        ServiceTimeSummaryJson {
            protocol: protocol.label(),
            answered: self.answered,
            unanswered: self.unanswered,
            untracked: self.untracked,
            min_us: self.min_us,
            max_us: self.max_us,
            sample_count: sorted.len() as u64,
            median_us: nearest_rank(&sorted, 50),
            p95_us: nearest_rank(&sorted, 95),
        }
    }
}

/// The nearest-rank percentile of an ascending slice: the smallest value
/// with at least `percent`% of the samples at or below it. Always one of the
/// observed values, never an interpolation.
fn nearest_rank(sorted: &[u64], percent: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (percent * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

#[derive(Debug, Default)]
pub struct ServiceTimeStats {
    dns: ProtocolStats,
    http: ProtocolStats,
}

impl ServiceTimeStats {
    fn for_protocol(&mut self, protocol: TxnProtocol) -> &mut ProtocolStats {
        match protocol {
            TxnProtocol::Dns => &mut self.dns,
            TxnProtocol::Http => &mut self.http,
        }
    }

    /// One summary per protocol, in a fixed order. Both are always present,
    /// so a client can show "0 answered" instead of guessing why a protocol
    /// is missing.
    pub fn snapshot(&self) -> Vec<ServiceTimeSummaryJson> {
        vec![self.dns.summary(TxnProtocol::Dns), self.http.summary(TxnProtocol::Http)]
    }
}

/// Renders untrusted request text (a DNS name, an HTTP method and path) for
/// a finding summary: printable ASCII passes through, everything else is
/// escaped as `\u{..}`, and the result is truncated. Control characters,
/// ANSI escape sequences and bidirectional overrides therefore arrive as
/// visible text, never as instructions to a terminal or a renderer.
fn display_safe(text: &str) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == MAX_LABEL_CHARS {
            out.push('…');
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

pub struct TransactionTracker {
    dns: HashMap<(FlowKey, u16), PendingRequest>,
    http: HashMap<FlowKey, VecDeque<PendingRequest>>,
    /// DNS transactions answered within the last `DNS_TIMEOUT_US`, so a
    /// second response to one is reported as a duplicate rather than as
    /// unmatched. Value is the capture time it was answered.
    answered_dns: HashMap<(FlowKey, u16), u64>,
    pending_total: usize,
    next_http_seq: u64,
    last_sweep_us: Option<u64>,
    stats: Arc<Mutex<ServiceTimeStats>>,
}

impl TransactionTracker {
    pub fn new(stats: Arc<Mutex<ServiceTimeStats>>) -> Self {
        TransactionTracker {
            dns: HashMap::new(),
            http: HashMap::new(),
            answered_dns: HashMap::new(),
            pending_total: 0,
            next_http_seq: 0,
            last_sweep_us: None,
            stats,
        }
    }

    /// Pending requests across every flow — the quantity `MAX_PENDING`
    /// bounds.
    pub fn pending_len(&self) -> usize {
        self.pending_total
    }

    /// Forgets every pending request and remembered answer, keeping the
    /// cumulative statistics. Called on a runtime interface switch (as
    /// `StreamReassembler::reset` is, JAM-183): requests seen on the old
    /// interface can never be answered on the new one, and reporting them
    /// as unanswered would be false.
    pub fn reset(&mut self) {
        self.dns.clear();
        self.http.clear();
        self.answered_dns.clear();
        self.pending_total = 0;
        self.last_sweep_us = None;
    }

    /// Matches one frame. `flow` is `FlowTable::key_for`'s result for it;
    /// `ts_us` is the frame's capture timestamp in microseconds.
    ///
    /// `is_tcp_retransmit` is `FlowTable::observe`'s verdict for the frame.
    /// A retransmitted segment carries the same request line again, and
    /// queueing it a second time would leave a phantom request behind its
    /// real response, to be reported as unanswered 30 s later.
    pub fn observe_frame(
        &mut self,
        flow: Option<(&FlowKey, bool)>,
        l7: &L7Info,
        ts_us: u64,
        is_tcp_retransmit: bool,
    ) -> TxnEvent {
        if is_tcp_retransmit {
            return TxnEvent::None;
        }
        let Some((key, is_outbound)) = flow else { return TxnEvent::None };
        match l7 {
            L7Info::Dns { query_name, id, qtype } => {
                self.dns_query(key, is_outbound, query_name, *id, *qtype, ts_us)
            }
            L7Info::DnsResponse { query_name, id, .. } => {
                self.dns_response(key, is_outbound, query_name, *id, ts_us)
            }
            L7Info::Http { method, path } => self.http_request(key, is_outbound, method, path, ts_us),
            L7Info::HttpResponse { status } => self.http_response(key, is_outbound, status, ts_us),
            L7Info::TlsClientHello { .. } | L7Info::None => TxnEvent::None,
        }
    }

    /// Records the packet-event id of a request `observe` just returned as
    /// `TxnEvent::Request`. Does nothing if the request is already gone.
    pub fn attach_frame_id(&mut self, request: &RequestRef, frame_id: String) {
        match request {
            RequestRef::Dns(key, id) => {
                if let Some(pending) = self.dns.get_mut(&(key.clone(), *id)) {
                    pending.frame_id = Some(frame_id);
                }
            }
            RequestRef::Http(key, seq) => {
                if let Some(pending) = self
                    .http
                    .get_mut(key)
                    .and_then(|queue| queue.iter_mut().find(|p| p.http_seq == *seq))
                {
                    pending.frame_id = Some(frame_id);
                }
            }
        }
    }

    /// Removes and returns every request whose timeout has passed by capture
    /// time `now_us`. Runs a full scan at most once per `SWEEP_INTERVAL_US`
    /// of capture time; calls in between return nothing.
    pub fn expire(&mut self, now_us: u64) -> Vec<Unanswered> {
        if let Some(last) = self.last_sweep_us {
            if now_us.saturating_sub(last) < SWEEP_INTERVAL_US {
                return Vec::new();
            }
        }
        self.last_sweep_us = Some(now_us);

        let timed_out = |pending: &PendingRequest, protocol: TxnProtocol| {
            now_us.saturating_sub(pending.sent_at_us) >= protocol.timeout_us()
        };
        let mut expired = Vec::new();

        let dns_keys: Vec<(FlowKey, u16)> = self
            .dns
            .iter()
            .filter(|(_, pending)| timed_out(pending, TxnProtocol::Dns))
            .map(|(key, _)| key.clone())
            .collect();
        for key in dns_keys {
            if let Some(pending) = self.dns.remove(&key) {
                expired.push(Unanswered {
                    protocol: TxnProtocol::Dns,
                    flow_id: key.0.connection_id(),
                    request_frame_id: pending.frame_id,
                    description: pending.description,
                });
            }
        }

        for (key, queue) in self.http.iter_mut() {
            // A queue is in send order, so its expired requests are a prefix.
            while queue.front().is_some_and(|pending| timed_out(pending, TxnProtocol::Http)) {
                let pending = queue.pop_front().expect("front was just checked");
                expired.push(Unanswered {
                    protocol: TxnProtocol::Http,
                    flow_id: key.connection_id(),
                    request_frame_id: pending.frame_id,
                    description: pending.description,
                });
            }
        }
        self.http.retain(|_, queue| !queue.is_empty());
        self.answered_dns.retain(|_, answered_at| now_us.saturating_sub(*answered_at) < DNS_TIMEOUT_US);

        self.pending_total -= expired.len();
        if !expired.is_empty() {
            let mut stats = self.stats.lock().unwrap();
            for unanswered in &expired {
                stats.for_protocol(unanswered.protocol).unanswered += 1;
            }
        }
        expired
    }

    fn untracked(&mut self, protocol: TxnProtocol) -> TxnEvent {
        self.stats.lock().unwrap().for_protocol(protocol).untracked += 1;
        TxnEvent::Untracked
    }

    fn answered(&mut self, protocol: TxnProtocol, pending: PendingRequest, ts_us: u64) -> TxnEvent {
        self.pending_total -= 1;
        // A response timestamped before its request (an out-of-order capture
        // file) reports zero rather than wrapping.
        let service_time_us = ts_us.saturating_sub(pending.sent_at_us);
        self.stats.lock().unwrap().for_protocol(protocol).record(service_time_us);
        TxnEvent::Answered { protocol, service_time_us, request_frame_id: pending.frame_id }
    }

    /// Only unicast DNS over UDP to port 53 is matched. mDNS (5353) and
    /// LLMNR (5355) queries go to a multicast group and are answered on a
    /// different flow, so tracking them would turn every one into a false
    /// unanswered finding. DNS over TCP carries a length prefix the parser
    /// doesn't decode.
    fn is_dns_service(key: &FlowKey, server_is_remote: bool) -> bool {
        let server_port = if server_is_remote { key.remote_port } else { key.local_port };
        key.protocol == TransportProtocol::Udp && server_port == 53
    }

    fn dns_query(&mut self, key: &FlowKey, is_outbound: bool, name: &str, id: u16, qtype: u16, ts_us: u64) -> TxnEvent {
        // An outbound query is addressed to the remote side.
        if !Self::is_dns_service(key, is_outbound) {
            return TxnEvent::None;
        }
        let map_key = (key.clone(), id);
        if self.dns.contains_key(&map_key) {
            return TxnEvent::RetransmittedRequest;
        }
        if self.pending_total >= MAX_PENDING {
            return self.untracked(TxnProtocol::Dns);
        }
        // A new query reusing an answered transaction's id is a new
        // transaction; its answer must not be called a duplicate.
        self.answered_dns.remove(&map_key);
        self.dns.insert(
            map_key,
            PendingRequest {
                sent_at_us: ts_us,
                request_is_outbound: is_outbound,
                description: format!("\"{}\" {}", display_safe(name), dns_type_name(qtype)),
                frame_id: None,
                dns_qname: Some(name.to_ascii_lowercase()),
                http_seq: 0,
            },
        );
        self.pending_total += 1;
        TxnEvent::Request(RequestRef::Dns(key.clone(), id))
    }

    fn dns_response(&mut self, key: &FlowKey, is_outbound: bool, name: &str, id: u16, ts_us: u64) -> TxnEvent {
        // An inbound response comes from the remote side.
        if !Self::is_dns_service(key, !is_outbound) {
            return TxnEvent::None;
        }
        let map_key = (key.clone(), id);
        let matches = self.dns.get(&map_key).is_some_and(|pending| {
            // A response travels the opposite way to its query and echoes
            // its question (case-insensitively: RFC 4343, and 0x20 query-
            // name randomization relies on servers preserving case).
            pending.request_is_outbound != is_outbound
                && pending.dns_qname.as_deref() == Some(name.to_ascii_lowercase().as_str())
        });
        if matches {
            let pending = self.dns.remove(&map_key).expect("presence was just checked");
            if self.answered_dns.len() < MAX_PENDING {
                self.answered_dns.insert(map_key, ts_us);
            }
            return self.answered(TxnProtocol::Dns, pending, ts_us);
        }
        if !self.dns.contains_key(&map_key) && self.answered_dns.contains_key(&map_key) {
            return TxnEvent::DuplicateResponse;
        }
        TxnEvent::Unmatched
    }

    fn http_request(&mut self, key: &FlowKey, is_outbound: bool, method: &str, path: &str, ts_us: u64) -> TxnEvent {
        if self.pending_total >= MAX_PENDING
            || self.http.get(key).is_some_and(|queue| queue.len() >= MAX_HTTP_PIPELINE)
        {
            return self.untracked(TxnProtocol::Http);
        }
        let seq = self.next_http_seq;
        self.next_http_seq += 1;
        self.http.entry(key.clone()).or_default().push_back(PendingRequest {
            sent_at_us: ts_us,
            request_is_outbound: is_outbound,
            description: display_safe(&format!("{method} {path}")),
            frame_id: None,
            dns_qname: None,
            http_seq: seq,
        });
        self.pending_total += 1;
        TxnEvent::Request(RequestRef::Http(key.clone(), seq))
    }

    /// HTTP/1.x has no transaction id: responses come back in request order
    /// on a connection (RFC 9112 §9.3.2), so a final response answers the
    /// oldest outstanding request. It must travel the opposite way to it;
    /// if it doesn't, nothing is consumed, rather than guessing.
    fn http_response(&mut self, key: &FlowKey, is_outbound: bool, status: &str, ts_us: u64) -> TxnEvent {
        let Some(queue) = self.http.get_mut(key) else { return TxnEvent::Unmatched };
        let Some(front) = queue.front() else { return TxnEvent::Unmatched };
        if front.request_is_outbound == is_outbound {
            return TxnEvent::Unmatched;
        }
        // 1xx responses are interim (RFC 9110 §15.2), except 101, which
        // ends HTTP/1.x on this connection and is the request's final
        // response.
        if status.starts_with('1') && status != "101" {
            return TxnEvent::Informational;
        }
        let pending = queue.pop_front().expect("front was just checked");
        if queue.is_empty() {
            self.http.remove(key);
        }
        self.answered(TxnProtocol::Http, pending, ts_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::dns_test_support::{query, response};
    use crate::l7::sniff_l7;

    fn udp_flow(local_port: u16, remote_port: u16) -> FlowKey {
        FlowKey {
            protocol: TransportProtocol::Udp,
            local_addr: "192.168.1.10".into(),
            local_port,
            remote_addr: "192.168.1.1".into(),
            remote_port,
        }
    }

    fn tcp_flow() -> FlowKey {
        FlowKey {
            protocol: TransportProtocol::Tcp,
            local_addr: "192.168.1.10".into(),
            local_port: 50_000,
            remote_addr: "93.184.216.34".into(),
            remote_port: 80,
        }
    }

    impl TransactionTracker {
        fn observe(&mut self, flow: Option<(&FlowKey, bool)>, l7: &L7Info, ts_us: u64) -> TxnEvent {
            self.observe_frame(flow, l7, ts_us, false)
        }
    }

    fn tracker() -> (TransactionTracker, Arc<Mutex<ServiceTimeStats>>) {
        let stats = Arc::new(Mutex::new(ServiceTimeStats::default()));
        (TransactionTracker::new(stats.clone()), stats)
    }

    fn dns_q(id: u16, name: &str) -> L7Info {
        sniff_l7(&query(id, name, 1), Some(53))
    }

    fn dns_r(id: u16, name: &str) -> L7Info {
        sniff_l7(&response(id, name, 1, 0, &[(1, 60, vec![1, 2, 3, 4])]), Some(50_000))
    }

    fn http_req(path: &str) -> L7Info {
        L7Info::Http { method: "GET".into(), path: path.into() }
    }

    fn http_resp(status: &str) -> L7Info {
        L7Info::HttpResponse { status: status.into() }
    }

    fn answered_time(event: TxnEvent) -> u64 {
        match event {
            TxnEvent::Answered { service_time_us, .. } => service_time_us,
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    #[test]
    fn a_dns_response_is_matched_to_its_query_with_the_service_time_and_request_frame() {
        let (mut t, stats) = tracker();
        let flow = udp_flow(50_000, 53);
        let TxnEvent::Request(request) = t.observe(Some((&flow, true)), &dns_q(7, "example.com"), 1_000_000) else {
            panic!("expected Request")
        };
        t.attach_frame_id(&request, "pkt-1".into());
        assert_eq!(
            t.observe(Some((&flow, false)), &dns_r(7, "example.com"), 1_012_500),
            TxnEvent::Answered { protocol: TxnProtocol::Dns, service_time_us: 12_500, request_frame_id: Some("pkt-1".into()) }
        );
        assert_eq!(t.pending_len(), 0);
        assert_eq!(stats.lock().unwrap().snapshot()[0].answered, 1);
    }

    #[test]
    fn out_of_order_dns_responses_each_match_their_own_query() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(1, "a.com"), 0);
        t.observe(Some((&flow, true)), &dns_q(2, "b.com"), 1_000);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(2, "b.com"), 5_000)), 4_000);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(1, "a.com"), 9_000)), 9_000);
    }

    #[test]
    fn a_second_response_to_an_answered_query_is_a_duplicate_and_counts_once() {
        let (mut t, stats) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(3, "a.com"), 0);
        answered_time(t.observe(Some((&flow, false)), &dns_r(3, "a.com"), 10));
        assert_eq!(t.observe(Some((&flow, false)), &dns_r(3, "a.com"), 20), TxnEvent::DuplicateResponse);
        assert_eq!(stats.lock().unwrap().snapshot()[0].answered, 1);
    }

    #[test]
    fn a_reused_transaction_id_after_an_answer_is_a_new_transaction() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(3, "a.com"), 0);
        answered_time(t.observe(Some((&flow, false)), &dns_r(3, "a.com"), 10));
        t.observe(Some((&flow, true)), &dns_q(3, "a.com"), 100);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(3, "a.com"), 150)), 50);
    }

    #[test]
    fn a_response_echoing_a_different_question_does_not_consume_the_query() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(4, "a.com"), 0);
        assert_eq!(t.observe(Some((&flow, false)), &dns_r(4, "evil.com"), 5), TxnEvent::Unmatched);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(4, "A.COM"), 9)), 9);
    }

    #[test]
    fn a_response_travelling_the_same_way_as_the_query_does_not_match() {
        let (mut t, _) = tracker();
        // This host is the DNS server here. A "response" travelling toward
        // the server (inbound, so from the client's port, not 53) is not a
        // response to anything, and must not consume the query.
        let flow = udp_flow(53, 50_000);
        t.observe(Some((&flow, false)), &dns_q(5, "a.com"), 0);
        assert_eq!(t.observe(Some((&flow, false)), &dns_r(5, "a.com"), 5), TxnEvent::None);
        assert_eq!(t.pending_len(), 1);
    }

    #[test]
    fn a_retransmitted_query_keeps_the_first_attempts_send_time() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(6, "a.com"), 0);
        assert_eq!(t.observe(Some((&flow, true)), &dns_q(6, "a.com"), 1_000_000), TxnEvent::RetransmittedRequest);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(6, "a.com"), 1_200_000)), 1_200_000);
    }

    #[test]
    fn multicast_dns_is_not_tracked() {
        let (mut t, _) = tracker();
        let flow = udp_flow(5353, 5353);
        assert_eq!(t.observe(Some((&flow, true)), &dns_q(0, "printer.local"), 0), TxnEvent::None);
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn a_response_with_no_query_seen_is_unmatched() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        assert_eq!(t.observe(Some((&flow, false)), &dns_r(9, "a.com"), 0), TxnEvent::Unmatched);
    }

    #[test]
    fn an_unanswered_query_is_reported_once_after_its_timeout_and_then_forgotten() {
        let (mut t, stats) = tracker();
        let flow = udp_flow(50_000, 53);
        let TxnEvent::Request(request) = t.observe(Some((&flow, true)), &dns_q(8, "slow.example"), 0) else {
            panic!("expected Request")
        };
        t.attach_frame_id(&request, "pkt-9".into());
        assert!(t.expire(DNS_TIMEOUT_US - 1).is_empty());
        let expired = t.expire(DNS_TIMEOUT_US + SWEEP_INTERVAL_US);
        assert_eq!(
            expired,
            vec![Unanswered {
                protocol: TxnProtocol::Dns,
                flow_id: flow.connection_id(),
                request_frame_id: Some("pkt-9".into()),
                description: "\"slow.example\" A".into(),
            }]
        );
        assert_eq!(expired[0].summary(), "no DNS response to \"slow.example\" A within 5 s");
        assert_eq!(t.pending_len(), 0);
        assert!(t.expire(10 * DNS_TIMEOUT_US).is_empty());
        assert_eq!(stats.lock().unwrap().snapshot()[0].unanswered, 1);
        // A late response after the report is unmatched, not answered.
        assert_eq!(t.observe(Some((&flow, false)), &dns_r(8, "slow.example"), 10 * DNS_TIMEOUT_US), TxnEvent::Unmatched);
    }

    #[test]
    fn sweeps_are_rate_limited_on_capture_time() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.expire(DNS_TIMEOUT_US);
        t.observe(Some((&flow, true)), &dns_q(1, "a.com"), 0);
        // Due, but inside the sweep interval since the last sweep.
        assert!(t.expire(DNS_TIMEOUT_US + 1).is_empty());
        assert_eq!(t.expire(DNS_TIMEOUT_US + SWEEP_INTERVAL_US).len(), 1);
    }

    #[test]
    fn a_query_flood_stops_at_the_pending_bound_and_counts_the_rest_as_untracked() {
        let (mut t, stats) = tracker();
        for i in 0..(MAX_PENDING + 500) {
            let flow = udp_flow(10_000 + (i / 1000) as u16, 53);
            t.observe(Some((&flow, true)), &dns_q((i % 1000) as u16, "a.com"), i as u64);
        }
        assert_eq!(t.pending_len(), MAX_PENDING);
        assert_eq!(stats.lock().unwrap().snapshot()[0].untracked, 500);
        // And all of it drains once it times out.
        assert_eq!(t.expire(DNS_TIMEOUT_US + MAX_PENDING as u64 + 500).len(), MAX_PENDING);
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn http_responses_match_pipelined_requests_in_order() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/a"), 0);
        t.observe(Some((&flow, true)), &http_req("/b"), 10);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &http_resp("200"), 100)), 100);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &http_resp("404"), 150)), 140);
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn a_retransmitted_request_segment_is_not_queued_a_second_time() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/a"), 0);
        assert_eq!(t.observe_frame(Some((&flow, true)), &http_req("/a"), 200_000, true), TxnEvent::None);
        answered_time(t.observe(Some((&flow, false)), &http_resp("200"), 300_000));
        assert_eq!(t.pending_len(), 0);
        assert!(t.expire(10 * HTTP_TIMEOUT_US).is_empty());
    }

    #[test]
    fn an_interim_100_continue_leaves_the_request_waiting_for_its_final_response() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/upload"), 0);
        assert_eq!(t.observe(Some((&flow, false)), &http_resp("100"), 5), TxnEvent::Informational);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &http_resp("201"), 50)), 50);
    }

    #[test]
    fn a_101_switching_protocols_response_is_final() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/ws"), 0);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &http_resp("101"), 7)), 7);
    }

    #[test]
    fn an_http_response_in_the_requests_own_direction_consumes_nothing() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/a"), 0);
        assert_eq!(t.observe(Some((&flow, true)), &http_resp("200"), 5), TxnEvent::Unmatched);
        assert_eq!(t.pending_len(), 1);
    }

    #[test]
    fn an_http_response_with_no_request_seen_is_unmatched() {
        let (mut t, _) = tracker();
        assert_eq!(t.observe(Some((&tcp_flow(), false)), &http_resp("200"), 0), TxnEvent::Unmatched);
    }

    #[test]
    fn an_unanswered_http_request_times_out_with_a_display_safe_description() {
        let (mut t, _) = tracker();
        let flow = tcp_flow();
        t.observe(Some((&flow, true)), &http_req("/a\u{1b}[31mred\u{202e}"), 0);
        let expired = t.expire(HTTP_TIMEOUT_US);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].description, "GET /a\\u{1b}[31mred\\u{202e}");
        assert_eq!(expired[0].summary(), "no HTTP response to GET /a\\u{1b}[31mred\\u{202e} within 30 s");
    }

    #[test]
    fn long_request_descriptions_are_truncated() {
        let long = "x".repeat(500);
        let safe = display_safe(&long);
        assert_eq!(safe.chars().count(), MAX_LABEL_CHARS + 1);
        assert!(safe.ends_with('…'));
    }

    #[test]
    fn an_http_pipeline_past_its_bound_is_untracked() {
        let (mut t, stats) = tracker();
        let flow = tcp_flow();
        for i in 0..(MAX_HTTP_PIPELINE + 3) {
            t.observe(Some((&flow, true)), &http_req("/"), i as u64);
        }
        assert_eq!(t.pending_len(), MAX_HTTP_PIPELINE);
        assert_eq!(stats.lock().unwrap().snapshot()[1].untracked, 3);
    }

    #[test]
    fn reset_forgets_pending_requests_so_none_are_reported_unanswered() {
        let (mut t, stats) = tracker();
        t.observe(Some((&udp_flow(50_000, 53), true)), &dns_q(1, "a.com"), 0);
        t.observe(Some((&tcp_flow(), true)), &http_req("/"), 0);
        t.reset();
        assert_eq!(t.pending_len(), 0);
        assert!(t.expire(HTTP_TIMEOUT_US * 2).is_empty());
        assert_eq!(stats.lock().unwrap().snapshot()[0].unanswered, 0);
    }

    #[test]
    fn frames_with_no_flow_or_no_l7_are_ignored() {
        let (mut t, _) = tracker();
        assert_eq!(t.observe(None, &dns_q(1, "a.com"), 0), TxnEvent::None);
        assert_eq!(t.observe(Some((&tcp_flow(), true)), &L7Info::None, 0), TxnEvent::None);
    }

    #[test]
    fn a_response_timestamped_before_its_request_reports_zero_not_a_wrapped_value() {
        let (mut t, _) = tracker();
        let flow = udp_flow(50_000, 53);
        t.observe(Some((&flow, true)), &dns_q(1, "a.com"), 1_000);
        assert_eq!(answered_time(t.observe(Some((&flow, false)), &dns_r(1, "a.com"), 500)), 0);
    }

    #[test]
    fn summaries_report_exact_extremes_and_nearest_rank_percentiles() {
        let mut stats = ProtocolStats::default();
        for us in 1..=100u64 {
            stats.record(us * 1_000);
        }
        let summary = stats.summary(TxnProtocol::Dns);
        assert_eq!(summary.answered, 100);
        assert_eq!(summary.min_us, Some(1_000));
        assert_eq!(summary.max_us, Some(100_000));
        assert_eq!(summary.sample_count, 100);
        assert_eq!(summary.median_us, Some(50_000));
        assert_eq!(summary.p95_us, Some(95_000));
    }

    #[test]
    fn percentiles_cover_only_the_recent_window_while_extremes_cover_everything() {
        let mut stats = ProtocolStats::default();
        stats.record(1);
        for _ in 0..RECENT_SAMPLES {
            stats.record(500);
        }
        let summary = stats.summary(TxnProtocol::Http);
        assert_eq!(summary.answered, RECENT_SAMPLES as u64 + 1);
        assert_eq!(summary.sample_count, RECENT_SAMPLES as u64);
        assert_eq!(summary.min_us, Some(1));
        assert_eq!(summary.median_us, Some(500));
    }

    #[test]
    fn an_empty_protocol_summarizes_with_no_timing_values() {
        let summary = ProtocolStats::default().summary(TxnProtocol::Dns);
        assert_eq!((summary.min_us, summary.median_us, summary.p95_us, summary.max_us), (None, None, None, None));
        assert_eq!(nearest_rank(&[7], 95), Some(7));
    }
}
