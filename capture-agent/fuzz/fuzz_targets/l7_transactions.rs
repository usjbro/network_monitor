#![no_main]
//! JAM-15: the DNS response parser and request/response matcher on
//! arbitrary bytes, reached directly rather than through `parse_packet`'s
//! framing (which most mutated inputs never get past).
//!
//! Properties under test: no panic anywhere, and the tracker's pending set
//! never exceeds its documented bound however the messages arrive.
use std::sync::{Arc, Mutex};

use capture_agent::dns_names::ObservedDnsNames;
use capture_agent::flow::FlowKey;
use capture_agent::l7::{sniff_dns_tcp, sniff_for_transport, sniff_l7, L7Info};
use capture_agent::parse::TransportProtocol;
use capture_agent::transaction::{ServiceTimeStats, TransactionTracker, MAX_PENDING};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let stats = Arc::new(Mutex::new(ServiceTimeStats::default()));
    let mut tracker = TransactionTracker::new(stats.clone());
    let mut ts_us: u64 = 0;
    // JAM-21: the observed name table, fed every decoded response on the
    // fuzzed clock; its bound must hold whatever arrives.
    let mut names = ObservedDnsNames::new(64);
    let mut rest = data;
    // Each record: control byte, then a 1-byte length, then that many bytes
    // of message. The control byte picks the flow, the direction, the
    // transport, a TCP-retransmit flag and how far the clock advances.
    while let [control, len, tail @ ..] = rest {
        let len = (*len as usize).min(tail.len());
        let (message, next) = tail.split_at(len);
        rest = next;

        let udp = control & 0x01 != 0;
        let outbound = control & 0x02 != 0;
        let retransmit = control & 0x04 != 0;
        let flow = FlowKey {
            protocol: if udp { TransportProtocol::Udp } else { TransportProtocol::Tcp },
            local_addr: "10.0.0.2".into(),
            local_port: 40_000 + u16::from(control >> 6),
            remote_addr: "10.0.0.1".into(),
            remote_port: if udp { 53 } else { 80 },
        };
        let dst_port = if outbound { flow.remote_port } else { flow.local_port };
        let l7 = sniff_l7(message, Some(dst_port));
        // JAM-21: the same message as DNS over TCP, with a correct length
        // prefix so mutated bytes reach `sniff_dns` past the length check.
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(message);
        let _ = sniff_dns_tcp(&framed);
        // JAM-21: TCP/53 in each direction, including source 53 to a port
        // that is not an HTTP or TLS port, which tries HTTP and TLS first.
        for (src, dst) in [(40_000, 53), (53, 40_000), (53, 8_443), (53, 80), (53, 53)] {
            let _ = sniff_for_transport(message, TransportProtocol::Tcp, Some(src), Some(dst));
            let _ = sniff_for_transport(&framed, TransportProtocol::Tcp, Some(src), Some(dst));
        }
        ts_us = ts_us.saturating_add(u64::from(control >> 3) * 250_000);
        if let L7Info::DnsResponse { query_name, answers, .. } = &l7 {
            names.learn_response(query_name, answers, ts_us / 1_000);
            assert!(names.len() <= 64);
        }
        let _ = tracker.observe_frame(Some((&flow, outbound)), &l7, ts_us, retransmit);
        let _ = tracker.expire(ts_us);
        assert!(tracker.pending_len() <= MAX_PENDING);
    }
    let _ = stats.lock().unwrap().snapshot();
    // And the same bytes through every sniff entry point.
    let _ = sniff_l7(data, Some(53));
    let _ = sniff_l7(data, None);
    let _ = sniff_dns_tcp(data);
});
