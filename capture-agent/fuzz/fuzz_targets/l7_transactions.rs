#![no_main]
//! JAM-15: the DNS response parser and request/response matcher on
//! arbitrary bytes, reached directly rather than through `parse_packet`'s
//! framing (which most mutated inputs never get past).
//!
//! Properties under test: no panic anywhere, and the tracker's pending set
//! never exceeds its documented bound however the messages arrive.
use std::sync::{Arc, Mutex};

use capture_agent::flow::FlowKey;
use capture_agent::l7::sniff_l7;
use capture_agent::parse::TransportProtocol;
use capture_agent::transaction::{ServiceTimeStats, TransactionTracker, MAX_PENDING};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let stats = Arc::new(Mutex::new(ServiceTimeStats::default()));
    let mut tracker = TransactionTracker::new(stats.clone());
    let mut ts_us: u64 = 0;
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
        ts_us = ts_us.saturating_add(u64::from(control >> 3) * 250_000);
        let _ = tracker.observe_frame(Some((&flow, outbound)), &l7, ts_us, retransmit);
        let _ = tracker.expire(ts_us);
        assert!(tracker.pending_len() <= MAX_PENDING);
    }
    let _ = stats.lock().unwrap().snapshot();
    // And the same bytes through every sniff entry point.
    let _ = sniff_l7(data, Some(53));
    let _ = sniff_l7(data, None);
});
