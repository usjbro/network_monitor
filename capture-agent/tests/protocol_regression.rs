//! Protocol-classification regression corpus (issue #115 / JAM-53).
//!
//! One table-driven test that runs every fixture in `tests/fixtures/`
//! through the real classification pipeline (`parse_packet` -> `sniff_l7`,
//! plus `Http2Reassembler`/HPACK where relevant) and asserts the expected
//! result. Existing unit tests in `src/parse.rs`, `src/l7.rs`, `src/ja3.rs`,
//! and `src/http2.rs` already cover these code paths individually; this
//! test exists as a single, stable regression net so an accidental
//! classification break in any one of them shows up as one clear, curated
//! failure list here, at the integration level, rather than only in
//! scattered unit tests that could each be edited away independently.
//!
//! All fixtures run every time (no `#[test]` early-exits), and failures are
//! collected and reported together at the end, so a break in one protocol
//! never hides a break in another.

mod fixtures;

use capture_agent::http2::{FrameOutcome, Http2Reassembler};
use capture_agent::ja3::compute_ja3;
use capture_agent::l7::{sniff_l7, L7Info};
use capture_agent::parse::{parse_packet, LinkType, TransportProtocol};

fn check(name: &'static str, run: impl FnOnce() -> Result<(), String> + std::panic::UnwindSafe) -> Result<(), String> {
    std::panic::catch_unwind(run).unwrap_or_else(|payload| {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panicked".to_string());
        Err(format!("{name}: PANICKED — {msg}"))
    })
}

fn require(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(msg.into())
    }
}

type CaseFn = Box<dyn FnOnce() -> Result<(), String>>;

#[test]
fn protocol_classification_regression_corpus() {
    let mut failures: Vec<String> = Vec::new();

    let cases: Vec<(&'static str, CaseFn)> = vec![
        (
            "ethernet_ipv4_tcp_handshake",
            Box::new(|| {
                let [syn, syn_ack, ack] = fixtures::ethernet_ipv4_tcp_handshake();

                let p = parse_packet(&syn, LinkType::Ethernet).ok_or("SYN failed to parse")?;
                require(p.protocol == TransportProtocol::Tcp, "SYN: wrong protocol")?;
                require(p.tcp_flags.map(|f| f.syn && !f.ack).unwrap_or(false), "SYN: expected syn && !ack")?;
                require(p.ip_version == 4, "SYN: expected IPv4")?;
                require(p.dst_port == Some(443), "SYN: wrong dst_port")?;

                let p = parse_packet(&syn_ack, LinkType::Ethernet).ok_or("SYN+ACK failed to parse")?;
                require(p.tcp_flags.map(|f| f.syn && f.ack).unwrap_or(false), "SYN+ACK: expected syn && ack")?;

                let p = parse_packet(&ack, LinkType::Ethernet).ok_or("ACK failed to parse")?;
                require(p.tcp_flags.map(|f| !f.syn && f.ack).unwrap_or(false), "ACK: expected !syn && ack")?;
                Ok(())
            }),
        ),
        (
            "ethernet_ipv6_tcp_syn",
            Box::new(|| {
                let data = fixtures::ethernet_ipv6_tcp_syn();
                let p = parse_packet(&data, LinkType::Ethernet).ok_or("failed to parse")?;
                require(p.ip_version == 6, "expected IPv6")?;
                require(p.ip_checksum.is_none(), "IPv6 must never report a header checksum")?;
                require(p.protocol == TransportProtocol::Tcp, "wrong protocol")?;
                require(p.dst_ip.contains(':'), "dst_ip does not look like IPv6")?;
                Ok(())
            }),
        ),
        (
            "null_loopback_tcp",
            Box::new(|| {
                let data = fixtures::null_loopback_tcp();
                let p = parse_packet(&data, LinkType::NullLoopback).ok_or("failed to parse")?;
                require(p.src_ip == "127.0.0.1", "wrong src_ip")?;
                require(p.src_mac == "00:00:00:00:00:00", "loopback must report synthetic all-zero MAC")?;
                Ok(())
            }),
        ),
        (
            "raw_ip_udp",
            Box::new(|| {
                let data = fixtures::raw_ip_udp();
                let p = parse_packet(&data, LinkType::Raw).ok_or("failed to parse")?;
                require(p.protocol == TransportProtocol::Udp, "wrong protocol")?;
                require(p.dst_port == Some(12345), "wrong dst_port")?;
                Ok(())
            }),
        ),
        (
            "vlan_tagged_tcp",
            Box::new(|| {
                let data = fixtures::vlan_tagged_tcp();
                let p = parse_packet(&data, LinkType::Ethernet).ok_or("failed to parse")?;
                require(p.vlan_tag.as_deref() == Some("100"), "wrong or missing vlan_tag")?;
                require(p.protocol == TransportProtocol::Tcp, "VLAN tag disturbed transport parsing")?;
                Ok(())
            }),
        ),
        (
            "truncated_ethernet_frame_rejected_not_panicking",
            Box::new(|| {
                let data = fixtures::truncated_ethernet_frame();
                require(
                    parse_packet(&data, LinkType::Ethernet).is_none(),
                    "a snaplen-truncated frame must be rejected, not fabricate a partial result",
                )
            }),
        ),
        (
            "http11_request",
            Box::new(|| match sniff_l7(&fixtures::http11_request(), Some(80)) {
                L7Info::Http { method, path } => {
                    require(method == "GET", "wrong method")?;
                    require(path == "/index.html", "wrong path")
                }
                other => Err(format!("expected Http, got {other:?}")),
            }),
        ),
        (
            "http11_response",
            Box::new(|| match sniff_l7(&fixtures::http11_response(), Some(51000)) {
                L7Info::HttpResponse { status } => require(status == "200", "wrong status"),
                other => Err(format!("expected HttpResponse, got {other:?}")),
            }),
        ),
        (
            "dns_query",
            Box::new(|| match sniff_l7(&fixtures::dns_query(), Some(53)) {
                L7Info::Dns { query_name } => require(query_name == "a.com", "wrong query_name"),
                other => Err(format!("expected Dns, got {other:?}")),
            }),
        ),
        (
            "tls12_client_hello",
            Box::new(|| {
                let (record, fields) = fixtures::tls12_client_hello();
                let expected_ja3 = compute_ja3(&fields);
                match sniff_l7(&record, Some(443)) {
                    L7Info::TlsClientHello { sni, ja3, .. } => {
                        require(sni == "example.com", "wrong sni")?;
                        require(ja3.as_deref() == Some(expected_ja3.as_str()), "ja3 hash does not match independently computed value")
                    }
                    other => Err(format!("expected TlsClientHello, got {other:?}")),
                }
            }),
        ),
        (
            "tls13_client_hello",
            Box::new(|| {
                let (record, fields) = fixtures::tls13_client_hello();
                let expected_ja3 = compute_ja3(&fields);
                match sniff_l7(&record, Some(443)) {
                    L7Info::TlsClientHello { sni, ja3, .. } => {
                        require(sni == "example.com", "wrong sni")?;
                        require(ja3.as_deref() == Some(expected_ja3.as_str()), "ja3 hash does not match independently computed value")?;
                        // The TLS 1.2 and 1.3 fixtures must not collide on
                        // JA3 — they carry different extension lists (the
                        // supported_versions extension is TLS 1.3-only),
                        // which is exactly what JA3 is supposed to capture.
                        let (_, tls12_fields) = fixtures::tls12_client_hello();
                        require(expected_ja3 != compute_ja3(&tls12_fields), "TLS 1.2 and 1.3 fixtures must not hash identically")
                    }
                    other => Err(format!("expected TlsClientHello, got {other:?}")),
                }
            }),
        ),
        (
            "http2_headers_then_data",
            Box::new(|| {
                let mut r = Http2Reassembler::new();
                let outcomes = r.feed(0, &fixtures::http2_headers_then_data());
                let saw_headers = outcomes.iter().any(|o| {
                    matches!(o, FrameOutcome::Frame { stream_id: 1, headers, .. } if !headers.is_empty())
                });
                let saw_data = outcomes
                    .iter()
                    .any(|o| matches!(o, FrameOutcome::Frame { stream_id: 1, body, .. } if body == b"hello world"));
                require(saw_headers, "expected a HEADERS frame outcome on stream 1")?;
                require(saw_data, "expected a DATA frame outcome with body 'hello world' on stream 1")
            }),
        ),
    ];

    for (name, run) in cases {
        if let Err(msg) = check(name, std::panic::AssertUnwindSafe(run)) {
            failures.push(format!("{name}: {msg}"));
        }
    }

    if !failures.is_empty() {
        panic!("protocol classification regressions detected:\n{}", failures.join("\n"));
    }
}
