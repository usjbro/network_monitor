//! JAM-165/JAM-192: exercise actual capture-loop counters and findings.
#[path = "fixtures/agent_auth.rs"]
mod agent_auth;
use capture_agent::parse::{parse_packet, parse_packet_result, LinkType, ParseFailure};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn arp() -> Vec<u8> {
    let mut frame = vec![0xff; 6];
    frame.extend([0, 1, 2, 3, 4, 5, 0x08, 0x06]);
    frame.extend([0, 1, 0x08, 0, 6, 4, 0, 1]);
    frame.extend([0, 1, 2, 3, 4, 5, 192, 0, 2, 1]);
    frame.extend([0, 0, 0, 0, 0, 0, 192, 0, 2, 2]);
    frame
}

#[test]
fn valid_arp_and_vlan_arp_are_unsupported_instead_of_malformed() {
    let arp = arp();
    for tags in [
        vec![],
        vec![0x81, 0, 0, 7],
        vec![0x88, 0xa8, 0, 2, 0x81, 0, 0, 7],
    ] {
        let mut frame = arp[..12].to_vec();
        frame.extend(tags);
        frame.extend(&arp[12..]);
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::UnsupportedNonIp
        );
        assert!(
            parse_packet(&frame, LinkType::Ethernet).is_none(),
            "legacy API still omits non-IP events"
        );
    }
}

#[test]
fn truncated_ethernet_arp_and_vlan_headers_still_fail_as_malformed() {
    let arp = arp();
    for len in 0..arp.len() {
        assert_eq!(
            parse_packet_result(&arp[..len], LinkType::Ethernet).unwrap_err(),
            ParseFailure::Malformed,
            "ARP prefix {len}"
        );
    }
    let mut vlan = arp[..12].to_vec();
    vlan.extend([0x81, 0, 0]);
    assert_eq!(
        parse_packet_result(&vlan, LinkType::Ethernet).unwrap_err(),
        ParseFailure::Malformed
    );
}

#[test]
fn unknown_non_ip_ethertypes_are_unsupported_after_ethernet_framing_decodes() {
    for ethertype in [0x888eu16, 0x88cc, 0x88b5] {
        let mut frame = vec![0; 12];
        frame.extend(ethertype.to_be_bytes());
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::UnsupportedNonIp
        );
    }
}

#[test]
fn ieee8023_llc_stp_is_unsupported_instead_of_malformed() {
    // 802.3 length field followed by LLC (STP SAP 0x42) and a configuration BPDU.
    let mut payload = vec![0x42, 0x42, 0x03];
    payload.extend([0; 35]);
    let mut frame = vec![0x01, 0x80, 0xc2, 0, 0, 0, 0, 1, 2, 3, 4, 5];
    frame.extend((payload.len() as u16).to_be_bytes());
    frame.extend(payload);
    frame.resize(60, 0);
    assert_eq!(
        parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
        ParseFailure::UnsupportedNonIp
    );
}

#[test]
fn ip_carrying_pppoe_and_mpls_remain_decode_failures() {
    let mut ip = Vec::new();
    etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
        .udp(12000, 12001)
        .write(&mut ip, b"inner")
        .unwrap();
    for kind in [0x8864u16, 0x8847, 0x8848] {
        let mut payload = if kind == 0x8864 {
            let mut p = vec![0x11, 0, 0, 1];
            p.extend(((ip.len() + 2) as u16).to_be_bytes());
            p.extend([0, 0x21]);
            p
        } else {
            vec![0, 0, 1, 64]
        };
        payload.extend(&ip);
        for tagged in [false, true] {
            let mut frame = vec![0; 12];
            if tagged {
                frame.extend([0x81, 0, 0, 7]);
            }
            frame.extend(kind.to_be_bytes());
            frame.extend(&payload);
            assert_eq!(
                parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
                ParseFailure::Malformed,
                "kind {kind:#06x}, tagged {tagged}"
            );
        }
    }
}

#[test]
fn ieee8023_length_requires_complete_payload_and_allows_padding() {
    for tagged in [false, true] {
        for (declared, captured, expected) in [
            (100u16, 0, ParseFailure::Malformed),
            (100, 46, ParseFailure::Malformed),
            (1500, 1499, ParseFailure::Malformed),
            (1500, 1500, ParseFailure::UnsupportedNonIp),
            (38, 46, ParseFailure::UnsupportedNonIp),
            (0, 46, ParseFailure::UnsupportedNonIp),
            (1501, 1501, ParseFailure::Malformed),
            (1535, 1535, ParseFailure::Malformed),
            (1536, 0, ParseFailure::UnsupportedNonIp),
        ] {
            let mut frame = vec![0; 12];
            if tagged {
                frame.extend([0x81, 0, 0, 7]);
            }
            frame.extend(declared.to_be_bytes());
            frame.resize(frame.len() + captured, 0);
            assert_eq!(
                parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
                expected,
                "declared {declared}, captured {captured}, tagged {tagged}"
            );
        }
    }
}

#[test]
fn ethernet_padding_does_not_turn_valid_arp_into_a_parse_failure() {
    for padding in [0, 0xa5] {
        let mut frame = arp();
        frame.resize(60, padding);
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::UnsupportedNonIp
        );
    }
}

#[test]
fn opaque_macsec_is_not_silently_classified_as_non_ip() {
    // Modified, encrypted-unmodified, and encrypted MACsec payloads conceal
    // the next EtherType; successful SecTag parsing does not establish non-IP.
    for tci in [0x04, 0x08, 0x0c] {
        let mut frame = vec![0; 12];
        frame.extend([0x88, 0xe5, tci, 0, 0, 0, 0, 1]);
        frame.extend([0; 48]);
        assert!(etherparse::SlicedPacket::from_ethernet(&frame).is_ok());
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::Malformed
        );
    }
}

#[test]
fn cleartext_macsec_follows_the_decoded_inner_protocol() {
    let mut ip = Vec::new();
    etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
        .udp(12000, 12001)
        .write(&mut ip, b"inside")
        .unwrap();
    let wrap = |inner_type: u16, payload: &[u8]| {
        let mut frame = vec![0; 12];
        frame.extend([0x88, 0xe5, 0, 0, 0, 0, 0, 1]);
        frame.extend(inner_type.to_be_bytes());
        frame.extend(payload);
        frame
    };
    let parsed = parse_packet_result(&wrap(0x0800, &ip), LinkType::Ethernet).unwrap();
    assert_eq!(parsed.src_port, Some(12000));
    assert_eq!(parsed.payload, b"inside");
    assert_eq!(
        parse_packet_result(&wrap(0x0806, &arp()[14..]), LinkType::Ethernet).unwrap_err(),
        ParseFailure::UnsupportedNonIp
    );
}

#[test]
fn malformed_ip_is_not_hidden_as_unsupported_traffic() {
    let mut frame = vec![0; 12];
    frame.extend([0x08, 0]);
    frame.extend([0x45, 0, 0, 60]); // truncated IPv4 header and declared packet
    assert_eq!(
        parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
        ParseFailure::Malformed
    );
    assert_eq!(
        parse_packet_result(&frame[14..], LinkType::Raw).unwrap_err(),
        ParseFailure::Malformed
    );
    let mut loopback = vec![2, 0, 0, 0];
    loopback.extend(&frame[14..]);
    assert_eq!(
        parse_packet_result(&loopback, LinkType::NullLoopback).unwrap_err(),
        ParseFailure::Malformed
    );
}

#[test]
fn vlan_decoder_limit_does_not_hide_undecoded_known_headers() {
    for trailing_type in [0x8100u16, 0x0800, 0x0806] {
        let mut frame = vec![0; 12];
        frame.extend(0x8100u16.to_be_bytes());
        for next_type in [0x8100u16, 0x8100, trailing_type] {
            frame.extend([0, 7]);
            frame.extend(next_type.to_be_bytes());
        }
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::Malformed,
            "undecoded EtherType {trailing_type:#06x}"
        );
    }
}

#[test]
fn arp_address_lengths_must_match_known_address_types() {
    for (hardware_len, protocol_len) in [(0, 0), (5, 4), (6, 3)] {
        let mut frame = arp();
        frame[18] = hardware_len;
        frame[19] = protocol_len;
        assert_eq!(
            parse_packet_result(&frame, LinkType::Ethernet).unwrap_err(),
            ParseFailure::Malformed,
            "ARP address sizes {hardware_len}/{protocol_len}"
        );
    }
}

#[test]
#[ignore = "requires exclusive 127.0.0.1:9990; run with --ignored --test-threads=1"]
fn non_ip_replay_counts_only_malformed_frames_and_emits_only_their_findings() {
    // Refuse to connect to an operator's agent if the port is occupied.
    drop(TcpListener::bind("127.0.0.1:9990").expect("exclusive test port required"));
    let auth = agent_auth::AuthFixture::new();
    let path = auth.token_path().with_extension("pcap");
    let mut valid = Vec::new();
    etherparse::PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
        .udp(12000, 12001)
        .write(&mut valid, b"test")
        .unwrap();
    let arp = arp();
    let mut lldp = vec![0; 12];
    lldp.extend([0x88, 0xcc, 0, 0]);
    let mut vlan_arp = arp[..12].to_vec();
    vlan_arp.extend([0x81, 0, 0, 7]);
    vlan_arp.extend(&arp[12..]);
    let frames = [&valid[..], &arp, &lldp, &vlan_arp, &[0u8; 4], &valid];
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    pcap.extend([0; 8]);
    pcap.extend(65535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    for (seconds, frame) in frames.into_iter().enumerate() {
        pcap.extend((seconds as u32).to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        // The LLDP frame was cut during capture, but its Ethernet header
        // remains decodable. It is unsupported traffic, not a parse failure.
        let original_len = if seconds == 2 { 60 } else { frame.len() as u32 };
        pcap.extend(original_len.to_le_bytes());
        pcap.extend(frame);
    }
    std::fs::write(&path, pcap).unwrap();
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_capture-agent"))
            .env("AGENT_TOKEN_FILE", auth.token_path())
            .env("REPLAY_FILE", &path)
            .env("REPLAY_SPEED", "realtime")
            .env("REPLAY_LOCAL_ADDRS", "192.0.2.1")
            .env_remove("CAPTURE_INTERFACE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let stdout = agent.0.stdout.take().unwrap();
    let stderr = agent.0.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<_>>()
            .join("\n")
    });
    let output = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("replay finished") {
                let _ = finished_tx.send(());
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let stream = loop {
        match TcpStream::connect("127.0.0.1:9990") {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("agent did not start: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut reader = auth.authenticate(stream);
    let mut finished = false;
    let mut count = None;
    let mut summaries = Vec::new();
    while Instant::now() < deadline {
        finished |= finished_rx.try_recv().is_ok();
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let event: serde_json::Value = serde_json::from_str(&line).unwrap();
                if event["type"] == "finding" && event["finding"]["code"] == "malformed-frame" {
                    summaries.push(event["finding"]["summary"].as_str().unwrap().to_owned());
                }
                if finished && event["type"] == "capture_stats" {
                    count = event["stats"]["unparseableFrames"].as_u64();
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("wire read: {error}"),
        }
    }
    drop(agent);
    output.join().unwrap();
    let stderr = errors.join().unwrap();
    assert!(finished, "replay did not reach EOF");
    assert!(
        stderr.contains(
            "frames are being cut short at capture (16 captured bytes, 60 original bytes)"
        ),
        "capture truncation must remain visible independently of parse failures: {stderr}"
    );
    eprintln!("mixed capture: unparseableFrames={count:?}, malformed summaries={summaries:?}");
    assert_eq!(
        count,
        Some(1),
        "three supported link-layer/non-IP frames must not inflate parse failures"
    );
    assert_eq!(
        summaries.len(),
        1,
        "unsupported traffic must not emit malformed-frame findings: {summaries:?}"
    );
    assert!(summaries[0].starts_with("4-byte frame"));
}
