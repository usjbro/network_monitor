//! Round-trip integration test for the pcapng codec (JAM-140 / issue #71).
//!
//! `src/pcapng.rs`'s own unit tests already cover `Writer`/`Reader` in
//! isolation; this test exists as the most direct correctness check
//! available for a file format meant to be read back later (offline
//! replay, a following task, and any external tool such as Wireshark): a
//! real file on disk, written through the public `Writer` API exactly as
//! `capture-agent`'s writer thread does, then read back end to end through
//! the public `Reader` API, asserting every packet's direction and bytes
//! survive unchanged and in order.

use capture_agent::parse::LinkType;
use capture_agent::pcapng::{Direction, InterfaceDescriptionBlock, Reader, Writer};
use std::fs::File;
use std::time::SystemTime;

fn unique_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "pcapng-roundtrip-test-{label}-{}-{}.pcapng",
        std::process::id(),
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
    ))
}

#[test]
fn a_file_written_by_writer_reads_back_identically_through_reader() {
    let path = unique_path("basic");
    let idb = InterfaceDescriptionBlock {
        interface_name: "en0".into(),
        link_type: LinkType::Ethernet,
        snaplen: 65535,
        timestamp_resolution_exponent: 9,
    };

    let packets: Vec<(Direction, Vec<u8>)> = vec![
        (Direction::Inbound, vec![0xAA; 40]),
        (Direction::Outbound, vec![0xBB; 128]),
        (Direction::Inbound, vec![0xCC; 1]),
        (Direction::Unknown, vec![]), // a zero-length capture must still round-trip cleanly
        (Direction::Outbound, (0u8..=255).collect()),
    ];

    let mut writer = Writer::create(&path, &idb, "roundtrip-host", "9.9.9").unwrap();
    for (direction, data) in &packets {
        writer.write_packet(SystemTime::now(), *direction, data).unwrap();
    }
    writer.write_interface_stats(42, 7).unwrap(); // an interleaved ISB must not appear as a packet on read-back
    for (direction, data) in &packets {
        writer.write_packet(SystemTime::now(), *direction, data).unwrap();
    }
    writer.finish().unwrap();

    let file = File::open(&path).unwrap();
    let (mut reader, interface) = Reader::new(file).unwrap();
    assert_eq!(interface.interface_name.as_deref(), Some("en0"));
    assert_eq!(interface.link_type, LinkType::Ethernet);
    assert_eq!(interface.snaplen, 65535);

    let mut read_back = Vec::new();
    while let Some(packet) = reader.next_packet().unwrap() {
        read_back.push((packet.direction, packet.data));
    }

    let expected: Vec<(Direction, Vec<u8>)> = packets.iter().cloned().chain(packets.iter().cloned()).collect();
    assert_eq!(read_back, expected, "packets must read back in the same order, direction, and bytes as written");

    std::fs::remove_file(&path).ok();
}

#[test]
fn an_empty_capture_reads_back_as_a_valid_interface_with_zero_packets() {
    let path = unique_path("empty");
    let idb = InterfaceDescriptionBlock {
        interface_name: "lo".into(),
        link_type: LinkType::NullLoopback,
        snaplen: 65535,
        timestamp_resolution_exponent: 6,
    };

    Writer::create(&path, &idb, "roundtrip-host", "9.9.9").unwrap().finish().unwrap();

    let file = File::open(&path).unwrap();
    let (mut reader, interface) = Reader::new(file).unwrap();
    assert_eq!(interface.link_type, LinkType::NullLoopback);
    assert!(reader.next_packet().unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn reader_rejects_a_file_that_is_not_valid_pcapng() {
    let path = unique_path("garbage");
    std::fs::write(&path, b"this is not a pcapng file, just plain bytes").unwrap();

    let file = File::open(&path).unwrap();
    assert!(Reader::new(file).is_err(), "a non-pcapng file must be rejected, not silently misparsed");

    std::fs::remove_file(&path).ok();
}
