//! Fixture corpus for `tests/protocol_regression.rs` (issue #115 / JAM-53).
//!
//! Every fixture here is hand-built rather than captured from a real
//! network — the same posture `src/parse.rs`'s and `src/l7.rs`'s own unit
//! tests already take (via `etherparse::PacketBuilder` and raw byte
//! construction respectively), and explicitly allowed by this corpus's own
//! acceptance criteria ("raw captured-once byte blobs, or hand-built
//! minimal-but-valid frames"). Hand-building is deterministic, needs no
//! live interface or root/`access_bpf` access (this repo's CI has neither),
//! and is reviewable byte-by-byte in this file rather than opaque in a
//! `.bin` blob. Where a real capture *is* the only way to observe a
//! platform-specific behavior (BSD raw-socket framing quirks), see
//! `tests/fixtures/icmp/README.md` for that alternative approach — no such
//! platform quirk applies to any protocol covered here.

use capture_agent::ja3::ClientHelloFields;
use etherparse::{PacketBuilder, VlanId};

// ---------------------------------------------------------------------
// Link-layer / network-layer fixtures (src/parse.rs's `parse_packet`)
// ---------------------------------------------------------------------

/// A standard Ethernet+IPv4 TCP three-way handshake: SYN, SYN+ACK, ACK.
pub fn ethernet_ipv4_tcp_handshake() -> [Vec<u8>; 3] {
    let client_mac = [0, 1, 2, 3, 4, 5];
    let server_mac = [6, 7, 8, 9, 10, 11];
    let client_ip = [192, 168, 1, 10];
    let server_ip = [93, 184, 216, 34];

    let mut syn = Vec::new();
    PacketBuilder::ethernet2(client_mac, server_mac)
        .ipv4(client_ip, server_ip, 64)
        .tcp(51000, 443, 1000, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();

    let mut syn_ack = Vec::new();
    PacketBuilder::ethernet2(server_mac, client_mac)
        .ipv4(server_ip, client_ip, 64)
        .tcp(443, 51000, 5000, 65535)
        .syn()
        .ack(1001)
        .write(&mut syn_ack, &[])
        .unwrap();

    let mut ack = Vec::new();
    PacketBuilder::ethernet2(client_mac, server_mac)
        .ipv4(client_ip, server_ip, 64)
        .tcp(51000, 443, 1001, 65535)
        .ack(5001)
        .write(&mut ack, &[])
        .unwrap();

    [syn, syn_ack, ack]
}

/// An Ethernet+IPv6 TCP SYN — exercises the `NetSlice::Ipv6` branch of
/// `build_parsed_packet` (no header checksum field, hop_limit instead of
/// ttl), which the IPv4-only fixtures above never touch.
pub fn ethernet_ipv6_tcp_syn() -> Vec<u8> {
    let mut data = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            64,
        )
        .tcp(51000, 443, 1000, 65535)
        .syn()
        .write(&mut data, &[])
        .unwrap();
    data
}

/// BSD loopback framing (`DLT_NULL`/`DLT_LOOP`): 4-byte address-family
/// header directly followed by a bare IPv4/TCP packet, no link header.
pub fn null_loopback_tcp() -> Vec<u8> {
    let mut ip_packet = Vec::new();
    PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64)
        .tcp(51000, 8080, 1000, 65535)
        .syn()
        .write(&mut ip_packet, &[])
        .unwrap();
    let mut data = vec![2, 0, 0, 0]; // AF_INET, arbitrary byte order — never inspected
    data.extend_from_slice(&ip_packet);
    data
}

/// Raw IP framing (`DLT_RAW`): the frame bytes are the IP packet directly,
/// with a UDP payload so `TransportProtocol::Udp` is exercised alongside
/// TCP everywhere else in this corpus.
pub fn raw_ip_udp() -> Vec<u8> {
    let mut data = Vec::new();
    PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(53, 12345)
        .write(&mut data, &[9, 9, 9])
        .unwrap();
    data
}

/// An 802.1Q VLAN-tagged Ethernet+IPv4 TCP SYN.
pub fn vlan_tagged_tcp() -> Vec<u8> {
    let mut data = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .single_vlan(VlanId::try_new(100).unwrap())
        .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
        .tcp(51000, 443, 1000, 65535)
        .syn()
        .write(&mut data, &[])
        .unwrap();
    data
}

/// A valid Ethernet+IPv4 TCP frame truncated well inside its TCP header —
/// the shape a small `snaplen` capture produces (issue #68's runtime
/// snaplen control). Must be rejected cleanly (`None`), never panic.
pub fn truncated_ethernet_frame() -> Vec<u8> {
    let mut data = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
        .tcp(51000, 443, 1000, 65535)
        .syn()
        .write(&mut data, &[])
        .unwrap();
    // Ethernet(14) + IPv4(20) = 34 bytes before the TCP header even starts;
    // cutting to 40 leaves only 6 bytes of the 20-byte TCP header.
    data.truncate(40);
    data
}

// ---------------------------------------------------------------------
// Layer-7 fixtures (src/l7.rs's `sniff_l7`)
// ---------------------------------------------------------------------

pub fn http11_request() -> Vec<u8> {
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()
}

pub fn http11_response() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>".to_vec()
}

pub fn dns_query() -> Vec<u8> {
    // Minimal DNS query for "a.com": header (12 bytes) + QNAME + QTYPE/QCLASS.
    let mut payload = vec![
        0x12, 0x34, // transaction id
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // qdcount = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar counts = 0
    ];
    payload.push(1);
    payload.extend_from_slice(b"a");
    payload.push(3);
    payload.extend_from_slice(b"com");
    payload.push(0); // root label
    payload.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    payload.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    payload
}

/// Builds a hand-crafted TLS ClientHello record from an explicit
/// `ClientHelloFields`-shaped set of inputs, returning both the raw record
/// bytes `sniff_l7` consumes and the `ClientHelloFields` an independent
/// `ja3::compute_ja3` call can be run against — so the regression test can
/// assert the *exact* JA3 hash `sniff_l7` should produce, not just "some
/// 32-char string", genuinely exercising the byte-layout parsing in
/// `sniff_tls_client_hello` rather than only its presence/absence.
fn build_client_hello(
    sni: &str,
    cipher_suites: &[u16],
    include_supported_versions_ext: bool,
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> (Vec<u8>, ClientHelloFields) {
    let mut hs = vec![0x01]; // handshake type: ClientHello
    hs.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder, fixed up below
    hs.extend_from_slice(&[0x03, 0x03]); // legacy client_version (RFC 8446 §4.1.2: always 0x0303, even for TLS 1.3)
    hs.extend_from_slice(&[0u8; 32]); // random
    hs.push(0x00); // session_id_len = 0

    let cs_bytes: Vec<u8> = cipher_suites.iter().flat_map(|c| c.to_be_bytes()).collect();
    hs.extend_from_slice(&(cs_bytes.len() as u16).to_be_bytes());
    hs.extend_from_slice(&cs_bytes);
    hs.push(0x01); // compression_methods_len = 1
    hs.push(0x00); // null compression

    let mut extensions = Vec::new();
    let mut ext_types = Vec::new();

    // server_name extension (type 0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() as u16 + 3).to_be_bytes()));
    sni_ext.push(0x00); // name_type: host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);
    ext_types.push(0x0000);

    // supported_groups extension (type 0x000a)
    let curves_bytes: Vec<u8> = elliptic_curves.iter().flat_map(|c| c.to_be_bytes()).collect();
    let mut sg_ext = Vec::new();
    sg_ext.extend_from_slice(&(curves_bytes.len() as u16).to_be_bytes());
    sg_ext.extend_from_slice(&curves_bytes);
    extensions.extend_from_slice(&[0x00, 0x0a]);
    extensions.extend_from_slice(&(sg_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sg_ext);
    ext_types.push(0x000a);

    // ec_point_formats extension (type 0x000b)
    let mut epf_ext = Vec::new();
    epf_ext.push(ec_point_formats.len() as u8);
    epf_ext.extend_from_slice(ec_point_formats);
    extensions.extend_from_slice(&[0x00, 0x0b]);
    extensions.extend_from_slice(&(epf_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&epf_ext);
    ext_types.push(0x000b);

    if include_supported_versions_ext {
        // supported_versions extension (type 0x002b): advertises TLS 1.3
        // (0x0304) alongside the legacy_version compat value above — this
        // is the real-world signal that distinguishes a TLS 1.3 ClientHello
        // from a TLS 1.2 one, since the legacy client_version field itself
        // never changes.
        let sv_ext: Vec<u8> = vec![0x02, 0x03, 0x04]; // list_len(1) + TLS 1.3
        extensions.extend_from_slice(&[0x00, 0x2b]);
        extensions.extend_from_slice(&(sv_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sv_ext);
        ext_types.push(0x002b);
    }

    hs.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hs.extend_from_slice(&extensions);

    let body_len = (hs.len() - 4) as u32;
    hs[1] = ((body_len >> 16) & 0xff) as u8;
    hs[2] = ((body_len >> 8) & 0xff) as u8;
    hs[3] = (body_len & 0xff) as u8;

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);

    let fields = ClientHelloFields {
        tls_version: 0x0303,
        cipher_suites: cipher_suites.to_vec(),
        extensions: ext_types,
        elliptic_curves: elliptic_curves.to_vec(),
        ec_point_formats: ec_point_formats.to_vec(),
    };
    (record, fields)
}

/// A TLS 1.2 ClientHello: no `supported_versions` extension, the classic
/// signal (by its absence) that a ClientHello predates TLS 1.3.
pub fn tls12_client_hello() -> (Vec<u8>, ClientHelloFields) {
    build_client_hello("example.com", &[0x00, 0x2f, 0xc0, 0x13], false, &[0x001d], &[0x00])
}

/// A TLS 1.3 ClientHello: carries a `supported_versions` extension
/// advertising 0x0304, alongside the same always-0x0303 legacy version
/// field TLS 1.2 also uses (RFC 8446 §4.1.2) — this corpus's coverage of
/// "TLS 1.2 and TLS 1.3 ClientHello" therefore has to (and does) tell them
/// apart via that extension, not the legacy version field alone.
pub fn tls13_client_hello() -> (Vec<u8>, ClientHelloFields) {
    build_client_hello("example.com", &[0x13, 0x01, 0x13, 0x02, 0x13, 0x03], true, &[0x001d, 0x0017], &[0x00])
}

// ---------------------------------------------------------------------
// HTTP/2 fixture (src/http2.rs's `Http2Reassembler`)
// ---------------------------------------------------------------------

/// A minimal HPACK-encoded header block using only a fully-indexed static
/// table entry (no dynamic table, no Huffman) — ":method: GET" is static
/// index 2, encoded as a single byte 0x82 per RFC 7541 §6.1.
fn static_indexed_get_header_block() -> Vec<u8> {
    vec![0x82]
}

fn http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]); // 24-bit length
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// One HEADERS frame (`:method: GET`, static HPACK indexing) immediately
/// followed by one DATA frame on the same stream — the minimal
/// request-with-body shape `Http2Reassembler::feed` is meant to reassemble
/// and hand back as two `FrameOutcome::Frame`s.
pub fn http2_headers_then_data() -> Vec<u8> {
    let mut data = http2_frame(0x01, 0x04, 1, &static_indexed_get_header_block()); // HEADERS, END_HEADERS
    data.extend_from_slice(&http2_frame(0x00, 0x00, 1, b"hello world")); // DATA
    data
}
