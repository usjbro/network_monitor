use etherparse::{LinkExtSlice, NetSlice, SlicedPacket, TransportSlice};

/// The link-layer framing a captured frame's raw bytes are in, matching the
/// open capture handle's datalink type (`pcap::Capture::get_datalink()`,
/// read once at startup in `main.rs` and passed into every `parse_packet`
/// call). Before this existed, `parse_packet` unconditionally assumed
/// Ethernet II framing and silently rejected every frame from a loopback or
/// raw-IP interface — indistinguishable from an idle network (issue #63).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Standard Ethernet II framing (`DLT_EN10MB`) — real source/destination
    /// MAC addresses precede the network-layer header.
    Ethernet,
    /// BSD loopback framing (`DLT_NULL`/`DLT_LOOP`): a 4-byte
    /// address-family header, then a bare IP packet. No real MAC addresses
    /// exist on a loopback interface. The address-family value itself is
    /// never inspected — the IP header right after it is self-describing
    /// (its version nibble is 4 or 6) — so skipping exactly 4 bytes is
    /// correct regardless of which byte order that platform used for it.
    NullLoopback,
    /// Raw IP framing (`DLT_RAW`): the frame *is* the IP packet, with no
    /// link header at all.
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub window_size: u16,
    pub ack_number: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: TransportProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
    pub ttl: u8,
    pub total_len: u16,
    pub payload: Vec<u8>,
    /// Every byte before `payload` starts, in whichever slice was actually
    /// parsed — the Ethernet/IP/transport headers, with no artificial cap
    /// (bounded naturally: every currently-decoded field lives in a fixed
    /// header portion, worst case Ethernet+VLAN+IPv4+TCP ≈ 78 bytes). Used
    /// to build the wire's `headerHexDump`, a separate pane from the
    /// existing payload-only `hexDump`.
    pub header_bytes: Vec<u8>,
    /// Length of the parsed IP header and its extension headers, including
    /// IPv4 options or IPv6 extensions, from the network-layer slice.
    pub ip_header_len: u32,
    /// Length of the parsed TCP/UDP header, including TCP options.
    pub transport_header_len: u32,
    /// 4 or 6, from the IP header actually parsed.
    pub ip_version: u8,
    /// IPv4 header checksum. Always `None` for IPv6, which has no header
    /// checksum field — that is a protocol fact, not a gap.
    pub ip_checksum: Option<u16>,
    /// The 802.1Q VLAN identifier (0-4094), as a decimal string, if this
    /// frame carried a VLAN tag between its Ethernet header and network
    /// layer. `None` for untagged frames — not a gap: most traffic on a
    /// typical access-port capture is untagged, and that is the correct,
    /// honest value for it. Only the outermost tag is reported when a frame
    /// is double-tagged (QinQ); see `docs/wire-protocol.md`.
    pub vlan_tag: Option<String>,
}

fn mac_to_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Reported for a frame captured on a link type with no real link-layer
/// addresses at all (loopback, raw IP) — an honest, visibly-synthetic
/// all-zero value rather than omitting the field or fabricating a
/// plausible-looking one.
const NO_MAC: &str = "00:00:00:00:00:00";

/// Byte length of the BSD loopback header (`DLT_NULL`/`DLT_LOOP`): a single
/// 4-byte address-family value, immediately followed by the IP packet.
const NULL_LOOPBACK_HEADER_LEN: usize = 4;

/// Never panics on malformed input — returns None instead. This function
/// is exercised by the cargo-fuzz target in `fuzz/fuzz_targets/parse_packet.rs`
/// specifically because it runs on untrusted, attacker-reachable bytes, for
/// every `LinkType`.
pub fn parse_packet(data: &[u8], link_type: LinkType) -> Option<ParsedPacket> {
    match link_type {
        LinkType::Ethernet => {
            let sliced = SlicedPacket::from_ethernet(data).ok()?;
            let (src_mac, dst_mac) = match &sliced.link {
                Some(etherparse::LinkSlice::Ethernet2(eth)) => {
                    (mac_to_string(eth.source()), mac_to_string(eth.destination()))
                }
                _ => return None,
            };
            // The outermost 802.1Q tag, if this frame is VLAN-tagged —
            // `link_exts` also carries MACsec headers, which aren't a VLAN
            // tag, so this only matches the `Vlan` variant. A double-tagged
            // (QinQ) frame reports only its first/outer tag, matching the
            // single `vlan_tag` field's shape.
            let vlan_tag = sliced.link_exts.iter().find_map(|ext| match ext {
                LinkExtSlice::Vlan(vlan) => Some(vlan.vlan_identifier().value().to_string()),
                _ => None,
            });
            build_parsed_packet(&sliced, src_mac, dst_mac, vlan_tag, data)
        }
        LinkType::NullLoopback => {
            let ip_data = data.get(NULL_LOOPBACK_HEADER_LEN..)?;
            let sliced = SlicedPacket::from_ip(ip_data).ok()?;
            build_parsed_packet(&sliced, NO_MAC.to_string(), NO_MAC.to_string(), None, ip_data)
        }
        LinkType::Raw => {
            let sliced = SlicedPacket::from_ip(data).ok()?;
            build_parsed_packet(&sliced, NO_MAC.to_string(), NO_MAC.to_string(), None, data)
        }
    }
}

/// Shared network/transport-layer parsing for every `LinkType` above — only
/// how `src_mac`/`dst_mac`/`vlan_tag` are obtained (or synthesized) differs
/// between them.
fn build_parsed_packet(
    sliced: &SlicedPacket,
    src_mac: String,
    dst_mac: String,
    vlan_tag: Option<String>,
    frame_data: &[u8],
) -> Option<ParsedPacket> {
    let (src_ip, dst_ip, ttl, ip_version, ip_checksum, ip_header_len) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
            ipv4.header().ttl(),
            4u8,
            Some(ipv4.header().header_checksum()),
            (ipv4.header().slice().len()
                + ipv4.extensions().auth.map_or(0, |auth| auth.slice().len())) as u32,
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
            ipv6.header().hop_limit(),
            6u8,
            None,
            (ipv6.header().slice().len() + ipv6.extensions().slice().len()) as u32,
        ),
        None => return None,
        _ => return None,
    };

    let (protocol, src_port, dst_port, tcp_flags, seq, payload, transport_header_len) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            TransportProtocol::Tcp,
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                window_size: tcp.window_size(),
                ack_number: tcp.acknowledgment_number(),
            }),
            Some(tcp.sequence_number()),
            tcp.payload().to_vec(),
            tcp.header_slice().len() as u32,
        ),
        Some(TransportSlice::Udp(udp)) => (
            TransportProtocol::Udp,
            Some(udp.source_port()),
            Some(udp.destination_port()),
            None,
            None,
            udp.payload().to_vec(),
            udp.header_slice().len() as u32,
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (TransportProtocol::Icmp, None, None, None, None, Vec::new(), 0)
        }
        None => (TransportProtocol::Other, None, None, None, None, Vec::new(), 0),
    };

    let header_bytes = frame_data[..frame_data.len() - payload.len()].to_vec();

    Some(ParsedPacket {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        seq,
        ttl,
        total_len: frame_data.len() as u16,
        payload,
        header_bytes,
        ip_header_len,
        transport_header_len,
        ip_version,
        ip_checksum,
        vlan_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{
        IpFragOffset, IpNumber, Ipv4Header, PacketBuilder, TcpHeader, TcpOptionElement, VlanId,
    };

    #[test]
    fn parses_a_tcp_syn_packet() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = &[];
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed =
            parse_packet(&data, LinkType::Ethernet).expect("should parse a valid TCP/IP packet");

        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.src_port, Some(51000));
        assert_eq!(parsed.dst_port, Some(443));
        let flags = parsed.tcp_flags.unwrap();
        assert!(flags.syn);
        assert_eq!(flags.window_size, 65535);
        assert_eq!(flags.ack_number, 0);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.ip_header_len, 20);
        assert_eq!(parsed.transport_header_len, 20);
        assert!(parsed.ip_checksum.is_some());
        // Untagged frame — must read as absent, not a fabricated 0/default,
        // and not confused with "unparsed" (see issue #62).
        assert_eq!(parsed.vlan_tag, None);
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        let garbage = [0u8, 1, 2, 3, 4];
        assert!(parse_packet(&garbage, LinkType::Ethernet).is_none());
    }

    #[test]
    fn parses_the_802_1q_vlan_tag_when_present() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .single_vlan(VlanId::try_new(100).unwrap())
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = &[];
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed = parse_packet(&data, LinkType::Ethernet)
            .expect("should parse a VLAN-tagged TCP/IP packet");

        assert_eq!(parsed.vlan_tag.as_deref(), Some("100"));
        // The tag must not disturb parsing of anything past it.
        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.dst_port, Some(443));
    }

    #[test]
    fn parses_a_null_loopback_encapsulated_frame() {
        // DLT_NULL/DLT_LOOP: 4-byte address-family header, then a bare IP
        // packet — build the IP+TCP bytes with etherparse (no link header),
        // then prepend a 4-byte header exactly like the real BSD loopback
        // framing this variant exists to handle (see issue #63). The header
        // value itself is irrelevant to parsing (never inspected), only its
        // length matters, so an arbitrary non-zero value here also proves
        // that.
        let builder = PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64)
            .tcp(51000, 8080, 1000, 65535)
            .syn();
        let payload: &[u8] = &[];
        let mut ip_packet = Vec::new();
        builder.write(&mut ip_packet, payload).unwrap();
        let mut data = vec![2, 0, 0, 0]; // AF_INET, arbitrary byte order
        data.extend_from_slice(&ip_packet);

        let parsed = parse_packet(&data, LinkType::NullLoopback)
            .expect("should parse a loopback-encapsulated TCP/IP packet");

        assert_eq!(parsed.src_ip, "127.0.0.1");
        assert_eq!(parsed.dst_ip, "127.0.0.1");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.dst_port, Some(8080));
        // No real MAC addresses exist on loopback — must be the honest
        // synthetic all-zero value, not fabricated-looking or absent.
        assert_eq!(parsed.src_mac, "00:00:00:00:00:00");
        assert_eq!(parsed.dst_mac, "00:00:00:00:00:00");
    }

    #[test]
    fn returns_none_for_a_null_loopback_frame_shorter_than_its_own_header() {
        let data = [1u8, 2, 3];
        assert!(parse_packet(&data, LinkType::NullLoopback).is_none());
    }

    #[test]
    fn parses_a_raw_ip_frame() {
        // DLT_RAW: no link header at all — the frame bytes are the IP
        // packet directly.
        let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(53, 12345);
        let payload: &[u8] = &[9, 9, 9];
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed =
            parse_packet(&data, LinkType::Raw).expect("should parse a raw IPv4/UDP packet");

        assert_eq!(parsed.src_ip, "10.0.0.1");
        assert_eq!(parsed.dst_ip, "10.0.0.2");
        assert_eq!(parsed.protocol, TransportProtocol::Udp);
        assert_eq!(parsed.src_port, Some(53));
        assert_eq!(parsed.dst_port, Some(12345));
        assert_eq!(parsed.src_mac, "00:00:00:00:00:00");
        assert_eq!(parsed.dst_mac, "00:00:00:00:00:00");
    }

    #[test]
    fn parses_a_non_first_ipv4_fragment_without_panicking_or_misattributing_l4_fields() {
        // `PacketBuilder`'s fluent API has no fragment support, so this
        // builds the IP header directly. A non-first fragment's payload is
        // raw fragment bytes, not a real UDP header — etherparse correctly
        // refuses to parse a transport layer for any fragmented IP payload
        // (`sliced.transport` is `None` whenever `more_fragments`/a nonzero
        // `fragment_offset` is set), so this must land in the `Other`/no-port
        // arm rather than being misread as UDP with garbage ports.
        let payload = b"raw-fragment-bytes-not-a-udp-header";
        let mut ip = Ipv4Header::new(payload.len() as u16, 64, IpNumber::UDP, [192, 168, 1, 10], [93, 184, 216, 34])
            .unwrap();
        ip.more_fragments = true;
        ip.fragment_offset = IpFragOffset::try_new(185).unwrap();
        ip.header_checksum = ip.calc_header_checksum();

        let mut data = Vec::new();
        ip.write(&mut data).unwrap();
        data.extend_from_slice(payload);

        let parsed = parse_packet(&data, LinkType::Raw)
            .expect("a fragmented IPv4 packet must still parse, not return None");

        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.protocol, TransportProtocol::Other);
        assert_eq!(parsed.src_port, None);
        assert_eq!(parsed.dst_port, None);
    }

    #[test]
    fn parses_a_tcp_header_with_options_present() {
        // MSS (4 bytes) + WindowScale (3 bytes) + a Noop pad byte (1 byte)
        // pushes the header 8 bytes past the fixed 20-byte minimum —
        // `payload` must start after all of it, not partway through the
        // options.
        let mut tcp = TcpHeader::new(51000, 443, 1000, 65535);
        tcp.syn = true;
        tcp.set_options(&[
            TcpOptionElement::MaximumSegmentSize(1460),
            TcpOptionElement::WindowScale(7),
            TcpOptionElement::Noop,
        ])
        .unwrap();

        let payload = b"hello";
        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [192, 168, 1, 10],
            [93, 184, 216, 34],
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();

        let mut data = Vec::new();
        ip.write(&mut data).unwrap();
        tcp.write(&mut data).unwrap();
        data.extend_from_slice(payload);

        let parsed = parse_packet(&data, LinkType::Raw)
            .expect("should parse a TCP packet carrying header options");

        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.src_port, Some(51000));
        assert_eq!(parsed.dst_port, Some(443));
        let flags = parsed.tcp_flags.unwrap();
        assert!(flags.syn);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.ip_header_len, 20);
        assert_eq!(parsed.transport_header_len, 28);
    }

    #[test]
    fn header_bytes_excludes_the_payload() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = b"hello";
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed = parse_packet(&data, LinkType::Ethernet).unwrap();

        assert_eq!(parsed.header_bytes.len(), data.len() - payload.len());
        assert_eq!(parsed.header_bytes, &data[..data.len() - payload.len()]);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn header_bytes_excludes_the_null_loopback_af_prefix() {
        let builder = PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64)
            .tcp(51000, 8080, 1000, 65535)
            .syn();
        let payload: &[u8] = b"hi";
        let mut ip_packet = Vec::new();
        builder.write(&mut ip_packet, payload).unwrap();
        let mut data = vec![2, 0, 0, 0]; // 4-byte AF_INET prefix, never a real header
        data.extend_from_slice(&ip_packet);

        let parsed = parse_packet(&data, LinkType::NullLoopback).unwrap();

        // header_bytes must be relative to ip_packet, not the wire bytes
        // that also carried the 4-byte AF prefix — that prefix is not a
        // protocol header and must never show up in a byte-highlighting pane.
        assert_eq!(parsed.header_bytes.len(), ip_packet.len() - payload.len());
        assert_eq!(parsed.header_bytes, &ip_packet[..ip_packet.len() - payload.len()]);
    }
}
