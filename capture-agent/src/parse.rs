use etherparse::{SlicedPacket, NetSlice, TransportSlice};

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
}

fn mac_to_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Never panics on malformed input — returns None instead. This function
/// is exercised by the cargo-fuzz target in `fuzz/fuzz_targets/parse_packet.rs`
/// specifically because it runs on untrusted, attacker-reachable bytes.
pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_mac, dst_mac) = match &sliced.link {
        Some(etherparse::LinkSlice::Ethernet2(eth)) => {
            (mac_to_string(eth.source()), mac_to_string(eth.destination()))
        }
        _ => return None,
    };

    let (src_ip, dst_ip, ttl) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
            ipv4.header().ttl(),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
            ipv6.header().hop_limit(),
        ),
        None => return None,
        _ => return None,
    };

    let (protocol, src_port, dst_port, tcp_flags, seq, payload) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            TransportProtocol::Tcp,
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            }),
            Some(tcp.sequence_number()),
            tcp.payload().to_vec(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            TransportProtocol::Udp,
            Some(udp.source_port()),
            Some(udp.destination_port()),
            None,
            None,
            udp.payload().to_vec(),
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (TransportProtocol::Icmp, None, None, None, None, Vec::new())
        }
        None => (TransportProtocol::Other, None, None, None, None, Vec::new()),
    };

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
        total_len: data.len() as u16,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn parses_a_tcp_syn_packet() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = &[];
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed = parse_packet(&data).expect("should parse a valid TCP/IP packet");

        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.src_port, Some(51000));
        assert_eq!(parsed.dst_port, Some(443));
        assert_eq!(parsed.tcp_flags.unwrap().syn, true);
        assert_eq!(parsed.ttl, 64);
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        let garbage = [0u8, 1, 2, 3, 4];
        assert!(parse_packet(&garbage).is_none());
    }
}
