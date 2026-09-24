use serde::Serialize;

use crate::parse::{ParsedPacket, TransportProtocol};

const ETH_HEADER_LEN: u32 = 14;
const VLAN_TAG_LEN: u32 = 4;
const IPV4_HEADER_LEN: u32 = 20;
const IPV6_HEADER_LEN: u32 = 40;
const TCP_HEADER_LEN: u32 = 20;
const UDP_HEADER_LEN: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Group,
    Bool,
    Uint,
    Str,
    Addr,
    Bytes,
}

/// Which of the two hex-dump panes a field's `offset`/`len` is relative to.
/// Header fields (eth/ip/tcp/udp/vlan) are offset into `headerHexDump`;
/// app-layer fields (http/dns/tls) are offset into the existing `hexDump`
/// — the two panes are never merged into one shared byte space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteRegion {
    Header,
    Payload,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Bool(bool),
    Uint(u64),
    Str(String),
    #[allow(dead_code)] // no currently-decoded field uses this yet; kept for future dissector work per the spec's type enum
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub path: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldValue>,
    pub region: ByteRegion,
    pub offset: u32,
    pub len: u32,
}

impl Field {
    pub fn group(path: &str, label: &str, group: Option<&str>, region: ByteRegion, offset: u32, len: u32) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: group.map(|g| g.to_string()),
            field_type: FieldType::Group,
            value: None,
            region,
            offset,
            len,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn leaf(
        path: &str,
        label: &str,
        group: &str,
        field_type: FieldType,
        value: FieldValue,
        region: ByteRegion,
        offset: u32,
        len: u32,
    ) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: Some(group.to_string()),
            field_type,
            value: Some(value),
            region,
            offset,
            len,
        }
    }
}

fn protocol_num(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
        TransportProtocol::Icmp => 1,
        TransportProtocol::Other => 0,
    }
}

/// Returns fields and the byte offset where the IP header begins.
fn eth_fields(parsed: &ParsedPacket) -> (Vec<Field>, u32) {
    let vlan_tagged = parsed.vlan_tag.is_some();
    let eth_len = ETH_HEADER_LEN + if vlan_tagged { VLAN_TAG_LEN } else { 0 };
    let mut fields = vec![Field::group(
        "eth",
        "Ethernet II",
        None,
        ByteRegion::Header,
        0,
        eth_len,
    )];
    fields.push(Field::leaf(
        "eth.dst",
        "Destination MAC",
        "eth",
        FieldType::Addr,
        FieldValue::Str(parsed.dst_mac.clone()),
        ByteRegion::Header,
        0,
        6,
    ));
    fields.push(Field::leaf(
        "eth.src",
        "Source MAC",
        "eth",
        FieldType::Addr,
        FieldValue::Str(parsed.src_mac.clone()),
        ByteRegion::Header,
        6,
        6,
    ));
    if let Some(vlan_tag) = &parsed.vlan_tag {
        fields.push(Field::group(
            "eth.vlan",
            "802.1Q VLAN Tag",
            Some("eth"),
            ByteRegion::Header,
            12,
            VLAN_TAG_LEN,
        ));
        fields.push(Field::leaf(
            "eth.vlan.id",
            "VLAN ID",
            "eth.vlan",
            FieldType::Uint,
            FieldValue::Uint(vlan_tag.parse().unwrap_or(0)),
            ByteRegion::Header,
            14,
            2,
        ));
    }
    let ethertype_offset = if vlan_tagged { 16 } else { 12 };
    let ethertype_label = match parsed.ip_version {
        4 => "IPv4",
        6 => "IPv6",
        _ => "Unknown",
    };
    fields.push(Field::leaf(
        "eth.type",
        "EtherType",
        "eth",
        FieldType::Str,
        FieldValue::Str(ethertype_label.to_string()),
        ByteRegion::Header,
        ethertype_offset,
        2,
    ));
    (fields, eth_len)
}

/// Returns fields and the byte offset where the transport header begins.
fn ip_fields(parsed: &ParsedPacket, ip_start: u32) -> (Vec<Field>, u32) {
    if parsed.ip_version == 6 {
        let mut fields = vec![Field::group(
            "ip6",
            "Internet Protocol Version 6",
            None,
            ByteRegion::Header,
            ip_start,
            IPV6_HEADER_LEN,
        )];
        fields.push(Field::leaf(
            "ip6.src",
            "Source Address",
            "ip6",
            FieldType::Addr,
            FieldValue::Str(parsed.src_ip.clone()),
            ByteRegion::Header,
            ip_start + 8,
            16,
        ));
        fields.push(Field::leaf(
            "ip6.dst",
            "Destination Address",
            "ip6",
            FieldType::Addr,
            FieldValue::Str(parsed.dst_ip.clone()),
            ByteRegion::Header,
            ip_start + 24,
            16,
        ));
        fields.push(Field::leaf(
            "ip6.hop_limit",
            "Hop Limit",
            "ip6",
            FieldType::Uint,
            FieldValue::Uint(parsed.ttl.into()),
            ByteRegion::Header,
            ip_start + 7,
            1,
        ));
        fields.push(Field::leaf(
            "ip6.next_header",
            "Next Header",
            "ip6",
            FieldType::Uint,
            FieldValue::Uint(protocol_num(parsed.protocol).into()),
            ByteRegion::Header,
            ip_start + 6,
            1,
        ));
        (fields, ip_start + IPV6_HEADER_LEN)
    } else {
        let mut fields = vec![Field::group(
            "ip",
            "Internet Protocol Version 4",
            None,
            ByteRegion::Header,
            ip_start,
            IPV4_HEADER_LEN,
        )];
        fields.push(Field::leaf(
            "ip.src",
            "Source Address",
            "ip",
            FieldType::Addr,
            FieldValue::Str(parsed.src_ip.clone()),
            ByteRegion::Header,
            ip_start + 12,
            4,
        ));
        fields.push(Field::leaf(
            "ip.dst",
            "Destination Address",
            "ip",
            FieldType::Addr,
            FieldValue::Str(parsed.dst_ip.clone()),
            ByteRegion::Header,
            ip_start + 16,
            4,
        ));
        fields.push(Field::leaf(
            "ip.ttl",
            "Time to Live",
            "ip",
            FieldType::Uint,
            FieldValue::Uint(parsed.ttl.into()),
            ByteRegion::Header,
            ip_start + 8,
            1,
        ));
        fields.push(Field::leaf(
            "ip.protocol_num",
            "Protocol",
            "ip",
            FieldType::Uint,
            FieldValue::Uint(protocol_num(parsed.protocol).into()),
            ByteRegion::Header,
            ip_start + 9,
            1,
        ));
        if let Some(checksum) = parsed.ip_checksum {
            fields.push(Field::leaf(
                "ip.checksum",
                "Header Checksum",
                "ip",
                FieldType::Str,
                FieldValue::Str(format!("0x{checksum:04x}")),
                ByteRegion::Header,
                ip_start + 10,
                2,
            ));
        }
        (fields, ip_start + IPV4_HEADER_LEN)
    }
}

fn transport_fields(parsed: &ParsedPacket, start: u32) -> Vec<Field> {
    match parsed.protocol {
        TransportProtocol::Tcp => {
            let flags = parsed.tcp_flags.unwrap_or_default();
            vec![
                Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, start, TCP_HEADER_LEN),
                Field::leaf("tcp.src_port", "Source Port", "tcp", FieldType::Uint, FieldValue::Uint(parsed.src_port.unwrap_or(0).into()), ByteRegion::Header, start, 2),
                Field::leaf("tcp.dst_port", "Destination Port", "tcp", FieldType::Uint, FieldValue::Uint(parsed.dst_port.unwrap_or(0).into()), ByteRegion::Header, start + 2, 2),
                Field::leaf("tcp.seq", "Sequence Number", "tcp", FieldType::Uint, FieldValue::Uint(parsed.seq.unwrap_or(0).into()), ByteRegion::Header, start + 4, 4),
                Field::leaf("tcp.ack_number", "Acknowledgment Number", "tcp", FieldType::Uint, FieldValue::Uint(flags.ack_number.into()), ByteRegion::Header, start + 8, 4),
                Field::group("tcp.flags", "Flags", Some("tcp"), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.syn", "SYN", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.syn), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.ack", "ACK", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.ack), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.fin", "FIN", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.fin), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.rst", "RST", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.rst), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.window_size", "Window Size", "tcp", FieldType::Uint, FieldValue::Uint(flags.window_size.into()), ByteRegion::Header, start + 14, 2),
            ]
        }
        TransportProtocol::Udp => vec![
            Field::group("udp", "User Datagram Protocol", None, ByteRegion::Header, start, UDP_HEADER_LEN),
            Field::leaf("udp.src_port", "Source Port", "udp", FieldType::Uint, FieldValue::Uint(parsed.src_port.unwrap_or(0).into()), ByteRegion::Header, start, 2),
            Field::leaf("udp.dst_port", "Destination Port", "udp", FieldType::Uint, FieldValue::Uint(parsed.dst_port.unwrap_or(0).into()), ByteRegion::Header, start + 2, 2),
        ],
        TransportProtocol::Icmp | TransportProtocol::Other => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ParsedPacket, TransportProtocol};

    fn base_packet() -> ParsedPacket {
        ParsedPacket {
            src_mac: "00:01:02:03:04:05".to_string(),
            dst_mac: "06:07:08:09:0a:0b".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            protocol: TransportProtocol::Other,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: 100,
            payload: vec![],
            header_bytes: vec![],
            ip_version: 4,
            ip_checksum: Some(0xbeef),
            vlan_tag: None,
        }
    }

    #[test]
    fn a_group_omits_the_value_key_entirely() {
        let f = Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, 34, 20);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("\"value\""), "group entries must carry no value key at all, not null: {json}");
        assert!(!json.contains("\"group\":"), "a top-level group must omit the group key, not send null: {json}");
        assert!(json.contains("\"type\":\"group\""));
        assert!(json.contains("\"region\":\"header\""));
    }

    #[test]
    fn a_leaf_serializes_its_typed_value_untagged() {
        let f = Field::leaf(
            "tcp.flags.syn",
            "SYN",
            "tcp.flags",
            FieldType::Bool,
            FieldValue::Bool(true),
            ByteRegion::Header,
            47,
            1,
        );
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":true"), "bool value must serialize as a bare JSON bool, not {{\"Bool\":true}}: {json}");
        assert!(json.contains("\"group\":\"tcp.flags\""));
    }

    #[test]
    fn a_uint_leaf_serializes_as_a_bare_number() {
        let f = Field::leaf("tcp.src_port", "Source Port", "tcp", FieldType::Uint, FieldValue::Uint(51000), ByteRegion::Header, 34, 2);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":51000"), "{json}");
    }

    #[test]
    fn field_uses_camel_case_keys() {
        let f = Field::leaf("ip.ttl", "Time to Live", "ip", FieldType::Uint, FieldValue::Uint(64), ByteRegion::Header, 22, 1);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"path\":\"ip.ttl\""));
        assert!(json.contains("\"offset\":22"));
        assert!(json.contains("\"len\":1"));
    }

    #[test]
    fn eth_fields_places_the_ip_header_right_after_a_14_byte_untagged_ethernet_header() {
        let (fields, ip_start) = eth_fields(&base_packet());
        assert_eq!(ip_start, 14);
        let eth = fields.iter().find(|f| f.path == "eth").unwrap();
        assert_eq!(eth.offset, 0);
        assert_eq!(eth.len, 14);
        let src = fields.iter().find(|f| f.path == "eth.src").unwrap();
        assert_eq!(src.offset, 6);
        assert_eq!(src.len, 6);
        assert!(matches!(&src.value, Some(FieldValue::Str(v)) if v == "00:01:02:03:04:05"));
    }

    #[test]
    fn eth_fields_accounts_for_the_4_byte_vlan_tag_when_present() {
        let mut packet = base_packet();
        packet.vlan_tag = Some("100".to_string());
        let (fields, ip_start) = eth_fields(&packet);
        assert_eq!(ip_start, 18, "a VLAN-tagged frame's IP header starts 4 bytes later");
        let vlan_id = fields.iter().find(|f| f.path == "eth.vlan.id").unwrap();
        assert!(matches!(&vlan_id.value, Some(FieldValue::Uint(100))));
        assert_eq!(vlan_id.offset, 14);
        assert_eq!(vlan_id.len, 2);
    }

    #[test]
    fn ip_fields_places_ipv4_addresses_at_their_rfc_791_offsets() {
        let (fields, transport_start) = ip_fields(&base_packet(), 14);
        assert_eq!(transport_start, 34, "14 (eth) + 20 (ipv4) = 34");
        let src = fields.iter().find(|f| f.path == "ip.src").unwrap();
        assert_eq!(src.offset, 14 + 12);
        assert_eq!(src.len, 4);
        assert!(matches!(&src.value, Some(FieldValue::Str(v)) if v == "192.168.1.10"));
        let ttl = fields.iter().find(|f| f.path == "ip.ttl").unwrap();
        assert_eq!(ttl.offset, 14 + 8);
        assert!(matches!(&ttl.value, Some(FieldValue::Uint(64))));
        let checksum = fields.iter().find(|f| f.path == "ip.checksum").unwrap();
        assert!(matches!(&checksum.value, Some(FieldValue::Str(v)) if v == "0xbeef"));
    }

    #[test]
    fn ip_fields_uses_the_ip6_group_and_16_byte_addresses_for_ipv6() {
        let mut packet = base_packet();
        packet.ip_version = 6;
        packet.ip_checksum = None;
        let (fields, transport_start) = ip_fields(&packet, 14);
        assert_eq!(transport_start, 14 + 40);
        assert!(fields.iter().any(|f| f.path == "ip6"));
        assert!(fields.iter().all(|f| f.path != "ip.checksum"), "IPv6 must never fabricate a checksum field");
        let src = fields.iter().find(|f| f.path == "ip6.src").unwrap();
        assert_eq!(src.len, 16);
    }

    #[test]
    fn transport_fields_places_tcp_ports_and_flags_at_their_fixed_offsets() {
        let mut packet = base_packet();
        packet.protocol = TransportProtocol::Tcp;
        packet.src_port = Some(51000);
        packet.dst_port = Some(443);
        packet.seq = Some(1000);
        packet.tcp_flags = Some(crate::parse::TcpFlags { syn: true, ack: false, fin: false, rst: false, window_size: 65535, ack_number: 0 });
        let fields = transport_fields(&packet, 34);
        let tcp = fields.iter().find(|f| f.path == "tcp").unwrap();
        assert_eq!((tcp.offset, tcp.len), (34, 20));
        let src_port = fields.iter().find(|f| f.path == "tcp.src_port").unwrap();
        assert_eq!(src_port.offset, 34);
        assert!(matches!(&src_port.value, Some(FieldValue::Uint(51000))));
        let syn = fields.iter().find(|f| f.path == "tcp.flags.syn").unwrap();
        assert_eq!(syn.offset, 47);
        assert_eq!(syn.group.as_deref(), Some("tcp.flags"));
        assert!(matches!(&syn.value, Some(FieldValue::Bool(true))));
        let ack = fields.iter().find(|f| f.path == "tcp.flags.ack").unwrap();
        assert_eq!(ack.offset, 47);
        assert!(matches!(&ack.value, Some(FieldValue::Bool(false))));
        let window = fields.iter().find(|f| f.path == "tcp.window_size").unwrap();
        assert_eq!(window.offset, 48);
        assert!(matches!(&window.value, Some(FieldValue::Uint(65535))));
    }

    #[test]
    fn transport_fields_covers_udp_with_just_ports_no_fabricated_flags_or_seq() {
        let mut packet = base_packet();
        packet.protocol = TransportProtocol::Udp;
        packet.src_port = Some(60123);
        packet.dst_port = Some(53);
        let fields = transport_fields(&packet, 34);
        assert!(fields.iter().any(|f| f.path == "udp.src_port"));
        assert!(fields.iter().any(|f| f.path == "udp.dst_port"));
        assert!(fields.iter().all(|f| !f.path.starts_with("tcp")));
        assert!(fields.iter().all(|f| !f.path.contains("flags") && !f.path.contains("seq")));
    }

    #[test]
    fn transport_fields_is_empty_for_icmp_and_other_nothing_decoded_to_show() {
        let mut packet = base_packet();
        packet.protocol = TransportProtocol::Icmp;
        assert!(transport_fields(&packet, 34).is_empty());
        packet.protocol = TransportProtocol::Other;
        assert!(transport_fields(&packet, 34).is_empty());
    }
}
