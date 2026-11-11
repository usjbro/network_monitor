use serde::Serialize;

use crate::l7::{dns_rcode_name, dns_type_name, L7Info};
use crate::parse::{ParsedPacket, TransportProtocol};

const ETH_HEADER_LEN: u32 = 14;
const VLAN_TAG_LEN: u32 = 4;
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

/// The largest integer a JSON number carries exactly to a JS client: 2^53 - 1.
const MAX_EXACT_JSON_UINT: u64 = (1 << 53) - 1;

/// Field paths whose values are always `uint` (JAM-18 Task 5): the only
/// fields an IO graph aggregate may name (spec D10). Kept next to the
/// builders below, which are the only places fields are made; a test in this
/// module checks every uint leaf they build is listed. `frame.len` is the
/// filter's virtual field (the captured length).
const UINT_PATHS: &[&str] = &[
    "frame.len",
    "eth.vlan.id",
    "ip.ttl",
    "ip.protocol_num",
    "ip6.hop_limit",
    "ip6.next_header",
    "tcp.src_port",
    "tcp.dst_port",
    "tcp.seq",
    "tcp.ack_number",
    "tcp.window_size",
    "udp.src_port",
    "udp.dst_port",
    "http.response.code",
    "http.content_length",
    "http.time_us",
    "dns.id",
    "dns.count.answers",
    "dns.time_us",
];

/// True for a path naming a uint field (case-insensitive, as filter paths
/// are), including each indexed DNS answer's `dns.answer.<n>.ttl`.
pub fn is_uint_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    if UINT_PATHS.contains(&path.as_str()) {
        return true;
    }
    path.strip_prefix("dns.answer.")
        .and_then(|rest| rest.strip_suffix(".ttl"))
        .is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
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
            parsed.ip_header_len,
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
            FieldValue::Uint(parsed.header_bytes.get((ip_start + 6) as usize).copied().unwrap_or_else(|| protocol_num(parsed.protocol)).into()),
            ByteRegion::Header,
            ip_start + 6,
            1,
        ));
        (fields, ip_start + parsed.ip_header_len)
    } else {
        let mut fields = vec![Field::group(
            "ip",
            "Internet Protocol Version 4",
            None,
            ByteRegion::Header,
            ip_start,
            parsed.ip_header_len,
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
            FieldValue::Uint(parsed.header_bytes.get((ip_start + 9) as usize).copied().unwrap_or_else(|| protocol_num(parsed.protocol)).into()),
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
        (fields, ip_start + parsed.ip_header_len)
    }
}

fn transport_fields(parsed: &ParsedPacket, start: u32) -> Vec<Field> {
    match parsed.protocol {
        TransportProtocol::Tcp => {
            let flags = parsed.tcp_flags.unwrap_or_default();
            vec![
                Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, start, parsed.transport_header_len),
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

/// Application ranges are relative to the full payload. The wire's payload
/// hex dump shows only its first 64 bytes, so a valid SNI range can lie beyond
/// the visible dump; its offset is retained rather than moved or truncated.
/// Text fields and derived JA3 values span their source payload. Only SNI's
/// bytes are located precisely by the TLS extension parser.
/// `dns_offset` is where the DNS message starts in the payload: 2 over TCP,
/// after the length prefix, and 0 over UDP.
fn app_fields(l7: &L7Info, payload_len: u32, dns_offset: u32) -> Vec<Field> {
    match l7 {
        L7Info::Http { method, path } => vec![
            Field::group("http", "Hypertext Transfer Protocol", None, ByteRegion::Payload, 0, payload_len),
            Field::leaf("http.request.method", "Request Method", "http", FieldType::Str, FieldValue::Str(method.clone()), ByteRegion::Payload, 0, payload_len),
            Field::leaf("http.request.uri", "Request URI", "http", FieldType::Str, FieldValue::Str(path.clone()), ByteRegion::Payload, 0, payload_len),
        ],
        L7Info::HttpResponse { status, reason, content_type, content_length } => {
            let mut fields = vec![
                Field::group("http", "Hypertext Transfer Protocol", None, ByteRegion::Payload, 0, payload_len),
                Field::leaf("http.response.code", "Status Code", "http", FieldType::Uint, FieldValue::Uint(status.parse().unwrap_or(0)), ByteRegion::Payload, 0, payload_len),
            ];
            // Each leaf is present only when decoded: absent means "not
            // observed in this segment", not "the response had none".
            if let Some(reason) = reason {
                fields.push(Field::leaf("http.response.phrase", "Response Phrase", "http", FieldType::Str, FieldValue::Str(reason.clone()), ByteRegion::Payload, 0, payload_len));
            }
            if let Some(content_type) = content_type {
                fields.push(Field::leaf("http.content_type", "Content-Type", "http", FieldType::Str, FieldValue::Str(content_type.clone()), ByteRegion::Payload, 0, payload_len));
            }
            if let Some(content_length) = content_length {
                // Past this a JS client's number would silently round, so the
                // value travels as a string; the field is a uint either way.
                let value = if *content_length > MAX_EXACT_JSON_UINT {
                    FieldValue::Str(content_length.to_string())
                } else {
                    FieldValue::Uint(*content_length)
                };
                fields.push(Field::leaf("http.content_length", "Content-Length", "http", FieldType::Uint, value, ByteRegion::Payload, 0, payload_len));
            }
            fields
        }
        L7Info::Dns { query_name, id, qtype } => vec![
            Field::group("dns", "Domain Name System", None, ByteRegion::Payload, 0, payload_len),
            Field::leaf("dns.id", "Transaction ID", "dns", FieldType::Uint, FieldValue::Uint((*id).into()), ByteRegion::Payload, dns_offset, 2),
            Field::leaf("dns.flags.response", "Response", "dns", FieldType::Bool, FieldValue::Bool(false), ByteRegion::Payload, dns_offset + 2, 1),
            Field::leaf("dns.qry.name", "Query Name", "dns", FieldType::Str, FieldValue::Str(query_name.clone()), ByteRegion::Payload, 0, payload_len),
            Field::leaf("dns.qry.type", "Query Type", "dns", FieldType::Str, FieldValue::Str(dns_type_name(*qtype)), ByteRegion::Payload, 0, payload_len),
        ],
        L7Info::DnsResponse { query_name, id, qtype, rcode, answer_count, answers } => {
            let mut fields = vec![
                Field::group("dns", "Domain Name System", None, ByteRegion::Payload, 0, payload_len),
                Field::leaf("dns.id", "Transaction ID", "dns", FieldType::Uint, FieldValue::Uint((*id).into()), ByteRegion::Payload, dns_offset, 2),
                Field::leaf("dns.flags.response", "Response", "dns", FieldType::Bool, FieldValue::Bool(true), ByteRegion::Payload, dns_offset + 2, 1),
                Field::leaf("dns.flags.rcode", "Response Code", "dns", FieldType::Str, FieldValue::Str(dns_rcode_name(*rcode)), ByteRegion::Payload, dns_offset + 3, 1),
                Field::leaf("dns.qry.name", "Query Name", "dns", FieldType::Str, FieldValue::Str(query_name.clone()), ByteRegion::Payload, 0, payload_len),
                Field::leaf("dns.qry.type", "Query Type", "dns", FieldType::Str, FieldValue::Str(dns_type_name(*qtype)), ByteRegion::Payload, 0, payload_len),
                Field::leaf("dns.count.answers", "Answer RRs", "dns", FieldType::Uint, FieldValue::Uint((*answer_count).into()), ByteRegion::Payload, dns_offset + 6, 2),
            ];
            // Each answer gets an indexed path: field paths are unique per
            // packet (the UI's field tree keys on them), so a repeated
            // `dns.a` per record, as some analyzers emit, isn't available.
            if !answers.is_empty() {
                fields.push(Field::group("dns.answers", "Answers", Some("dns"), ByteRegion::Payload, 0, payload_len));
            }
            for (i, answer) in answers.iter().enumerate() {
                let base = format!("dns.answer.{i}");
                let type_name = dns_type_name(answer.rtype);
                fields.push(Field::group(&base, &format!("{} {}", answer.name, type_name), Some("dns.answers"), ByteRegion::Payload, 0, payload_len));
                fields.push(Field::leaf(&format!("{base}.name"), "Name", &base, FieldType::Str, FieldValue::Str(answer.name.clone()), ByteRegion::Payload, 0, payload_len));
                fields.push(Field::leaf(&format!("{base}.type"), "Type", &base, FieldType::Str, FieldValue::Str(type_name), ByteRegion::Payload, 0, payload_len));
                fields.push(Field::leaf(&format!("{base}.ttl"), "Time to Live (s)", &base, FieldType::Uint, FieldValue::Uint(answer.ttl.into()), ByteRegion::Payload, 0, payload_len));
                if !answer.data.is_empty() {
                    let data_type = if matches!(answer.rtype, 1 | 28) { FieldType::Addr } else { FieldType::Str };
                    fields.push(Field::leaf(&format!("{base}.data"), "Data", &base, data_type, FieldValue::Str(answer.data.clone()), ByteRegion::Payload, 0, payload_len));
                }
                if answer.data_truncated {
                    fields.push(Field::leaf(&format!("{base}.truncated"), "Data Truncated", &base, FieldType::Bool, FieldValue::Bool(true), ByteRegion::Payload, 0, payload_len));
                }
            }
            fields
        }
        L7Info::TlsClientHello { sni, ja3, ja3_label, sni_offset, sni_len, .. } => {
            let mut fields = vec![
                Field::group("tls", "Transport Layer Security", None, ByteRegion::Payload, 0, payload_len),
                Field::leaf("tls.handshake.sni", "Server Name", "tls", FieldType::Str, FieldValue::Str(sni.clone()), ByteRegion::Payload, *sni_offset as u32, *sni_len as u32),
            ];
            if let Some(ja3_hash) = ja3 {
                fields.push(Field::leaf("tls.ja3", "JA3 Fingerprint", "tls", FieldType::Str, FieldValue::Str(ja3_hash.clone()), ByteRegion::Payload, 0, payload_len));
            }
            if let Some(label) = ja3_label {
                fields.push(Field::leaf("tls.ja3_label", "JA3 Label", "tls", FieldType::Str, FieldValue::Str(label.to_string()), ByteRegion::Payload, 0, payload_len));
            }
            fields
        }
        L7Info::None => Vec::new(),
    }
}

/// JAM-15: fields derived from request/response matching rather than from
/// this packet's own bytes, so they cover no bytes (`len` 0). Appended after
/// `build_fields`' output by the capture loop, which is the only place that
/// knows both the match and, for the request, its packet-event id.
///
/// `time_us` is microseconds because the display filter language compares
/// integers only, and milliseconds would round a sub-millisecond cached DNS
/// answer down to zero.
pub fn transaction_fields(event: &crate::transaction::TxnEvent) -> Vec<Field> {
    use crate::transaction::{TxnEvent, TxnProtocol};
    match event {
        TxnEvent::Answered { protocol, service_time_us, request_frame_id } => {
            let group = match protocol {
                TxnProtocol::Dns => "dns",
                TxnProtocol::Http => "http",
            };
            let mut fields = vec![Field::leaf(
                &format!("{group}.time_us"),
                "Service Time (µs)",
                group,
                FieldType::Uint,
                FieldValue::Uint(*service_time_us),
                ByteRegion::Payload,
                0,
                0,
            )];
            if let Some(frame_id) = request_frame_id {
                fields.push(Field::leaf(
                    &format!("{group}.response_to"),
                    "Response To",
                    group,
                    FieldType::Str,
                    FieldValue::Str(frame_id.clone()),
                    ByteRegion::Payload,
                    0,
                    0,
                ));
            }
            fields
        }
        TxnEvent::DuplicateResponse => vec![Field::leaf(
            "dns.response.duplicate",
            "Duplicate Response",
            "dns",
            FieldType::Bool,
            FieldValue::Bool(true),
            ByteRegion::Payload,
            0,
            0,
        )],
        _ => Vec::new(),
    }
}

/// Assemble the field list for one packet in its actual link framing.
pub fn build_fields(parsed: &ParsedPacket, l7: &L7Info, link_type: crate::parse::LinkType) -> Vec<Field> {
    let mut fields = Vec::new();
    let ip_start = if link_type == crate::parse::LinkType::Ethernet {
        let (eth, next) = eth_fields(parsed);
        fields.extend(eth);
        next
    } else {
        0
    };
    let (ip, transport_start) = ip_fields(parsed, ip_start);
    fields.extend(ip);
    fields.extend(transport_fields(parsed, transport_start));
    let dns_offset = if crate::l7::is_dns_over_tcp(parsed.protocol, parsed.src_port, parsed.dst_port) { 2 } else { 0 };
    fields.extend(app_fields(l7, parsed.payload.len() as u32, dns_offset));
    fields
}

/// Builds fields for the physical packet event. Reassembled L7 info describes
/// bytes reconstructed from multiple frames, while the event carries only this
/// frame's payload, so its application offsets cannot be attached safely.
pub fn build_packet_fields(
    parsed: &ParsedPacket,
    l7: &L7Info,
    link_type: crate::parse::LinkType,
    l7_from_reassembly: bool,
) -> Vec<Field> {
    if l7_from_reassembly {
        let mut fields = build_fields(parsed, &L7Info::None, link_type);
        // A DNS message reassembled from a TCP stream has no byte range in
        // this frame, but its decoded values are still real: emit them with
        // an empty range, as `transaction_fields` does. HTTP is deliberately
        // left out, and so is a message rebuilt from IP fragments (its frame
        // is not TCP), which keeps no application fields on the fragment.
        if parsed.protocol == TransportProtocol::Tcp
            && matches!(l7, L7Info::Dns { .. } | L7Info::DnsResponse { .. })
        {
            fields.extend(app_fields(l7, 0, 0).into_iter().map(|mut field| {
                field.offset = 0;
                field.len = 0;
                field
            }));
        }
        fields
    } else {
        build_fields(parsed, l7, link_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{Ipv4Header, PacketBuilder};
    use crate::l7::L7Info;
    use crate::parse::{parse_packet, LinkType, ParsedPacket, TransportProtocol};

    fn field<'a>(fields: &'a [Field], path: &str) -> &'a Field {
        fields.iter().find(|field| field.path == path).expect(path)
    }

    #[test]
    fn ipv4_options_move_udp_ranges_after_the_full_ip_header() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 0, 2, 1], [198, 51, 100, 2], 64)
            .udp(0x1234, 0x5678);
        let mut bytes = Vec::new();
        builder.write(&mut bytes, b"data").unwrap();
        bytes.splice(34..34, [1, 1, 1, 1]); // four IPv4 option bytes
        bytes[14] = 0x46; // IPv4, IHL = 24 bytes
        bytes[16..18].copy_from_slice(&36u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&[0, 0]);
        let (ip, _) = Ipv4Header::from_slice(&bytes[14..]).unwrap();
        bytes[24..26].copy_from_slice(&ip.calc_header_checksum().to_be_bytes());

        let parsed = parse_packet(&bytes, LinkType::Ethernet).unwrap();
        let fields = build_fields(&parsed, &L7Info::None, LinkType::Ethernet);
        assert_eq!((field(&fields, "ip").offset, field(&fields, "ip").len), (14, 24));
        assert_eq!((field(&fields, "udp").offset, field(&fields, "udp").len), (38, 8));
        assert_eq!((field(&fields, "udp.src_port").offset, field(&fields, "udp.src_port").len), (38, 2));
        assert_eq!(&parsed.header_bytes[38..40], &[0x12, 0x34]);
        assert_eq!((field(&fields, "udp.dst_port").offset, field(&fields, "udp.dst_port").len), (40, 2));
        assert_eq!(&parsed.header_bytes[40..42], &[0x56, 0x78]);
    }

    #[test]
    fn ipv6_hop_by_hop_extension_moves_tcp_ranges_after_the_extension() {
        let builder = PacketBuilder::ipv6([0; 16], [1; 16], 64)
            .tcp(0x1234, 0x5678, 1000, 4096)
            .syn();
        let mut bytes = Vec::new();
        builder.write(&mut bytes, b"data").unwrap();
        bytes.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]); // hop-by-hop, next TCP
        bytes[6] = 0; // IPv6 next header = hop-by-hop
        bytes[4..6].copy_from_slice(&32u16.to_be_bytes());

        let parsed = parse_packet(&bytes, LinkType::Raw).unwrap();
        let fields = build_fields(&parsed, &L7Info::None, LinkType::Raw);
        assert_eq!((field(&fields, "ip6").offset, field(&fields, "ip6").len), (0, 48));
        assert_eq!((field(&fields, "tcp").offset, field(&fields, "tcp").len), (48, 20));
        assert_eq!((field(&fields, "tcp.src_port").offset, field(&fields, "tcp.src_port").len), (48, 2));
        assert_eq!(&parsed.header_bytes[48..50], &[0x12, 0x34]);
        assert_eq!((field(&fields, "tcp.flags.syn").offset, field(&fields, "tcp.flags.syn").len), (61, 1));
        assert_eq!(field(&fields, "ip6.next_header").value, Some(FieldValue::Uint(0)));
    }

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
            ip_header_len: 20,
            transport_header_len: 20,
            ip_version: 4,
            ip_checksum: Some(0xbeef),
            vlan_tag: None,
            ip_declared_payload_len: 0,
            ip_fragment: None,
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
        packet.ip_header_len = 40;
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
        packet.tcp_flags = Some(crate::parse::TcpFlags { syn: true, ack: false, fin: false, rst: false, window_size: 65535, ack_number: 0, ..Default::default() });
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

    #[test]
    fn reassembled_dns_emits_leaves_with_empty_ranges_but_http_does_not() {
        let mut packet = base_packet();
        packet.protocol = TransportProtocol::Tcp;
        let dns = L7Info::DnsResponse {
            query_name: "example.com".into(), id: 7, qtype: 1, rcode: 0,
            answer_count: 1, answers: Vec::new(),
        };
        let fields = build_packet_fields(&packet, &dns, crate::parse::LinkType::Raw, true);
        let name = fields.iter().find(|f| f.path == "dns.qry.name").expect("dns.qry.name");
        assert_eq!(name.value, Some(FieldValue::Str("example.com".into())));
        for f in fields.iter().filter(|f| f.path.starts_with("dns")) {
            assert_eq!((f.offset, f.len), (0, 0), "{}", f.path);
        }
        let http = L7Info::HttpResponse { status: "200".into(), reason: None, content_type: None, content_length: None };
        let fields = build_packet_fields(&packet, &http, crate::parse::LinkType::Raw, true);
        assert!(!fields.iter().any(|f| f.path.starts_with("http")));
        // A frame that is not TCP (an IP fragment) keeps no application fields.
        packet.protocol = TransportProtocol::Other;
        let fields = build_packet_fields(&packet, &dns, crate::parse::LinkType::Raw, true);
        assert!(!fields.iter().any(|f| f.path.starts_with("dns")));
    }

    #[test]
    fn app_fields_cover_the_existing_application_decodes() {
        let cases = [
            (L7Info::Http { method: "GET".into(), path: "/index.html".into() }, "http.request.uri", FieldValue::Str("/index.html".into())),
            (L7Info::HttpResponse { status: "404".into(), reason: None, content_type: None, content_length: None }, "http.response.code", FieldValue::Uint(404)),
            (L7Info::Dns { query_name: "example.com".into(), id: 1, qtype: 1 }, "dns.qry.name", FieldValue::Str("example.com".into())),
        ];
        for (l7, path, value) in cases {
            let fields = app_fields(&l7, 50, 0);
            let field = fields.iter().find(|f| f.path == path).expect(path);
            assert_eq!(field.value, Some(value));
            assert_eq!(field.region, ByteRegion::Payload);
            assert_eq!((field.offset, field.len), (0, 50));
        }
        assert!(app_fields(&L7Info::None, 50, 0).is_empty());
    }

    #[test]
    fn http_response_fields_are_present_only_when_decoded() {
        let paths = |l7: &L7Info| app_fields(l7, 50, 0).into_iter().map(|f| f.path).collect::<Vec<_>>();
        let bare = L7Info::HttpResponse { status: "200".into(), reason: None, content_type: None, content_length: None };
        let bare = paths(&bare);
        for absent in ["http.response.phrase", "http.content_type", "http.content_length"] {
            assert!(!bare.iter().any(|p| p == absent), "{absent}");
        }
        let full = L7Info::HttpResponse {
            status: "200".into(), reason: Some("OK".into()),
            content_type: Some("text/html".into()), content_length: Some(12),
        };
        let fields = app_fields(&full, 50, 0);
        let value = |path: &str| fields.iter().find(|f| f.path == path).expect(path).value.clone();
        assert_eq!(value("http.response.phrase"), Some(FieldValue::Str("OK".into())));
        assert_eq!(value("http.content_type"), Some(FieldValue::Str("text/html".into())));
        assert_eq!(value("http.content_length"), Some(FieldValue::Uint(12)));
    }

    #[test]
    fn an_empty_content_type_gives_no_field() {
        for payload in [&b"HTTP/1.1 200 OK\r\nContent-Type:\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nContent-Type: \r\n\r\n"] {
            let l7 = crate::l7::sniff_l7(payload, Some(51000));
            assert!(matches!(l7, L7Info::HttpResponse { .. }), "{l7:?}");
            assert!(!app_fields(&l7, payload.len() as u32, 0).iter().any(|f| f.path == "http.content_type"));
        }
    }

    #[test]
    fn http_content_length_is_a_json_string_past_the_exact_integer_limit() {
        let json = |n: u64| {
            let l7 = L7Info::HttpResponse { status: "200".into(), reason: None, content_type: None, content_length: Some(n) };
            let fields = app_fields(&l7, 50, 0);
            let field = fields.iter().find(|f| f.path == "http.content_length").expect("the field");
            serde_json::to_value(field).expect("serializes")
        };
        let limit = 9_007_199_254_740_991u64;
        assert_eq!(json(limit)["value"], serde_json::json!(9_007_199_254_740_991u64));
        assert_eq!(json(limit + 1)["value"], serde_json::json!("9007199254740992"));
        assert_eq!(json(u64::MAX)["value"], serde_json::json!("18446744073709551615"));
        assert_eq!(json(0)["value"], serde_json::json!(0));
        // The field stays an unsigned integer whichever way its value travels.
        assert_eq!(json(limit + 1)["type"], "uint");
    }

    #[test]
    fn tls_sni_uses_its_real_range_even_when_the_dump_is_capped() {
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".into(), ja3: Some("deadbeef".into()),
            ja3_label: Some("matches Chrome 12x"), client_random: None,
            sni_offset: 80, sni_len: 11,
        };
        let fields = app_fields(&l7, 165, 0);
        let sni = fields.iter().find(|f| f.path == "tls.handshake.sni").unwrap();
        assert_eq!((sni.offset, sni.len), (80, 11));
        assert_eq!(sni.value, Some(FieldValue::Str("example.com".into())));
        assert!(fields.iter().any(|f| f.path == "tls.ja3"));
        assert!(fields.iter().any(|f| f.path == "tls.ja3_label"));
    }

    #[test]
    fn tls_omits_unavailable_ja3_fields() {
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".into(), ja3: None, ja3_label: None,
            client_random: None, sni_offset: 63, sni_len: 11,
        };
        let fields = app_fields(&l7, 100, 0);
        assert!(fields.iter().all(|f| f.path != "tls.ja3" && f.path != "tls.ja3_label"));
    }

    #[test]
    fn build_fields_assembles_headers_and_application_for_ethernet() {
        let mut p = base_packet();
        p.protocol = TransportProtocol::Tcp;
        p.src_port = Some(51000);
        p.dst_port = Some(80);
        let l7 = L7Info::Http { method: "GET".into(), path: "/".into() };
        let fields = build_fields(&p, &l7, LinkType::Ethernet);
        for group in ["eth", "ip", "tcp", "http"] {
            assert!(fields.iter().any(|f| f.path == group), "missing {group}");
        }
    }

    #[test]
    fn every_uint_leaf_the_builders_make_is_an_aggregate_field_and_nothing_else_is() {
        // JAM-18 Task 5: IO graph aggregates accept only is_uint_path
        // fields. Build every kind of leaf the builders make, and check the
        // list agrees with the types they actually carry.
        use crate::l7::{dns_test_support::response, sniff_l7};
        use crate::parse::TcpFlags;
        use crate::transaction::{TxnEvent, TxnProtocol};
        let mut leaves = Vec::new();
        let mut tcp = base_packet();
        tcp.protocol = TransportProtocol::Tcp;
        tcp.src_port = Some(80);
        tcp.dst_port = Some(51000);
        tcp.seq = Some(7);
        tcp.tcp_flags = Some(TcpFlags { syn: false, ack: true, fin: false, rst: false, window_size: 512, ack_number: 9, ..Default::default() });
        tcp.vlan_tag = Some("10".into());
        tcp.header_bytes = vec![0; 80];
        let http = L7Info::HttpResponse { status: "200".into(), reason: Some("OK".into()), content_type: Some("text/html".into()), content_length: Some(5) };
        leaves.extend(build_fields(&tcp, &http, LinkType::Ethernet));
        let mut v6 = base_packet();
        v6.ip_version = 6;
        v6.protocol = TransportProtocol::Udp;
        v6.src_port = Some(53);
        v6.dst_port = Some(50_000);
        v6.header_bytes = vec![0; 80];
        let msg = response(0x42, "example.com", 1, 0, &[(1, 300, vec![93, 184, 216, 34])]);
        leaves.extend(build_fields(&v6, &sniff_l7(&msg, Some(50_000)), LinkType::Ethernet));
        leaves.extend(build_fields(&base_packet(), &L7Info::Dns { query_name: "example.com".into(), id: 1, qtype: 1 }, LinkType::Ethernet));
        for protocol in [TxnProtocol::Dns, TxnProtocol::Http] {
            leaves.extend(transaction_fields(&TxnEvent::Answered { protocol, service_time_us: 3, request_frame_id: Some("pkt-1".into()) }));
        }
        let uint: Vec<_> = leaves.iter().filter(|f| f.field_type == FieldType::Uint).map(|f| f.path.as_str()).collect();
        for path in ["eth.vlan.id", "ip6.hop_limit", "tcp.window_size", "http.content_length", "dns.answer.0.ttl", "dns.time_us"] {
            assert!(uint.contains(&path), "fixture lacks {path}: {uint:?}");
        }
        for f in &leaves {
            assert_eq!(is_uint_path(&f.path), f.field_type == FieldType::Uint, "{} is {:?}", f.path, f.field_type);
        }
        assert!(is_uint_path("frame.len") && is_uint_path("TCP.Window_Size"));
        assert!(!is_uint_path("dns.answer.x.ttl") && !is_uint_path("dns.answer..ttl") && !is_uint_path("dns.qry.name"));
    }

    #[test]
    fn build_fields_omits_ethernet_for_loopback_and_raw() {
        for link_type in [LinkType::NullLoopback, LinkType::Raw] {
            let fields = build_fields(&base_packet(), &L7Info::None, link_type);
            assert!(fields.iter().all(|f| !f.path.starts_with("eth")));
            assert_eq!(fields.iter().find(|f| f.path == "ip").unwrap().offset, 0);
        }
    }

    #[test]
    fn a_matched_response_gets_its_service_time_and_request_link_under_its_protocol_group() {
        use crate::transaction::{TxnEvent, TxnProtocol};
        let fields = transaction_fields(&TxnEvent::Answered {
            protocol: TxnProtocol::Dns,
            service_time_us: 1_250,
            request_frame_id: Some("pkt-1-2".into()),
        });
        let summary: Vec<_> = fields.iter().map(|f| (f.path.as_str(), f.group.as_deref(), f.value.clone(), f.len)).collect();
        assert_eq!(
            summary,
            vec![
                ("dns.time_us", Some("dns"), Some(FieldValue::Uint(1_250)), 0),
                ("dns.response_to", Some("dns"), Some(FieldValue::Str("pkt-1-2".into())), 0),
            ]
        );
        let http = transaction_fields(&TxnEvent::Answered { protocol: TxnProtocol::Http, service_time_us: 9, request_frame_id: None });
        assert_eq!(http.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), vec!["http.time_us"]);
        assert_eq!(transaction_fields(&TxnEvent::DuplicateResponse)[0].path, "dns.response.duplicate");
        assert!(transaction_fields(&TxnEvent::Unmatched).is_empty());
    }

    #[test]
    fn a_dns_response_reports_its_header_question_and_indexed_answers() {
        use crate::l7::{dns_test_support::response, sniff_l7};
        let msg = response(0x42, "example.com", 1, 0, &[(1, 300, vec![93, 184, 216, 34]), (5, 30, vec![1, b'x', 0xc0, 0x0c])]);
        let l7 = sniff_l7(&msg, Some(50_000));
        let fields = app_fields(&l7, msg.len() as u32, 0);
        let value = |path: &str| fields.iter().find(|f| f.path == path).and_then(|f| f.value.clone());
        assert_eq!(value("dns.id"), Some(FieldValue::Uint(0x42)));
        assert_eq!(value("dns.flags.response"), Some(FieldValue::Bool(true)));
        assert_eq!(value("dns.flags.rcode"), Some(FieldValue::Str("NOERROR".into())));
        assert_eq!(value("dns.qry.type"), Some(FieldValue::Str("A".into())));
        assert_eq!(value("dns.count.answers"), Some(FieldValue::Uint(2)));
        assert_eq!(value("dns.answer.0.data"), Some(FieldValue::Str("93.184.216.34".into())));
        assert_eq!(value("dns.answer.0.ttl"), Some(FieldValue::Uint(300)));
        assert_eq!(value("dns.answer.1.type"), Some(FieldValue::Str("CNAME".into())));
        assert_eq!(value("dns.answer.1.data"), Some(FieldValue::Str("x.example.com".into())));
        // Every path is unique within the packet, and every grouped field's
        // group exists, so the UI's field tree can place all of them.
        let paths: std::collections::HashSet<_> = fields.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths.len(), fields.len());
        assert!(fields.iter().all(|f| f.group.as_deref().is_none_or(|g| paths.contains(g))));
    }

    #[test]
    fn truncated_txt_answer_reports_the_truncated_field() {
        use crate::l7::{dns_test_support::response, sniff_l7};
        let txt = |len: usize| {
            let mut rdata = Vec::new();
            let mut left = len;
            while left > 0 {
                let n = left.min(255);
                rdata.push(n as u8);
                rdata.extend(std::iter::repeat_n(b'a', n));
                left -= n;
            }
            rdata
        };
        let field = |rdatas: &[Vec<u8>], i: usize, leaf: &str| {
            let answers: Vec<_> = rdatas.iter().map(|r| (16u16, 60u32, r.clone())).collect();
            let msg = response(1, "t.example.com", 16, 0, &answers);
            let fields = app_fields(&sniff_l7(&msg, None), msg.len() as u32, 0);
            let path = format!("dns.answer.{i}.{leaf}");
            fields.iter().find(|f| f.path == path).and_then(|f| f.value.clone())
        };
        assert_eq!(field(&[txt(500)], 0, "truncated"), None);
        assert_eq!(field(&[txt(513)], 0, "truncated"), Some(FieldValue::Bool(true)));
        // Once the response budget is spent an answer has no data at all,
        // yet still says it was cut.
        let spent = [txt(512), txt(512), txt(512), txt(512), txt(10)];
        assert_eq!(field(&spent, 4, "data"), None);
        assert_eq!(field(&spent, 4, "truncated"), Some(FieldValue::Bool(true)));
    }

    #[test]
    fn dns_byte_ranges_skip_the_length_prefix_over_tcp_and_not_over_udp() {
        use crate::l7::{dns_test_support::response, sniff_l7};
        let msg = response(0x42, "example.com", 1, 0, &[(1, 300, vec![93, 184, 216, 34])]);
        let ranges = |protocol, src_port, dst_port, payload: Vec<u8>, l7: &L7Info| {
            let mut parsed = base_packet();
            parsed.protocol = protocol;
            parsed.src_port = Some(src_port);
            parsed.dst_port = Some(dst_port);
            parsed.payload = payload;
            let fields = build_fields(&parsed, l7, crate::parse::LinkType::Raw);
            let range = |path: &str| {
                let f = fields.iter().find(|f| f.path == path).unwrap_or_else(|| panic!("{path} missing"));
                (f.offset, f.len)
            };
            ["dns.id", "dns.flags.response", "dns.flags.rcode", "dns.count.answers"].map(range)
        };
        let l7 = sniff_l7(&msg, Some(51000));
        let udp = ranges(TransportProtocol::Udp, 53, 51000, msg.clone(), &l7);
        assert_eq!(udp, [(0, 2), (2, 1), (3, 1), (6, 2)], "UDP is unchanged");

        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        // A response (source port 53) and a request direction both skip the prefix.
        let tcp = ranges(TransportProtocol::Tcp, 53, 51000, framed.clone(), &l7);
        assert_eq!(tcp, [(2, 2), (4, 1), (5, 1), (8, 2)]);
        let query = L7Info::Dns { query_name: "a.com".into(), id: 7, qtype: 1 };
        let tcp_query = {
            let mut parsed = base_packet();
            parsed.protocol = TransportProtocol::Tcp;
            parsed.src_port = Some(51000);
            parsed.dst_port = Some(53);
            parsed.payload = framed;
            let fields = build_fields(&parsed, &query, crate::parse::LinkType::Raw);
            let f = |path: &str| fields.iter().find(|f| f.path == path).map(|f| (f.offset, f.len));
            (f("dns.id"), f("dns.flags.response"))
        };
        assert_eq!(tcp_query, (Some((2, 2)), Some((4, 1))));
    }

    #[test]
    fn byte_ranges_are_right_for_each_tcp_53_path() {
        use crate::l7::dns_test_support::response;
        let offset_of = |parsed_ports: (u16, u16), payload: Vec<u8>, l7: &L7Info, path: &str| {
            let mut parsed = base_packet();
            parsed.protocol = TransportProtocol::Tcp;
            parsed.src_port = Some(parsed_ports.0);
            parsed.dst_port = Some(parsed_ports.1);
            parsed.payload = payload;
            let fields = build_fields(&parsed, l7, crate::parse::LinkType::Raw);
            fields.iter().find(|f| f.path == path).map(|f| (f.offset, f.len))
        };
        let msg = response(0x42, "example.com", 1, 0, &[(1, 30, vec![1, 2, 3, 4])]);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        let l7 = crate::l7::sniff_l7(&msg, Some(51000));
        // A response from source 53 to an ephemeral port, and to 8443.
        assert_eq!(offset_of((53, 51000), framed.clone(), &l7, "dns.id"), Some((2, 2)));
        assert_eq!(offset_of((53, 8443), framed, &l7, "dns.count.answers"), Some((8, 2)));
        // TLS from source 53: the SNI range comes from the ClientHello, unshifted.
        let hello = crate::l7::build_client_hello("example.com");
        let tls = crate::l7::sniff_l7(&hello, Some(443));
        let L7Info::TlsClientHello { sni_offset, sni_len, .. } = tls else { panic!("fixture") };
        assert_eq!(
            offset_of((53, 8443), hello, &tls, "tls.handshake.sni"),
            Some((sni_offset as u32, sni_len as u32))
        );
    }
}
