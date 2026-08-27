use crate::l7::L7Info;
use crate::parse::{ParsedPacket, TransportProtocol};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionJson {
    pub id: String,
    pub protocol: String,
    pub app_layer_protocol: String,
    pub transport_protocol: String,
    pub osi_stack: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub process_name: String,
    pub pid: u32,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub latency_ms: f64,
    pub packet_loss: f64,
    pub status: String,
    pub encryption: String,
    pub sparkline: Vec<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerStatsJson {
    pub layer: u8,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
    pub total_bytes: u64,
    pub error_rate: f64,
    pub active_sockets: u32,
    pub sparkline: Vec<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketJson {
    pub id: String,
    pub timestamp: String,
    pub relative_time_ms: u64,
    pub layer: u8,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub length: u32,
    pub summary: String,
    pub hex_dump: String,
    pub header_breakdown: HeaderBreakdownJson,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Layer7Json {
    pub app: String,
    pub method_or_type: String,
    pub path_or_query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_or_code: Option<String>,
    pub payload_bytes: u32,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Layer4Json {
    pub transport: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: String,
    pub window_size: u16,
    pub seq_ack: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Layer3Json {
    pub ip_version: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub ttl: u8,
    pub protocol_num: u8,
    pub checksum: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Layer2Json {
    pub src_mac: String,
    pub dst_mac: String,
    pub eth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_tag: Option<String>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HeaderBreakdownJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer7: Option<Layer7Json>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer4: Option<Layer4Json>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer3: Option<Layer3Json>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer2: Option<Layer2Json>,
}

/// Maps a `TransportProtocol` to its IANA protocol number, for
/// `Layer3Json.protocol_num`. `Other`/`Icmp` cover cases etherparse
/// classifies without exposing a raw protocol number at the current call
/// site, so `Icmp` uses the well-known IANA value and `Other` reports 0
/// rather than a fabricated number.
fn protocol_num(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
        TransportProtocol::Icmp => 1,
        TransportProtocol::Other => 0,
    }
}

/// Builds the wire `headerBreakdown` for one packet from data already
/// extracted by `parse::parse_packet` and `l7::sniff_l7`. Always fills
/// layer2/3/4 (every captured packet has an Ethernet/IP/transport header by
/// construction — `parse_packet` returns `None` otherwise and this function
/// is never called for that packet). `layer7` is filled only when L7 info
/// was actually sniffed. `layer1`/`layer5`/`layer6` are left `None`: no PHY,
/// session, or TLS-version/cipher data is ever extracted anywhere in this
/// agent, and fabricating it would contradict main.rs's own precedent of
/// reporting zero rather than invented numbers for unmeasurable layers.
pub fn build_header_breakdown(parsed: &ParsedPacket, l7: &L7Info) -> HeaderBreakdownJson {
    let flags = parsed.tcp_flags.unwrap_or_default();
    let flags_str = if parsed.tcp_flags.is_some() {
        [
            ("SYN", flags.syn),
            ("ACK", flags.ack),
            ("FIN", flags.fin),
            ("RST", flags.rst),
        ]
        .into_iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| name)
        .collect::<Vec<_>>()
        .join(",")
    } else {
        String::new()
    };

    let layer7 = match l7 {
        L7Info::Http { method, path } => Some(Layer7Json {
            app: "HTTP".to_string(),
            method_or_type: method.clone(),
            path_or_query: path.clone(),
            status_or_code: None,
            payload_bytes: parsed.payload.len() as u32,
        }),
        L7Info::Dns { query_name } => Some(Layer7Json {
            app: "DNS".to_string(),
            method_or_type: "QUERY".to_string(),
            path_or_query: query_name.clone(),
            status_or_code: None,
            payload_bytes: parsed.payload.len() as u32,
        }),
        L7Info::TlsClientHello { sni } => Some(Layer7Json {
            app: "TLS".to_string(),
            method_or_type: "ClientHello".to_string(),
            path_or_query: sni.clone(),
            status_or_code: None,
            payload_bytes: parsed.payload.len() as u32,
        }),
        L7Info::None => None,
    };

    HeaderBreakdownJson {
        layer7,
        layer4: Some(Layer4Json {
            transport: format!("{:?}", parsed.protocol).to_uppercase(),
            src_port: parsed.src_port.unwrap_or(0),
            dst_port: parsed.dst_port.unwrap_or(0),
            flags: flags_str,
            window_size: flags.window_size,
            seq_ack: format!(
                "seq={} ack={}",
                parsed.seq.unwrap_or(0),
                flags.ack_number
            ),
        }),
        layer3: Some(Layer3Json {
            ip_version: format!("IPv{}", parsed.ip_version),
            src_ip: parsed.src_ip.clone(),
            dst_ip: parsed.dst_ip.clone(),
            ttl: parsed.ttl,
            protocol_num: protocol_num(parsed.protocol),
            checksum: parsed
                .ip_checksum
                .map(|c| format!("0x{c:04x}"))
                .unwrap_or_default(),
        }),
        layer2: Some(Layer2Json {
            src_mac: parsed.src_mac.clone(),
            dst_mac: parsed.dst_mac.clone(),
            eth_type: match parsed.ip_version {
                4 => "IPv4".to_string(),
                6 => "IPv6".to_string(),
                _ => "Unknown".to_string(),
            },
            vlan_tag: None,
        }),
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    // Boxed alongside `Packet` below: `ConnectionJson` (~320B, mostly its
    // nine `String` fields) is otherwise by far the largest variant once
    // `Packet` is boxed, and every `AgentEvent` gets cloned into a
    // 1024-slot broadcast channel — every slot would pay that worst case
    // regardless of which variant it actually holds. Also what keeps
    // `clippy::large_enum_variant` (`-D warnings` in CI) satisfied.
    ConnectionUpdate { connection: Box<ConnectionJson> },
    ConnectionClosed { id: String },
    // Boxed because `PacketJson` (with `header_breakdown`) is by far the
    // largest variant here (568B) — see the `ConnectionUpdate` comment
    // above for why boxing matters for this broadcast-cloned enum.
    Packet { packet: Box<PacketJson> },
    LayerUpdate { layers: Vec<LayerStatsJson> },
    AgentStatus { interface: String, capturing: bool },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Pause,
    Resume,
}

pub fn encode_event(event: &AgentEvent) -> String {
    let mut line = serde_json::to_string(event).expect("AgentEvent serialization cannot fail");
    line.push('\n');
    line
}

pub fn decode_control(line: &str) -> Option<ControlMessage> {
    serde_json::from_str(line.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_connection_update_as_one_json_line_camel_case() {
        let event = AgentEvent::ConnectionUpdate {
            connection: Box::new(ConnectionJson {
                id: "tcp-192.168.1.10:51000-93.184.216.34:443".to_string(),
                protocol: "TCP".to_string(),
                app_layer_protocol: "HTTPS/TLS".to_string(),
                transport_protocol: "TCP".to_string(),
                osi_stack: "L4:TCP -> L3:IPv4".to_string(),
                local_addr: "192.168.1.10".to_string(),
                local_port: 51000,
                remote_addr: "93.184.216.34".to_string(),
                remote_port: 443,
                process_name: "Safari".to_string(),
                pid: 1234,
                rx_speed: 1024.0,
                tx_speed: 512.0,
                rx_bytes_total: 4096,
                tx_bytes_total: 2048,
                latency_ms: 20.0,
                packet_loss: 0.0,
                status: "ESTABLISHED".to_string(),
                encryption: "TLS".to_string(),
                sparkline: vec![1, 2, 3],
            }),
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"appLayerProtocol\":\"HTTPS/TLS\""));
        assert!(line.contains("\"processName\":\"Safari\""));
        assert!(line.contains("\"type\":\"connection_update\""));
    }

    #[test]
    fn encodes_connection_closed_event() {
        let event = AgentEvent::ConnectionClosed {
            id: "Tcp-192.168.1.10:51000-93.184.216.34:443".to_string(),
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"type\":\"connection_closed\""));
        assert!(line.contains("\"id\":\"Tcp-192.168.1.10:51000-93.184.216.34:443\""));
    }

    #[test]
    fn decodes_pause_and_resume() {
        assert!(matches!(decode_control("{\"type\":\"pause\"}"), Some(ControlMessage::Pause)));
        assert!(matches!(decode_control("{\"type\":\"resume\"}"), Some(ControlMessage::Resume)));
        assert!(decode_control("not json").is_none());
    }

    fn sample_tcp_packet(payload: Vec<u8>) -> ParsedPacket {
        ParsedPacket {
            src_mac: "00:01:02:03:04:05".to_string(),
            dst_mac: "06:07:08:09:0a:0b".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            protocol: TransportProtocol::Tcp,
            src_port: Some(51000),
            dst_port: Some(80),
            tcp_flags: Some(crate::parse::TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                window_size: 65535,
                ack_number: 0,
            }),
            seq: Some(1000),
            ttl: 64,
            total_len: 60,
            payload,
            ip_version: 4,
            ip_checksum: Some(0xbeef),
        }
    }

    fn sample_udp_packet(payload: Vec<u8>) -> ParsedPacket {
        ParsedPacket {
            src_mac: "00:01:02:03:04:05".to_string(),
            dst_mac: "06:07:08:09:0a:0b".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            protocol: TransportProtocol::Udp,
            src_port: Some(51000),
            dst_port: Some(53),
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: 60,
            payload,
            ip_version: 4,
            ip_checksum: Some(0xdead),
        }
    }

    #[test]
    fn build_header_breakdown_fills_layer7_for_tcp_http() {
        let parsed = sample_tcp_packet(b"irrelevant".to_vec());
        let l7 = L7Info::Http {
            method: "GET".to_string(),
            path: "/index.html".to_string(),
        };

        let breakdown = build_header_breakdown(&parsed, &l7);

        let layer7 = breakdown.layer7.expect("layer7 should be present for HTTP");
        assert_eq!(layer7.app, "HTTP");
        assert_eq!(layer7.method_or_type, "GET");
        assert_eq!(layer7.path_or_query, "/index.html");
        let layer4 = breakdown.layer4.expect("layer4 always present");
        assert_eq!(layer4.transport, "TCP");
        assert_eq!(layer4.src_port, 51000);
        assert_eq!(layer4.window_size, 65535);
        assert!(layer4.flags.contains("SYN"));
    }

    #[test]
    fn build_header_breakdown_fills_layer7_for_udp_dns() {
        let parsed = sample_udp_packet(b"irrelevant".to_vec());
        let l7 = L7Info::Dns {
            query_name: "example.com".to_string(),
        };

        let breakdown = build_header_breakdown(&parsed, &l7);

        let layer7 = breakdown.layer7.expect("layer7 should be present for DNS");
        assert_eq!(layer7.app, "DNS");
        assert_eq!(layer7.path_or_query, "example.com");
        let layer4 = breakdown.layer4.expect("layer4 always present");
        assert_eq!(layer4.transport, "UDP");
        assert_eq!(layer4.dst_port, 53);
    }

    #[test]
    fn build_header_breakdown_omits_layer7_when_no_l7_info() {
        let parsed = sample_tcp_packet(b"unrecognized bytes".to_vec());

        let breakdown = build_header_breakdown(&parsed, &L7Info::None);

        assert!(breakdown.layer7.is_none());
        assert!(breakdown.layer4.is_some());
        assert!(breakdown.layer3.is_some());
        assert!(breakdown.layer2.is_some());
    }

    #[test]
    fn encode_event_uses_camel_case_and_omits_unmeasurable_layers() {
        let parsed = sample_tcp_packet(b"GET / HTTP/1.1\r\n".to_vec());
        let l7 = L7Info::Http {
            method: "GET".to_string(),
            path: "/".to_string(),
        };
        let header_breakdown = build_header_breakdown(&parsed, &l7);

        let event = AgentEvent::Packet {
            packet: Box::new(PacketJson {
                id: "pkt-1".to_string(),
                timestamp: "1000".to_string(),
                relative_time_ms: 1,
                layer: 4,
                protocol: "TCP".to_string(),
                src: "192.168.1.10:51000".to_string(),
                dst: "93.184.216.34:80".to_string(),
                length: 60,
                summary: "TCP 192.168.1.10 -> 93.184.216.34".to_string(),
                hex_dump: "00 01".to_string(),
                header_breakdown,
            }),
        };

        let line = encode_event(&event);

        assert!(line.contains("\"windowSize\":65535"));
        assert!(line.contains("\"srcPort\":51000"));
        assert!(line.contains("\"methodOrType\":\"GET\""));
        assert!(!line.contains("\"layer1\""));
        assert!(!line.contains("\"layer5\""));
        assert!(!line.contains("\"layer6\""));
    }
}
