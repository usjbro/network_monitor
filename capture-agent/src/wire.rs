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
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    ConnectionUpdate { connection: ConnectionJson },
    ConnectionClosed { id: String },
    Packet { packet: PacketJson },
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
            connection: ConnectionJson {
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
            },
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
}
