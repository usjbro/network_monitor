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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_label: Option<String>,
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
        L7Info::HttpResponse { status } => Some(Layer7Json {
            app: "HTTP".to_string(),
            method_or_type: "RESPONSE".to_string(),
            path_or_query: String::new(),
            status_or_code: Some(status.clone()),
            payload_bytes: parsed.payload.len() as u32,
        }),
        L7Info::Dns { query_name } => Some(Layer7Json {
            app: "DNS".to_string(),
            method_or_type: "QUERY".to_string(),
            path_or_query: query_name.clone(),
            status_or_code: None,
            payload_bytes: parsed.payload.len() as u32,
        }),
        L7Info::TlsClientHello { sni, .. } => Some(Layer7Json {
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
            vlan_tag: parsed.vlan_tag.clone(),
        }),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedPayloadJson {
    pub connection_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    pub redacted: bool,
    pub data_base64: String,
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
    AgentStatus { status: AgentStatusJson },
    DecryptedPayload { payload: Box<DecryptedPayloadJson> },
    TracerouteHop { hop: Box<TracerouteHopJson> },
    CaptureStats { stats: CaptureStatsJson },
    SystemStats { stats: SystemStatsJson },
    CaptureConfig { config: CaptureConfigJson },
    CaptureConfigError { message: String },
    InterfaceList { interfaces: Vec<InterfaceJson> },
    InterfaceChanged { interface: InterfaceChangedJson },
    InterfaceError { message: String },
    CaptureFileStatus { status: CaptureFileStatusJson },
    /// Sent once, immediately, when a `start_capture_file` control message
    /// is rejected — an unsafe/empty path, ring/autostop options not yet
    /// supported, or a capture already active. Same flat, one-off shape as
    /// `capture_config_error`/`interface_error` (issues #68/#69) — a
    /// dedicated event per control-message domain rather than reusing one
    /// generic error type across them, matching this file's existing
    /// convention.
    CaptureFileError { message: String },
}

/// One capturable network interface, as reported in response to a
/// `list_interfaces` control message (issue #69). Only interfaces
/// `is_capturable` accepts (i.e. have at least one assigned address) are
/// ever included — an addressless interface can't be attributed as
/// local/remote and would silently capture nothing if selected, so it's
/// never offered as a choice in the first place.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceJson {
    pub name: String,
    pub addresses: Vec<String>,
}

/// Sent once, immediately, on a successful `set_interface` (issue #69) —
/// an ack for UI responsiveness (e.g. closing the picker) rather than
/// waiting for the next `system_stats` tick, which also carries the same
/// `interfaceName`/`ipAddress` values every tick thereafter as the
/// enduring source of truth.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceChangedJson {
    pub name: String,
    pub ip_address: String,
}

/// Sent every tick alongside `capture_stats`/`system_stats`/`capture_config`
/// — the live/replay mode indicator JAM-133 needs, resolving this event's
/// previous "defined but never sent" state (see `docs/wire-protocol.md`
/// history). `mode`/`replay_source` come from `resolve_packet_source`,
/// fixed for the life of the process; `direction_attribution_unavailable`
/// is true only when `local_addrs` was empty at startup (replay with no
/// `REPLAY_LOCAL_ADDRS` and no IDB address option) — see
/// `FlowTable::key_for`'s canonical-endpoint-ordering fallback in
/// `flow.rs`.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatusJson {
    pub interface: String,
    pub capturing: bool,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_source: Option<String>,
    pub direction_attribution_unavailable: bool,
}

/// Sent every tick alongside `capture_stats`/`capture_config`, same
/// "always-current snapshot" pattern used throughout this wire protocol.
/// `path`/`bytesWritten` keep reporting the most recently active capture
/// file's last known values even after `writing` goes back to `false`, so a
/// client sees the run's actual end state rather than the field just
/// disappearing — they're only reset by the next successful
/// `start_capture_file`. `ringFile`/`ringTotal`/`autostopReason` fields a
/// later ring-buffer rotation task (epic #55) will add are deliberately not
/// present yet — this task only implements a single, non-rotating capture
/// file.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFileStatusJson {
    pub writing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub bytes_written: u64,
    /// Present only while `ring` was configured on the `start_capture_file`
    /// request that's currently active — a plain, non-rotating capture
    /// never has a ring file number at all (JAM-5/GitHub #72).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_file: Option<u32>,
    /// Reserved for a future fixed-size ring (wraps after N files); every
    /// ring mode this task implements (size/duration/count) rotates
    /// indefinitely rather than wrapping, so this is always absent for now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_total: Option<u32>,
    /// Present only on the one tick a run just stopped itself —
    /// `"duration"`/`"totalSize"` (an autostop condition fired) or
    /// `"lowDisk"` (the disk-space guard fired). Absent while still
    /// actively writing, and absent again on an operator-requested
    /// `stop_capture_file` (that's not an *auto*-stop).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostop_reason: Option<String>,
    /// Cumulative count of packets the writer's bounded queue couldn't
    /// accept because the writer thread was falling behind (e.g. a slow
    /// disk) — never silently dropped from the operator's view even though
    /// the frame itself is gone. Distinct from `capture_stats`' existing
    /// `dropped`/`unparseableFrames` counters, which are about the kernel
    /// and the parser respectively, not this writer.
    pub backpressure_drops: u64,
}

/// The capture-time controls currently in effect — a BPF capture filter
/// (narrows what's captured at the source, cheapest possible volume
/// control) and the capture snap length (truncates each frame past this
/// many bytes, keeping headers while discarding payload). Sent once per
/// tick alongside `capture_stats`/`system_stats`, so a client that just
/// (re)connected always has the current values, not only a client that
/// happened to be connected at the moment a `set_capture_filter`/
/// `set_snaplen` control message was applied. See issue #68.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureConfigJson {
    /// `None` when no filter is active (the default) — every frame the
    /// interface hands the kernel is captured.
    pub filter: Option<String>,
    /// Bytes of each frame actually retained; anything beyond this is
    /// truncated by the kernel before this process ever sees it. `65535`
    /// (the agent's startup default) is effectively "full frame" for any
    /// real interface's MTU.
    pub snaplen: u32,
}

/// Capture health, sent once per tick (~1s) alongside `layer_update`. Three
/// independent loss sources, all real and all distinct from the
/// retransmit-derived `packetLoss` reported per connection in
/// `ConnectionJson`: `dropped`/`ifDropped` come from the kernel/driver
/// (packets that never reached this process at all — see
/// `pcap::Capture::stats()`), `relayLaggedEvents` counts *this process's
/// own* broadcast channel falling behind a slow SSE client (see
/// `main.rs`'s `RecvError::Lagged` handling), and `unparseableFrames`
/// counts frames this process *did* receive but couldn't decode at all
/// (see issue #63). A connection's retransmit-based loss percentage is
/// only trustworthy when all of these read zero — a capture with any
/// non-zero has silently missed data upstream of wherever that percentage
/// gets computed. See issue #61 and docs/wire-protocol.md.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatsJson {
    /// Total packets received by the capture handle since it opened, per
    /// the OS packet-filter driver's own count (`pcap::Stat::received`).
    pub received: u32,
    /// Packets dropped because the kernel/driver's capture buffer filled
    /// up before this process could read them (`pcap::Stat::dropped`).
    pub dropped: u32,
    /// Packets dropped by the network interface driver itself, upstream of
    /// the capture buffer (`pcap::Stat::if_dropped`) — `0` on platforms
    /// that don't report this separately from `dropped`.
    pub if_dropped: u32,
    /// Cumulative count of discrete `Packet`/`decrypted_payload` wire
    /// events this process has silently skipped delivering to a lagging
    /// SSE client, across the agent's lifetime (not per-tick). Unrelated to
    /// `dropped`/`if_dropped` above — this is the relay's own outbound
    /// backlog, not a capture-side loss.
    pub relay_lagged_events: u64,
    /// Cumulative count of frames this process received from the capture
    /// handle but `parse::parse_packet` couldn't decode at all — an
    /// unsupported or malformed link-layer/network-layer shape. Unrelated
    /// to `dropped`/`if_dropped` (which never even reached this process)
    /// and to `relay_lagged_events` (a purely relay-side backlog) — see
    /// issue #63.
    pub unparseable_frames: u64,
    /// Cumulative count of distinct flows this `FlowTable` has ever
    /// observed — the "N" half of an honest "showing N of M" horizon
    /// (JAM-6/GitHub #73). A repeat packet on an already-tracked flow never
    /// inflates this; see `FlowTable::observe`.
    pub total_connections_observed: u64,
    /// Cumulative count of flows evicted because the table exceeded its
    /// capacity ceiling, not because they went idle — see
    /// `FlowTable::EvictedFlows`. A nonzero, growing value here means this
    /// session is dropping still-active flows under memory pressure, a
    /// materially different health signal from `idle_evictions` below.
    pub capacity_evictions: u64,
    /// Cumulative count of flows evicted for going idle past their
    /// status-appropriate threshold — ordinary connection turnover, not a
    /// capacity concern.
    pub idle_evictions: u64,
}

/// Host/interface identity and aggregate throughput, sent once per tick
/// (~1s) alongside `layer_update`/`capture_stats`. Replaces the placeholder
/// values `SystemStats` used to be seeded with client-side (issue #64) —
/// every field here is a real measurement, never a fabricated number.
/// Deliberately narrower than the old placeholder shape: host CPU/memory/
/// uptime and interface speed/duplex are not included at all rather than
/// faked, since none of them are measurable from this agent today (see the
/// issue for why they were dropped instead of wired up).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatsJson {
    /// This machine's hostname, from `gethostname(2)`. Empty string if the
    /// lookup failed for any reason (never fabricated).
    pub hostname: String,
    /// The interface this agent is actually capturing on — the same value
    /// `detect_interface()` resolved at startup, not user-editable.
    pub interface_name: String,
    /// The first address assigned to the capture interface, if any. Empty
    /// string if the interface has no assigned address (shouldn't happen in
    /// practice — `is_capturable` rejects such an interface at startup —
    /// but reported honestly rather than assumed).
    pub ip_address: String,
    /// Aggregate inbound/outbound throughput across the whole interface,
    /// computed from a byte counter delta between ticks — not a sum over
    /// currently-live flows, which would move when a flow evicts even
    /// though no throughput actually changed.
    pub rx_total_mbps: f64,
    pub tx_total_mbps: f64,
    pub rx_pps_total: f64,
    pub tx_pps_total: f64,
    /// Total packets received by the capture handle since it opened — the
    /// same `pcap::Stat::received` count `capture_stats` reports, repeated
    /// here so this event is self-contained. Cumulative, not a per-tick
    /// delta.
    pub total_packets_captured: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHopJson {
    pub target_ip: String,
    pub hop_number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Pause,
    Resume,
    RegisterDecryptEligible {
        pid: u32,
        #[serde(rename = "keylogPath")]
        keylog_path: String,
    },
    UnregisterDecryptEligible {
        pid: u32,
    },
    TraceRoute {
        #[serde(rename = "targetIp")]
        target_ip: String,
    },
    /// An empty `filter` means "clear the active filter" (compiles to an
    /// unconditional-match BPF program, equivalent to no filter at all) —
    /// there is no separate clear variant, matching how the command bar's
    /// `filter clear` and `SetCaptureFilter` are meant to be one and the
    /// same request. See issue #68.
    SetCaptureFilter {
        filter: String,
    },
    SetSnaplen {
        bytes: u32,
    },
    /// Issue #69. No payload — the response is an `InterfaceList` event
    /// carrying every currently-capturable interface.
    ListInterfaces,
    SetInterface {
        name: String,
    },
    /// Starts writing the live capture to `path` as a pcapng file —
    /// operator-triggered only, never automatic (epic #55, JAM-132/GitHub
    /// #70). `ring`/`autostop` are accepted on the wire now (so a client
    /// built against the eventual full contract doesn't need a later
    /// breaking change) but always rejected with `capture_file_error` until
    /// the ring-buffer rotation task lands — this task implements a single,
    /// non-rotating capture file only.
    StartCaptureFile {
        path: String,
        #[serde(default)]
        ring: Option<RingConfigJson>,
        #[serde(default)]
        autostop: Option<AutostopConfigJson>,
    },
    StopCaptureFile,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RingConfigJson {
    pub mode: String,
    pub threshold: u64,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AutostopConfigJson {
    pub mode: String,
    pub threshold: u64,
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

    /// Shared fixture for `ConnectionJson` tests: fills every field with the
    /// same baseline values `encodes_connection_update_as_one_json_line_camel_case`
    /// has historically used, so individual tests only need to override the
    /// field(s) under test via struct-update syntax (`..fixture_connection_json()`).
    fn fixture_connection_json() -> ConnectionJson {
        ConnectionJson {
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
            ja3_fingerprint: None,
            ja3_label: None,
        }
    }

    #[test]
    fn encodes_connection_update_as_one_json_line_camel_case() {
        let event = AgentEvent::ConnectionUpdate {
            connection: Box::new(fixture_connection_json()),
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"appLayerProtocol\":\"HTTPS/TLS\""));
        assert!(line.contains("\"processName\":\"Safari\""));
        assert!(line.contains("\"type\":\"connection_update\""));
    }

    #[test]
    fn connection_json_serializes_ja3_fields_as_camel_case_when_present() {
        let json = ConnectionJson {
            ja3_fingerprint: Some("deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            ja3_label: Some("matches Chrome 12x".to_string()),
            ..fixture_connection_json()
        };
        let s = serde_json::to_string(&json).unwrap();
        assert!(s.contains("\"ja3Fingerprint\":\"deadbeefdeadbeefdeadbeefdeadbeef\""));
        assert!(s.contains("\"ja3Label\":\"matches Chrome 12x\""));
    }

    #[test]
    fn connection_json_omits_ja3_fields_entirely_when_absent() {
        let json = ConnectionJson {
            ja3_fingerprint: None,
            ja3_label: None,
            ..fixture_connection_json()
        };
        let s = serde_json::to_string(&json).unwrap();
        assert!(!s.contains("ja3Fingerprint"));
        assert!(!s.contains("ja3Label"));
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

    #[test]
    fn decode_control_rejects_malformed_shapes_without_panicking() {
        // main.rs's read loop has a bare `None => {}` arm for whatever this
        // returns and never breaks the connection on it — this test is what
        // actually proves that's safe: a malformed-but-non-empty control
        // line must decode to `None`, never panic.
        let cases = [
            r#"{"type":"nonexistent"}"#,
            // register_decrypt_eligible missing its required keylogPath.
            r#"{"type":"register_decrypt_eligible","pid":4242}"#,
            // pid is a string, not the required u32.
            r#"{"type":"register_decrypt_eligible","pid":"not-a-number","keylogPath":"/tmp/x.keylog"}"#,
            // bytes is a string, not the required u32.
            r#"{"type":"set_snaplen","bytes":"not-a-number"}"#,
            r#"{}"#,
            r#"[]"#,
        ];
        for case in cases {
            assert!(decode_control(case).is_none(), "expected None for malformed input: {case}");
        }
    }

    #[test]
    fn decodes_set_capture_filter_and_set_snaplen() {
        let msg = decode_control("{\"type\":\"set_capture_filter\",\"filter\":\"tcp port 443\"}");
        match msg {
            Some(ControlMessage::SetCaptureFilter { filter }) => assert_eq!(filter, "tcp port 443"),
            other => panic!("expected SetCaptureFilter, got {other:?}"),
        }

        // An empty filter is the "clear" request — no separate variant.
        let msg = decode_control("{\"type\":\"set_capture_filter\",\"filter\":\"\"}");
        match msg {
            Some(ControlMessage::SetCaptureFilter { filter }) => assert_eq!(filter, ""),
            other => panic!("expected SetCaptureFilter, got {other:?}"),
        }

        let msg = decode_control("{\"type\":\"set_snaplen\",\"bytes\":96}");
        match msg {
            Some(ControlMessage::SetSnaplen { bytes }) => assert_eq!(bytes, 96),
            other => panic!("expected SetSnaplen, got {other:?}"),
        }
    }

    #[test]
    fn encodes_capture_config_with_and_without_an_active_filter() {
        let with_filter = AgentEvent::CaptureConfig {
            config: CaptureConfigJson { filter: Some("tcp port 443".to_string()), snaplen: 96 },
        };
        let line = encode_event(&with_filter);
        assert!(line.contains("\"type\":\"capture_config\""));
        assert!(line.contains("\"filter\":\"tcp port 443\""));
        assert!(line.contains("\"snaplen\":96"));

        let without_filter = AgentEvent::CaptureConfig {
            config: CaptureConfigJson { filter: None, snaplen: 65535 },
        };
        let line = encode_event(&without_filter);
        assert!(line.contains("\"filter\":null"), "no active filter must be explicit null, not omitted");
    }

    #[test]
    fn encodes_agent_status_with_mode_and_direction_flag() {
        let event = AgentEvent::AgentStatus {
            status: AgentStatusJson {
                interface: "lo".into(),
                capturing: true,
                mode: "replay".into(),
                replay_source: Some("/tmp/test.pcapng".into()),
                direction_attribution_unavailable: true,
            },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"agent_status\""));
        assert!(line.contains("\"mode\":\"replay\""));
        assert!(line.contains("\"replaySource\":\"/tmp/test.pcapng\""));
        assert!(line.contains("\"directionAttributionUnavailable\":true"));
    }

    #[test]
    fn agent_status_omits_replay_source_in_live_mode() {
        let event = AgentEvent::AgentStatus {
            status: AgentStatusJson {
                interface: "en0".into(),
                capturing: true,
                mode: "live".into(),
                replay_source: None,
                direction_attribution_unavailable: false,
            },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"mode\":\"live\""));
        assert!(!line.contains("replaySource"), "replay_source must be omitted, not null, when mode is live");
    }

    #[test]
    fn encodes_capture_config_error_with_type_tag() {
        let event = AgentEvent::CaptureConfigError { message: "invalid capture filter: syntax error".to_string() };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"capture_config_error\""));
        assert!(line.contains("\"message\":\"invalid capture filter: syntax error\""));
    }

    #[test]
    fn decodes_list_interfaces_and_set_interface() {
        assert!(matches!(
            decode_control("{\"type\":\"list_interfaces\"}"),
            Some(ControlMessage::ListInterfaces)
        ));

        let msg = decode_control("{\"type\":\"set_interface\",\"name\":\"en1\"}");
        match msg {
            Some(ControlMessage::SetInterface { name }) => assert_eq!(name, "en1"),
            other => panic!("expected SetInterface, got {other:?}"),
        }
    }

    #[test]
    fn encodes_interface_list_with_addresses_per_interface() {
        let event = AgentEvent::InterfaceList {
            interfaces: vec![
                InterfaceJson { name: "en0".to_string(), addresses: vec!["192.168.1.10".to_string()] },
                InterfaceJson {
                    name: "en1".to_string(),
                    addresses: vec!["10.0.0.5".to_string(), "fe80::1".to_string()],
                },
            ],
        };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"interface_list\""));
        assert!(line.contains("\"name\":\"en0\""));
        assert!(line.contains("\"addresses\":[\"192.168.1.10\"]"));
        assert!(line.contains("\"addresses\":[\"10.0.0.5\",\"fe80::1\"]"));
    }

    #[test]
    fn encodes_interface_list_as_an_empty_array_when_nothing_is_capturable() {
        let event = AgentEvent::InterfaceList { interfaces: vec![] };
        let line = encode_event(&event);
        assert!(line.contains("\"interfaces\":[]"));
    }

    #[test]
    fn encodes_interface_changed_with_camel_case_ip_address() {
        let event = AgentEvent::InterfaceChanged {
            interface: InterfaceChangedJson { name: "en1".to_string(), ip_address: "10.0.0.5".to_string() },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"interface_changed\""));
        assert!(line.contains("\"name\":\"en1\""));
        assert!(line.contains("\"ipAddress\":\"10.0.0.5\""));
    }

    #[test]
    fn encodes_interface_error_with_type_tag() {
        let event = AgentEvent::InterfaceError { message: "no such interface: en9".to_string() };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"interface_error\""));
        assert!(line.contains("\"message\":\"no such interface: en9\""));
    }

    #[test]
    fn decodes_start_capture_file_with_ring_and_autostop() {
        let json = r#"{"type":"start_capture_file","path":"/Users/me/captures/run1.pcapng","ring":{"mode":"size","threshold":104857600},"autostop":{"mode":"duration","threshold":3600}}"#;
        match decode_control(json) {
            Some(ControlMessage::StartCaptureFile { path, ring, autostop }) => {
                assert_eq!(path, "/Users/me/captures/run1.pcapng");
                assert_eq!(ring, Some(RingConfigJson { mode: "size".into(), threshold: 104_857_600 }));
                assert_eq!(autostop, Some(AutostopConfigJson { mode: "duration".into(), threshold: 3600 }));
            }
            other => panic!("expected StartCaptureFile, got {other:?}"),
        }
    }

    #[test]
    fn decodes_start_capture_file_with_no_ring_or_autostop() {
        let json = r#"{"type":"start_capture_file","path":"/tmp/one-shot.pcapng"}"#;
        match decode_control(json) {
            Some(ControlMessage::StartCaptureFile { path, ring, autostop }) => {
                assert_eq!(path, "/tmp/one-shot.pcapng");
                assert!(ring.is_none());
                assert!(autostop.is_none());
            }
            other => panic!("expected StartCaptureFile, got {other:?}"),
        }
    }

    #[test]
    fn decodes_stop_capture_file() {
        assert!(matches!(decode_control(r#"{"type":"stop_capture_file"}"#), Some(ControlMessage::StopCaptureFile)));
    }

    #[test]
    fn encodes_capture_file_status_omitting_absent_fields() {
        let event = AgentEvent::CaptureFileStatus {
            status: CaptureFileStatusJson {
                writing: false,
                path: None,
                bytes_written: 0,
                ring_file: None,
                ring_total: None,
                autostop_reason: None,
                backpressure_drops: 0,
            },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"capture_file_status\""));
        assert!(line.contains("\"writing\":false"));
        assert!(!line.contains("\"path\""), "absent Option fields must be omitted, not null");
        assert!(!line.contains("\"ringFile\""));
        assert!(!line.contains("\"ringTotal\""));
        assert!(!line.contains("\"autostopReason\""));
    }

    #[test]
    fn encodes_capture_file_status_including_present_fields() {
        let event = AgentEvent::CaptureFileStatus {
            status: CaptureFileStatusJson {
                writing: true,
                path: Some("/tmp/capture-0002.pcapng".to_string()),
                bytes_written: 4096,
                ring_file: Some(2),
                ring_total: None,
                autostop_reason: None,
                backpressure_drops: 2,
            },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"path\":\"/tmp/capture-0002.pcapng\""));
        assert!(line.contains("\"bytesWritten\":4096"));
        assert!(line.contains("\"ringFile\":2"));
        assert!(line.contains("\"backpressureDrops\":2"));
    }

    #[test]
    fn encodes_capture_file_status_autostop_reason_when_a_run_just_stopped() {
        let event = AgentEvent::CaptureFileStatus {
            status: CaptureFileStatusJson {
                writing: false,
                path: Some("/tmp/capture.pcapng".to_string()),
                bytes_written: 8192,
                ring_file: None,
                ring_total: None,
                autostop_reason: Some("lowDisk".to_string()),
                backpressure_drops: 0,
            },
        };
        let line = encode_event(&event);
        assert!(line.contains("\"autostopReason\":\"lowDisk\""));
        assert!(line.contains("\"writing\":false"));
    }

    #[test]
    fn encodes_capture_file_error_with_type_tag() {
        let event = AgentEvent::CaptureFileError { message: "refused: already active".to_string() };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"capture_file_error\""));
        assert!(line.contains("\"message\":\"refused: already active\""));
    }

    #[test]
    fn decrypted_payload_json_serializes_expected_camel_case_fields() {
        let json = DecryptedPayloadJson {
            connection_id: "Tcp-1.2.3.4:1-5.6.7.8:443".to_string(),
            stream_id: Some(3),
            redacted: false,
            data_base64: "aGVsbG8=".to_string(),
        };
        let s = serde_json::to_string(&json).unwrap();
        assert!(s.contains("\"connectionId\""));
        assert!(s.contains("\"streamId\":3"));
        assert!(s.contains("\"redacted\":false"));
        assert!(s.contains("\"dataBase64\""));
    }

    #[test]
    fn encodes_decrypted_payload_event_with_type_tag() {
        let event = AgentEvent::DecryptedPayload {
            payload: Box::new(DecryptedPayloadJson {
                connection_id: "Tcp-1.2.3.4:1-5.6.7.8:443".to_string(),
                stream_id: None,
                redacted: true,
                data_base64: "".to_string(),
            }),
        };
        let line = encode_event(&event);
        assert!(line.contains("\"type\":\"decrypted_payload\""));
        assert!(!line.contains("\"streamId\""), "streamId should be omitted when None");
    }

    #[test]
    fn decodes_register_and_unregister_decrypt_eligible_control_messages() {
        let msg = decode_control("{\"type\":\"register_decrypt_eligible\",\"pid\":4242,\"keylogPath\":\"/tmp/x.keylog\"}");
        match msg {
            Some(ControlMessage::RegisterDecryptEligible { pid, keylog_path }) => {
                assert_eq!(pid, 4242);
                assert_eq!(keylog_path, "/tmp/x.keylog");
            }
            other => panic!("expected RegisterDecryptEligible, got {other:?}"),
        }

        let msg = decode_control("{\"type\":\"unregister_decrypt_eligible\",\"pid\":4242}");
        match msg {
            Some(ControlMessage::UnregisterDecryptEligible { pid }) => assert_eq!(pid, 4242),
            other => panic!("expected UnregisterDecryptEligible, got {other:?}"),
        }
    }

    #[test]
    fn control_message_deserializes_trace_route_with_target_ip() {
        let msg: ControlMessage =
            serde_json::from_str(r#"{"type":"trace_route","targetIp":"93.184.216.34"}"#).unwrap();
        match msg {
            ControlMessage::TraceRoute { target_ip } => assert_eq!(target_ip, "93.184.216.34"),
            _ => panic!("expected TraceRoute variant"),
        }
    }

    #[test]
    fn traceroute_hop_json_serializes_camel_case_with_optional_fields_omitted_when_none() {
        let event = AgentEvent::TracerouteHop {
            hop: Box::new(TracerouteHopJson {
                target_ip: "93.184.216.34".to_string(),
                hop_number: 4,
                hop_ip: None,
                rtt_ms: None,
            }),
        };
        let s = serde_json::to_string(&event).unwrap();
        assert!(s.contains("\"type\":\"traceroute_hop\""));
        assert!(s.contains("\"targetIp\":\"93.184.216.34\""));
        assert!(s.contains("\"hopNumber\":4"));
        assert!(!s.contains("hopIp"));
        assert!(!s.contains("rttMs"));
    }

    #[test]
    fn traceroute_hop_json_includes_hop_ip_and_rtt_when_present() {
        let event = AgentEvent::TracerouteHop {
            hop: Box::new(TracerouteHopJson {
                target_ip: "93.184.216.34".to_string(),
                hop_number: 4,
                hop_ip: Some("12.122.1.1".to_string()),
                rtt_ms: Some(18.4),
            }),
        };
        let s = serde_json::to_string(&event).unwrap();
        assert!(s.contains("\"hopIp\":\"12.122.1.1\""));
        assert!(s.contains("\"rttMs\":18.4"));
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
            header_bytes: vec![],
            ip_version: 4,
            ip_checksum: Some(0xbeef),
            vlan_tag: None,
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
            header_bytes: vec![],
            ip_version: 4,
            ip_checksum: Some(0xdead),
            vlan_tag: None,
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
    fn build_header_breakdown_fills_layer7_status_or_code_for_http_response() {
        // Regression coverage for issue #65: status_or_code was declared on
        // the wire and never populated by anything.
        let parsed = sample_tcp_packet(b"irrelevant".to_vec());
        let l7 = L7Info::HttpResponse { status: "404".to_string() };

        let breakdown = build_header_breakdown(&parsed, &l7);

        let layer7 = breakdown.layer7.expect("layer7 should be present for an HTTP response");
        assert_eq!(layer7.app, "HTTP");
        assert_eq!(layer7.method_or_type, "RESPONSE");
        assert_eq!(layer7.path_or_query, "");
        assert_eq!(layer7.status_or_code.as_deref(), Some("404"));
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

    #[test]
    fn encodes_capture_stats_as_one_json_line_camel_case() {
        let event = AgentEvent::CaptureStats {
            stats: CaptureStatsJson {
                received: 1000,
                dropped: 3,
                if_dropped: 1,
                relay_lagged_events: 42,
                unparseable_frames: 5,
                total_connections_observed: 17,
                capacity_evictions: 2,
                idle_evictions: 6,
            },
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"type\":\"capture_stats\""));
        assert!(line.contains("\"received\":1000"));
        assert!(line.contains("\"dropped\":3"));
        assert!(line.contains("\"ifDropped\":1"));
        assert!(line.contains("\"relayLaggedEvents\":42"));
        assert!(line.contains("\"unparseableFrames\":5"));
        assert!(line.contains("\"totalConnectionsObserved\":17"));
        assert!(line.contains("\"capacityEvictions\":2"));
        assert!(line.contains("\"idleEvictions\":6"));
    }

    #[test]
    fn encodes_system_stats_as_one_json_line_camel_case() {
        let event = AgentEvent::SystemStats {
            stats: SystemStatsJson {
                hostname: "osi-gw-01".to_string(),
                interface_name: "en0".to_string(),
                ip_address: "192.168.1.104".to_string(),
                rx_total_mbps: 12.5,
                tx_total_mbps: 3.25,
                rx_pps_total: 480.0,
                tx_pps_total: 220.0,
                total_packets_captured: 184200,
            },
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"type\":\"system_stats\""));
        assert!(line.contains("\"hostname\":\"osi-gw-01\""));
        assert!(line.contains("\"interfaceName\":\"en0\""));
        assert!(line.contains("\"ipAddress\":\"192.168.1.104\""));
        assert!(line.contains("\"rxTotalMbps\":12.5"));
        assert!(line.contains("\"txTotalMbps\":3.25"));
        assert!(line.contains("\"rxPpsTotal\":480.0"));
        assert!(line.contains("\"txPpsTotal\":220.0"));
        assert!(line.contains("\"totalPacketsCaptured\":184200"));
    }
}
