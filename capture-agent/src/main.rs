use base64::Engine;
use capture_agent::{
    flow::{FlowKey, FlowTable},
    http2::{FrameOutcome, Http2Reassembler},
    keylog::KeyLogWatcher,
    l7, parse, process_lookup,
    rate_limit::PacketEventLimiter,
    ring_buffer::DecryptedRingBuffer,
    tls_decrypt::{self, DecryptOutcome},
    wire,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// Per-connection state for Tier B decrypted content: the HTTP/2 byte-stream
/// reassembler and the capped ring buffer that holds this connection's
/// decrypted-and-redacted content in memory only. Torn down when the flow
/// itself is evicted (see the periodic emitter's `ConnectionClosed`
/// handling below).
type DecryptState = HashMap<String, (Http2Reassembler, DecryptedRingBuffer)>;

/// Per-connection ring buffer cap. Matches the spirit of the existing
/// packet-stream cap discipline (issue #27: bounded per connection, never
/// unbounded) — 256KiB is generous for the handful of headers/small bodies
/// this view is meant to show, without letting one busy decrypt-eligible
/// connection grow without bound for the lifetime of the agent process.
const DECRYPT_RING_CAP_BYTES: usize = 256 * 1024;

/// Returns this packet's local-side port (the process-attribution key used
/// by `process_map`), using the same local-address check `FlowTable`
/// applies internally — duplicated here (rather than locking `FlowTable`
/// just to ask) because this runs in the hot per-packet capture path and
/// `local_addrs` is already available in this scope for free.
fn local_port_of(parsed: &parse::ParsedPacket, local_addrs: &[String]) -> Option<u16> {
    if local_addrs.iter().any(|a| a == &parsed.src_ip) {
        parsed.src_port
    } else if local_addrs.iter().any(|a| a == &parsed.dst_ip) {
        parsed.dst_port
    } else {
        None
    }
}

/// Builds the same canonical `FlowKey` `FlowTable::observe` would have used
/// for this packet, so the capture loop can ask `FlowTable::client_random_for`
/// about this exact flow without exposing `FlowTable`'s internal key
/// construction.
fn build_flow_key(parsed: &parse::ParsedPacket, local_addrs: &[String]) -> Option<FlowKey> {
    if local_addrs.iter().any(|a| a == &parsed.src_ip) {
        Some(FlowKey {
            protocol: parsed.protocol,
            local_addr: parsed.src_ip.clone(),
            local_port: parsed.src_port?,
            remote_addr: parsed.dst_ip.clone(),
            remote_port: parsed.dst_port?,
        })
    } else if local_addrs.iter().any(|a| a == &parsed.dst_ip) {
        Some(FlowKey {
            protocol: parsed.protocol,
            local_addr: parsed.dst_ip.clone(),
            local_port: parsed.dst_port?,
            remote_addr: parsed.src_ip.clone(),
            remote_port: parsed.src_port?,
        })
    } else {
        None
    }
}

fn emit_decrypted(
    connection_id: &str,
    stream_id: Option<u32>,
    redacted: bool,
    data: &[u8],
    limiter: &Mutex<PacketEventLimiter>,
    now_ms: u64,
    tx: &broadcast::Sender<String>,
) {
    // Same discrete-event rate cap as the existing packet_event_limiter
    // (100/sec) — stats/redaction/decryption already happened above this
    // call regardless; this only gates how often a *browser-visible* event
    // goes out.
    if !limiter.lock().unwrap().allow(now_ms) {
        return;
    }
    let event = wire::AgentEvent::DecryptedPayload {
        payload: Box::new(wire::DecryptedPayloadJson {
            connection_id: connection_id.to_string(),
            stream_id,
            redacted,
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
        }),
    };
    let _ = tx.send(wire::encode_event(&event));
}

/// Attempts Tier B decryption + HTTP/2 framing for one captured packet.
/// Entirely best-effort: any missing prerequisite (no attributed process,
/// not decrypt-eligible, no logged secret yet, undecodable record) is a
/// silent no-op, never a panic — this runs on the overwhelming majority of
/// captured packets, for which none of Tier B applies at all.
///
/// Only ever decrypts a captured TCP payload that itself begins with the
/// TLS `application_data` record type (0x17): this agent has no separate
/// TLS-record-boundary reassembler distinct from `Http2Reassembler`'s own
/// byte-stream reassembly, so a record split across multiple TCP segments
/// is not reconstructed before this check — such a record is silently
/// skipped here (not decrypted, not emitted), same as any other
/// `Undecryptable` outcome. Similarly, `tls_decrypt::decrypt_record` derives
/// its key/IV straight from the logged secret with no per-record sequence
/// number, so only the FIRST application_data record on a given secret
/// decrypts correctly — later records on the same secret fail the AEAD tag
/// check and are silently skipped too, same fail-closed path. Both are
/// named, disclosed limitations of this pass, not silent data corruption:
/// every failure here degrades to "nothing shown for this record," never a
/// wrong/garbled one.
#[allow(clippy::too_many_arguments)]
fn try_decrypt_and_emit(
    parsed: &parse::ParsedPacket,
    now_ms: u64,
    local_addrs: &[String],
    process_map: &Mutex<HashMap<u16, process_lookup::ProcessInfo>>,
    flow_table: &Mutex<FlowTable>,
    keylog_watcher: &Mutex<KeyLogWatcher>,
    decrypt_state: &Mutex<DecryptState>,
    decrypt_event_limiter: &Mutex<PacketEventLimiter>,
    tx: &broadcast::Sender<String>,
) {
    if parsed.payload.first() != Some(&0x17) {
        return; // not a TLS application_data record — nothing to decrypt
    }
    let Some(local_port) = local_port_of(parsed, local_addrs) else { return };
    let Some(pid) = process_map.lock().unwrap().get(&local_port).map(|p| p.pid) else { return };

    let secret = {
        let mut watcher = keylog_watcher.lock().unwrap();
        // Cheap when the eligible set is empty (the overwhelming common
        // case) — only currently-registered PIDs' key-log files are read.
        watcher.poll();
        if !watcher.is_eligible(pid) {
            return;
        }
        let Some(flow_key) = build_flow_key(parsed, local_addrs) else { return };
        let Some(client_random) = flow_table.lock().unwrap().client_random_for(&flow_key) else { return };
        let Some(secret) = watcher.secret_for(&client_random).cloned() else { return };
        secret
    };

    let DecryptOutcome::Plaintext(bytes) = tls_decrypt::decrypt_record(&parsed.payload, &secret) else {
        return; // undecryptable (wrong record, wrong key, truncated, ...) — fail closed, no event
    };

    let Some(flow_key) = build_flow_key(parsed, local_addrs) else { return };
    let connection_id = flow_key.connection_id();
    let seq = parsed.seq.unwrap_or(0) as u64;

    let mut state = decrypt_state.lock().unwrap();
    let entry = state
        .entry(connection_id.clone())
        .or_insert_with(|| (Http2Reassembler::new(), DecryptedRingBuffer::new(DECRYPT_RING_CAP_BYTES)));
    let outcomes = entry.0.feed(seq, &bytes);

    for outcome in outcomes {
        // DesyncFallback/NeedMoreData never emit — the whole point of the
        // reassembler's desync handling is that garbled/out-of-order bytes
        // must never be surfaced as if they were real decoded content.
        let FrameOutcome::Frame { stream_id, headers, body } = outcome else { continue };
        if !headers.is_empty() {
            // redact_headers has already run inside Http2Reassembler::feed
            // before these headers were ever returned here.
            let text = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n");
            entry.1.push(text.clone().into_bytes());
            emit_decrypted(&connection_id, Some(stream_id), false, text.as_bytes(), decrypt_event_limiter, now_ms, tx);
        }
        if !body.is_empty() {
            entry.1.push(body.clone());
            emit_decrypted(&connection_id, Some(stream_id), false, &body, decrypt_event_limiter, now_ms, tx);
        }
    }
}

/// The interface name carrying the OS's default route (e.g. "en0"), read via
/// `route -n get default` and parsed from its "interface: <name>" line.
/// `pcap::Device::lookup()` alone is not reliable for this: on macOS it can
/// return a virtual/link-local interface (e.g. AWDL's "ap1") that is up but
/// carries near-zero real traffic, rather than the interface actually
/// carrying the user's internet traffic.
fn default_route_interface_name() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .map(|name| name.to_string())
}

fn find_device_by_name<'a>(devices: &'a [pcap::Device], name: &str) -> Option<&'a pcap::Device> {
    devices.iter().find(|d| d.name == name)
}

/// `CAPTURE_INTERFACE`, when set, always wins over auto-detection — this is
/// the escape hatch for exactly the case auto-detection can't handle: the
/// OS's default route pointing at an interface (e.g. a VPN's `utun*`
/// tunnel) that `route -n get default` correctly reports but that pcap
/// can't actually capture real traffic on. An override naming an interface
/// that doesn't exist fails loudly, listing what's actually available,
/// rather than silently falling back to auto-detection — a silent fallback
/// would defeat the entire point of setting the override in the first
/// place (see docs/troubleshooting.md's "Wrong interface detected").
fn detect_interface() -> pcap::Device {
    if let Ok(name) = std::env::var("CAPTURE_INTERFACE") {
        let devices = pcap::Device::list()
            .unwrap_or_else(|e| panic!("CAPTURE_INTERFACE={name} set, but failed to list capture devices: {e}"));
        return find_device_by_name(&devices, &name)
            .cloned()
            .unwrap_or_else(|| {
                let available: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
                panic!(
                    "CAPTURE_INTERFACE={name} does not match any capture-capable interface. Available: {}",
                    available.join(", ")
                )
            });
    }

    if let Some(name) = default_route_interface_name() {
        if let Ok(devices) = pcap::Device::list() {
            if let Some(device) = find_device_by_name(&devices, &name) {
                return device.clone();
            }
        }
    }

    // Fall back to pcap's own default-device heuristic if the OS route
    // lookup fails or doesn't match any capturable device (e.g. non-macOS).
    match pcap::Device::lookup() {
        Ok(Some(device)) => device,
        Ok(None) => panic!("no capture-capable network interface found"),
        Err(e) => panic!("failed to look up default capture device: {e}"),
    }
}

fn local_addrs_for(device: &pcap::Device) -> Vec<String> {
    device
        .addresses
        .iter()
        .map(|a| a.addr.to_string())
        .collect()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    if let Err(e) = capture_agent::core_limits::disable_core_dumps() {
        eprintln!("capture-agent: WARNING failed to disable core dumps: {e}");
    }

    let device = detect_interface();
    let interface_name = device.name.clone();
    let local_addrs = local_addrs_for(&device);
    println!("capture-agent: using interface {interface_name}");

    // Shared clock: both the capture thread and the periodic emitter need
    // `now_ms` to mean "milliseconds since agent start" on the SAME clock —
    // creating a fresh Instant and immediately reading its own elapsed time
    // (`Instant::now().elapsed()`) always returns ~0, not time-since-start.
    let start = Instant::now();
    let paused = Arc::new(AtomicBool::new(false));
    // Cloned before the move into FlowTable::new below — the capture thread
    // (Tier B decrypt-eligibility lookups) and FlowTable both need their own
    // copy of the local-address list.
    let local_addrs_for_capture = local_addrs.clone();
    let flow_table = Arc::new(Mutex::new(FlowTable::new(local_addrs)));
    let process_map = Arc::new(Mutex::new(process_lookup::refresh()));
    // Tier B (opt-in decrypted TLS content) state — all in-memory only,
    // never persisted across a restart (spec: "opt-in never persists").
    let keylog_watcher = Arc::new(Mutex::new(KeyLogWatcher::new()));
    let decrypt_state: Arc<Mutex<DecryptState>> = Arc::new(Mutex::new(HashMap::new()));
    let decrypt_event_limiter = Arc::new(Mutex::new(PacketEventLimiter::new(100, 1000)));
    // Monotonic counter appended to packet IDs. epoch_ms/now_ms are both
    // millisecond-resolution clocks, so two packets captured within the same
    // millisecond would otherwise get identical IDs — and the TS side uses
    // pkt.id as a React list key, so a collision causes a rendering bug.
    let packet_seq = Arc::new(AtomicU64::new(0));

    let (tx, _rx) = broadcast::channel::<String>(1024);

    // Background: refresh the process-attribution map every 3s.
    {
        let process_map = process_map.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(3));
            let fresh = process_lookup::refresh();
            *process_map.lock().unwrap() = fresh;
        });
    }

    // Blocking capture loop on a dedicated OS thread.
    {
        let flow_table = flow_table.clone();
        let paused = paused.clone();
        let device = device.clone();
        let tx = tx.clone();
        let packet_seq = packet_seq.clone();
        let local_addrs = local_addrs_for_capture;
        let process_map = process_map.clone();
        let keylog_watcher = keylog_watcher.clone();
        let decrypt_state = decrypt_state.clone();
        let decrypt_event_limiter = decrypt_event_limiter.clone();
        std::thread::spawn(move || {
            let mut cap = match pcap::Capture::from_device(device)
                .and_then(|c| {
                    c.promisc(true)
                        .snaplen(65535)
                        .timeout(1000)
                        // Without this, macOS BPF only flushes its buffer to
                        // userspace once it's full, which on a normal-traffic
                        // interface can mean no packets are delivered for a
                        // very long time. Immediate mode delivers each packet
                        // as soon as it arrives instead.
                        .immediate_mode(true)
                        .open()
                })
            {
                Ok(cap) => cap,
                Err(e) => {
                    eprintln!("capture-agent: failed to open capture device: {e}");
                    return;
                }
            };
            // Caps discrete Packet events to the browser at 100/sec — the UI
            // only keeps the last 100 anyway (app/page.tsx's
            // `prev.slice(0, 100)`), so anything above that is pure waste.
            // Connection/layer aggregates below are unaffected: `observe()`
            // runs on every packet regardless of this limiter.
            let mut packet_event_limiter = PacketEventLimiter::new(100, 1000);
            loop {
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                match cap.next_packet() {
                    Ok(packet) => {
                        let Some(parsed) = parse::parse_packet(packet.data) else { continue };
                        let l7_info = l7::sniff_l7(&parsed.payload, parsed.dst_port);
                        let now_ms = start.elapsed().as_millis() as u64;
                        flow_table.lock().unwrap().observe(&parsed, &l7_info, now_ms);

                        // Tier B: best-effort, entirely opt-in — a no-op for
                        // the overwhelming majority of packets (see
                        // try_decrypt_and_emit's own doc comment for the
                        // early-return conditions).
                        try_decrypt_and_emit(
                            &parsed,
                            now_ms,
                            &local_addrs,
                            &process_map,
                            &flow_table,
                            &keylog_watcher,
                            &decrypt_state,
                            &decrypt_event_limiter,
                            &tx,
                        );

                        if !packet_event_limiter.allow(now_ms) {
                            continue; // stats already recorded; just skip the discrete event
                        }

                        // Emit a Packet event for the packet stream view. hex_dump is
                        // capped to the first 64 bytes of payload — plenty for display,
                        // avoids sending huge lines for large payloads.
                        let epoch_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0);
                        let seq = packet_seq.fetch_add(1, Ordering::Relaxed);
                        let header_breakdown = wire::build_header_breakdown(&parsed, &l7_info);
                        let packet_json = wire::PacketJson {
                            id: format!("pkt-{epoch_ms}-{seq}"),
                            timestamp: epoch_ms.to_string(),
                            relative_time_ms: now_ms,
                            layer: 4,
                            protocol: format!("{:?}", parsed.protocol).to_uppercase(),
                            src: format!("{}:{}", parsed.src_ip, parsed.src_port.unwrap_or(0)),
                            dst: format!("{}:{}", parsed.dst_ip, parsed.dst_port.unwrap_or(0)),
                            length: parsed.total_len as u32,
                            summary: format!(
                                "{:?} {} -> {}",
                                parsed.protocol, parsed.src_ip, parsed.dst_ip
                            ),
                            hex_dump: parsed
                                .payload
                                .iter()
                                .take(64)
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                            header_breakdown,
                        };
                        let _ = tx.send(wire::encode_event(&wire::AgentEvent::Packet {
                            packet: Box::new(packet_json),
                        }));
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        eprintln!("capture-agent: capture error (skipping): {e}");
                        continue;
                    }
                }
            }
        });
    }

    // Periodic emitter: every 1s, snapshot the flow table and broadcast connection_update events.
    {
        let flow_table = flow_table.clone();
        let process_map = process_map.clone();
        let decrypt_state = decrypt_state.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let now_ms = start.elapsed().as_millis() as u64;
                // Evict first so a flow that goes stale this tick emits only
                // a ConnectionClosed event, not also a now-stale
                // connection_update in the same pass.
                let (evicted, snapshots) = {
                    let mut ft = flow_table.lock().unwrap();
                    let evicted = ft.evict_stale(now_ms);
                    (evicted, ft.snapshot(now_ms))
                };
                let processes = process_map.lock().unwrap();

                // Per-layer aggregates for the layer_update event, accumulated
                // alongside the per-connection events below. This agent only
                // independently observes IP (L3) and TCP/UDP (L4) traffic, plus
                // L7 for flows with a recognized application protocol — L1/L2/L5/L6
                // aren't separately measurable from captured packets, so those
                // layers report zero activity rather than a fabricated number.
                let mut l3_l4_rx = 0.0_f64;
                let mut l3_l4_tx = 0.0_f64;
                let mut l3_l4_bytes = 0u64;
                let mut l3_l4_active = 0u32;
                let mut l7_rx = 0.0_f64;
                let mut l7_tx = 0.0_f64;
                let mut l7_bytes = 0u64;
                let mut l7_active = 0u32;
                let mut loss_sum = 0.0_f64;
                let mut loss_count = 0u32;

                for snap in snapshots {
                    l3_l4_rx += snap.rx_speed;
                    l3_l4_tx += snap.tx_speed;
                    l3_l4_bytes += snap.rx_bytes_total + snap.tx_bytes_total;
                    if snap.status == "ESTABLISHED" {
                        l3_l4_active += 1;
                    }
                    if snap.app_layer_protocol != "Unknown" {
                        l7_rx += snap.rx_speed;
                        l7_tx += snap.tx_speed;
                        l7_bytes += snap.rx_bytes_total + snap.tx_bytes_total;
                        l7_active += 1;
                    }
                    loss_sum += snap.packet_loss;
                    loss_count += 1;

                    let proc_info = processes.get(&snap.key.local_port);
                    let connection = wire::ConnectionJson {
                        id: snap.key.connection_id(),
                        protocol: snap.app_layer_protocol.clone(),
                        app_layer_protocol: snap.app_layer_protocol,
                        transport_protocol: format!("{:?}", snap.key.protocol).to_uppercase(),
                        osi_stack: format!(
                            "L4:{:?} -> L3:IP",
                            snap.key.protocol
                        ),
                        local_addr: snap.key.local_addr,
                        local_port: snap.key.local_port,
                        remote_addr: snap.key.remote_addr,
                        remote_port: snap.key.remote_port,
                        process_name: proc_info.map(|p| p.name.clone()).unwrap_or_else(|| "unknown".to_string()),
                        pid: proc_info.map(|p| p.pid).unwrap_or(0),
                        rx_speed: snap.rx_speed,
                        tx_speed: snap.tx_speed,
                        rx_bytes_total: snap.rx_bytes_total,
                        tx_bytes_total: snap.tx_bytes_total,
                        latency_ms: snap.latency_ms,
                        packet_loss: snap.packet_loss,
                        status: snap.status,
                        encryption: snap.encryption,
                        sparkline: vec![],
                        ja3_fingerprint: snap.ja3_fingerprint.clone(),
                        ja3_label: snap.ja3_label.map(|s| s.to_string()),
                    };
                    let event = wire::AgentEvent::ConnectionUpdate {
                        connection: Box::new(connection),
                    };
                    let _ = tx.send(wire::encode_event(&event));
                }

                for key in evicted {
                    let connection_id = key.connection_id();
                    // Tear down this connection's decrypted-content ring
                    // buffer/reassembler along with the flow itself — the
                    // ring buffer's own Drop (via zeroize on eviction, plus
                    // ordinary deallocation here) means no decrypted
                    // plaintext outlives the connection it belonged to.
                    decrypt_state.lock().unwrap().remove(&connection_id);
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::ConnectionClosed {
                        id: connection_id,
                    }));
                }

                let avg_loss = if loss_count > 0 {
                    loss_sum / loss_count as f64
                } else {
                    0.0
                };
                let layers = vec![
                    wire::LayerStatsJson {
                        layer: 3,
                        rx_speed: l3_l4_rx,
                        tx_speed: l3_l4_tx,
                        rx_packets_per_sec: 0.0,
                        tx_packets_per_sec: 0.0,
                        total_bytes: l3_l4_bytes,
                        error_rate: avg_loss,
                        active_sockets: l3_l4_active,
                        sparkline: vec![],
                    },
                    wire::LayerStatsJson {
                        layer: 4,
                        rx_speed: l3_l4_rx,
                        tx_speed: l3_l4_tx,
                        rx_packets_per_sec: 0.0,
                        tx_packets_per_sec: 0.0,
                        total_bytes: l3_l4_bytes,
                        error_rate: avg_loss,
                        active_sockets: l3_l4_active,
                        sparkline: vec![],
                    },
                    wire::LayerStatsJson {
                        layer: 7,
                        rx_speed: l7_rx,
                        tx_speed: l7_tx,
                        rx_packets_per_sec: 0.0,
                        tx_packets_per_sec: 0.0,
                        total_bytes: l7_bytes,
                        error_rate: avg_loss,
                        active_sockets: l7_active,
                        sparkline: vec![],
                    },
                ];
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::LayerUpdate { layers }));
            }
        });
    }

    let listener = TcpListener::bind("127.0.0.1:9990").await?;
    println!("capture-agent: listening on 127.0.0.1:9990");

    loop {
        let (socket, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("capture-agent: accept error (continuing): {e}");
                continue;
            }
        };
        let mut rx = tx.subscribe();
        let paused = paused.clone();
        let keylog_watcher = keylog_watcher.clone();
        let trace_tx = tx.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half).lines();

            loop {
                tokio::select! {
                    line = reader.next_line() => {
                        match line {
                            Ok(Some(text)) => {
                                match wire::decode_control(&text) {
                                    Some(wire::ControlMessage::Pause) => paused.store(true, Ordering::Relaxed),
                                    Some(wire::ControlMessage::Resume) => paused.store(false, Ordering::Relaxed),
                                    Some(wire::ControlMessage::RegisterDecryptEligible { pid, keylog_path }) => {
                                        keylog_watcher.lock().unwrap().register_eligible_pid(pid, PathBuf::from(keylog_path));
                                    }
                                    Some(wire::ControlMessage::UnregisterDecryptEligible { pid }) => {
                                        keylog_watcher.lock().unwrap().unregister_pid(pid);
                                    }
                                    Some(wire::ControlMessage::TraceRoute { target_ip }) => {
                                        // Traceroute is on-demand only (never
                                        // automatic) and bounded (hop
                                        // ceiling/timeouts enforced inside
                                        // traceroute::run_traceroute) — spawn
                                        // it on its own task so a trace (up
                                        // to 45s) never blocks this
                                        // connection's control-message read
                                        // loop or its event forwarding.
                                        let tx = trace_tx.clone();
                                        tokio::spawn(async move {
                                            let result = capture_agent::traceroute::run_traceroute(&target_ip, |hop| {
                                                let hop_json = wire::TracerouteHopJson {
                                                    target_ip: target_ip.clone(),
                                                    hop_number: hop.hop_number,
                                                    hop_ip: hop.hop_ip,
                                                    rtt_ms: hop.rtt_ms,
                                                };
                                                let _ = tx.send(wire::encode_event(&wire::AgentEvent::TracerouteHop {
                                                    hop: Box::new(hop_json),
                                                }));
                                            })
                                            .await;
                                            if let Err(e) = result {
                                                eprintln!("capture-agent: traceroute to {target_ip} failed: {e}");
                                            }
                                        });
                                    }
                                    None => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    event = rx.recv() => {
                        match event {
                            Ok(line) => {
                                if write_half.write_all(line.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                eprintln!("capture-agent: client lagged, dropped {skipped} events");
                                continue;
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::find_device_by_name;
    use tokio::sync::broadcast;

    fn fake_device(name: &str) -> pcap::Device {
        pcap::Device {
            name: name.to_string(),
            desc: None,
            addresses: vec![],
            flags: pcap::DeviceFlags::empty(),
        }
    }

    #[test]
    fn find_device_by_name_returns_the_matching_device() {
        let devices = vec![fake_device("lo0"), fake_device("en0"), fake_device("utun8")];
        let found = find_device_by_name(&devices, "en0");
        assert_eq!(found.map(|d| d.name.as_str()), Some("en0"));
    }

    #[test]
    fn find_device_by_name_returns_none_for_an_unknown_name() {
        let devices = vec![fake_device("lo0"), fake_device("en0")];
        assert!(find_device_by_name(&devices, "en99").is_none());
    }

    #[test]
    fn find_device_by_name_returns_none_for_an_empty_list() {
        let devices: Vec<pcap::Device> = vec![];
        assert!(find_device_by_name(&devices, "en0").is_none());
    }

    /// Proves the Lagged branch is reachable and recoverable: a slow
    /// receiver that falls behind a broadcast channel's capacity gets
    /// `Err(RecvError::Lagged(_))` on its next `recv()`, not a fatal error —
    /// and a subsequent `recv()` succeeds normally afterward. Drives the
    /// broadcast channel directly rather than extracting the relay loop, so
    /// this needs no sockets/pcap.
    #[tokio::test]
    async fn lagged_receiver_recovers_instead_of_erroring_fatally() {
        let (tx, mut rx) = broadcast::channel::<String>(2);

        for i in 0..5 {
            let _ = tx.send(format!("event-{i}"));
        }

        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                assert!(skipped > 0, "expected a nonzero skipped count");
            }
            other => panic!("expected Lagged, got {other:?}"),
        }

        // The channel should be usable again after Lagged, not stuck.
        let next = rx.recv().await;
        assert!(next.is_ok(), "recv after Lagged should succeed, got {next:?}");
    }
}
