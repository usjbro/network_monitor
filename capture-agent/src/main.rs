use capture_agent::{flow::FlowTable, l7, parse, process_lookup, rate_limit::PacketEventLimiter, wire};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

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

fn detect_interface() -> pcap::Device {
    if let Some(name) = default_route_interface_name() {
        if let Ok(devices) = pcap::Device::list() {
            if let Some(device) = devices.into_iter().find(|d| d.name == name) {
                return device;
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
    let flow_table = Arc::new(Mutex::new(FlowTable::new(local_addrs)));
    let process_map = Arc::new(Mutex::new(process_lookup::refresh()));
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
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::ConnectionClosed {
                        id: key.connection_id(),
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
    use tokio::sync::broadcast;

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
