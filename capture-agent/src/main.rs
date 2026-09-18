use base64::Engine;
use capture_agent::{
    flow::{FlowKey, FlowTable},
    host_stats,
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

/// A device with no assigned addresses can still be *found* by name, but
/// FlowTable::is_local (flow.rs) — which decides whether an observed
/// packet's src/dst IP counts as "this machine" — checks membership in
/// exactly this addresses list. An addressless device therefore silently
/// captures nothing: every packet's key_for() returns None and observe()
/// no-ops, with no error at all. Rejecting it here, loudly, at startup
/// turns that into an immediate, diagnosable failure instead of a repeat
/// of the exact "starts cleanly, captures zero packets forever" bug this
/// whole override exists to let users escape.
fn is_capturable(device: &pcap::Device) -> bool {
    !device.addresses.is_empty()
}

/// Treats an empty or whitespace-only `CAPTURE_INTERFACE` value the same as
/// unset (falls through to auto-detection) rather than as an explicit,
/// confusing "" override — e.g. a templated launch script or CI config
/// that defines the variable but leaves it blank shouldn't produce
/// `CAPTURE_INTERFACE= does not match any capture-capable interface`.
fn is_meaningful_override(raw: &str) -> bool {
    !raw.trim().is_empty()
}

/// `CAPTURE_INTERFACE`, when set to a non-empty value, always wins over
/// auto-detection — this is the escape hatch for exactly the case
/// auto-detection can't handle: the OS's default route pointing at an
/// interface (e.g. a VPN's `utun*` tunnel) that `route -n get default`
/// correctly reports but that pcap can't actually capture real traffic on.
/// An override naming an interface that doesn't exist or isn't capturable
/// fails loudly rather than silently falling back to auto-detection — a
/// silent fallback would defeat the entire point of setting the override
/// in the first place (see docs/troubleshooting.md's "Wrong interface
/// detected"). A value that fails to decode as UTF-8 is treated the same
/// way, not silently ignored — `std::env::var`'s `Result` alone would
/// quietly treat that case as "unset."
fn detect_interface() -> pcap::Device {
    if let Some(raw) = std::env::var_os("CAPTURE_INTERFACE") {
        let name = raw
            .into_string()
            .unwrap_or_else(|invalid| panic!("CAPTURE_INTERFACE is set but not valid UTF-8: {invalid:?}"));
        if is_meaningful_override(&name) {
            let devices = pcap::Device::list().unwrap_or_else(|e| {
                panic!("CAPTURE_INTERFACE={name} set, but failed to list capture devices: {e}")
            });
            let available: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
            let device = find_device_by_name(&devices, &name).unwrap_or_else(|| {
                panic!(
                    "CAPTURE_INTERFACE={name} does not match any capture-capable interface. Available: {}",
                    available.join(", ")
                )
            });
            if !is_capturable(device) {
                panic!(
                    "CAPTURE_INTERFACE={name} matches an interface with no assigned address, so \
                     captured packets can't be attributed as local/remote and nothing will be \
                     recorded. Interfaces with an address: {}",
                    devices
                        .iter()
                        .filter(|d| is_capturable(d))
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            return device.clone();
        }
    }

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

/// Maps an opened capture handle's reported datalink type
/// (`pcap::Capture::get_datalink()`) to the `parse::LinkType` this agent's
/// parser knows how to decode. Panics for anything else: a link type
/// `parse::parse_packet` can't handle means it would reject every single
/// captured frame, and the agent would otherwise start up looking healthy
/// (interface found, listening on 9990) while silently showing an idle
/// network forever — the exact bug class issue #63 exists to close. Failing
/// here, loudly, naming the interface and its link type, matches the
/// `CAPTURE_INTERFACE` precedent from #51 (docs/troubleshooting.md).
fn resolve_link_type(datalink: pcap::Linktype, interface_name: &str) -> parse::LinkType {
    match datalink {
        pcap::Linktype::ETHERNET => parse::LinkType::Ethernet,
        pcap::Linktype::NULL | pcap::Linktype::LOOP => parse::LinkType::NullLoopback,
        pcap::Linktype::RAW => parse::LinkType::Raw,
        other => {
            let name = other.get_name().unwrap_or_else(|_| format!("{other:?}"));
            panic!(
                "capture-agent: interface {interface_name} uses link type {name} (dlt={}), \
                 which this agent doesn't know how to parse. Supported: Ethernet, loopback \
                 (DLT_NULL/DLT_LOOP), and raw IP (DLT_RAW). Refusing to start rather than \
                 silently showing an idle network.",
                other.0
            )
        }
    }
}

/// Builds the `capture_stats` wire event from the latest kernel-side
/// `pcap::Stat` snapshot (or `None` if the capture thread hasn't polled one
/// yet), the cumulative relay-lag counter, and the cumulative count of
/// frames the capture thread received but couldn't parse at all (issue
/// #63) — a third, independent loss source distinct from both `dropped`
/// (kernel/driver never delivered the frame to this process) and
/// `relay_lagged_events` (this process's own outbound backlog to a slow
/// client). Kept as a small pure function, separate from the
/// periodic-emitter loop that calls it, so the mapping from these inputs to
/// the wire shape is unit-testable without a real capture handle or a
/// running tokio runtime — see issue #61.
fn build_capture_stats_json(
    stat: Option<pcap::Stat>,
    relay_lagged_events: u64,
    unparseable_frames: u64,
) -> wire::CaptureStatsJson {
    let (received, dropped, if_dropped) = match stat {
        Some(s) => (s.received, s.dropped, s.if_dropped),
        None => (0, 0, 0),
    };
    wire::CaptureStatsJson {
        received,
        dropped,
        if_dropped,
        relay_lagged_events,
        unparseable_frames,
    }
}

/// Builds the `system_stats` wire event from this tick's inputs: identity
/// values that never change after startup (hostname/interface/address),
/// this tick's byte/packet deltas (already computed by the caller as
/// `this_tick - previous_tick` over the byte/packet counters the capture
/// loop maintains), and the same cumulative `received` count
/// `capture_stats` reports. A small pure function for the same reason as
/// `build_capture_stats_json`: unit-testable without a running capture loop
/// or tokio runtime — see issue #64.
#[allow(clippy::too_many_arguments)]
fn build_system_stats_json(
    hostname: &str,
    interface_name: &str,
    ip_address: &str,
    rx_bytes_delta: u64,
    tx_bytes_delta: u64,
    rx_packets_delta: u64,
    tx_packets_delta: u64,
    tick_seconds: f64,
    total_packets_captured: u32,
) -> wire::SystemStatsJson {
    // Bits/sec / 1_000_000 = Mbps. tick_seconds is always the emitter's
    // fixed 1s interval in production; taken as a parameter (rather than
    // hard-coded) so a test can assert the arithmetic independent of that
    // constant, and so a paused/delayed tick (a longer-than-1s gap) still
    // reports an honest rate instead of quietly assuming exactly 1s elapsed.
    let mbps = |bytes_delta: u64| -> f64 {
        if tick_seconds <= 0.0 {
            return 0.0;
        }
        (bytes_delta as f64 * 8.0) / tick_seconds / 1_000_000.0
    };
    let pps = |packets_delta: u64| -> f64 {
        if tick_seconds <= 0.0 {
            return 0.0;
        }
        packets_delta as f64 / tick_seconds
    };
    wire::SystemStatsJson {
        hostname: hostname.to_string(),
        interface_name: interface_name.to_string(),
        ip_address: ip_address.to_string(),
        rx_total_mbps: mbps(rx_bytes_delta),
        tx_total_mbps: mbps(tx_bytes_delta),
        rx_pps_total: pps(rx_packets_delta),
        tx_pps_total: pps(tx_packets_delta),
        total_packets_captured,
    }
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

    // Opened synchronously here, before anything else starts (including the
    // TCP listener below), rather than inside the capture thread: this is a
    // startup precondition, and both failure modes below (device won't
    // open, or opens with a link type this agent can't parse — issue #63)
    // need to fail the whole process loudly and immediately, not leave a
    // dead capture thread behind a process that otherwise looks healthy.
    let cap = pcap::Capture::from_device(device)
        .and_then(|c| {
            c.promisc(true)
                .snaplen(65535)
                .timeout(1000)
                // Without this, macOS BPF only flushes its buffer to
                // userspace once it's full, which on a normal-traffic
                // interface can mean no packets are delivered for a very
                // long time. Immediate mode delivers each packet as soon as
                // it arrives instead.
                .immediate_mode(true)
                .open()
        })
        .unwrap_or_else(|e| panic!("capture-agent: failed to open capture device {interface_name}: {e}"));
    let datalink = cap.get_datalink();
    let link_type = resolve_link_type(datalink, &interface_name);
    println!("capture-agent: link type {datalink:?} on {interface_name}");

    // Both read once at startup and never change for the life of this
    // process — computed here, not per-tick, since neither can change
    // without restarting the agent (a new interface needs a restart; the
    // OS hostname isn't re-read either, matching that same "identity is
    // fixed at startup" assumption already made for `interface_name`).
    let hostname = host_stats::hostname();
    let ip_address = local_addrs.first().cloned().unwrap_or_default();

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
    // Latest kernel-side capture stats (issue #61) — written by the capture
    // thread roughly once a second (see below), read by the periodic
    // emitter. `None` until the capture thread's first successful poll.
    let capture_stats: Arc<Mutex<Option<pcap::Stat>>> = Arc::new(Mutex::new(None));
    // Cumulative count of discrete events this process has ever silently
    // dropped for a lagging SSE client (RecvError::Lagged, below) — a
    // relay-side loss source distinct from capture_stats above. Summed
    // across all connected clients over the agent's lifetime, not reset
    // per-tick, so a lag that already happened is never un-reported once
    // the client catches up.
    let relay_lagged_events = Arc::new(AtomicU64::new(0));
    // Cumulative count of frames the capture thread received but couldn't
    // parse at all (`parse::parse_packet` returned `None`) — an
    // unsupported/malformed link-layer or network-layer shape, distinct
    // from both `capture_stats.dropped` (the kernel/driver never delivered
    // the frame to this process at all) and `relay_lagged_events` above
    // (this process's own outbound backlog). Before this counter existed,
    // an unparseable frame vanished with zero signal anywhere — see issue
    // #63.
    let unparseable_frames = Arc::new(AtomicU64::new(0));
    // Aggregate interface throughput (issue #64), updated per-packet in the
    // capture loop. Cumulative counters, never reset — the periodic emitter
    // computes a per-tick delta from them, rather than summing live flows'
    // own totals the way the old layer_update aggregation does, because a
    // flow leaving the table (eviction) would otherwise look like a drop in
    // throughput even though nothing about the wire changed.
    let total_rx_bytes = Arc::new(AtomicU64::new(0));
    let total_tx_bytes = Arc::new(AtomicU64::new(0));
    let total_rx_packets = Arc::new(AtomicU64::new(0));
    let total_tx_packets = Arc::new(AtomicU64::new(0));

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

    // Blocking capture loop on a dedicated OS thread. `cap`/`link_type` were
    // already resolved synchronously in main(), above — opening the device
    // and reading its link type are startup preconditions, not something
    // that can fail silently mid-thread (see issue #63).
    {
        let flow_table = flow_table.clone();
        let paused = paused.clone();
        let tx = tx.clone();
        let packet_seq = packet_seq.clone();
        let local_addrs = local_addrs_for_capture;
        let process_map = process_map.clone();
        let keylog_watcher = keylog_watcher.clone();
        let decrypt_state = decrypt_state.clone();
        let decrypt_event_limiter = decrypt_event_limiter.clone();
        let capture_stats = capture_stats.clone();
        let unparseable_frames = unparseable_frames.clone();
        let total_rx_bytes = total_rx_bytes.clone();
        let total_tx_bytes = total_tx_bytes.clone();
        let total_rx_packets = total_rx_packets.clone();
        let total_tx_packets = total_tx_packets.clone();
        std::thread::spawn(move || {
            let mut cap = cap;
            // Caps discrete Packet events to the browser at 100/sec — the UI
            // only keeps the last 100 anyway (app/page.tsx's
            // `prev.slice(0, 100)`), so anything above that is pure waste.
            // Connection/layer aggregates below are unaffected: `observe()`
            // runs on every packet regardless of this limiter.
            let mut packet_event_limiter = PacketEventLimiter::new(100, 1000);
            // `cap` (the pcap handle) only ever lives on this thread, so
            // polling pcap_stats() has to happen here rather than from the
            // periodic emitter task — see build_capture_stats_json's doc
            // comment for why this is split into a separate pure function.
            let mut last_stats_poll = Instant::now();
            loop {
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                if last_stats_poll.elapsed() >= Duration::from_secs(1) {
                    last_stats_poll = Instant::now();
                    match cap.stats() {
                        Ok(stat) => *capture_stats.lock().unwrap() = Some(stat),
                        Err(e) => eprintln!("capture-agent: failed to read capture stats: {e}"),
                    }
                }
                match cap.next_packet() {
                    Ok(packet) => {
                        let Some(parsed) = parse::parse_packet(packet.data, link_type) else {
                            unparseable_frames.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let l7_info = l7::sniff_l7(&parsed.payload, parsed.dst_port);
                        let now_ms = start.elapsed().as_millis() as u64;
                        flow_table.lock().unwrap().observe(&parsed, &l7_info, now_ms);

                        // Aggregate throughput counters (issue #64) — same
                        // src/dst-vs-local_addrs direction check
                        // local_port_of/build_flow_key use elsewhere in this
                        // file. A packet matching neither (e.g. broadcast/
                        // multicast traffic captured in promiscuous mode)
                        // counts toward neither total, same as it's excluded
                        // from FlowTable's own local/remote attribution.
                        let len = parsed.total_len as u64;
                        if local_addrs.iter().any(|a| a == &parsed.src_ip) {
                            total_tx_bytes.fetch_add(len, Ordering::Relaxed);
                            total_tx_packets.fetch_add(1, Ordering::Relaxed);
                        } else if local_addrs.iter().any(|a| a == &parsed.dst_ip) {
                            total_rx_bytes.fetch_add(len, Ordering::Relaxed);
                            total_rx_packets.fetch_add(1, Ordering::Relaxed);
                        }

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
        let capture_stats = capture_stats.clone();
        let relay_lagged_events = relay_lagged_events.clone();
        let unparseable_frames = unparseable_frames.clone();
        let total_rx_bytes = total_rx_bytes.clone();
        let total_tx_bytes = total_tx_bytes.clone();
        let total_rx_packets = total_rx_packets.clone();
        let total_tx_packets = total_tx_packets.clone();
        let hostname = hostname.clone();
        let interface_name = interface_name.clone();
        let ip_address = ip_address.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            // Previous tick's cumulative counter readings, so each tick can
            // report this-tick-only deltas (see build_system_stats_json's
            // doc comment for why a delta rather than a live-flow sum).
            // Starts at 0, so the very first tick's rate is measured from
            // agent start, not from some earlier baseline.
            let mut prev_rx_bytes = 0u64;
            let mut prev_tx_bytes = 0u64;
            let mut prev_rx_packets = 0u64;
            let mut prev_tx_packets = 0u64;
            let mut prev_tick_at = Instant::now();
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

                let stat = *capture_stats.lock().unwrap();
                let lagged = relay_lagged_events.load(Ordering::Relaxed);
                let unparseable = unparseable_frames.load(Ordering::Relaxed);
                let stats_json = build_capture_stats_json(stat, lagged, unparseable);
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureStats { stats: stats_json }));

                // System/throughput stats (issue #64) — reuses `stat.received`
                // above as this event's total_packets_captured rather than a
                // separate counter, and this tick's actual elapsed wall time
                // (not assumed to be exactly 1s) as the rate denominator, so
                // a delayed tick still reports an honest, not inflated, rate.
                let tick_elapsed = prev_tick_at.elapsed().as_secs_f64();
                prev_tick_at = Instant::now();
                let rx_bytes_now = total_rx_bytes.load(Ordering::Relaxed);
                let tx_bytes_now = total_tx_bytes.load(Ordering::Relaxed);
                let rx_packets_now = total_rx_packets.load(Ordering::Relaxed);
                let tx_packets_now = total_tx_packets.load(Ordering::Relaxed);
                let total_packets_captured = stat.map(|s| s.received).unwrap_or(0);
                let system_stats_json = build_system_stats_json(
                    &hostname,
                    &interface_name,
                    &ip_address,
                    rx_bytes_now.saturating_sub(prev_rx_bytes),
                    tx_bytes_now.saturating_sub(prev_tx_bytes),
                    rx_packets_now.saturating_sub(prev_rx_packets),
                    tx_packets_now.saturating_sub(prev_tx_packets),
                    tick_elapsed,
                    total_packets_captured,
                );
                prev_rx_bytes = rx_bytes_now;
                prev_tx_bytes = tx_bytes_now;
                prev_rx_packets = rx_packets_now;
                prev_tx_packets = tx_packets_now;
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::SystemStats { stats: system_stats_json }));
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
        let relay_lagged_events = relay_lagged_events.clone();
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
                                relay_lagged_events.fetch_add(skipped, Ordering::Relaxed);
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
    use super::{
        build_capture_stats_json, build_system_stats_json, find_device_by_name, is_capturable,
        is_meaningful_override, resolve_link_type,
    };
    use capture_agent::parse::LinkType;
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

    fn fake_device_with_addr(name: &str) -> pcap::Device {
        pcap::Device {
            name: name.to_string(),
            desc: None,
            addresses: vec![pcap::Address {
                addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
                netmask: None,
                broadcast_addr: None,
                dst_addr: None,
            }],
            flags: pcap::DeviceFlags::empty(),
        }
    }

    #[test]
    fn device_has_addresses_is_true_for_a_device_with_an_assigned_address() {
        assert!(is_capturable(&fake_device_with_addr("en0")));
    }

    #[test]
    fn device_has_addresses_is_false_for_an_addressless_device() {
        // A name-matching but addressless interface (e.g. a VPN adapter
        // that exists but isn't connected, or an unused bridge) would
        // otherwise be accepted by CAPTURE_INTERFACE and then silently
        // capture nothing: FlowTable::is_local (flow.rs) checks membership
        // in exactly this addresses list, so every packet's key_for()
        // would return None and observe() would no-op forever, with no
        // error — reproducing the exact bug this override exists to fix.
        assert!(!is_capturable(&fake_device("utun9")));
    }

    #[test]
    fn resolve_link_type_maps_ethernet() {
        assert_eq!(resolve_link_type(pcap::Linktype::ETHERNET, "en0"), LinkType::Ethernet);
    }

    #[test]
    fn resolve_link_type_maps_null_and_loop_to_null_loopback() {
        assert_eq!(resolve_link_type(pcap::Linktype::NULL, "lo0"), LinkType::NullLoopback);
        assert_eq!(resolve_link_type(pcap::Linktype::LOOP, "lo0"), LinkType::NullLoopback);
    }

    #[test]
    fn resolve_link_type_maps_raw() {
        assert_eq!(resolve_link_type(pcap::Linktype::RAW, "tun0"), LinkType::Raw);
    }

    #[test]
    #[should_panic(expected = "utun8")]
    fn resolve_link_type_panics_loudly_naming_the_interface_for_an_unsupported_link_type() {
        // Never silently drop every frame from a link type this parser
        // can't decode (see issue #63) — fail at startup instead, naming
        // the interface so the failure is immediately diagnosable.
        resolve_link_type(pcap::Linktype(113), "utun8"); // DLT_LINUX_SLL
    }

    #[test]
    fn is_meaningful_override_rejects_empty_and_whitespace_only_values() {
        assert!(!is_meaningful_override(""));
        assert!(!is_meaningful_override("   "));
        assert!(is_meaningful_override("en0"));
        assert!(is_meaningful_override("  en0  "));
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

    #[test]
    fn build_capture_stats_json_carries_stat_fields_and_lag_counter_through() {
        let stat = pcap::Stat {
            received: 500,
            dropped: 7,
            if_dropped: 2,
        };
        let json = build_capture_stats_json(Some(stat), 15, 4);
        assert_eq!(json.received, 500);
        assert_eq!(json.dropped, 7);
        assert_eq!(json.if_dropped, 2);
        assert_eq!(json.relay_lagged_events, 15);
        assert_eq!(json.unparseable_frames, 4);
    }

    #[test]
    fn build_capture_stats_json_reports_zero_capture_counts_before_first_poll() {
        // The capture thread hasn't successfully called cap.stats() yet
        // (e.g. right at agent startup) — this must report honest zeros,
        // not panic and not fabricate a nonzero drop count.
        let json = build_capture_stats_json(None, 0, 0);
        assert_eq!(json.received, 0);
        assert_eq!(json.dropped, 0);
        assert_eq!(json.if_dropped, 0);
        assert_eq!(json.relay_lagged_events, 0);
        assert_eq!(json.unparseable_frames, 0);
    }

    #[test]
    fn build_capture_stats_json_carries_unparseable_frames_independent_of_other_counters() {
        // A capture with zero kernel drops and zero relay lag can still
        // have nonzero unparseable frames (e.g. a link type this parser
        // only partially understands) — the three counters are independent
        // signals, not one derived from another (see issue #63).
        let stat = pcap::Stat {
            received: 100,
            dropped: 0,
            if_dropped: 0,
        };
        let json = build_capture_stats_json(Some(stat), 0, 9);
        assert_eq!(json.dropped, 0);
        assert_eq!(json.relay_lagged_events, 0);
        assert_eq!(json.unparseable_frames, 9);
    }

    #[test]
    fn build_system_stats_json_computes_mbps_and_pps_over_a_one_second_tick() {
        // 1,250,000 bytes/sec = 10 Mbps exactly (bytes * 8 / 1_000_000).
        let json = build_system_stats_json(
            "osi-gw-01",
            "en0",
            "192.168.1.104",
            1_250_000,
            125_000,
            500,
            50,
            1.0,
            184_200,
        );
        assert_eq!(json.hostname, "osi-gw-01");
        assert_eq!(json.interface_name, "en0");
        assert_eq!(json.ip_address, "192.168.1.104");
        assert!((json.rx_total_mbps - 10.0).abs() < 1e-9, "got {}", json.rx_total_mbps);
        assert!((json.tx_total_mbps - 1.0).abs() < 1e-9, "got {}", json.tx_total_mbps);
        assert!((json.rx_pps_total - 500.0).abs() < 1e-9);
        assert!((json.tx_pps_total - 50.0).abs() < 1e-9);
        assert_eq!(json.total_packets_captured, 184_200);
    }

    #[test]
    fn build_system_stats_json_halves_the_rate_over_a_two_second_tick() {
        // Same byte delta as the 1s case above, but spread over 2 elapsed
        // seconds — the rate must come out half as large, proving this
        // divides by actual elapsed time rather than assuming a fixed 1s
        // tick (a delayed tick must not report an inflated rate).
        let json = build_system_stats_json("h", "en0", "10.0.0.1", 1_250_000, 0, 0, 0, 2.0, 0);
        assert!((json.rx_total_mbps - 5.0).abs() < 1e-9, "got {}", json.rx_total_mbps);
    }

    #[test]
    fn build_system_stats_json_reports_zero_rate_rather_than_dividing_by_zero() {
        let json = build_system_stats_json("h", "en0", "10.0.0.1", 1_000, 1_000, 10, 10, 0.0, 0);
        assert_eq!(json.rx_total_mbps, 0.0);
        assert_eq!(json.tx_total_mbps, 0.0);
        assert_eq!(json.rx_pps_total, 0.0);
        assert_eq!(json.tx_pps_total, 0.0);
    }
}
