use base64::Engine;
use capture_agent::{
    flow::{FlowKey, FlowTable},
    host_stats,
    http2::{FrameOutcome, Http2Reassembler},
    keylog::KeyLogWatcher,
    l7, parse, pcapng, process_lookup,
    rate_limit::PacketEventLimiter,
    ring,
    ring_buffer::DecryptedRingBuffer,
    tls_decrypt::{self, DecryptOutcome},
    wire,
};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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
/// parser knows how to decode, or `None` if it's a link type
/// `parse::parse_packet` can't handle at all. Pure and non-panicking on
/// purpose: `resolve_link_type` below is the panicking startup wrapper
/// around this, but issue #69's runtime interface switch also needs this
/// same mapping *without* panicking — a user picking an interface with an
/// unsupported link type from the picker must get a rejected request, not
/// a crashed agent.
fn datalink_to_link_type(datalink: pcap::Linktype) -> Option<parse::LinkType> {
    match datalink {
        pcap::Linktype::ETHERNET => Some(parse::LinkType::Ethernet),
        pcap::Linktype::NULL | pcap::Linktype::LOOP => Some(parse::LinkType::NullLoopback),
        pcap::Linktype::RAW => Some(parse::LinkType::Raw),
        _ => None,
    }
}

/// Panicking startup wrapper around `datalink_to_link_type`. A link type
/// `parse::parse_packet` can't handle means it would reject every single
/// captured frame, and the agent would otherwise start up looking healthy
/// (interface found, listening on 9990) while silently showing an idle
/// network forever — the exact bug class issue #63 exists to close. Failing
/// here, loudly, naming the interface and its link type, matches the
/// `CAPTURE_INTERFACE` precedent from #51 (docs/troubleshooting.md). Only
/// ever called at startup — issue #69's runtime interface switch calls
/// `datalink_to_link_type` directly instead, since panicking there would
/// crash the whole agent over a user's interface choice.
fn resolve_link_type(datalink: pcap::Linktype, interface_name: &str) -> parse::LinkType {
    datalink_to_link_type(datalink).unwrap_or_else(|| {
        let name = datalink.get_name().unwrap_or_else(|_| format!("{datalink:?}"));
        panic!(
            "capture-agent: interface {interface_name} uses link type {name} (dlt={}), \
             which this agent doesn't know how to parse. Supported: Ethernet, loopback \
             (DLT_NULL/DLT_LOOP), and raw IP (DLT_RAW). Refusing to start rather than \
             silently showing an idle network.",
            datalink.0
        )
    })
}

/// One packet source, abstracting over live capture, a replayed pcapng
/// file (this agent's own writer output, or any modern tool's), and a
/// replayed classic-pcap file (legacy Wireshark/tcpdump captures) — see
/// docs/superpowers/specs/2026-09-19-capture-files-design.md Components §2
/// for why these three variants, and why the capture loop below never
/// needs to know which one is active: `parse::parse_packet` and everything
/// downstream of it only ever sees the `(data, timestamp)` shape
/// `next_frame` yields.
enum PacketSource {
    Live(pcap::Capture<pcap::Active>),
    ReplayPcapng(pcapng::Reader<std::fs::File>),
    ReplayClassic(pcap::Capture<pcap::Offline>),
}

/// One frame read from a `PacketSource`. `Timeout` is live mode's existing
/// read-timeout case (already relied on today to poll `capture_config_rx`/
/// `pause` between packets on a quiet interface); `Eof` covers both a
/// replay file being fully consumed and a live device erroring out for any
/// other reason — the same "no more frames coming" outcome either way.
enum SourceFrame {
    Bytes { data: Vec<u8>, timestamp: std::time::SystemTime },
    Timeout,
    Eof,
}

impl PacketSource {
    fn next_frame(&mut self) -> SourceFrame {
        match self {
            PacketSource::Live(cap) => match cap.next_packet() {
                Ok(packet) => SourceFrame::Bytes {
                    data: packet.data.to_vec(),
                    timestamp: std::time::SystemTime::now(), // live mode's existing behavior — unchanged
                },
                Err(pcap::Error::TimeoutExpired) => SourceFrame::Timeout,
                Err(_) => SourceFrame::Eof, // a live device closing is treated the same as replay EOF — both mean "no more frames"
            },
            PacketSource::ReplayPcapng(reader) => match reader.next_packet() {
                Ok(Some(packet)) => SourceFrame::Bytes { data: packet.data, timestamp: packet.timestamp },
                Ok(None) => SourceFrame::Eof,
                Err(_) => SourceFrame::Eof, // a malformed trailing block ends replay early rather than looping forever on the same error
            },
            PacketSource::ReplayClassic(cap) => match cap.next_packet() {
                Ok(packet) => SourceFrame::Bytes {
                    data: packet.data.to_vec(),
                    timestamp: std::time::UNIX_EPOCH
                        + std::time::Duration::new(packet.header.ts.tv_sec as u64, (packet.header.ts.tv_usec as u32) * 1000),
                },
                Err(_) => SourceFrame::Eof,
            },
        }
    }
}

/// Pure parser behind `replay_local_addrs`, split out so it has a direct
/// unit test that doesn't mutate a real process env var — this file has no
/// precedent for that (`detect_interface`'s own `CAPTURE_INTERFACE`-reading
/// logic is likewise tested only through its pure `is_meaningful_override`
/// helper), and `cargo test`'s parallel runner makes mutating shared
/// process-global state from multiple tests a real flakiness risk.
fn parse_replay_local_addrs(raw: Option<&str>) -> Vec<String> {
    raw.map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// `REPLAY_LOCAL_ADDRS`, comma-separated — spec Components §2's resolution
/// for "`FlowTable::new`'s `local_addrs` cannot come from this machine's
/// interfaces when replaying someone else's capture." Empty (never
/// guessed) if unset; Task 8 covers the resulting "unknown direction"
/// degradation this produces.
fn replay_local_addrs() -> Vec<String> {
    parse_replay_local_addrs(std::env::var("REPLAY_LOCAL_ADDRS").ok().as_deref())
}

/// `REPLAY_SPEED` — `fast` (default, and the only meaningful value in live
/// mode, where it's simply never read) replays every frame back-to-back as
/// quickly as the pipeline can process them; `realtime` sleeps between
/// frames to reproduce the file's own inter-packet timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySpeed {
    Fast,
    Realtime,
}

/// Pure parser behind `replay_speed` — same env-var-free-test rationale as
/// `parse_replay_local_addrs` above.
fn parse_replay_speed(raw: Option<&str>) -> ReplaySpeed {
    match raw {
        Some("realtime") => ReplaySpeed::Realtime,
        _ => ReplaySpeed::Fast,
    }
}

fn replay_speed() -> ReplaySpeed {
    parse_replay_speed(std::env::var("REPLAY_SPEED").ok().as_deref())
}

/// Everything `resolve_packet_source` resolves once at startup and never
/// re-resolves — this repo's own explicit design decision (spec Components
/// §2) to avoid doubling the state space of the capture loop with a
/// live<->replay runtime-switching mechanism nothing in the acceptance
/// criteria actually asks for.
struct ResolvedPacketSource {
    source: PacketSource,
    interface_name: String,
    local_addrs: Vec<String>,
    link_type: parse::LinkType,
    /// `"live"` or `"replay"` — Task 9 revives this onto the `agent_status`
    /// wire event; for now it's used locally to gate the runtime
    /// capture-reconfiguration control messages (Live-only) and realtime
    /// replay pacing.
    mode: &'static str,
    replay_source: Option<String>,
    /// The `pcap::Device` behind `source`, kept around so a later
    /// `set_interface`/`set_capture_filter`/`set_snaplen` control message
    /// can reopen it — mirrors the existing live-mode `device_for_reopen`
    /// local this replaces. Always `Some` exactly when `source` is
    /// `PacketSource::Live`, `None` otherwise: those control messages
    /// aren't available in replay mode (Components §2: "existing
    /// runtime-reconfiguration code path completely unaware replay mode
    /// exists at all").
    device_for_reopen: Option<pcap::Device>,
}

/// pcapng's Section Header Block type, as it appears literally on disk —
/// the same four bytes regardless of the file's internal byte-order marker
/// (0x0A0D0D0A's byte representation is identical little- or big-endian),
/// which is exactly why real pcapng readers use it to detect the format
/// before even knowing which endianness the rest of the file uses.
const PCAPNG_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

/// Peeks the first four bytes of `path` to check whether it's shaped like a
/// pcapng file, without needing a full parse. Used only to decide whether a
/// file that already failed this agent's own pcapng reader should be
/// refused outright rather than handed to libpcap's own competing pcapng
/// parser (see the caller's comment). Any I/O failure here (can't open,
/// too short) is treated as "not pcapng-shaped" — the caller's subsequent
/// `pcap::Capture::from_file` attempt will surface the real error.
fn looks_like_pcapng(path: &str) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|()| magic == PCAPNG_MAGIC)
        .unwrap_or(false)
}

/// Mirrors `detect_interface()`'s existing fail-loud posture exactly: an
/// unparseable or self-contradictory startup configuration panics with a
/// specific message naming what's wrong, never silently falls back.
fn resolve_packet_source() -> ResolvedPacketSource {
    let replay_file = std::env::var("REPLAY_FILE").ok().filter(|s| !s.trim().is_empty());
    let capture_interface_set = std::env::var_os("CAPTURE_INTERFACE")
        .map(|v| !v.to_string_lossy().trim().is_empty())
        .unwrap_or(false);

    if let Some(path) = replay_file {
        if capture_interface_set {
            panic!("both CAPTURE_INTERFACE and REPLAY_FILE are set — these are mutually exclusive; unset one");
        }

        let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("REPLAY_FILE={path} could not be opened: {e}"));

        // Try pcapng first (this agent's own writer always produces it, and
        // it's the richer format — a real interface name/link type from the
        // file's own Interface Description block); fall back to classic
        // pcap via libpcap's own file-open support, per spec Components
        // §2's two-path design. `pcap::Capture::from_file` opens the path
        // itself rather than reusing `file`, so there's no conflict with
        // `file` having already been partially read by the failed pcapng
        // attempt below.
        return match pcapng::Reader::new(file) {
            Ok((reader, interface)) => {
                let interface_name = interface
                    .interface_name
                    .unwrap_or_else(|| "unknown (replayed pcapng, no if_name recorded)".to_string());
                ResolvedPacketSource {
                    source: PacketSource::ReplayPcapng(reader),
                    interface_name,
                    local_addrs: replay_local_addrs(),
                    link_type: interface.link_type,
                    mode: "replay",
                    replay_source: Some(path),
                    device_for_reopen: None,
                }
            }
            Err(_) => {
                // Security-review finding: libpcap (>=1.10) auto-detects
                // and natively parses pcapng too, not just classic pcap —
                // so without this check, a file that merely *fails* our
                // own strict, fuzzed pcapng reader (malformed in some way
                // it doesn't tolerate) would fall through to libpcap's own
                // C-based pcapng parser, which has real CVE history on
                // malformed capture files (e.g. CVE-2019-15161) and has no
                // fuzz coverage in this repo. Refusing any file whose first
                // four bytes are the pcapng Section Header Block's block
                // type (a fixed byte sequence regardless of the file's
                // internal byte-order, since it's the same four bytes
                // whichever way you encode 0x0A0D0D0A) keeps every
                // pcapng-shaped file on our own audited/fuzzed path only —
                // it either parses there or is rejected outright, never
                // handed to a second, unfuzzed pcapng parser as a fallback.
                if looks_like_pcapng(&path) {
                    panic!(
                        "REPLAY_FILE={path} looks like a pcapng file (starts with the pcapng \
                         Section Header Block signature) but failed to parse with this agent's \
                         own reader — refusing to fall back to libpcap's own pcapng parser for a \
                         file already known to be malformed or unsupported"
                    );
                }
                let cap = pcap::Capture::from_file(&path)
                    .unwrap_or_else(|e| panic!("REPLAY_FILE={path} is neither valid pcapng nor classic pcap: {e}"));
                let link_type = resolve_link_type(cap.get_datalink(), &path);
                ResolvedPacketSource {
                    source: PacketSource::ReplayClassic(cap),
                    interface_name: "unknown (replayed classic pcap)".to_string(),
                    local_addrs: replay_local_addrs(),
                    link_type,
                    mode: "replay",
                    replay_source: Some(path),
                    device_for_reopen: None,
                }
            }
        };
    }

    // Existing live-mode startup path, moved here verbatim from main() —
    // unchanged by this task other than being wrapped in this match arm.
    let device = detect_interface();
    let interface_name = device.name.clone();
    let local_addrs = local_addrs_for(&device);
    println!("capture-agent: using interface {interface_name}");
    // Kept around for the life of the process so a later `snaplen <bytes>`
    // control message (issue #68) can reopen the same device — `device`
    // itself is consumed by `Capture::from_device` immediately below.
    let device_for_reopen = device.clone();
    let cap = pcap::Capture::from_device(device)
        .and_then(|c| {
            c.promisc(true)
                .snaplen(DEFAULT_SNAPLEN)
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

    ResolvedPacketSource {
        source: PacketSource::Live(cap),
        interface_name,
        local_addrs,
        link_type,
        mode: "live",
        replay_source: None,
        device_for_reopen: Some(device_for_reopen),
    }
}

/// Maximum accepted length for a browser-supplied BPF filter expression, in
/// bytes — rejected before it ever reaches libpcap's compiler. Generous for
/// any real filter (see http://biot.com/capstats/bpf.html) while bounding
/// this new attacker-reachable input to the privileged capture process, per
/// issue #68's security considerations.
const MAX_CAPTURE_FILTER_LEN: usize = 1024;

/// Snap length the agent opens its capture handle with at startup — large
/// enough to hold any real interface's full MTU, so nothing is truncated
/// until an operator explicitly narrows it. `snaplen <bytes>` (issue #68)
/// can shrink this at runtime; `snaplen full` restores exactly this value.
const DEFAULT_SNAPLEN: i32 = 65535;

/// Maximum accepted length for a browser-supplied interface name, in bytes
/// — same "bound new attacker-reachable input before it touches anything"
/// discipline as `MAX_CAPTURE_FILTER_LEN` (issue #68). Real interface names
/// (`en0`, `lo0`, `utun8`, ...) are a handful of bytes; this is generous
/// while still rejecting an obviously-bogus request outright.
const MAX_INTERFACE_NAME_LEN: usize = 256;

/// A capture-time control change requested over the wire (issues #68 and
/// #69), queued from the async control-message-handling task into the
/// capture thread via an `std::sync::mpsc` channel — the open
/// `pcap::Capture` handle only ever lives on the capture thread (same
/// reason `capture_stats` polling has to happen there, see
/// `build_capture_stats_json`'s doc comment), so applying any of these has
/// to happen there too, not in the async task that received the control
/// message. `SetFilter`/`SetSnaplen` are applied by
/// `apply_capture_config_request`; `SwitchInterface` needs a wider set of
/// shared state (link type, local addresses, the flow table) and gets its
/// own `apply_interface_switch_request`.
enum CaptureConfigRequest {
    SetFilter(String),
    SetSnaplen(u32),
    SwitchInterface(String),
}

/// A command queued to the dedicated pcapng-writer thread (epic #55,
/// JAM-132/GitHub #70) — `Packet`/`Stats` come from the hot capture-loop
/// thread via a bounded channel (so a slow disk backs up this queue rather
/// than ever blocking packet processing), while `Start`/`Stop` come from
/// the async control-message task. Routing all four through one channel,
/// rather than a separate signal for start/stop, means they're naturally
/// serialized with in-flight packet writes — no risk of a `Stop` racing a
/// `Packet` that was queued just before it.
enum WriterCommand {
    Start {
        path: PathBuf,
        ring: Option<wire::RingConfigJson>,
        autostop: Option<wire::AutostopConfigJson>,
        idb: pcapng::InterfaceDescriptionBlock,
        hostname: String,
        agent_version: String,
    },
    Stop,
    Packet {
        timestamp: std::time::SystemTime,
        direction: pcapng::Direction,
        data: Vec<u8>,
    },
    Stats {
        received: u32,
        dropped: u32,
    },
}

/// Bounded at 4096 — generous relative to this agent's existing 100/sec
/// discrete `packet` wire-event rate limit (every captured frame reaches
/// this queue, not just the ones that pass that limiter), sized so a brief
/// disk hiccup doesn't immediately start dropping, while still bounding
/// memory if the disk stalls for longer than that.
const WRITER_QUEUE_CAPACITY: usize = 4096;

/// Validates and resolves an operator-supplied capture-file path (epic #55,
/// JAM-132/GitHub #70) before ever opening it: refuses a path that resolves
/// inside `cwd` (this agent's own working directory — source, `.data/`,
/// and other small ephemeral metadata, never multi-gigabyte capture
/// artifacts an operator explicitly asked to keep) or that names a `.data/`
/// component anywhere, per the design spec's Components §1. Pure and
/// unit-testable: takes `cwd` as a parameter rather than calling
/// `std::env::current_dir()` itself.
fn validate_capture_file_path(path: &str, cwd: &Path) -> Result<PathBuf, String> {
    if path.trim().is_empty() {
        return Err("capture file path must not be empty".to_string());
    }
    if path.contains(".data/") || path.contains(".data\\") {
        return Err(format!("capture file path rejected: {path} must not be inside .data/"));
    }
    let candidate = Path::new(path);
    let resolved = if candidate.is_absolute() { candidate.to_path_buf() } else { cwd.join(candidate) };
    if resolved.starts_with(cwd) {
        return Err(format!(
            "capture file path rejected: {path} resolves inside this agent's working directory ({}) — choose a location outside it",
            cwd.display()
        ));
    }
    Ok(resolved)
}

/// Validates a `start_capture_file` request's `ring` option before it ever
/// reaches `ring.rs` — an unknown mode or a zero threshold is rejected
/// outright rather than silently never rotating.
fn validate_ring_config(ring: &wire::RingConfigJson) -> Result<(), String> {
    match ring.mode.as_str() {
        "size" | "duration" | "count" => {}
        other => return Err(format!("unknown ring mode {other:?} — expected \"size\", \"duration\", or \"count\"")),
    }
    if ring.threshold == 0 {
        return Err("ring threshold must be greater than zero".to_string());
    }
    Ok(())
}

/// Same discipline as `validate_ring_config`, for the `autostop` option.
fn validate_autostop_config(autostop: &wire::AutostopConfigJson) -> Result<(), String> {
    match autostop.mode.as_str() {
        "duration" | "totalSize" => {}
        other => return Err(format!("unknown autostop mode {other:?} — expected \"duration\" or \"totalSize\"")),
    }
    if autostop.threshold == 0 {
        return Err("autostop threshold must be greater than zero".to_string());
    }
    Ok(())
}

/// Validates a browser-supplied BPF filter expression's length before it
/// ever reaches libpcap's compiler — pure and unit-testable, unlike the
/// actual `cap.filter()` call below, which needs a live capture handle.
fn validate_capture_filter_len(filter: &str) -> Result<(), String> {
    if filter.len() > MAX_CAPTURE_FILTER_LEN {
        Err(format!(
            "capture filter rejected: {} bytes exceeds the {MAX_CAPTURE_FILTER_LEN}-byte limit",
            filter.len()
        ))
    } else {
        Ok(())
    }
}

/// Validates and converts a browser-supplied snap length into the `i32`
/// libpcap's `Capture::snaplen()` builder expects — pure and
/// unit-testable. `0` is rejected (not a meaningful capture request);
/// anything not representable as a positive `i32` is rejected outright
/// rather than silently truncated or wrapped.
fn validate_snaplen(bytes: u32) -> Result<i32, String> {
    let snaplen = i32::try_from(bytes).map_err(|_| format!("snap length {bytes} is out of range"))?;
    if snaplen <= 0 {
        return Err("snap length must be greater than zero".to_string());
    }
    Ok(snaplen)
}

/// Applies one queued `CaptureConfigRequest` against the live capture
/// handle, updating `state` and emitting a `CaptureConfig`/
/// `CaptureConfigError` wire event to reflect the outcome. A filter change
/// is applied live (`Capture::filter` compiles and installs a new BPF
/// program on the already-open handle); a snap length change has no live
/// equivalent in libpcap, so it closes and reopens the handle entirely —
/// `*cap` is replaced in place, and the capture loop's very next
/// `next_packet()` call transparently picks up the new handle. Any
/// currently-active filter is reapplied to a reopened handle, since filter
/// state doesn't survive a reopen — and if that reapply itself fails, the
/// whole snap length change is rejected rather than silently installing a
/// broader, unfiltered handle in its place: a snap length change must
/// never widen what gets captured as a side effect.
///
/// On failure (an invalid filter, a length that fails validation, a reopen
/// error, or a post-reopen filter-reapply failure), `state` and `*cap` are
/// left exactly as they were — the previous capture configuration keeps
/// running uninterrupted — per issue #68's acceptance criteria that a
/// rejected change must never leave the agent in a half-applied state.
fn apply_capture_config_request(
    request: CaptureConfigRequest,
    cap: &mut pcap::Capture<pcap::Active>,
    device: &pcap::Device,
    state: &Mutex<wire::CaptureConfigJson>,
    tx: &broadcast::Sender<String>,
) {
    match request {
        CaptureConfigRequest::SetFilter(filter) => {
            if let Err(message) = validate_capture_filter_len(&filter) {
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError { message }));
                return;
            }
            match cap.filter(&filter, true) {
                Ok(()) => {
                    let mut s = state.lock().unwrap();
                    s.filter = if filter.is_empty() { None } else { Some(filter) };
                    let snapshot = s.clone();
                    drop(s);
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfig { config: snapshot }));
                }
                Err(e) => {
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError {
                        message: format!("invalid capture filter: {e}"),
                    }));
                }
            }
        }
        CaptureConfigRequest::SetSnaplen(bytes) => {
            let snaplen = match validate_snaplen(bytes) {
                Ok(snaplen) => snaplen,
                Err(message) => {
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError { message }));
                    return;
                }
            };
            let reopened = pcap::Capture::from_device(device.clone())
                .and_then(|c| c.promisc(true).snaplen(snaplen).timeout(1000).immediate_mode(true).open());
            let mut new_cap = match reopened {
                Ok(new_cap) => new_cap,
                Err(e) => {
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError {
                        message: format!("failed to apply snap length {bytes}: {e}"),
                    }));
                    return;
                }
            };
            let existing_filter = state.lock().unwrap().filter.clone();
            if let Some(ref expr) = existing_filter {
                // This expression already compiled successfully once (or it
                // couldn't have become the active filter), so a failure
                // here would mean the reopened handle rejects it for some
                // other reason. Reject the whole snap length change rather
                // than silently install a broader, unfiltered `new_cap` in
                // its place — a snap length change must never widen what
                // gets captured as a side effect. `new_cap` is dropped here
                // (closing that handle); `*cap` is never touched, so the
                // previous snap length AND filter both keep running exactly
                // as before.
                if let Err(e) = new_cap.filter(expr, true) {
                    let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError {
                        message: format!(
                            "snap length {bytes} rejected: the active capture filter could not be reapplied after reopening ({e}) — keeping the previous configuration"
                        ),
                    }));
                    return;
                }
            }
            *cap = new_cap;
            let mut s = state.lock().unwrap();
            s.snaplen = bytes;
            let snapshot = s.clone();
            drop(s);
            println!("capture-agent: snap length changed to {bytes} bytes (capture briefly reopened)");
            let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfig { config: snapshot }));
        }
        CaptureConfigRequest::SwitchInterface(_) => {
            unreachable!(
                "the capture thread's drain loop dispatches SwitchInterface to \
                 apply_interface_switch_request directly, never to this function"
            )
        }
    }
}

/// Validates a browser-supplied interface name's length before it's ever
/// looked up against `pcap::Device::list()` — pure and unit-testable, same
/// discipline as `validate_capture_filter_len`.
fn validate_interface_name_len(name: &str) -> Result<(), String> {
    if name.len() > MAX_INTERFACE_NAME_LEN {
        Err(format!(
            "interface name rejected: {} bytes exceeds the {MAX_INTERFACE_NAME_LEN}-byte limit",
            name.len()
        ))
    } else {
        Ok(())
    }
}

/// Applies a `SetInterface` request (issue #69) — switches which physical
/// interface the agent captures on, without restarting the process. Unlike
/// `apply_capture_config_request` (issue #68), this touches nearly every
/// piece of per-interface state the capture thread and periodic emitter
/// share: the open capture handle, the device used for any future
/// snaplen-triggered reopen, the resolved link type (a different interface
/// can have a different link type entirely — e.g. switching from `en0`
/// (Ethernet) to `lo0` (loopback)), the local-address list `FlowTable` uses
/// to decide packet direction, and the identity `system_stats` reports.
///
/// A rejected switch — an oversized name, no such interface, an
/// addressless (uncapturable) interface, a device-list/open failure, or an
/// unsupported link type — leaves every one of those exactly as it was,
/// same "never a half-applied state" discipline as #68; `new_cap` (if one
/// was even opened) is simply dropped, closing it, while `*cap` keeps
/// running untouched. On success, the existing flow table is entirely
/// reset (every previously-tracked flow belonged to the interface that
/// just stopped being captured — an old flow lingering with a
/// now-wrong local-address frame of reference is exactly the
/// direction-flips-silently bug this issue calls out as "the one
/// genuinely error-prone part of the change"), and the active capture
/// filter/snap length reset to their defaults, since a filter tuned for
/// one interface may not even be meaningful on another.
#[allow(clippy::too_many_arguments)]
fn apply_interface_switch_request(
    name: &str,
    cap: &mut pcap::Capture<pcap::Active>,
    device_for_reopen: &mut pcap::Device,
    link_type: &mut parse::LinkType,
    local_addrs: &mut Vec<String>,
    current_interface: &Mutex<(String, String)>,
    current_link_type: &Mutex<parse::LinkType>,
    capture_config_state: &Mutex<wire::CaptureConfigJson>,
    flow_table: &Mutex<FlowTable>,
    tx: &broadcast::Sender<String>,
) {
    if let Err(message) = validate_interface_name_len(name) {
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError { message }));
        return;
    }
    let devices = match pcap::Device::list() {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError {
                message: format!("failed to list capture devices: {e}"),
            }));
            return;
        }
    };
    let Some(device) = find_device_by_name(&devices, name) else {
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError {
            message: format!("no such interface: {name}"),
        }));
        return;
    };
    if !is_capturable(device) {
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError {
            message: format!(
                "{name} has no assigned address, so captured packets can't be attributed as \
                 local/remote and nothing would be recorded"
            ),
        }));
        return;
    }

    let reopened = pcap::Capture::from_device(device.clone())
        .and_then(|c| c.promisc(true).snaplen(DEFAULT_SNAPLEN).timeout(1000).immediate_mode(true).open());
    let new_cap = match reopened {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError {
                message: format!("failed to open {name}: {e}"),
            }));
            return;
        }
    };
    let Some(new_link_type) = datalink_to_link_type(new_cap.get_datalink()) else {
        let datalink = new_cap.get_datalink();
        let dl_name = datalink.get_name().unwrap_or_else(|_| format!("{datalink:?}"));
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceError {
            message: format!(
                "{name} uses link type {dl_name}, which this agent doesn't know how to parse"
            ),
        }));
        return; // new_cap drops here, closing it — *cap is never touched
    };

    let new_local_addrs = local_addrs_for(device);
    let new_ip_address = new_local_addrs.first().cloned().unwrap_or_default();
    let new_device = device.clone();

    // Every previously-tracked flow belonged to the interface that just
    // stopped being captured — reset rather than let them linger with a
    // now-wrong local-address frame of reference (see this fn's doc
    // comment).
    let closed_ids: Vec<String> = {
        let mut ft = flow_table.lock().unwrap();
        ft.reset(new_local_addrs.clone()).into_iter().map(|k| k.connection_id()).collect()
    };
    for id in closed_ids {
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::ConnectionClosed { id }));
    }

    *cap = new_cap;
    *device_for_reopen = new_device;
    *link_type = new_link_type;
    *local_addrs = new_local_addrs;
    *current_interface.lock().unwrap() = (name.to_string(), new_ip_address.clone());
    *current_link_type.lock().unwrap() = new_link_type;
    // A filter/snaplen tuned for the previous interface may not even be
    // meaningful on this one — reset to defaults rather than carry it
    // forward silently.
    *capture_config_state.lock().unwrap() =
        wire::CaptureConfigJson { filter: None, snaplen: DEFAULT_SNAPLEN as u32 };

    println!("capture-agent: switched capture interface to {name}");
    let _ = tx.send(wire::encode_event(&wire::AgentEvent::InterfaceChanged {
        interface: wire::InterfaceChangedJson { name: name.to_string(), ip_address: new_ip_address },
    }));
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
    total_connections_observed: u64,
    capacity_evictions: u64,
    idle_evictions: u64,
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
        total_connections_observed,
        capacity_evictions,
        idle_evictions,
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

    // Resolved once, here, and never again — see `ResolvedPacketSource`'s
    // own doc comment for why replay mode is never runtime-switchable.
    // Opened synchronously, before anything else starts (including the TCP
    // listener below), rather than inside the capture thread: this is a
    // startup precondition, and every failure mode inside it (device won't
    // open, opens with a link type this agent can't parse — issue #63, or a
    // REPLAY_FILE that's neither valid pcapng nor classic pcap) needs to
    // fail the whole process loudly and immediately, not leave a dead
    // capture thread behind a process that otherwise looks healthy.
    let ResolvedPacketSource {
        source: packet_source,
        interface_name,
        local_addrs,
        link_type,
        mode,
        replay_source,
        device_for_reopen,
    } = resolve_packet_source();
    println!(
        "capture-agent: mode={mode} interface={interface_name}{}",
        replay_source.as_deref().map(|s| format!(" replay_source={s}")).unwrap_or_default()
    );

    // Hostname is read once at startup and never changes for the life of
    // this process — the OS hostname isn't re-read at runtime.
    // `interface_name`/`ip_address`, by contrast, CAN change at runtime as
    // of issue #69 (a `set_interface` control message) — the initial
    // values computed here just seed `current_interface` below.
    let hostname = host_stats::hostname();
    let ip_address = local_addrs.first().cloned().unwrap_or_default();
    // Computed here, before `local_addrs` is moved into `FlowTable::new`
    // below — true only when replay had no derivable local-address
    // information at all, the one case where `FlowTable::key_for` falls
    // back to its canonical-endpoint-ordering convention instead of a real
    // local/remote determination. Fixed for the life of the process, same
    // as `mode`/`replay_source`.
    let direction_attribution_unavailable = local_addrs.is_empty();

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
    // Replay mode: `process_lookup::refresh()` walks *this* machine's live
    // socket table, which is meaningless for a replayed capture — the
    // processes that owned those flows may never have run on this machine
    // at all, or have long since exited. Never populating `process_map`
    // means every connection reports `processName: "unknown"`/`pid: 0` via
    // the existing no-match fallback, rather than mis-attributing to
    // whatever unrelated process happens to hold a matching local port
    // today (spec Components §2).
    let process_map = Arc::new(Mutex::new(if mode == "live" {
        process_lookup::refresh()
    } else {
        HashMap::new()
    }));
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
    // Active capture filter/snap length (issue #68) — written by the
    // capture thread whenever a `set_capture_filter`/`set_snaplen` control
    // message is successfully applied, read every tick by the periodic
    // emitter so a client that only just (re)connected sees the current
    // values immediately, not only a client that was connected at the
    // moment the change happened.
    let capture_config_state = Arc::new(Mutex::new(wire::CaptureConfigJson { filter: None, snaplen: DEFAULT_SNAPLEN as u32 }));
    // The open `pcap::Capture` handle only ever lives on the capture
    // thread, so a capture-config change requested from the async
    // control-message task below has to be queued across this channel
    // rather than applied directly — see `CaptureConfigRequest`'s doc
    // comment.
    let (capture_config_tx, capture_config_rx) = mpsc::channel::<CaptureConfigRequest>();
    // Current interface identity (issue #69) — (name, ip_address). Written
    // by the capture thread on a successful `set_interface`, read every
    // tick by the periodic emitter so `system_stats.interfaceName`/
    // `ipAddress` reflect a switch immediately rather than only after a
    // restart. Deliberately NOT behind the same lock as the hot per-packet
    // hostname/local_addrs path (see the capture thread's own `local_addrs`/
    // `link_type`/`device_for_reopen` locals below) — only the periodic
    // emitter (once/sec) and a switch (rare, user-initiated) ever touch
    // this, so a small dedicated Mutex costs nothing on the capture loop.
    let current_interface = Arc::new(Mutex::new((interface_name.clone(), ip_address.clone())));
    // Mirrors `link_type` (a capture-thread-local, updated on a successful
    // `set_interface`) for the async control-message task, which needs the
    // *current* link type to build a `start_capture_file` request's
    // Interface Description Block but never touches the live `pcap::Capture`
    // handle itself. Same "small dedicated Mutex, rarely written, cheap to
    // read" shape as `current_interface` just above.
    let current_link_type = Arc::new(Mutex::new(link_type));

    let (tx, _rx) = broadcast::channel::<String>(1024);

    // Capture-to-file (epic #55, JAM-132/JAM-5/GitHub #70/#72) shared
    // state: never on by default. `writer_active` is the hot capture
    // loop's single cheap check per packet; `writer_path`/
    // `writer_bytes_written`/`writer_ring_file`/`writer_autostop_reason`
    // feed the per-tick `capture_file_status` event; `writer_backpressure_drops`
    // is written by the capture loop (a full queue) and never reset. The
    // `ring::RingState` (which itself owns the only `pcapng::Writer` this
    // process ever opens) lives only inside the dedicated writer thread
    // below — nothing else ever touches an open file handle.
    let writer_active = Arc::new(AtomicBool::new(false));
    let writer_bytes_written = Arc::new(AtomicU64::new(0));
    let writer_backpressure_drops = Arc::new(AtomicU64::new(0));
    let writer_path: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let writer_ring_file: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let writer_autostop_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let (writer_tx, writer_rx) = mpsc::sync_channel::<WriterCommand>(WRITER_QUEUE_CAPACITY);

    // Dedicated OS thread owning the only active capture-to-file run this
    // process ever has open — a slow disk therefore only ever backs up
    // this thread's own queue, never the hot capture loop (which only ever
    // does a bounded `try_send`, above). `current` is a plain local, not
    // behind a Mutex: this is the only thread that ever reads or writes it.
    // Rotation/autostop/disk-guard policy (JAM-5/GitHub #72) all live in
    // `ring.rs`, called from here rather than reimplemented inline.
    {
        let tx = tx.clone();
        let writer_active = writer_active.clone();
        let writer_bytes_written = writer_bytes_written.clone();
        let writer_path = writer_path.clone();
        let writer_ring_file = writer_ring_file.clone();
        let writer_autostop_reason = writer_autostop_reason.clone();
        std::thread::spawn(move || {
            let mut current: Option<ring::RingState> = None;
            let apply_status = |status: &wire::CaptureFileStatusJson,
                                 writer_active: &AtomicBool,
                                 writer_path: &Mutex<Option<String>>,
                                 writer_bytes_written: &AtomicU64,
                                 writer_ring_file: &Mutex<Option<u32>>,
                                 writer_autostop_reason: &Mutex<Option<String>>| {
                writer_active.store(status.writing, Ordering::Relaxed);
                *writer_path.lock().unwrap() = status.path.clone();
                writer_bytes_written.store(status.bytes_written, Ordering::Relaxed);
                *writer_ring_file.lock().unwrap() = status.ring_file;
                *writer_autostop_reason.lock().unwrap() = status.autostop_reason.clone();
            };
            while let Ok(cmd) = writer_rx.recv() {
                match cmd {
                    WriterCommand::Start { path, ring: ring_config, autostop, idb, hostname, agent_version } => {
                        match ring::start(&mut current, &path, ring_config, autostop, &idb, &hostname, &agent_version, ring::real_free_space_bytes) {
                            Ok(()) => {
                                *writer_autostop_reason.lock().unwrap() = None;
                                *writer_ring_file.lock().unwrap() = None;
                                *writer_path.lock().unwrap() = Some(path.display().to_string());
                                writer_bytes_written.store(0, Ordering::Relaxed);
                                writer_active.store(true, Ordering::Relaxed);
                            }
                            Err(message) => {
                                let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileError { message }));
                            }
                        }
                    }
                    WriterCommand::Stop => {
                        writer_active.store(false, Ordering::Relaxed);
                        *writer_autostop_reason.lock().unwrap() = None; // operator-requested, not an *auto*-stop
                        ring::stop(&mut current);
                    }
                    WriterCommand::Packet { timestamp, direction, data } => {
                        if let Some(ring_state) = current.as_mut() {
                            // I/O errors here surface via the next tick's
                            // capture_file_status simply reporting a stalled
                            // bytesWritten, not panicked on — matching this
                            // writer thread's own "never take the process
                            // down over a disk problem" posture.
                            if ring_state.write_packet(timestamp, direction, &data).is_ok() {
                                writer_bytes_written.store(ring_state.bytes_written(), Ordering::Relaxed);
                            }
                        }
                    }
                    WriterCommand::Stats { received, dropped } => {
                        if let Some(status) = ring::on_tick(&mut current, received as u64, dropped as u64, ring::real_free_space_bytes) {
                            apply_status(&status, &writer_active, &writer_path, &writer_bytes_written, &writer_ring_file, &writer_autostop_reason);
                        }
                    }
                }
            }
        });
    }

    // Background: refresh the process-attribution map every 3s. Live mode
    // only — in replay mode `process_map` stays permanently empty (see
    // where it's constructed above), so refreshing it would just be wasted
    // work re-populating a map nothing ever reads.
    if mode == "live" {
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
        let capture_config_state = capture_config_state.clone();
        let device_for_reopen = device_for_reopen.clone();
        let current_interface = current_interface.clone();
        let current_link_type = current_link_type.clone();
        let writer_tx = writer_tx.clone();
        let writer_active = writer_active.clone();
        let writer_backpressure_drops = writer_backpressure_drops.clone();
        std::thread::spawn(move || {
            let mut packet_source = packet_source;
            // Mutable locals, not Arc<Mutex<_>>: only this thread ever
            // reads or writes them, and this is the hot per-packet path —
            // `local_addrs` in particular is checked on every captured
            // packet (see the direction checks below), so a lock here
            // would mean contending for it thousands of times a second.
            // They only change on a successful `set_interface` (issue
            // #69, Live mode only), applied in the drain loop below, on
            // this same thread.
            let mut local_addrs = local_addrs;
            let mut link_type = link_type;
            let mut device_for_reopen = device_for_reopen;
            // Caps discrete Packet events to the browser at 100/sec — the UI
            // only keeps the last 100 anyway (app/page.tsx's
            // `prev.slice(0, 100)`), so anything above that is pure waste.
            // Connection/layer aggregates below are unaffected: `observe()`
            // runs on every packet regardless of this limiter.
            let mut packet_event_limiter = PacketEventLimiter::new(100, 1000);
            // The live pcap handle (when `packet_source` is `Live`) only
            // ever lives on this thread, so polling pcap_stats() has to
            // happen here rather than from the periodic emitter task — see
            // build_capture_stats_json's doc comment for why this is split
            // into a separate pure function. Meaningless for a replay, so
            // simply never polled in that mode — `capture_stats` stays
            // `None` for the life of a replay process, reporting absent
            // rather than a fabricated value.
            let mut last_stats_poll = Instant::now();
            // Realtime replay pacing (spec Components §2) — both are no-ops
            // in Live mode: `replay_speed()` is only ever read when
            // `mode == "replay"`, below.
            let replay_speed = replay_speed();
            let mut previous_frame_timestamp: Option<std::time::SystemTime> = None;
            loop {
                // Non-blocking: applies at most whatever has queued up since
                // the last iteration. `next_frame()`'s 1s live-mode timeout
                // below (and every real packet arrival) guarantees this runs
                // frequently, so a `filter`/`snaplen` command bar action
                // takes effect within about a second, not indefinitely
                // delayed behind a quiet capture (issue #68).
                while let Ok(request) = capture_config_rx.try_recv() {
                    match (&mut packet_source, device_for_reopen.as_mut()) {
                        (PacketSource::Live(cap), Some(device_for_reopen)) => match request {
                            CaptureConfigRequest::SwitchInterface(name) => {
                                apply_interface_switch_request(
                                    &name,
                                    cap,
                                    device_for_reopen,
                                    &mut link_type,
                                    &mut local_addrs,
                                    &current_interface,
                                    &current_link_type,
                                    &capture_config_state,
                                    &flow_table,
                                    &tx,
                                );
                            }
                            other => {
                                apply_capture_config_request(other, cap, device_for_reopen, &capture_config_state, &tx);
                            }
                        },
                        // Replay mode: these control messages have no live
                        // device to act on (spec Components §2 — "existing
                        // runtime-reconfiguration code path completely
                        // unaware replay mode exists at all"). Reported,
                        // not silently dropped, matching this codebase's
                        // existing posture for every other rejected request.
                        _ => {
                            let event = match request {
                                CaptureConfigRequest::SwitchInterface(_) => wire::AgentEvent::InterfaceError {
                                    message: "interface switching is not available during file replay".to_string(),
                                },
                                _ => wire::AgentEvent::CaptureConfigError {
                                    message: "capture filter/snap length changes are not available during file replay".to_string(),
                                },
                            };
                            let _ = tx.send(wire::encode_event(&event));
                        }
                    }
                }
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                if let PacketSource::Live(cap) = &mut packet_source {
                    if last_stats_poll.elapsed() >= Duration::from_secs(1) {
                        last_stats_poll = Instant::now();
                        match cap.stats() {
                            Ok(stat) => {
                                *capture_stats.lock().unwrap() = Some(stat);
                                if writer_active.load(Ordering::Relaxed) {
                                    let _ = writer_tx.try_send(WriterCommand::Stats { received: stat.received, dropped: stat.dropped });
                                }
                            }
                            Err(e) => eprintln!("capture-agent: failed to read capture stats: {e}"),
                        }
                    }
                }
                match packet_source.next_frame() {
                    SourceFrame::Bytes { data, timestamp } => {
                        if mode == "replay" {
                            if let (ReplaySpeed::Realtime, Some(prev_ts)) = (replay_speed, previous_frame_timestamp) {
                                if let Ok(delta) = timestamp.duration_since(prev_ts) {
                                    std::thread::sleep(delta.min(Duration::from_secs(5)));
                                }
                            }
                            previous_frame_timestamp = Some(timestamp);
                        }
                        let Some(parsed) = parse::parse_packet(&data, link_type) else {
                            unparseable_frames.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let l7_info = l7::sniff_l7(&parsed.payload, parsed.dst_port);
                        let now_ms = start.elapsed().as_millis() as u64;
                        let is_outbound = flow_table.lock().unwrap().observe(&parsed, &l7_info, now_ms);

                        // Aggregate throughput counters (issue #64) — driven
                        // by the same direction FlowTable::observe just
                        // attributed this packet, rather than a separate
                        // src/dst-vs-local_addrs check of our own that could
                        // drift out of sync with it. A packet matching no
                        // tracked flow (e.g. broadcast/multicast traffic
                        // captured in promiscuous mode) counts toward
                        // neither total, same as before.
                        let len = parsed.total_len as u64;
                        let direction = match is_outbound {
                            Some(true) => {
                                total_tx_bytes.fetch_add(len, Ordering::Relaxed);
                                total_tx_packets.fetch_add(1, Ordering::Relaxed);
                                pcapng::Direction::Outbound
                            }
                            Some(false) => {
                                total_rx_bytes.fetch_add(len, Ordering::Relaxed);
                                total_rx_packets.fetch_add(1, Ordering::Relaxed);
                                pcapng::Direction::Inbound
                            }
                            None => pcapng::Direction::Unknown,
                        };

                        // Capture-to-file (epic #55, JAM-132/GitHub #70):
                        // never on by default, and a cheap atomic check when
                        // it's off (the overwhelming majority of the time) —
                        // only touches the writer's channel when a capture is
                        // actually active. A full queue means the writer
                        // thread can't keep up (e.g. a slow disk); counted,
                        // never silently dropped, and never blocks this hot
                        // path (`try_send`, not `send`). `data` is moved
                        // (not cloned) here — nothing downstream needs the
                        // raw frame bytes again after this point.
                        if writer_active.load(Ordering::Relaxed) {
                            let cmd = WriterCommand::Packet { timestamp, direction, data };
                            if writer_tx.try_send(cmd).is_err() {
                                writer_backpressure_drops.fetch_add(1, Ordering::Relaxed);
                            }
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
                    SourceFrame::Timeout => continue,
                    SourceFrame::Eof => {
                        // Replay fully consumed, or a live device errored
                        // out for good (spec Components §2: both mean "no
                        // more frames coming"). Ends this thread cleanly —
                        // the rest of the agent (relay, control channel,
                        // periodic emitter) keeps running on whatever state
                        // it already has.
                        println!(
                            "capture-agent: {} finished — no more frames",
                            if mode == "replay" { "replay" } else { "capture" }
                        );
                        break;
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
        let current_interface = current_interface.clone();
        let capture_config_state = capture_config_state.clone();
        let writer_active = writer_active.clone();
        let writer_bytes_written = writer_bytes_written.clone();
        let writer_path = writer_path.clone();
        let writer_ring_file = writer_ring_file.clone();
        let writer_autostop_reason = writer_autostop_reason.clone();
        let writer_backpressure_drops = writer_backpressure_drops.clone();
        let paused = paused.clone();
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
                let (evicted, snapshots, total_flows_observed, capacity_evictions, idle_evictions) = {
                    let mut ft = flow_table.lock().unwrap();
                    let evicted = ft.evict_stale(now_ms);
                    let snapshots = ft.snapshot(now_ms);
                    (evicted, snapshots, ft.total_flows_observed(), ft.capacity_evictions(), ft.idle_evictions())
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

                for key in evicted.iter() {
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
                let stats_json = build_capture_stats_json(
                    stat,
                    lagged,
                    unparseable,
                    total_flows_observed,
                    capacity_evictions,
                    idle_evictions,
                );
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
                let (current_name, current_ip) = current_interface.lock().unwrap().clone();
                let system_stats_json = build_system_stats_json(
                    &hostname,
                    &current_name,
                    &current_ip,
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

                // Active capture filter/snap length (issue #68) — sent every
                // tick, same as capture_stats/system_stats above, so a
                // client that only just (re)connected sees the current
                // values immediately rather than only a client that was
                // connected at the moment a filter/snaplen change happened.
                let config_snapshot = capture_config_state.lock().unwrap().clone();
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfig { config: config_snapshot }));

                // Capture-to-file status (epic #55, JAM-132/GitHub #70) —
                // same "sent every tick, always current" pattern as
                // capture_stats/capture_config above, so a client that just
                // (re)connected sees the current state immediately.
                let capture_file_status = wire::CaptureFileStatusJson {
                    writing: writer_active.load(Ordering::Relaxed),
                    path: writer_path.lock().unwrap().clone(),
                    bytes_written: writer_bytes_written.load(Ordering::Relaxed),
                    ring_file: *writer_ring_file.lock().unwrap(),
                    ring_total: None,
                    autostop_reason: writer_autostop_reason.lock().unwrap().clone(),
                    backpressure_drops: writer_backpressure_drops.load(Ordering::Relaxed),
                };
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileStatus { status: capture_file_status }));

                // Agent mode/direction-attribution status (issue #73/
                // JAM-133) — same "sent every tick, always current" pattern
                // as capture_stats/capture_config/capture_file_status
                // above. `interface` reuses `current_name` (just computed
                // for system_stats) rather than the frozen startup value,
                // so a runtime interface switch (issue #69) is reflected
                // here too, not only in system_stats.
                let agent_status = wire::AgentStatusJson {
                    interface: current_name.clone(),
                    capturing: !paused.load(Ordering::Relaxed),
                    mode: mode.to_string(),
                    replay_source: replay_source.clone(),
                    direction_attribution_unavailable,
                };
                let _ = tx.send(wire::encode_event(&wire::AgentEvent::AgentStatus { status: agent_status }));
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
        let capture_config_tx = capture_config_tx.clone();
        let writer_tx = writer_tx.clone();
        let writer_active = writer_active.clone();
        let capture_config_state = capture_config_state.clone();
        let current_interface = current_interface.clone();
        let current_link_type = current_link_type.clone();
        let hostname = hostname.clone();
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
                                    Some(wire::ControlMessage::SetCaptureFilter { filter }) => {
                                        // Actually applying this needs the
                                        // live `pcap::Capture` handle, which
                                        // only ever lives on the capture
                                        // thread — queue it there rather
                                        // than touch `cap` from this async
                                        // task (see CaptureConfigRequest).
                                        let _ = capture_config_tx.send(CaptureConfigRequest::SetFilter(filter));
                                    }
                                    Some(wire::ControlMessage::SetSnaplen { bytes }) => {
                                        let _ = capture_config_tx.send(CaptureConfigRequest::SetSnaplen(bytes));
                                    }
                                    Some(wire::ControlMessage::ListInterfaces) => {
                                        // Doesn't touch the open capture
                                        // handle at all — just enumerates
                                        // devices, so this runs directly
                                        // here rather than round-tripping
                                        // through the capture thread.
                                        let interfaces = pcap::Device::list()
                                            .map(|devices| {
                                                devices
                                                    .iter()
                                                    .filter(|d| is_capturable(d))
                                                    .map(|d| wire::InterfaceJson {
                                                        name: d.name.clone(),
                                                        addresses: local_addrs_for(d),
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        let _ = trace_tx.send(wire::encode_event(&wire::AgentEvent::InterfaceList { interfaces }));
                                    }
                                    Some(wire::ControlMessage::SetInterface { name }) => {
                                        // Reopening the capture handle and
                                        // reassigning FlowTable's local_addrs
                                        // (issue #69) both need to happen on
                                        // the capture thread, same reason as
                                        // SetCaptureFilter/SetSnaplen above.
                                        let _ = capture_config_tx.send(CaptureConfigRequest::SwitchInterface(name));
                                    }
                                    Some(wire::ControlMessage::StartCaptureFile { path, ring, autostop }) => {
                                        let config_error = ring
                                            .as_ref()
                                            .and_then(|r| validate_ring_config(r).err())
                                            .or_else(|| autostop.as_ref().and_then(|a| validate_autostop_config(a).err()));
                                        if let Some(message) = config_error {
                                            let _ = trace_tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileError { message }));
                                        } else if writer_active.load(Ordering::Relaxed) {
                                            let _ = trace_tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileError {
                                                message: "a capture file is already active — stop it first".to_string(),
                                            }));
                                        } else {
                                            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                                            match validate_capture_file_path(&path, &cwd) {
                                                Ok(resolved) => {
                                                    let idb = pcapng::InterfaceDescriptionBlock {
                                                        interface_name: current_interface.lock().unwrap().0.clone(),
                                                        link_type: *current_link_type.lock().unwrap(),
                                                        snaplen: capture_config_state.lock().unwrap().snaplen,
                                                        timestamp_resolution_exponent: 9,
                                                    };
                                                    let _ = writer_tx.send(WriterCommand::Start {
                                                        path: resolved,
                                                        ring,
                                                        autostop,
                                                        idb,
                                                        hostname: hostname.clone(),
                                                        agent_version: env!("CARGO_PKG_VERSION").to_string(),
                                                    });
                                                }
                                                Err(message) => {
                                                    let _ = trace_tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileError { message }));
                                                }
                                            }
                                        }
                                    }
                                    Some(wire::ControlMessage::StopCaptureFile) => {
                                        // Idempotent, matching pause/resume's
                                        // existing tolerance for a redundant
                                        // call — the writer thread's Stop
                                        // handler already no-ops when there's
                                        // no writer open.
                                        let _ = writer_tx.send(WriterCommand::Stop);
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
        build_capture_stats_json, build_system_stats_json, datalink_to_link_type, find_device_by_name,
        is_capturable, is_meaningful_override, looks_like_pcapng, parse_replay_local_addrs, parse_replay_speed,
        resolve_link_type, validate_capture_file_path, validate_capture_filter_len, validate_interface_name_len,
        validate_snaplen, ReplaySpeed, MAX_CAPTURE_FILTER_LEN, MAX_INTERFACE_NAME_LEN,
    };
    use capture_agent::parse::LinkType;
    use std::path::Path;
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
    fn datalink_to_link_type_maps_the_three_supported_datalinks() {
        assert_eq!(datalink_to_link_type(pcap::Linktype::ETHERNET), Some(LinkType::Ethernet));
        assert_eq!(datalink_to_link_type(pcap::Linktype::NULL), Some(LinkType::NullLoopback));
        assert_eq!(datalink_to_link_type(pcap::Linktype::LOOP), Some(LinkType::NullLoopback));
        assert_eq!(datalink_to_link_type(pcap::Linktype::RAW), Some(LinkType::Raw));
    }

    #[test]
    fn datalink_to_link_type_returns_none_rather_than_panicking_for_an_unsupported_datalink() {
        // Unlike resolve_link_type (startup, fails loudly), this is called
        // from the runtime interface-switch path (issue #69) where a user
        // picking an interface with an unsupported link type must get a
        // rejected request, not a crashed agent.
        assert_eq!(datalink_to_link_type(pcap::Linktype(113)), None); // DLT_LINUX_SLL
    }

    #[test]
    fn validate_capture_filter_len_accepts_a_normal_expression() {
        assert!(validate_capture_filter_len("tcp port 443").is_ok());
        assert!(validate_capture_filter_len("").is_ok(), "empty (clear) must always be accepted");
    }

    #[test]
    fn validate_capture_filter_len_rejects_an_oversized_expression() {
        let oversized = "a".repeat(MAX_CAPTURE_FILTER_LEN + 1);
        let err = validate_capture_filter_len(&oversized).expect_err("should reject");
        assert!(err.contains(&(MAX_CAPTURE_FILTER_LEN + 1).to_string()));
    }

    #[test]
    fn validate_capture_filter_len_accepts_exactly_at_the_limit() {
        let exact = "a".repeat(MAX_CAPTURE_FILTER_LEN);
        assert!(validate_capture_filter_len(&exact).is_ok());
    }

    #[test]
    fn validate_interface_name_len_accepts_a_normal_name() {
        assert!(validate_interface_name_len("en0").is_ok());
    }

    #[test]
    fn validate_interface_name_len_rejects_an_oversized_name() {
        let oversized = "a".repeat(MAX_INTERFACE_NAME_LEN + 1);
        assert!(validate_interface_name_len(&oversized).is_err());
    }

    #[test]
    fn validate_interface_name_len_accepts_exactly_at_the_limit() {
        let exact = "a".repeat(MAX_INTERFACE_NAME_LEN);
        assert!(validate_interface_name_len(&exact).is_ok());
    }

    #[test]
    fn validate_snaplen_accepts_a_normal_value() {
        assert_eq!(validate_snaplen(96), Ok(96));
        assert_eq!(validate_snaplen(65535), Ok(65535));
    }

    #[test]
    fn validate_snaplen_rejects_zero() {
        assert!(validate_snaplen(0).is_err());
    }

    #[test]
    fn validate_snaplen_rejects_a_value_too_large_for_i32() {
        // pcap's snaplen() builder takes an i32 — a u32 past i32::MAX must
        // be rejected outright, not silently truncated or wrapped negative.
        assert!(validate_snaplen(u32::MAX).is_err());
    }

    #[test]
    fn is_meaningful_override_rejects_empty_and_whitespace_only_values() {
        assert!(!is_meaningful_override(""));
        assert!(!is_meaningful_override("   "));
        assert!(is_meaningful_override("en0"));
        assert!(is_meaningful_override("  en0  "));
    }

    #[test]
    fn parse_replay_local_addrs_splits_on_commas_and_trims_whitespace() {
        let addrs = parse_replay_local_addrs(Some("192.168.1.10, 10.0.0.5,"));
        assert_eq!(addrs, vec!["192.168.1.10".to_string(), "10.0.0.5".to_string()]);
    }

    #[test]
    fn parse_replay_local_addrs_is_empty_when_absent() {
        assert!(parse_replay_local_addrs(None).is_empty());
    }

    #[test]
    fn parse_replay_local_addrs_is_empty_for_an_empty_string() {
        assert!(parse_replay_local_addrs(Some("")).is_empty());
    }

    #[test]
    fn looks_like_pcapng_recognizes_a_real_pcapng_files_magic_bytes() {
        let path = std::env::temp_dir().join(format!("looks-like-pcapng-test-real-{}.pcapng", std::process::id()));
        // The literal bytes a real Section Header Block starts with,
        // regardless of the rest of the file — this test only needs the
        // magic, not a fully valid file.
        std::fs::write(&path, [0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0]).unwrap();
        assert!(looks_like_pcapng(path.to_str().unwrap()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn looks_like_pcapng_rejects_classic_pcap_magic() {
        let path = std::env::temp_dir().join(format!("looks-like-pcapng-test-classic-{}.pcap", std::process::id()));
        std::fs::write(&path, [0xD4, 0xC3, 0xB2, 0xA1, 0, 0, 0, 0]).unwrap();
        assert!(!looks_like_pcapng(path.to_str().unwrap()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn looks_like_pcapng_is_false_for_a_nonexistent_path() {
        assert!(!looks_like_pcapng("/nonexistent/path/that/does/not/exist.pcapng"));
    }

    #[test]
    fn looks_like_pcapng_is_false_for_a_file_shorter_than_the_magic() {
        let path = std::env::temp_dir().join(format!("looks-like-pcapng-test-short-{}.bin", std::process::id()));
        std::fs::write(&path, [0x0A, 0x0D]).unwrap();
        assert!(!looks_like_pcapng(path.to_str().unwrap()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_replay_speed_recognizes_realtime_and_defaults_to_fast() {
        assert_eq!(parse_replay_speed(Some("realtime")), ReplaySpeed::Realtime);
        assert_eq!(parse_replay_speed(Some("fast")), ReplaySpeed::Fast);
        assert_eq!(parse_replay_speed(Some("bogus")), ReplaySpeed::Fast);
        assert_eq!(parse_replay_speed(None), ReplaySpeed::Fast);
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
        let json = build_capture_stats_json(Some(stat), 15, 4, 42, 3, 1);
        assert_eq!(json.received, 500);
        assert_eq!(json.dropped, 7);
        assert_eq!(json.if_dropped, 2);
        assert_eq!(json.relay_lagged_events, 15);
        assert_eq!(json.unparseable_frames, 4);
        assert_eq!(json.total_connections_observed, 42);
        assert_eq!(json.capacity_evictions, 3);
        assert_eq!(json.idle_evictions, 1);
    }

    #[test]
    fn build_capture_stats_json_reports_zero_capture_counts_before_first_poll() {
        // The capture thread hasn't successfully called cap.stats() yet
        // (e.g. right at agent startup) — this must report honest zeros,
        // not panic and not fabricate a nonzero drop count.
        let json = build_capture_stats_json(None, 0, 0, 0, 0, 0);
        assert_eq!(json.received, 0);
        assert_eq!(json.dropped, 0);
        assert_eq!(json.if_dropped, 0);
        assert_eq!(json.relay_lagged_events, 0);
        assert_eq!(json.unparseable_frames, 0);
        assert_eq!(json.total_connections_observed, 0);
        assert_eq!(json.capacity_evictions, 0);
        assert_eq!(json.idle_evictions, 0);
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
        let json = build_capture_stats_json(Some(stat), 0, 9, 0, 0, 0);
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

    #[test]
    fn validate_capture_file_path_rejects_an_empty_path() {
        assert!(validate_capture_file_path("", Path::new("/home/user/network_monitor/capture-agent")).is_err());
    }

    #[test]
    fn validate_capture_file_path_rejects_a_relative_path_resolving_inside_cwd() {
        let cwd = Path::new("/home/user/network_monitor/capture-agent");
        let err = validate_capture_file_path("captures/run1.pcapng", cwd).unwrap_err();
        assert!(err.contains("working directory"), "got: {err}");
    }

    #[test]
    fn validate_capture_file_path_rejects_an_absolute_path_inside_cwd() {
        let cwd = Path::new("/home/user/network_monitor/capture-agent");
        assert!(validate_capture_file_path("/home/user/network_monitor/capture-agent/run1.pcapng", cwd).is_err());
    }

    #[test]
    fn validate_capture_file_path_rejects_any_dot_data_component() {
        let cwd = Path::new("/home/user/network_monitor/capture-agent");
        let err = validate_capture_file_path("/home/user/network_monitor/.data/run1.pcapng", cwd).unwrap_err();
        assert!(err.contains(".data/"), "got: {err}");
    }

    #[test]
    fn validate_capture_file_path_accepts_an_absolute_path_outside_cwd() {
        let cwd = Path::new("/home/user/network_monitor/capture-agent");
        let resolved = validate_capture_file_path("/Users/me/captures/run1.pcapng", cwd).unwrap();
        assert_eq!(resolved, Path::new("/Users/me/captures/run1.pcapng"));
    }

    #[test]
    fn validate_capture_file_path_rejects_a_dot_dot_relative_path_even_when_semantically_outside_cwd() {
        // This resolves to cwd.join("../captures/run1.pcapng") — lexically
        // (not semantically) still prefixed by cwd's own components, since
        // this function never canonicalizes (the target file doesn't exist
        // yet, so canonicalize can't work anyway). Erring toward rejecting a
        // path this function can't be sure about is the safe default for a
        // security boundary, matching every other validator in this file
        // (e.g. an oversized filter is rejected outright, never "probably
        // fine").
        let cwd = Path::new("/home/user/network_monitor/capture-agent");
        assert!(validate_capture_file_path("../captures/run1.pcapng", cwd).is_err());
    }
}
