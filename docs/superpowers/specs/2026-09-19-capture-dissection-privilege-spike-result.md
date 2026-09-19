# Capture/Dissection Privilege Separation — Spike Result

**Date:** 2026-09-19
**Environment tested:** Linux (this session's sandbox, `x86_64-unknown-linux-gnu`, rustc 1.94.1). Production `capture-agent` runs on macOS in practice (`access_bpf` group setup, `capture-agent/README.md`) — the measurement below is an isolated IPC micro-benchmark, not a full-agent run, so the platform difference doesn't invalidate the pipe-cost numbers (Unix pipes/pipes-as-stdio behave the same way on both), but see the seccomp discussion in §4 where the platform *does* matter.
**Outcome:** Do not do the full process split now. Fuzzing (#66, merged) plus keeping this repo's own hostile-input code unsafe-free is the better-value mitigation at today's parser surface. Epic #58 is unblocked to proceed on the current architecture, conditional on the per-parser requirements in the Recommendation section.

This spike answers issue #91's four questions in order.

## 1. What the split would look like

A minimal version of the baseline's `dumpcap`/`epan` split, adapted to this codebase:

- **Privileged child:** owns the `pcap::Capture` handle (`main.rs`'s current `cap.next_packet()` loop) and nothing else. It never touches `parse_packet`, `l7.rs`, `http2.rs`, `tls_decrypt.rs`, `ja3.rs`, or the flow table. It reads a frame, prepends a small header (timestamp, on-wire length, capture length, an interface-switch/config-ack channel for #68/#69's existing control messages), and writes it to a pipe. It also relays `pcap::Stat()` drop counts (#61) the same way.
- **Unprivileged parent:** everything else — `parse_packet` onward, the flow table, TLS decrypt, the ring buffer, the TCP listener that serves the Next.js relay, and all of today's control-message handling (`set_capture_filter`, `set_interface`, etc., which still need to reach the child, so the pipe would need to be bidirectional or paired with a second pipe for child-bound commands).
- **Key material and the ring buffer move to the parent**, not the child — they're needed by `tls_decrypt.rs`/`ring_buffer.rs`, which stay in the parent under this split. The child never sees a decryption key or a decrypted byte; it only ever sees the same ciphertext-on-the-wire bytes it captures today.
- **Process lifecycle:** the child is spawned once at startup (same as this spike's benchmark spawns its child), and a child crash/exit needs to be treated as a hard capture-stopped condition, surfaced via the existing `connection_status`-style wire event rather than silently hanging.

This is a real architectural change — a new framed wire protocol between the two processes, restructuring `main.rs`'s single capture thread into two binaries or two `fork()`ed images, and re-plumbing every control message that currently mutates `cap` directly (issue #68's filter/snaplen, #69's interface switch) to instead round-trip through the new IPC channel. Genuinely **L**-sized, matching the issue's own estimate.

## 2. Cost (measured, not guessed)

**Method:** `capture-agent/examples/ipc_split_spike.rs` (kept in the repo as a scratch benchmark, not part of the shipped agent — same convention as `examples/icmp_ping_spike.rs`). It spawns a real second OS process (not a thread — this measures actual process-boundary IPC, including scheduling, not an in-process shortcut) connected via the child's stdin/stdout pipes, and sends length-prefixed frames carrying an embedded send timestamp so the child can compute genuine one-way latency against its own wall clock. Run via:

```
cd capture-agent && cargo build --release --example ipc_split_spike
./target/release/examples/ipc_split_spike
```

Four scenarios, chosen to bracket realistic home-network rates: small (64B, minimum Ethernet frame) and large (1500B, MTU) frames, each unpaced (max achievable throughput) and paced at 50,000 pps (aggressive for a home network — see the framing below). Run three times to check consistency:

| Scenario | Achieved rate | Mean latency | p50 | p99 | Max (worst outlier seen) |
| --- | --- | --- | --- | --- | --- |
| 64B unpaced (max throughput) | 378k–429k pps (193–220 Mbps) | 4.2–11.2 µs | 2.7–3.0 µs | 15.7–401.7 µs | 1.0 ms |
| 64B @ 50,000 pps | 49,961–49,963 pps (accurate pacing) | 12.3–30.5 µs | 11.2–11.4 µs | 24.2–324.7 µs | 5.7 ms |
| 1500B unpaced (max throughput) | 307k–339k pps (3.7–4.1 Gbps) | 3.7–4.3 µs | 3.4–3.7 µs | 13.7–20.1 µs | 1.2 ms |
| 1500B @ 50,000 pps (600 Mbps) | 49,958–49,962 pps (accurate pacing) | 12.3–12.8 µs | 11.4–11.6 µs | 23.6–24.8 µs | 1.1 ms |

Full raw output from all three runs is reproducible via the command above; not pasted in full here since the table already reports the range.

**Reading these numbers against this product's actual scale:** the current architecture's baseline cost for this same hop is a Rust function call — effectively zero, not measurable at this resolution. The IPC hop would add roughly **3–13 µs at the median**, with occasional tail spikes into the hundreds of microseconds (rarely low milliseconds) under scheduler contention — consistent with any cross-process IPC on a general-purpose OS scheduler, not specific to this design. For context, this tool's own traceroute feature reports RTTs in whole milliseconds, and the UI's packet-event stream is already rate-limited to 100/sec for display (`PacketEventLimiter`) — an added few-microsecond hop is a rounding error against both.

**Throughput is not a binding constraint either.** Max measured throughput (307k–429k pps depending on frame size, 3.7+ Gbps for MTU-sized frames) is far beyond anything a home-network capture agent needs to sustain — a fully saturated home gigabit line pushes at most ~1.48 Mpps in the theoretical minimum-frame-size worst case, and real mixed traffic on a home network is nowhere near that. The `50,000 pps` paced scenarios above (600 Mbps at MTU size) already represent a rate well above typical home-network sustained load, and latency at that rate is stable and low (p50 ~11.5 µs across both frame sizes).

**Conclusion: the split is cheap.** If a future decision reverses this spike's recommendation, performance is not the reason it would need to — this is a complexity/engineering-cost decision, not a performance one, and can be revisited on that basis alone without re-measuring.

## 3. What it actually buys, given Rust — the honest assessment the issue asked for

Checked every module named in #91's problem statement for `unsafe`:

| Module | `unsafe` in this repo's own code |
| --- | --- |
| `src/parse.rs` | none |
| `src/l7.rs` | none |
| `src/http2.rs` | none |
| `src/tls_decrypt.rs` | none |
| `src/ja3.rs` | none |
| `src/ring_buffer.rs` | 4 blocks — all `libc::mlock`/`munlock` FFI calls on pointers this process's own `Vec<u8>` already owns, not attacker-controlled pointer arithmetic |

**Our own code on the hostile-input path is 100% safe Rust.** That much of the baseline's motivating threat (a hand-rolled C dissector's buffer overflow) genuinely doesn't apply here the way it did to the systems that document was written about.

**But that's not the whole picture — one honest complication:** `parse.rs`'s entry point calls directly into `etherparse::SlicedPacket` to parse the Ethernet/IP/TCP/UDP structure of every captured frame. `etherparse` itself contains 69 `unsafe` blocks internally, including raw-pointer unchecked reads (`get_unchecked_be_u16` and siblings in `helpers.rs`) used on its parsing hot path — the standard, common "bounds-check then unchecked-read" performance pattern, not evidence of a bug, but a real dependency on a third-party crate's own unsafe code getting its bounds checks right on attacker-controlled bytes. This is categorically smaller than a from-scratch C parser (a small, focused set of helper functions in one well-regarded, actively-used crate, versus thousands of hand-rolled dissectors with a long history of exactly this bug class) — but it is not literally zero. `fluke-hpack` (HTTP/2 HPACK, `http2.rs`) has zero `unsafe` but still had a real bug (the `.ok().unwrap()` panic issue #66's fuzzing found and this campaign's own #110 fixed) — a useful reminder that "no `unsafe`" rules out the memory-corruption class specifically, not bugs generally.

**The good news: this exact surface is already being fuzzed, continuously, as of #66/#110 (merged in this same campaign).** `capture-agent/fuzz/fuzz_targets/parse_packet.rs` calls `parse::parse_packet` directly — which means `etherparse`'s internal unsafe code is exercised by every CI-gated fuzz run, on every push to `main` and every PR touching `parse.rs`/`http2.rs`/`fuzz/**`. This is not a hypothetical future mitigation; it is live, and it already found one real bug in a dependency this exact pipeline calls.

**A second, more fundamental reframing: there is no elevated privilege at stake here in the first place.** The baseline's `dumpcap` split exists because `dumpcap` traditionally runs setuid-root or with elevated OS capabilities specifically to open a raw capture device, and must not let a compromised dissector inherit that. This agent never has elevated privilege at all — `capture-agent/README.md`'s `access_bpf` group grants ordinary-user read access to a specific device file, and `main.rs` has no setuid/capability-dropping logic anywhere because there is nothing to drop. A full compromise of today's single process gets an attacker: whatever this repo's own user account and BPF-group membership already legitimately have (which is "can read raw traffic on this Mac" — the thing the tool is already doing), plus — only when TLS visibility (epic #25) is actively opted into for a specific process via `osi-inspect` — that connection's decryption keys and the `mlock`'d decrypted-content ring buffer.

**That reframing is what actually determines the split's value.** It isn't "prevent system compromise" (there was no elevated privilege to escalate to); it's specifically "keep a hostile-input parser bug away from TLS key material and decrypted content, but only during the narrow, opt-in window where those exist in the process at all." Outside that window (the common case — TLS visibility not in use), there is no secret material in the process to protect, and the split would buy nothing beyond what fuzzing already covers.

## 4. Alternatives, priced alongside the split

- **CI fuzzing (#66/#111/#112, all merged in this campaign).** Directly exercises the one identified real risk (`etherparse`'s internal unsafe code, reached via `parse_packet`) on every push. Already done, already found a real bug. Cost: effectively zero marginal cost now — it's shipped.
- **`seccomp`/OS sandboxing in place of a full split.** Priced as asked, and the answer is platform-specific in a way that matters: `seccomp-bpf` is Linux-only. This agent's actual deployment target is macOS (the entire `access_bpf` setup, `deploy/`, and `macos-app/` subprojects are macOS-specific). macOS's nearest equivalents are either the deprecated `sandbox_init()` Seatbelt API, or Apple's App Sandbox — the latter requires packaging as a signed, entitled `.app` bundle, which `capture-agent` (a bare CLI binary invoked directly, per its own README) is not today and would need real restructuring to become. **This alternative is meaningfully weaker on this project's real target platform than it would be on Linux**, which cuts against "harden in place with a sandbox profile" as a low-cost substitute here specifically.
- **Dropping privileges after opening the handle.** Not applicable — see §3: there is no elevated privilege being held to drop.
- **Arena/resource limits on parsing.** Not separately implemented and not evaluated in depth here; lower priority than the two items above given the concrete finding that memory-corruption-class bugs are the specific risk category in question, not resource exhaustion.

## Recommendation

**Don't build the full process split now.** The measured cost is low (§2), but the benefit is narrow and mostly already captured by CI fuzzing (§3) — and the split's real remaining benefit (protecting TLS key material/decrypted content from a hostile-parser bug) only applies during TLS visibility's already-narrow opt-in window. Building a new IPC protocol, a second binary, and re-plumbing every existing control message (#68, #69) to cross it is genuine, real complexity for a benefit that's concentrated in one already-opt-in feature.

**Epic #58 is unblocked to proceed on the current single-process architecture**, conditional on:

1. **Every new parser epic #58 adds (#88 DNS, #89 QUIC, #90 DHCP/ARP, and stream reassembly) ships its own `cargo-fuzz` target in the same PR that introduces it** — not deferred, given #66 now actually enforces this in CI rather than the old honour-system gap. This is the concrete, load-bearing mitigation this spike is betting on; it needs to actually happen every time, not just for the first parser.
2. **No new `unsafe` block in this repo's own parsing code without explicit justification and review.** Today's count is zero on the hostile-input path; keep it that way. A parser that genuinely needs `unsafe` for performance is a signal to revisit this decision for that specific parser, not a reason to add it quietly.
3. **#89 (QUIC) gets special attention when it's speced**, since it's the one epic #58 item doing real cryptographic operations on fully untrusted bytes — the closest analog to the TLS-decrypt code this spike already flagged as the actual sensitive asset. If QUIC's design can't avoid `unsafe` or ships crypto operations that materially change the risk calculus, that's the trigger to revisit this decision for that one feature specifically (e.g. a narrowly-scoped sandboxed subprocess just for QUIC decryption, not a full-agent redesign) rather than defaulting back to "redo the whole split."

`docs/security.md` has been updated to record this decision and its rationale (new section, "Privilege separation: capture and dissection share one process").
