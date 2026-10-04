# Stream Reassembly: IP Fragments and TCP Segments — Design Spec

**Issue:** JAM-16 — "Stream reassembly: IP fragments and TCP segments"
**Epic:** JAM-127
**Depends on:** #68 / `snaplen <bytes>` runtime snap-length control — already shipped (`main.rs`'s `SetSnaplen`/`validate_snaplen`/`DEFAULT_SNAPLEN`).

Written because three decisions here are judgment calls that should be reviewable before the code, not archaeology afterwards: the **overlap policy**, the **cap sizes**, and the **shape of the desegmentation hand-off**. Its sibling tasks (JAM-13/14/15) implemented straight from their Linear issue; this one is the epic's highest-risk item, so the decisions get written down.

## Problem

There is no reassembly. `parse::parse_packet` returns one `ParsedPacket` per frame and `l7::sniff_l7` runs on that one frame's payload in isolation (`main.rs`'s capture loop). Consequences:

- **IP fragments never rejoin.** etherparse refuses to decode a transport layer for any fragmented IPv4 payload, so every fragment lands in `TransportProtocol::Other` with no ports and an empty `payload` (see `parse.rs`'s existing `parses_a_non_first_ipv4_fragment_without_panicking_or_misattributing_l4_fields`). That behavior is correct *per frame* and must not regress — a fragment stays `Other` until something reassembles it.
- **TCP segments never rejoin.** An HTTP request line or a TLS ClientHello spanning two segments simply fails to decode, silently. The flow reads as "traffic with no L7", which is worse than an honest "incomplete" — it looks like a gap in the tool, not a gap in the capture.

`http2.rs`'s `Http2Reassembler` already desegments, but only inside the opt-in decrypted-TLS path. It is untouched by this work.

## The honest constraint: truncation vs. loss

`snaplen <bytes>` lets an operator narrow the capture snap length at runtime. Once frames are truncated at capture, reassembly is *structurally impossible* for the cut-off bytes — and from `payload.len()` alone that is indistinguishable from a frame that was never captured at all. Presenting a partial buffer as complete would be confidently wrong output, which this project treats as worse than no output.

So every reassembled buffer carries one of exactly three statuses, and the wording lives in one place (`ReassemblyStatus::label()`):

| Status | Meaning | How it is known |
|---|---|---|
| `reassembled` | Every byte the sender sent, for the extent covered, is present and contiguous. | Full fragment coverage 0..total, or a hole-free TCP prefix with no short segment. |
| `incomplete — frames truncated at capture` | The sender clearly sent more than was captured. | The IP header's own declared length (IPv4 `total_length`, IPv6 `payload_length`) exceeds the bytes actually captured. A real header field, not an estimate. |
| `incomplete — frames missing` | A hole in the fragment/sequence space with data on both sides. | Coverage gap not attributable to any short-captured frame. |

Precedence when both apply: **truncated-at-capture wins**, because it is a definite fact about this capture's configuration and the operator can act on it (raise the snap length); "frames missing" is the residual explanation.

**Reassembled output is always the contiguous prefix from offset 0, never spliced across a hole.** A consumer therefore cannot be handed bytes that look adjacent but aren't. Every L7 detector in `l7.rs` parses from the start of its buffer, so a prefix is exactly the useful shape.

### Requires two new `ParsedPacket` fields

Neither fact is derivable from the captured bytes `parse_packet` already keeps:

- `ip_declared_payload_len: u32` — IPv4 `total_length` minus header length, or IPv6 `payload_length` minus extension-header length. Saturating arithmetic throughout; a malformed header yields 0, never an underflow.
- `ip_fragment: Option<Ipv4Fragment>` — populated only for an IPv4 frame with `more_fragments` set or a nonzero fragment offset, carrying the identification, offset, MF bit, protocol number, the fragment's own IPv4 header bytes, and its payload bytes. `payload` on `ParsedPacket` stays empty for a fragment (unchanged existing behavior); the fragment's bytes live in this struct instead, so nothing about non-reassembled per-frame output moves.

Both are internal. **No wire field, no `lib/types.ts` change, no `docs/wire-protocol.md` change.** Reassembly correctness does not need a UI surface to be correct, and adding a status field to the wire is a separately-reviewable follow-up (see Deferred).

## IP fragment reassembly

Keyed on `(src, dst, identification, protocol)` — RFC 791's own reassembly key.

A group holds a byte-coverage map plus the first fragment's IPv4 header bytes. On completion the header is rewritten via etherparse (`total_len` set to the reassembled length, `more_fragments`/`fragment_offset` cleared, checksum recomputed) and prepended, so the result is a *real IPv4 datagram* that goes straight back through `parse_packet(_, LinkType::Raw)`. That reuses all existing transport decoding rather than duplicating it, and means ports/`payload`/`L7Info` for a reassembled datagram come from the same code path as an unfragmented one.

A group is emitted as soon as it is fully covered. A group that can provably make no further progress (a hole created by a short-captured fragment) is emitted immediately with `incomplete — frames truncated at capture` rather than held to timeout — no future fragment can fill bytes that were never captured. Everything else is emitted at timeout with `incomplete — frames missing`.

IPv4 with an authentication extension header is deliberately **not** reassembled (its extension bytes sit between the header slice and the fragment payload, and fragmented-plus-AH is vanishingly rare) — an explicit skip, not an unnoticed gap. IPv6 fragment extension headers are out of scope per the issue (IPv4 fragments and TCP segments only).

## TCP segment reassembly

Keyed on `(FlowKey, from_local)` — the *existing* per-flow identity from `flow.rs`, via a newly-public `FlowTable::key_for`, so reassembly and the flow table can never disagree about which flow a packet belongs to or which direction it travelled. `from_local` splits the two independent byte streams.

Sequence numbers are handled as 32-bit-signed deltas from the lowest sequence number seen (`(seq.wrapping_sub(base)) as i32`), the same wraparound-safe technique `flow.rs`'s retransmit detection already uses. A segment arriving *before* the current base rebases the buffer downward (bounded by the per-stream cap), which is what makes genuine out-of-order arrival work rather than being discarded.

### Overlap policy: first-seen bytes win

When a segment overlaps bytes already buffered, **the bytes already present are kept and the overlapping copy is discarded.** Chosen because:

1. It is deterministic and cheap — a single coverage check per byte range, no rewrite path.
2. A later segment cannot retroactively change content the monitor has already reported. The classic overlapping-segment evasion (Ptacek–Newsham) works by making a passive observer and the real endpoint disagree about which copy wins; last-seen-wins lets an attacker show the monitor benign bytes and overwrite them afterwards. First-seen-wins makes the monitor's view immutable once written.
3. Retransmissions — the overwhelmingly common real cause of overlap — are exactly bytes already held, so they become free no-ops.

Documented limitation, stated rather than hidden: a receiving host whose own TCP stack prefers later data would assemble something different. A passive monitor cannot know the receiver's policy without host knowledge, so *some* fixed choice is unavoidable; this one is the conservative direction. Overlaps whose bytes actually differ from what is held are counted (`conflicting_overlap_bytes`) so the condition is observable rather than invisible.

### Desegmentation hand-off

`sniff_l7(payload, dst_port) -> L7Info` keeps its exact current signature and behavior for every existing caller and test. Alongside it:

```rust
pub enum L7Sniff {
    Decided(L7Info),
    /// A lower bound only, never a guess dressed up as a measurement:
    /// derived from a real declared length where the protocol has one
    /// (a TLS record's own length field) and `1` where it does not
    /// (an HTTP start line with no line terminator yet).
    NeedMoreBytes { at_least: usize },
    Undecided,
}
pub fn sniff_l7_desegmenting(payload: &[u8], dst_port: Option<u16>) -> L7Sniff;
```

`sniff_l7` is then `sniff_l7_desegmenting(..)` collapsed to `L7Info::None` for the two non-`Decided` arms — byte-identical behavior, one implementation. The detectors themselves (`sniff_http`, `sniff_http_response`, `sniff_dns`, `sniff_tls_client_hello`) are **not modified**; incompleteness is a separate structural probe consulted only after all of them decline. Reassembly feeds those same detectors more complete buffers; it does not rewrite them.

The capture loop's integration: sniff this frame's own payload first (the common case — a single-segment request or ClientHello — costs nothing new and buffers nothing). Buffer and re-sniff the stream prefix only while a direction has not yet decided. On `Decided`, the direction's buffer is released immediately, which is also what bounds memory for long-lived streams: this is an L7-decision buffer, not a full stream store.

Not treating `Undecided` as terminal is deliberate: a stream whose first *captured* segment is mid-message is indistinguishable from one whose segments arrived out of order, and killing the buffer on `Undecided` would break genuine reordering. Memory is bounded by the caps below instead.

## Caps — all enforced, none aspirational

| Cap | Value | Why this value |
|---|---|---|
| Per fragment group | 65 535 B | The maximum length an IPv4 `total_length` can express. Cannot reject legitimate traffic by construction. |
| Concurrent fragment groups | 512 | Generous for real traffic (fragmentation is rare); the global byte cap binds first under attack. |
| Total fragment bytes | 4 MiB | The real binding constraint. Oldest groups evict until under. |
| Fragment group timeout | 15 s | RFC 791's recommended reassembly timeout. Linux uses 30 s; shorter is strictly better for a monitor that is not the datagram's destination. |
| Per TCP stream direction | 16 KiB | Covers a full HTTP header block (nginx/Apache default limits are 8 KiB) and a complete TLS record (16 KiB max, so any ClientHello including post-quantum key shares). Past this, no detector here is going to decide. |
| Concurrent TCP stream directions | 2 048 | Bounded well under the flow table's own `DEFAULT_MAX_FLOWS` (10 000); the global byte cap binds first. |
| Total TCP buffered bytes | 4 MiB | The real binding constraint. Oldest streams evict until under. |
| TCP stream idle timeout | 30 s | A direction that has not advanced in 30 s is not mid-message. |

Worst case across both reassemblers is therefore **8 MiB**, regardless of how many distinct keys hostile input invents, and `bytes_held()` on each reassembler is a real measured number (sum of held bytes), not a fabricated statistic. Nothing about it is put on the wire, so no invented-stat rule is in play.

Eviction is time-based *and* capacity-based, matching `FlowTable::evict_stale`'s existing pattern (retain-by-threshold, then drop oldest-first over capacity). It is driven from the capture loop rather than shared with `FlowTable::evict_stale` itself: that runs on the periodic emitter task, on the other side of the flow-table mutex from the reassembler, and plumbing evicted keys across that boundary to reuse one call site would be more coupling than the duplication it saves. Same mechanism, own call site.

Two later corrections (JAM-182):

- **Clock.** The timeouts describe the traffic, so they run on the traffic's own time. Live capture uses the agent's clock, which already is that time. Replay uses `ReplayClock` (`reassembly.rs`), which advances by each forward step between consecutive recorded timestamps and ignores backward steps. It never runs backwards, and unlike "time since the first frame, held at its maximum", it doesn't freeze after a large backward step or a corrupt first timestamp. On wall-clock time, a fast replay compressed minutes of capture into seconds, so nothing ever timed out. The flow table still runs on the agent clock during replay; that's tracked separately.
- **Expiry on arrival.** The periodic sweep runs at most once a second, and after the current frame is fed. Both reassemblers therefore also expire an entry in `feed` itself, when new data with the same key arrives, using the same criterion and accounting as the sweep. Without this, a fragment reusing an IP ID could join an expired group's bytes, and a new connection reusing an idle four-tuple would be judged against the old connection's buffer and lose its first L7 decision.

## Security posture

Every byte here is attacker-shaped and parsed in the process holding the capture handle.

- No new function panics on adversarial input: every length is `checked_`/`saturating_`, every index is bounds-tested, and the only allocations are bounded by the caps above *before* the allocation happens (never "reserve the declared length, then wait for it" — that is the failure mode `http2.rs`'s `MAX_FRAME_LEN` exists to prevent).
- Never-completing reassemblies are evicted by timeout and by capacity, so the tiny-fragment-flood / never-finish-it pattern costs an attacker memory that is already accounted for and bounded.
- A new `cargo-fuzz` target, `stream_reassembly`, drives both reassemblers with arbitrary bytes and **asserts the byte caps hold** rather than only checking for absence of panic — JAM-125's real out-of-memory bug was found by a fuzz target and missed by unit tests, so the invariant is asserted where the fuzzer can see it. Wired into the existing `fuzz` CI job (its steps are hand-listed per target, not globbed) and into that job's path filter.

## Deferred, explicitly

- **A wire-visible reassembly status.** A `reassembly-incomplete` finding code (`wire.rs`'s `FindingCode`) is the natural surface, and would let the UI say "this flow's L7 is incomplete because your snap length is 96 bytes". It needs the Rust + `lib/types.ts` + `docs/wire-protocol.md` + both-sides-test treatment this repo requires for any wire change, and no acceptance criterion here needs it. Left open, not dropped.
- **Follow Stream (JAM-17).** Deliberately not built. The per-direction cap here is sized for an L7 decision, not for holding a conversation; Follow Stream will want its own bounded store. Nothing in this design blocks that — the prefix and status are already the two things it needs.
- **UDP pseudo-streams, QUIC, IPv6 fragment extension headers.** Out of the issue's scope (TCP segments and IPv4 fragments only).
- **Stream-start detection from the SYN.** Knowing a direction's first data sequence number would let `Undecided` release a buffer immediately instead of waiting for the cap or the timeout. A pure memory optimization; the caps already make it unnecessary for correctness.
