# JAM-21 DNS and HTTP Decode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish JAM-21: decode TXT answers, DNS over TCP, and the HTTP/1 reason phrase, `Content-Type` and `Content-Length`, and show host names learned from observed DNS in the endpoint view with no outbound lookup.

**Architecture:** The three decoders extend `capture-agent/src/l7.rs`. DNS over TCP reuses the existing `StreamReassembler` and adds no new buffer. Learned names live in a new bounded table owned by `FlowTable`, fed only by UDP responses that `TransactionTracker` matched to a query, and reach the UI as one optional field on `endpoint_update`.

**Tech Stack:** Rust (capture-agent, cargo-fuzz), TypeScript, React 19, Vitest.

**Spec:** Linear JAM-21 ("Remaining scope" and "Acceptance criteria"), plus `docs/superpowers/specs/2026-10-04-service-response-time-design.md` for the JAM-15 decoder and matcher this extends. Verified against `62d9ef7`; recheck the line numbers below after rebasing.

## Global Constraints

- Decoding never resolves or contacts anything. Passive observation only.
- Every bound below is checked before allocation. A value past a bound is dropped or marked truncated, never guessed at.
- Timeouts and expiry use the replay-aware clock (`flow_aging_now_ms`), never wall time.
- A wire change updates `wire.rs`, `docs/wire-protocol.md`, `lib/types.ts`, `lib/agent-mapping.ts` and `lib/__tests__/fixtures/agent-wire-samples.jsonl` together.
- Tests come first and are shown failing. Bounds are tested at limit, limit + 1 and zero.
- Do not change when an HTTP response is decided: JAM-15's `http.time_us` depends on it.
- Do not widen DNS matching to TCP. JAM-15 excluded it, and JAM-21 says correlation stays separate.
- Do not change `redact.rs`'s visibility. Follow Stream Task 1 plans to widen `looks_like_bearer_token`; call the public `redact_headers` here so the two don't collide.
- The UI renders these strings as React text only. No `dangerouslySetInnerHTML`.

## Decisions

These settle the six questions in the gate's plan update.

**1. DNS over TCP framing.** Each message has a 2-byte length prefix (RFC 1035 §4.2.2). Today a TCP/53 payload goes to `sniff_dns` unframed, so every field is read two bytes off, and a response is only reached through the `_` branch because `sniff_l7_desegmenting` sees just `dst_port`. Route on transport and either port.

The bound is `MAX_TCP_STREAM_BYTES` (16 KiB) minus the prefix, so a message is either fully buffered or never buffered. A larger declared length is `Undecided`: nothing is buffered and no field is produced. That loses AXFR-sized messages, which is acceptable because TCP fallback answers are normally far smaller. Reordering, overlap (first-seen-wins), idle timeout, the 2 s decision window and per-stream, per-owner and global caps all stay as the reassembler has them.

Only the first message in a buffer is decoded, because `L7Info` is one value per packet. This is a named limitation.

**2. TXT.** Decode the RDATA as character-strings, concatenated with no separator, which is what SPF (RFC 7208 §3.3) and DKIM require. Bytes outside printable ASCII, and the backslash, use RFC 1035 §5.1 escapes (`\DDD`, `\\`).

Caps: 512 output bytes per answer and 2,048 per response. A DKIM 2048-bit record is about 410 characters and RFC 7208 advises keeping SPF under 450, so 512 holds the common large records whole. Past a cap, the text stops at a whole escape and `data_truncated` is set. A character-string that overruns its RDATA gives empty `data`, never a partial value.

Redaction: pass the text through `redact_headers` with the part before the first `=` as the name. That redacts `authorization=...` and bearer-looking values. TXT is otherwise public data, and it is not gated the way decrypted content is. A DNS-tunnel payload will appear as escaped text, which is the honest view of it.

**3. HTTP.** Add `reason`, `content_type` and `content_length` to `HttpResponse`, read from the bytes present when the status line decides. No extra buffering, so timing doesn't move. Headers that arrive in a later segment are absent, and absent means "not observed", not "no header". This is a named limitation.

- Scan at most 8,192 bytes and 100 lines after the status line, stop at the blank line, and ignore an unterminated final line.
- `content_type`: the media type only, lowercased, parameters dropped (boundaries and charsets add nothing and can carry arbitrary text). Must match `token/token`, at most 255 bytes, otherwise absent.
- `content_length`: ASCII digits that fit `u64`, otherwise absent.
- Conflicting duplicates of either header give absent, because a conflicting `Content-Length` is a smuggling signal and we must not pick a side. Identical duplicates are fine.
- `Content-Length : 5` (space before the colon) doesn't match. An obs-fold line after one of these headers discards it.
- `reason`: printable ASCII, at most 128 bytes, otherwise absent. Empty is absent.
- `reason` and `content_type` go through `redact_headers` before they leave the parser.

**4. Learned names.** A new `ObservedDnsNames` table maps address to name. `FlowTable` owns it because the emitter already holds that lock when it builds `EndpointSnapshot`, so no new lock or thread hand-off is needed.

- **Source:** only `TxnEvent::Answered { protocol: Dns, .. }` with rcode 0. An unsolicited response can't plant a name or fill the table, because it needs a query the client actually sent. TCP responses are never `Answered`, so they don't feed the table. This is a named limitation, confirmed by James.
- **Which name:** the question name, which is what the client resolved. Addresses count only from A/AAAA records whose owner is the question or reachable from it through the response's CNAMEs. Unrelated records in the answer section are ignored.
- **Accepted names:** ASCII letters, digits, `-`, `_` and `.`, at most 253 bytes, stored lowercase. Anything else isn't learned, so no escaping is needed downstream.
- **One name per address, most recent wins.** A CDN address shared by many names shows the last one resolved. Documented on the wire.
- **Expiry:** `now + clamp(ttl, 1 h, 24 h)`. The floor is there because flows outlive short CDN TTLs; the ceiling limits how long a forged answer lasts. Re-resolving refreshes it.
- **Capacity:** `MAX_OBSERVED_DNS_NAMES`, startup-only, same parsing rules as `MAX_FLOWS`, default `16_384`. Expired entries go first, then the entry expiring soonest. Evictions are counted. Task 4 measures the per-entry cost and records it; the default follows from that, and the estimate of about 420 B per entry (about 7 MiB at the default) is only a starting point.
- **Reset:** `FlowTable::reset` clears the table, matching `transactions.reset()` on an interface switch.

**5. Wire.** No new event. `endpoint_update` entries gain optional `observedName`, omitted when none is live. It stays separate from `remoteHostname`, which is opt-in enrichment PTR data. Packet fields gain `http.response.phrase`, `http.content_type`, `http.content_length` and `dns.answer.N.truncated`; TXT text uses the existing `dns.answer.N.data`.

**6. Fuzz.** Extend `l7_transactions` (framed DNS, name table bound) and `stream_reassembly` (TCP/53 across segments, including sequence wraparound). Both already run in CI. Add `src/dns_names\.rs` to the path filter at `.github/workflows/ci.yml:156`, or a change to the new file alone would skip fuzzing.

**On-path attacker.** A forged response that wins the race with a correct ID and question gets a wrong label for up to 24 h, the same thing it does to the client. That is misleading display, not a confidentiality issue, and the UI marks the name as learned from DNS. Holding back a TCP message only costs that message's fields.

## Confirmed by James (2026-11-05)

- Names are not learned from DNS over TCP. TCP has no query match, and adding one means widening JAM-15's matcher.
- Conversations don't show the name. JAM-21 asks for the endpoint view only.

## Review Focus

Each has a test in the owning task.

1. **Two DNS messages in one TCP segment:** the first decodes, the second is dropped without error, and nothing misframes (Task 2).
2. **A CNAME chain to a CDN:** the endpoint shows the name the client asked for, not the CDN's (Task 4).
3. **HTTP headers in a later segment than the status line:** `http.response.code` still appears and the other fields are absent, not zero (Task 3).
4. **A name expiring on a live endpoint:** the label disappears rather than being kept by the UI's merge (Task 5).
5. **An unsolicited response from a host the client never asked:** no name appears (Task 4).

---

### Task 1: TXT answer data

**Files:**
- Modify: `capture-agent/src/l7.rs` (`DnsAnswer`, `dns_rdata_text` :194, `sniff_dns` :212, tests)
- Modify: `capture-agent/src/fields.rs:352-372`
- Modify: `docs/wire-protocol.md` (DNS fields, :128)

**Interfaces:**
- Produces: `DnsAnswer { name, rtype, ttl, data, data_truncated: bool }`; `pub const MAX_DNS_TXT_ANSWER_BYTES: usize = 512`; `pub const MAX_DNS_TXT_RESPONSE_BYTES: usize = 2048`.

- [ ] **Step 1: Write the failing tests in `l7.rs`**, using the `response(...)` builder at :332:

| Test | RDATA | Assert |
|---|---|---|
| `txt_joins_character_strings` | `\x03v=s\x03pf1` | `data == "v=spf1"`, not truncated |
| `txt_escapes_non_printable_and_backslash` | `\x03a\x00\\` | `data == "a\\000\\\\"` |
| `txt_at_answer_limit_is_not_truncated` | 512 output bytes | `data.len() == 512`, not truncated |
| `txt_over_answer_limit_is_truncated` | 513 output bytes | `data.len() == 512`, truncated |
| `txt_truncation_never_splits_an_escape` | 511 `a`, then `\x00` | `data.len() == 511`, truncated |
| `txt_response_budget_is_shared_across_answers` | 5 × 512 | 2,048 bytes total; fifth is empty and truncated |
| `txt_overrunning_character_string_gives_empty_data` | `\x05ab` | `data` empty, not truncated |
| `txt_zero_rdata_gives_empty_data` | empty | `data` empty |
| `txt_sensitive_key_is_redacted` | `authorization=abc` | `data == "[REDACTED]"` |
| `txt_bearer_value_is_redacted` | `Bearer abc` | `data == "[REDACTED]"` |

In `fields.rs`, `truncated_txt_answer_reports_the_truncated_field` asserts `dns.answer.0.truncated` is `Bool(true)`, and the field is absent otherwise.

- [ ] **Step 2: Run them.** `cd capture-agent && cargo test txt_` — expect compile failure on `data_truncated`.

- [ ] **Step 3: Implement.** Add `fn dns_txt_text(rdata: &[u8], budget: usize) -> (String, bool)`. `sniff_dns` holds the remaining response budget and passes `min(budget, 512)`. Add the `dns.answer.N.truncated` leaf.

- [ ] **Step 4: Run.** `cargo test` — expect PASS.

- [ ] **Step 5: Document** TXT, its caps and the truncation field in `docs/wire-protocol.md`, then commit.

### Task 2: DNS over TCP

**Files:**
- Modify: `capture-agent/src/l7.rs`
- Modify: `capture-agent/src/reassembly.rs:1305,1366`
- Modify: `capture-agent/fuzz/fuzz_targets/l7_transactions.rs`, `capture-agent/fuzz/fuzz_targets/stream_reassembly.rs`
- Modify: `docs/wire-protocol.md`

**Interfaces:**
- Consumes: `MAX_TCP_STREAM_BYTES` from `reassembly.rs:171`.
- Produces: `pub const MAX_DNS_TCP_MESSAGE_BYTES: usize = MAX_TCP_STREAM_BYTES - 2`; `pub fn sniff_dns_tcp(stream: &[u8]) -> L7Sniff`; `pub fn sniff_for_transport(payload: &[u8], protocol: TransportProtocol, src_port: Option<u16>, dst_port: Option<u16>) -> L7Sniff`.

- [ ] **Step 1: Write the failing tests.** In `l7.rs`:

| Test | Input | Assert |
|---|---|---|
| `tcp_dns_empty_is_undecided` | `[]` | `Undecided`, so a bare ACK never buffers |
| `tcp_dns_one_prefix_byte_needs_one_more` | `[0]` | `NeedMoreBytes { at_least: 1 }` |
| `tcp_dns_zero_length_is_undecided` | `[0, 0]` | `Undecided` |
| `tcp_dns_below_header_size_is_undecided` | declared 11 | `Undecided` |
| `tcp_dns_partial_message_reports_the_shortfall` | declared 40, 10 present | `NeedMoreBytes { at_least: 32 }` |
| `tcp_dns_at_limit_needs_bytes` | declared 16,382 | `NeedMoreBytes` |
| `tcp_dns_over_limit_is_undecided` | declared 16,383 | `Undecided` |
| `tcp_dns_complete_query_decodes` | framed `query(7, "a.com", 1)` | `Decided(Dns { id: 7, .. })` |
| `tcp_dns_compression_pointers_are_relative_to_the_message` | framed response with an answer pointer | names read correctly |
| `tcp_dns_pointer_past_the_declared_end_fails` | pointer into bytes after the message | no bytes from past the message appear |
| `tcp_dns_second_message_in_a_buffer_is_ignored` | two framed responses | `Decided` with the first's `id` |

In `reassembly.rs`, using its `parse_packet` fixtures:

- `tcp_dns_split_across_segments_decodes_once_complete`, including a split inside the prefix.
- `tcp_dns_out_of_order_segments_decode`.
- `tcp_dns_overlap_keeps_first_seen_bytes`.
- `tcp_dns_response_from_port_53_uses_framing`, where `dst_port` is ephemeral.
- `tcp_dns_message_at_the_limit_decodes_through_the_reassembler`, at 16,382.
- `tcp_dns_over_limit_buffers_nothing`, asserting `bytes_held() == 0`.
- `udp_53_stays_unframed`. The existing test at :2797 pins the same thing and must keep passing unchanged.

- [ ] **Step 2: Run.** `cargo test tcp_dns` — expect compile failure on `sniff_dns_tcp`.

- [ ] **Step 3: Implement.** Check order in `sniff_dns_tcp`: empty → `Undecided`; fewer than 2 bytes → `NeedMoreBytes`; declared below 12 or above the limit → `Undecided`; short → `NeedMoreBytes`; otherwise `sniff_dns(&stream[2..2 + declared])`, with a miss as `Undecided`. The slice is what stops pointers escaping the message.

`sniff_for_transport` uses `sniff_dns_tcp` when the protocol is TCP and either port is 53, and otherwise calls `sniff_l7_desegmenting(payload, dst_port)`. Both `sniff_inner` call sites use it.

- [ ] **Step 4: Run.** `cargo test` — expect PASS.

- [ ] **Step 5: Extend fuzzing.** In `l7_transactions`, call `sniff_dns_tcp(data)` and run each record's message through it with a correct prefix prepended, so the fuzzer reaches `sniff_dns` past the length check. In `stream_reassembly`, let one control bit select `remote_port: 53` so segmented TCP/53 goes through the same sequence-wraparound and overlap cases. Run each for 60 s:

`cargo +nightly fuzz run l7_transactions -- -max_total_time=60` and the same for `stream_reassembly`. Expect no crash.

- [ ] **Step 6: Document** the framing, the 16,382-byte bound and the first-message limitation in `docs/wire-protocol.md`, then commit.

### Task 3: HTTP response fields

**Files:**
- Modify: `capture-agent/src/l7.rs:103` and `HttpResponse`
- Modify: `capture-agent/src/fields.rs:332`
- Modify: `capture-agent/src/transaction.rs:323,581`, `capture-agent/src/main.rs:4245`, and each test constructor
- Modify: `lib/__tests__/fixtures/agent-wire-samples.jsonl`, `docs/wire-protocol.md`

**Interfaces:**
- Produces: `L7Info::HttpResponse { status: String, reason: Option<String>, content_type: Option<String>, content_length: Option<u64> }`; `MAX_HTTP_HEADER_SCAN_BYTES = 8192`; `MAX_HTTP_HEADER_LINES = 100`; `MAX_HTTP_REASON_BYTES = 128`; `MAX_HTTP_CONTENT_TYPE_BYTES = 255`.

- [ ] **Step 1: Write the failing tests in `l7.rs`:**

| Test | Input | Assert |
|---|---|---|
| `http_response_decodes_all_fields` | `HTTP/1.1 404 Not Found\r\nContent-Type: Text/HTML; charset=utf-8\r\nContent-Length: 12\r\n\r\n` | `reason == "Not Found"`, `content_type == "text/html"`, `content_length == 12` |
| `http_header_names_are_case_insensitive` | `content-LENGTH: 1` | `Some(1)` |
| `http_empty_reason_is_absent` | `HTTP/1.1 200 \r\n\r\n` | `None` |
| `http_reason_at_limit_is_kept` / `http_reason_over_limit_is_absent` | 128 / 129 bytes | `Some` / `None` |
| `http_non_ascii_reason_is_absent` | reason with a control byte or UTF-8 | `None`, status still decoded |
| `http_bearer_reason_is_redacted` | `HTTP/1.1 200 Bearer abc` | `"[REDACTED]"` |
| `http_status_alone_when_headers_arrive_later` | status line only | `Decided`, all three `None` |
| `http_unterminated_final_header_is_ignored` | `Content-Length: 12` with no line end | `None` |
| `http_conflicting_content_lengths_are_absent` | `5` and `6` | `None` |
| `http_identical_content_lengths_are_kept` | `5` and `5` | `Some(5)` |
| `http_content_length_rejects_non_digits` | `+5`, `-1`, `5, 5`, `0x10` | `None` |
| `http_content_length_zero_is_kept` / `http_content_length_max_u64` / `http_content_length_overflow_is_absent` | `0`, `u64::MAX`, `u64::MAX + 1` | `Some(0)`, `Some(MAX)`, `None` |
| `http_space_before_colon_does_not_match` | `Content-Length : 5` | `None` |
| `http_obs_fold_discards_the_header` | `Content-Length: 5\r\n 6\r\n` | `None` |
| `http_malformed_content_type_is_absent` | `text`, `Bearer abc`, 256 bytes | `None` |
| `http_header_at_line_limit_is_read` / `http_header_past_line_limit_is_not` | target is line 100 / 101 | `Some` / `None` |
| `http_header_past_byte_limit_is_not_read` | target past byte 8,192 | `None` |
| `http_binary_body_does_not_matter` | headers, blank line, invalid UTF-8 | fields decoded |
| `http_headers_after_the_blank_line_are_body` | `Content-Length` after the blank line | `None` |

In `fields.rs`, `http_response_fields_are_present_only_when_decoded` covers `http.response.phrase`, `http.content_type` and `http.content_length` (`Uint`). In `transaction.rs`, `http_service_time_is_unchanged_by_response_fields` shows a response with headers matches on the same frame as one without.

- [ ] **Step 2: Run.** `cargo test http_` — expect compile failure on the new variant fields.

- [ ] **Step 3: Implement** `fn parse_response_headers(after_status_line: &[u8]) -> (Option<String>, Option<u64>)`. Header bytes are parsed from `payload`, not from `first_complete_line`'s `&str`, because the body may not be UTF-8. Add the leaves. Keep `transaction.rs` matching on `status` only.

- [ ] **Step 4: Run.** `cargo test`, then `npx vitest run lib/__tests__/agent-wire-contract.test.ts lib/__tests__/packet-stream-status-code.test.tsx` — expect PASS, adding the new fields to the fixture.

- [ ] **Step 5: Fuzz.** `sniff_l7(data, None)` in `l7_transactions` already reaches the header parser. Run it for 60 s and expect no crash.

- [ ] **Step 6: Document** the three fields and the "absent means not observed" rule, then commit.

### Task 4: Observed name table and wire field

**Files:**
- Create: `capture-agent/src/dns_names.rs`
- Modify: `capture-agent/src/lib.rs`, `capture-agent/src/flow.rs:269,395,943,1004`, `capture-agent/src/main.rs` (after :3133, :3470, `resolve_max_flows` :1380), `capture-agent/src/wire.rs:42`
- Modify: `capture-agent/fuzz/fuzz_targets/l7_transactions.rs`, `.github/workflows/ci.yml:156`
- Modify: `lib/types.ts:330`, `lib/agent-mapping.ts:297`, `lib/__tests__/fixtures/agent-wire-samples.jsonl`
- Modify: `docs/wire-protocol.md` (:262 and the note at :323), `docs/architecture.md:99`, `docs/security.md`

**Interfaces:**
- Consumes: `L7Info::DnsResponse`, `TxnEvent::Answered`, `TxnProtocol::Dns`.
- Produces:
  - `pub const DEFAULT_MAX_OBSERVED_DNS_NAMES: usize = 16_384`, `MIN_NAME_RETENTION_MS = 3_600_000`, `MAX_NAME_RETENTION_MS = 86_400_000`.
  - `ObservedDnsNames::new(capacity: usize)`, `learn_response(&mut self, query_name: &str, answers: &[DnsAnswer], now_ms: u64)`, `lookup(&self, addr: &str, now_ms: u64) -> Option<&str>`, `clear(&mut self)`, `len(&self) -> usize`, `evictions(&self) -> u64`.
  - `FlowTable::learn_dns_response(&mut self, query_name: &str, answers: &[DnsAnswer], now_ms: u64)`, `FlowTable::with_observed_name_capacity(self, capacity: usize) -> Self`.
  - `EndpointSnapshot.observed_name: Option<String>`, `EndpointJson.observed_name: Option<String>` (`observedName`, skipped when `None`), `Endpoint.observedName?: string`.

- [ ] **Step 1: Write the failing tests in `dns_names.rs`:**

| Test | Setup | Assert |
|---|---|---|
| `a_record_maps_address_to_question` | `example.com` A 1.2.3.4 | lookup gives `example.com` |
| `aaaa_key_matches_the_flow_table_address_form` | AAAA with compressible zeros | lookup by the form `FlowKey.remote_addr` holds |
| `cname_chain_maps_to_the_question` | `www.a.com` → `cdn.b.net` A 1.2.3.4 | `www.a.com` |
| `cname_order_in_the_answer_section_does_not_matter` | A record before its CNAME | `www.a.com` |
| `cname_loop_terminates` | `a` → `b` → `a` | returns, learns nothing |
| `unrelated_a_record_is_ignored` | question `a.com`, A owned by `evil.net` | lookup `None` |
| `owner_comparison_is_case_insensitive` | `WwW.A.cOm` owner | learned, stored lowercase |
| `name_with_disallowed_bytes_is_not_learned` | `a<b.com`, a UTF-8 name | `None` |
| `name_of_253_bytes_is_learned` / `name_of_254_bytes_is_not` | length boundary | `Some` / `None` |
| `most_recent_name_wins_for_a_shared_address` | two responses, same address | the second, `len() == 1` |
| `ttl_below_floor_uses_the_floor` | TTL 0 | alive at 1 h − 1 ms, gone at 1 h |
| `ttl_above_ceiling_uses_the_ceiling` | TTL `u32::MAX` | gone at 24 h, no overflow |
| `ttl_in_range_is_used` | TTL 7,200 | gone at 2 h |
| `re_resolving_extends_expiry` | same name, later | alive past the first expiry |
| `capacity_holds_at_the_limit` | capacity 2, 2 addresses | both present, `evictions() == 0` |
| `over_capacity_drops_expired_first` | one expired, then a new one | live entry stays, `evictions() == 0` |
| `over_capacity_evicts_the_soonest_to_expire` | none expired | soonest gone, `evictions() == 1`, `len() == 2` |
| `clear_empties_the_table` | | `len() == 0` |

In `flow.rs`: `endpoint_snapshot_carries_a_live_observed_name`, `endpoint_snapshot_omits_an_expired_name`, `reset_clears_observed_names`.

In `main.rs`, extract the gate as `fn learnable_dns_response<'a>(l7: &'a L7Info, event: &TxnEvent) -> Option<(&'a str, &'a [DnsAnswer])>` and test:

- `answered_noerror_dns_is_learnable`.
- `nxdomain_is_not_learnable`.
- `unmatched_response_is_not_learnable`.
- `duplicate_response_is_not_learnable`.
- `answered_http_is_not_learnable`.

In `transaction.rs`, `tcp_dns_response_is_not_answered` pins that a TCP/53 query and response give `TxnEvent::None`.

Also `parse_max_observed_dns_names` tests mirroring `parse_max_flows`: unset gives the default, `0` and non-numeric panic.

TypeScript, in `agent-mapping.test.ts`: `observedName` is kept when it is a string, and is `undefined` when missing or not a string, without throwing. `agent-wire-contract.test.ts` passes with the fixture updated.

- [ ] **Step 2: Run.** `cargo test dns_names` and `npx vitest run lib/__tests__/agent-mapping.test.ts` — expect failure.

- [ ] **Step 3: Implement `dns_names.rs`.** Store `HashMap<String, Entry>` plus `BTreeSet<(u64, u64, String)>` ordered by expiry, then a sequence number, so purging and eviction are not a full scan. Build the name set by repeating over the answers at most `answers.len()` times, which bounds the walk at 16 × 16 and ends on cycles because the set only grows.

- [ ] **Step 4: Wire it in.** After `observe_frame` (:3133), call `learn_dns_response` under the flow table lock when `learnable_dns_response` returns `Some`, using `flow_now_ms` — the same clock as the tick's `now_ms`, not `capture_ts_us`. Add `resolve_max_observed_dns_names()` and `parse_max_observed_dns_names(raw: Option<String>) -> usize` beside `resolve_max_flows`.

- [ ] **Step 5: Measure.** Add an ignored test `dns_names_entry_cost` that fills the table with worst-case entries (253-byte names, 39-byte addresses) at 4,096, 16,384 and 1,048,576 and reports the bytes, using a counting allocator in the test. Record the numbers in `docs/architecture.md:99`'s table. If 16,384 isn't justified by them, change the default and say why.

- [ ] **Step 6: Run.** `cargo test`, `npx vitest run`, `npm run lint` — expect PASS.

- [ ] **Step 7: Fuzz.** In `l7_transactions`, feed each `DnsResponse` to an `ObservedDnsNames::new(64)` with the fuzzed clock, and assert `len() <= 64`. Add `src/dns_names\.rs` to the CI filter. Run for 60 s and expect no crash.

- [ ] **Step 8: Document** `observedName`, its source rules, one-name-per-address and expiry in `docs/wire-protocol.md`, correct the note at :323, add `MAX_OBSERVED_DNS_NAMES` to `docs/architecture.md`, and state in `docs/security.md` that the table is passive, bounded and forgeable by an on-path attacker. Commit.

### Task 5: Endpoint view

**Files:**
- Modify: `components/EndpointsView.tsx:44-54`
- Test: `lib/__tests__/endpoints-view.test.tsx`, `lib/__tests__/rollup-state.test.ts`
- Modify: `docs/usage.md`

**Interfaces:**
- Consumes: `Endpoint.observedName?: string` from Task 4.

- [ ] **Step 1: Write the failing tests.**

`endpoints-view.test.tsx`:
- `shows_the_observed_name_under_the_host`, with a `title` of `Learned from observed DNS`.
- `shows_the_ptr_name_too_when_it_differs`.
- `shows_one_line_when_observed_and_ptr_names_match`.
- `search_matches_the_observed_name`.
- `renders_markup_in_a_name_as_text`.

`rollup-state.test.ts`:
- `a_name_gone_from_the_snapshot_is_not_retained`: previous has `observedName`, incoming doesn't, merged doesn't. `remoteHostname` is still retained, as it is today.

- [ ] **Step 2: Run.** `npx vitest run lib/__tests__/endpoints-view.test.tsx lib/__tests__/rollup-state.test.ts` — expect the view tests to fail. The retention test should pass already, because `mergeEndpointSnapshot` spreads `incoming`; keep it as the guard.

- [ ] **Step 3: Implement** in `endpointToRow`, and include `observedName` in `searchText`.

- [ ] **Step 4: Run.** `npx vitest run` and `npm run lint` — expect PASS.

- [ ] **Step 5: Verify the acceptance criterion end to end.** Replay a pcap holding a matched DNS exchange and traffic to the answered address, and confirm the endpoint shows the name while a packet capture on the host shows no new DNS or WHOIS traffic from the agent or relay. Record what was run in `.ai/TEST_STATUS.md`.

- [ ] **Step 6: Document** the label's meaning in `docs/usage.md`, then commit.

## Acceptance mapping

| JAM-21 criterion | Where |
|---|---|
| DNS answers, rcode and TTLs for A/AAAA/CNAME/PTR/TXT | JAM-15, plus Task 1 |
| Compression pointers can't loop | JAM-15, plus Task 2's message-relative test |
| HTTP status codes; #65's dead field | JAM-15, plus Task 3 for the rest |
| Observed mappings appear as host names, no outbound lookup | Tasks 4 and 5 |
| Fuzz coverage in CI | Tasks 2, 3 and 4 |
| `docs/wire-protocol.md` documents new fields | Each task |

## Security checklist (plan pass)

Reviewed against `docs/security-plan-review-checklist.md`. This is the author's self-check, not an independent review.

| Section | Result |
|---|---|
| 1. Inputs and bounds | Pass. All wire lengths are checked first; DNS over TCP uses the existing per-stream, global and stream-count caps; the name walk is bounded. |
| 2. State and failure | Pass. Oversize or malformed input gives no field; a partial TXT value is never emitted; TCP directions stay separate through `TcpStreamKey`; the on-path case is stated above. |
| 3. Cryptography | Not applicable. |
| 4. Secrets | Partial. `redact_headers` covers the new text, and nothing here is decrypted content. It is a heuristic, so a token in an unusual TXT form would pass through. |
| 5. Time | Pass. Expiry uses the replay-aware clock. |
| 6. Interfaces | Pass. Task 4 changes all contract files together, and `observedName` of the wrong type doesn't throw. No new event, so one-shot limiting doesn't apply. |
| 7. Tests and tooling | Pass for the plan. Failing-first tests at boundaries, fuzz in the same PR, and the CI filter fix. |

Not verified while planning: the real per-entry memory cost (Task 4 Step 5), how often clients use TCP-only DNS, and whether the decision window delays large TCP messages in practice.
