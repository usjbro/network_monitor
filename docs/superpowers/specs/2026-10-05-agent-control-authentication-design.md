# Capture-agent Socket Authentication — JAM-184

Status: approved by James directly in chat on 2026-10-05 after Claude Code feedback. Implementation plan approved for Native execution; implementation locally verified, independent review/publication pending.

Approved scope: gate both the feed and controls because they share one connection and capture data is sensitive. JAM-184's acceptance criteria explicitly require control authentication; James approved the revised scope directly in this session.

## Purpose and scope

Require possession of a fresh agent credential before reading the capture feed or submitting controls on 127.0.0.1:9990. Preserve existing control and event semantics after authentication, independent agent/relay startup, automatic relay reconnects, and the loopback/mTLS boundaries.

JAM-175 already rejects browser cross-protocol requests. Verified current code still streams immediately on accept; AgentClient reports connected on TCP connect and permits controls before any handshake. Authentication therefore gates both directions, rather than adding a check only to individual commands.

Existing direct socket tools must implement the handshake. There is no unauthenticated observation mode or compatibility fallback. bin/osi-inspect.js already uses the relay HTTP API and does not connect directly to 9990.

## Credential handoff

The agent generates 32 cryptographically random bytes with the existing ring SystemRandom primitive on every launch. Encode as 64 lowercase hexadecimal characters. Do not accept a caller-supplied reusable token.

Publish the credential through an owner-only file. Both processes resolve AGENT_TOKEN_FILE when set (absolute path required); otherwise use $HOME/.network-monitor/agent-control-token. An override must be configured identically in both processes. A dedicated default directory is created with 0700 permissions. A configured parent must already exist and be owned by the running UID with 0700 permissions; resolve platform-level ancestor aliases such as macOS /var to their canonical location, then validate the immediate credential directory and final file. The immediate directory must not itself be a symlink; the final file is opened without following symlinks. Reject foreign ownership, nonregular files, hard-linked credentials and insecure permissions. Anchor operations to the validated canonical directory. Do not reject the platform's /var alias merely because it is a symlink. Agent and relay run under the same UID; privilege-separated deployments need a future design.

Bind the listener before publishing, so an instance that loses the bind race cannot replace the running instance's token. Write to a uniquely named create-new 0600 file in the validated directory, then atomically rename it into place. Validate any existing credential's ownership/type/mode before replacing it; stale valid credentials are replaced. Temporary filenames must not contain the credential. The Rust agent opens and validates the immediate parent directory once, then performs credential creation, destination checks, atomic rename and cleanup relative to that descriptor (openat/fstatat/renameat/unlinkat). Do not repeat path-based lookups for these operations after validation. The relay opens the final credential without following symlinks, validates that opened file with fstat, and reads through the same file descriptor rather than checking a path and reopening it. Never print token bytes or put them in command arguments, wire events, browser state, errors or logs.

Hold the agent credential in zeroizing memory using the existing zeroize dependency. When the credential guard is dropped, remove only the credential file still belonging to this process; compare saved file identity to avoid unlinking a replacement. No signal handler is added: Ctrl-C/SIGTERM as well as abrupt termination or a crash can leave a stale 0600 file; the next successful launch rotates it. The relay reads the file fresh for each connection attempt using no-follow open, regular-file/UID/0600 checks and a 65-byte content bound (64 hex characters plus LF). Never cache across reconnects. Missing or invalid credentials yield disconnected state and normal reconnect scheduling.

## Wire handshake

The client's first line must be exactly the supported authentication message shape:

```json
{"type":"authenticate","token":"<64 lowercase hexadecimal characters>"}
```

The agent reads an authentication line of at most 256 bytes, including the newline, within 5 seconds. This limit applies only through the first newline, not to an entire TCP read containing authentication followed by a larger control message. Missing newline, EOF, timeout, invalid JSON/type/token, unknown fields, oversized input, a control as the first line or a wrong token closes the connection. Compare fixed-length token bytes with a constant-time primitive from existing dependencies. Never route this line through the normal control dispatcher. Never include supplied credentials in rejection diagnostics.

On success, write the acknowledgement successfully within a further 5-second deadline:

```json
{"type":"authenticated"}
```

Only then subscribe/forward capture events and accept normal controls. Buffered bytes after the first newline must remain available to the normal parser; valid authentication followed by a control in the same TCP write is supported. Authentication followed by an HTTP request still triggers JAM-175's strict framing rejection. The credential itself is never emitted back.

Use separate limits of 16 pending authentication tasks and 64 authenticated connections. Acquire a pending permit without waiting before spawning; release it after successful authentication or closure. Acquire an authenticated permit before acknowledging success and hold it for that connection's lifetime. Excess peers close. Pending peers cannot consume authenticated-client slots or interfere with existing authenticated connections. The absolute 5-second handshake deadline also covers slow-drip input. These are resource bounds, not a guarantee against local connection flooding: an attacker can still saturate pending admission and delay a new legitimate client; reserving authenticated slots cannot identify that client before authentication.

## Relay lifecycle and contract

AgentClient reads the credential, opens TCP, sends authentication first, and starts a 5-second acknowledgement deadline. It reports connected and allows sendControl only after the expected acknowledgement. Before it arrives, any other event closes the attempt without emission. Authentication acknowledgements are consumed inside AgentClient and never become SSE events. Controls requested before authentication are dropped rather than queued for a later connection.

On disconnect, reset authentication, partial-line buffering and timers before the existing single reconnect schedule. Delayed credential reads and callbacks from old sockets must be ignored after stop() or a newer attempt. Every reconnect reloads the credential, allowing an agent restart to rotate it without restarting Next.js. The relay's acknowledgement line is bounded to 256 bytes through its first newline; coalesced authenticated events after that newline retain their normal larger limits. The acknowledgement must have the exact supported shape. Missing/unsafe credentials and handshake closure or timeout produce a bounded, deduplicated server-side diagnostic reason without credential contents or raw authentication input; connected status remains false. Distinguish credential lookup/validation failure from handshake failure without promising the peer will disclose why it refused authentication.

Update capture-agent/src/wire.rs, lib/types.ts and lib/agent-mapping.ts together with explicit handshake types/contracts, plus lib/agent-client.ts and docs/wire-protocol.md. Mapping must never expose handshake credentials or acknowledgements to browser consumers. No TLS key or decrypt-opt-in changes.

## Security boundary

A 0600 file prevents other OS users from reading this credential, and the handshake rejects direct socket callers without it. It does not provide application-wide isolation from other OS users: the relay's unauthenticated HTTP routes can still expose the feed and forward controls for local non-browser callers. Code already running as the same UID can read that file; this does not isolate hostile programs under the operator's own account. The relay HTTP authentication gap is tracked separately as JAM-196. The relay HTTP boundary is unchanged: this task does not introduce HTTP session authentication, and local processes able to call an allowed relay route can still use its controls. Avoid claiming that the token blocks all local processes.

The authenticated acknowledgement proves acceptance of the client credential; it is not cryptographic server authentication. Preventing agent impersonation or port squatting is outside this direct-socket control-authentication scope.

## Alternatives

An environment token alone would require a shared launcher and lifecycle changes for independently started processes; it also invites accidentally reusing a fixed token. A Unix-domain socket with peer credentials changes transport and deployment semantics. The file-backed per-launch credential fits current startup with existing dependencies and is the selected approach. Multi-user credential sharing is excluded.

## Verification and publication

Rust unit tests cover random-token format/rotation, strict handshake schema, constant-length comparison, bounded reads/timeouts and safe file creation/validation/replacement/cleanup. Live socket tests prove missing/wrong/control-first/HTTP/oversized/idle peers receive no feed and cause no control side effects, while a correct credential receives the acknowledgement, feed and controls. Validate both caps, continued service to existing authenticated clients while pending admission is saturated, and buffered post-auth commands longer than 256 bytes coalesced with authentication.

TypeScript tests cover auth-first ordering, no premature events/connected/controls, bad/missing credentials, wrong/unexpected acknowledgement, split/coalesced lines, reconnect-token rotation and state/timer reset. Update existing stub servers, stream-integration tests and e2e/fake-agent.ts to perform authentication; do not add a test-only bypass in production.

Existing Rust live-loopback and replay binary tests must authenticate observers and use isolated private token directories. Run their ignored tests, including the actual live rejection case, in addition to default Rust tests/release/clippy and TypeScript tests/typecheck/lint/build. Use independent security/code review before publication and again on the published PR, wait for green CI and clean merge state, then squash merge and update Linear/Slack. No new dependencies or network binds.

Live capture omits TCP traffic between loopback peers involving the agent's `127.0.0.1:9990` endpoint before reassembly, packet/flow output and raw recording, so the plaintext authentication credential cannot escape as captured payload. IPv4 TCP fragments involving `127.0.0.1` and another loopback address lack reliable port attribution; these rare live fragments are conservatively omitted too. Other unfragmented loopback traffic, non-TCP fragments, non-loopback traffic and all replay frames retain their existing handling. Kernel capture counters may include omitted transport frames. This does not prevent a separately privileged packet sniffer from observing the plaintext loopback handshake.
