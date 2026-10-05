# Capture-agent Socket Authentication — JAM-184

Status: proposed for James's review. No product implementation yet.

## Purpose and scope

Require possession of a fresh agent credential before reading the capture feed or submitting controls on 127.0.0.1:9990. Preserve existing control and event semantics after authentication, independent agent/relay startup, automatic relay reconnects, and the loopback/mTLS boundaries.

JAM-175 already rejects browser cross-protocol requests. Verified current code still streams immediately on accept; AgentClient reports connected on TCP connect and permits controls before any handshake. Authentication therefore gates both directions, rather than adding a check only to individual commands.

Existing direct socket tools must implement the handshake. There is no unauthenticated observation mode or compatibility fallback. bin/osi-inspect.js already uses the relay HTTP API and does not connect directly to 9990.

## Credential handoff

The agent generates 32 cryptographically random bytes with the existing ring SystemRandom primitive on every launch. Encode as 64 lowercase hexadecimal characters. Do not accept a caller-supplied reusable token.

Publish the credential through an owner-only file. Both processes resolve AGENT_TOKEN_FILE when set (absolute path required); otherwise use $HOME/.network-monitor/agent-control-token. An override must be configured identically in both processes. A dedicated default directory is created with 0700 permissions. A configured parent must already exist and be owned by the runningUID with 0700 permissions; reject symlink traversal, foreign ownership, nonregular files, hard-linked credentials and insecure permissions. Agent and relay run under the same UID; privilege-separated deployments need a future design.

Bind the listener before publishing, so an instance that loses the bind race cannot replace the running instance's token. Write to a uniquely named create-new 0600 file in the validated directory, then atomically rename it into place. Validate any existing credential's ownership/type/mode before replacing it; stale valid credentials are replaced. Temporary filenames must not contain the credential. Anchor Rust file operations to a validated parent directory descriptor where practical; the relay validates the opened file with fstat rather than checking a path and then reading it. Never print token bytes or put them in command arguments, wire events, browser state, errors or logs.

Hold the agent credential in zeroizing memory using the existing zeroize dependency. On ordinary teardown remove only the credential file still belonging to this process; compare saved file identity to avoid unlinking a replacement. A crash can leave a stale 0600 file; the next successful launch rotates it. SIGKILL cannot guarantee cleanup. The relay reads the file fresh for each connection attempt using no-follow open, regular-file/UID/0600 checks and a 65-byte content bound (64 hex characters plusLF). Never cache across reconnects. Missing or invalid credentials yield disconnected state and normal reconnect scheduling.

## Wire handshake

The client's first line must be exactly the supported authentication message shape:

```json
{"type":"authenticate","token":"<64 lowercase hexadecimal characters>"}
```

The agent reads at most 256 bytes, including the newline, within 5 seconds. Missing newline, EOF, timeout, invalidJSON/type/token, unknown fields, oversized input, a control as the first line or a wrong token closes the connection. Compare fixed-length token bytes with a constant-time primitive from existing dependencies. Never route this line through the normal control dispatcher. Never include supplied credentials in rejection diagnostics.

On success, write the acknowledgement successfully within a further 5-second deadline:

```json
{"type":"authenticated"}
```

Only then subscribe/forward capture events and accept normal controls. Buffered bytes after the first newline must remain available to the normal parser; valid authentication followed by a control in the sameTCP write is supported. Authentication followed by an HTTP request still triggers JAM-175's strict framing rejection. The credential itself is never emitted back.

Bound socket tasks with at most 64 concurrent connections (including authenticated clients); excess accepted sockets close. This bounds idle unauthenticated tasks while the 5-second deadline bounds their lifetime. The listener remains responsive.

## Relay lifecycle and contract

AgentClient reads the credential, opens TCP, sends authentication first, and starts a 5-second acknowledgement deadline. It reports connected and allows sendControl only after the expected acknowledgement. Before it arrives, any other event closes the attempt without emission. Authentication acknowledgements are consumed inside AgentClient and never become SSE events. Controls requested before authentication are dropped rather than queued for a later connection.

On disconnect, reset authentication, partial-line buffering and timers before the existing single reconnect schedule. Delayed credential reads and callbacks from old sockets must be ignored after stop() or a newer attempt. Every reconnect reloads the credential, allowing an agent restart to rotate it without restarting Next.js. The relay's pre-ack receive buffer is bounded to 256 bytes; the acknowledgement must have the exact supported shape.

Update capture-agent/src/wire.rs, lib/types.ts and lib/agent-mapping.ts together with explicit handshake types/contracts, plus lib/agent-client.ts and docs/wire-protocol.md. Mapping must never expose handshake credentials or acknowledgements to browser consumers. No TLS key or decrypt-opt-in changes.

## Security boundary

A 0600 file protects against other OS users and callers without the credential. Code already running as the same UID can read that file; this does not isolate hostile programs under the operator's own account. The relay HTTP boundary is unchanged: this task does not introduce HTTP session authentication, and local processes able to call an allowed relay route can still use its controls. Avoid claiming that the token blocks all local processes.

The authenticated acknowledgement proves acceptance of the client credential; it is not cryptographic server authentication. Preventing agent impersonation or port squatting is outside this direct-socket control-authentication scope.

## Alternatives

An environment token alone would require a shared launcher and lifecycle changes for independently started processes; it also invites accidentally reusing a fixed token. A Unix-domain socket with peer credentials changes transport and deployment semantics. The file-backed per-launch credential fits current startup with existing dependencies and is the selected approach. Multi-user credential sharing is excluded.

## Verification and publication

Rust unit tests cover random-token format/rotation, strict handshake schema, constant-length comparison, bounded reads/timeouts and safe file creation/validation/replacement/cleanup. Live socket tests prove missing/wrong/control-first/HTTP/oversized/idle peers receive no feed and cause no control side effects, while a correct credential receives the acknowledgement, feed and controls. Validate the cap and ensure buffered post-auth commands survive.

TypeScript tests cover auth-first ordering, no premature events/connected/controls, bad/missing credentials, wrong/unexpected acknowledgement, split/coalesced lines, reconnect-token rotation and state/timer reset. Update existing stub servers and stream-integration tests to perform authentication; do not add a test-only bypass in production.

Existing Rust live-loopback and replay binary tests must authenticate observers and use isolated private token directories. Run their ignored tests, including the actual live rejection case, in addition to default Rust tests/release/clippy and TypeScript tests/typecheck/lint/build. Use independent security/code review before publication and again on the published PR, wait for green CI and clean merge state, then squash merge and update Linear/Slack. No new dependencies or network binds.
