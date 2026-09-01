# Path Visualization — Privilege Spike Result

**Date:** 2026-09-01
**macOS version tested:** macOS 26.6.2 (Darwin 25.6.0, BuildVersion 25G83)
**Outcome:** SUCCESS — unprivileged ping-socket works

## History of this finding

The spike was first run exactly per the original task brief, which left the
8-byte ICMP echo header's checksum field at 0. That run produced a FAILED result
(socket() and send_to() succeeded, but recv_from() timed out in 3/3 runs). A
follow-up review flagged that a zero checksum is not a valid ICMP checksum and
most IP stacks — including the loopback path — silently drop a packet that fails
checksum validation, which would produce exactly that symptom regardless of
whether the underlying unprivileged ping-socket mechanism works at all. The spike
binary was corrected to compute a real Internet checksum (RFC 1071: 16-bit
one's-complement sum with end-around carry, then one's complement of the sum)
over the 8-byte echo header before sending, and re-run. The corrected run is
what's recorded below as the finding of record.

## How it was run (corrected spike)

```
cd capture-agent && cargo run --example icmp_ping_spike
```

Run as an unprivileged user (`uid=501(jamesbrown)`, no `sudo`, no privilege beyond
the existing `access_bpf` grant from `capture-agent/README.md`'s one-time setup).
Run three consecutive times; all three produced identical output.

## Exact RESULT: lines (corrected spike, checksum computed correctly)

Run 1:
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: SUCCESS — received 28 bytes from 127.0.0.1:0. Unprivileged ICMP ping-socket confirmed working on this macOS version.
```

Run 2 (repeat):
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: SUCCESS — received 28 bytes from 127.0.0.1:0. Unprivileged ICMP ping-socket confirmed working on this macOS version.
```

Run 3 (repeat):
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: SUCCESS — received 28 bytes from 127.0.0.1:0. Unprivileged ICMP ping-socket confirmed working on this macOS version.
```

## Prior (superseded) result, for the record

With the checksum left at 0 (the original brief's script, unmodified), all 3 runs
instead produced:
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: FAILED — no reply received (Resource temporarily unavailable (os error 35)). Fallback required.
```
A sanity check at the time confirmed loopback ICMP itself was not broken (system
`ping -c 2 127.0.0.1`, itself unprivileged, succeeded normally), which in
hindsight pointed at the packet itself — the zero checksum — being the actual
cause, since the loopback path was otherwise demonstrably functional. This is
superseded by the corrected result above and is kept here only as a record of
the methodology correction, not as a competing finding.

## Decision for Task 2

Implement traceroute.rs using SOCK_DGRAM/IPPROTO_ICMP directly, per Components §1's primary recommendation.
