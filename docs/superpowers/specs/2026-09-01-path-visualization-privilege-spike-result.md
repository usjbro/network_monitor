# Path Visualization — Privilege Spike Result

**Date:** 2026-09-01
**macOS version tested:** macOS 26.6.2 (Darwin 25.6.0, BuildVersion 25G83)
**Outcome:** FAILED — fallback required

## How it was run

```
cd capture-agent && cargo run --example icmp_ping_spike
```

Run as an unprivileged user (`uid=501(jamesbrown)`, no `sudo`, not a member of any group beyond the existing `access_bpf` grant from `capture-agent/README.md`'s one-time setup). Run three consecutive times to rule out a one-off timing fluke; all three runs produced identical output.

## Exact RESULT: lines

Run 1:
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: FAILED — no reply received (Resource temporarily unavailable (os error 35)). Fallback required.
```

Run 2 (repeat, to check for flakiness):
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: FAILED — no reply received (Resource temporarily unavailable (os error 35)). Fallback required.
```

Run 3 (repeat):
```
RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.
RESULT: send_to() succeeded.
RESULT: FAILED — no reply received (Resource temporarily unavailable (os error 35)). Fallback required.
```

## Diagnostic note (informational, not a workaround)

To sanity-check that ICMP loopback itself is functional on this machine (i.e. that the failure is specific to the ping-socket mechanism/packet under test, not a broken loopback path), the system `ping` binary was run against `127.0.0.1` outside the spike:

```
$ ping -c 2 -t 2 127.0.0.1
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.065 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.068 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.065/0.067/0.068/0.002 ms
```

System `ping` (itself unprivileged on macOS, using the same `SOCK_DGRAM`/`IPPROTO_ICMP` primitive under the hood) works fine on loopback. This indicates the spike's `socket()`/`send_to()` calls succeeding but `recv_from()` timing out is not explained by a broken loopback path or a missing privilege on the *socket* itself — `socket()` did succeed unprivileged, confirming that half of the mechanism. The most likely proximate cause is the spike's own deliberately-zeroed ICMP checksum (per the brief's script comment: "checksum left as 0 for this loopback spike... this spike only needs a reply to arrive at all, which loopback ICMP handling tolerates for this check") — on this macOS version, that assumption did not hold; a reply was never observed. Per the task instructions, this was not "fixed" or worked around (e.g. by computing a real checksum) — the spike was run exactly as specified in the brief, and the real result is recorded as-is.

## Decision for Task 2

Implement traceroute.rs by shelling out to the system `traceroute` binary and parsing its output, per Components §1's named fallback.
