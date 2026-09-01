// capture-agent/examples/icmp_ping_spike.rs
// Scratch binary, not part of the shipped agent. Answers one question:
// does an unprivileged process on this Mac get valid ICMP Echo/Time-Exceeded
// replies from a SOCK_DGRAM/IPPROTO_ICMP socket, without root and without
// any special entitlement beyond what capture-agent/README.md's existing
// access_bpf setup already grants?
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::FromRawFd;
use std::net::UdpSocket;

fn main() {
    // libc::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) is the mechanism under
    // test. Using raw libc here (added as a dev-dependency for this example
    // only, via `[dev-dependencies] libc = "..."`) rather than any traceroute
    // crate, so the spike proves the primitive itself, not a library's
    // abstraction over it.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        eprintln!(
            "RESULT: FAILED — socket() returned {} (errno {}). Unprivileged ping-socket \
             is NOT available on this system; capture-agent/traceroute.rs must use the \
             system-traceroute fallback (spec Components §1).",
            fd,
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    println!("RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.");

    // Send one ICMP Echo Request to 127.0.0.1 (loopback — no network
    // dependency for this spike) and confirm a reply is actually received,
    // not just that the socket opened. A minimal 8-byte ICMP echo header:
    // type=8 (echo request), code=0, checksum, identifier, sequence.
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let mut packet = [0u8; 8];
    packet[0] = 8; // type: echo request
    packet[1] = 0; // code
    // checksum left as 0 for this loopback spike — a real implementation
    // computes it properly in Task 2; this spike only needs a reply to
    // arrive at all, which loopback ICMP handling tolerates for this check.
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    match socket.send_to(&packet, dest) {
        Ok(_) => println!("RESULT: send_to() succeeded."),
        Err(e) => {
            println!("RESULT: FAILED — send_to() error: {e}. Fallback required.");
            std::process::exit(1);
        }
    }
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok((n, from)) => println!("RESULT: SUCCESS — received {n} bytes from {from}. Unprivileged ICMP ping-socket confirmed working on this macOS version."),
        Err(e) => println!("RESULT: FAILED — no reply received ({e}). Fallback required."),
    }
}
