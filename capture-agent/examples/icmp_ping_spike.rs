// capture-agent/examples/icmp_ping_spike.rs
// Scratch binary, not part of the shipped agent. Answers one question:
// does an unprivileged process on this Mac get valid ICMP Echo/Time-Exceeded
// replies from a SOCK_DGRAM/IPPROTO_ICMP socket, without root and without
// any special entitlement beyond what capture-agent/README.md's existing
// access_bpf setup already grants?
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::FromRawFd;
use std::net::UdpSocket;

// Standard Internet checksum (RFC 1071 / the same algorithm ICMP, IP, and TCP
// all use): sum the packet as 16-bit big-endian words with end-around carry,
// then take the one's complement of the sum.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

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
    // Controller-directed correction: the original brief left the checksum at
    // 0, which is not a valid ICMP checksum and gets silently dropped by most
    // IP stacks (including loopback) before ever reaching a listener — that
    // would produce the exact "socket()/send_to() succeed, no reply ever
    // arrives" symptom independent of whether the unprivileged ping-socket
    // mechanism itself works. Compute a real checksum: 16-bit one's
    // complement sum of the packet as 16-bit words, then one's complement
    // the sum, written into bytes[2..4] before sending.
    // packet[2..4] (checksum field) and packet[4..8] (identifier/sequence)
    // are 0 at this point, so the initial sum below is just over
    // type/code/checksum-placeholder/id/seq, all currently zero except
    // bytes[0]=8.
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
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
