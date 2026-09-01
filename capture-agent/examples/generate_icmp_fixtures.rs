// capture-agent/examples/generate_icmp_fixtures.rs
// One-time manual fixture generator, not part of the shipped agent. Sends
// real ICMP Echo Requests (via the same SOCK_DGRAM/IPPROTO_ICMP mechanism
// traceroute.rs uses) against a real destination to capture genuine
// Time Exceeded and Echo Reply byte sequences, and writes them to
// tests/fixtures/icmp/. Run with: cargo run --example generate_icmp_fixtures
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::FromRawFd;
use std::time::Duration;

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

fn build_echo_request(identifier: u16, sequence: u16) -> [u8; 8] {
    let mut packet = [0u8; 8];
    packet[0] = 8; // type: echo request
    packet[1] = 0; // code
    packet[4] = (identifier >> 8) as u8;
    packet[5] = (identifier & 0xff) as u8;
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xff) as u8;
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
    packet
}

fn open_icmp_socket() -> UdpSocket {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    assert!(fd >= 0, "socket() failed: {}", std::io::Error::last_os_error());
    unsafe { UdpSocket::from_raw_fd(fd) }
}

fn set_ttl(socket: &UdpSocket, ttl: u32) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let ttl_val: libc::c_int = ttl as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(ret, 0, "setsockopt(IP_TTL) failed: {}", std::io::Error::last_os_error());
}

fn main() {
    let target: IpAddr = "8.8.8.8".parse().unwrap();
    let dest = SocketAddr::new(target, 0);

    // --- Time Exceeded fixture: TTL=1 forces the first-hop router to reply. ---
    {
        let socket = open_icmp_socket();
        set_ttl(&socket, 1);
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let packet = build_echo_request(0x1234, 1);
        socket.send_to(&packet, dest).expect("send_to failed");
        let mut buf = [0u8; 128];
        let (n, from) = socket.recv_from(&mut buf).expect("no Time Exceeded reply received");
        println!("Time Exceeded fixture: {n} bytes from {from}: {:02x?}", &buf[..n]);
        std::fs::create_dir_all("tests/fixtures/icmp").unwrap();
        std::fs::write("tests/fixtures/icmp/time_exceeded.bin", &buf[..n]).unwrap();
    }

    // --- Echo Reply fixture: default TTL, real reachable destination. ---
    {
        let socket = open_icmp_socket();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let packet = build_echo_request(0x1234, 1);
        socket.send_to(&packet, dest).expect("send_to failed");
        let mut buf = [0u8; 128];
        let (n, from) = socket.recv_from(&mut buf).expect("no Echo Reply received");
        println!("Echo Reply fixture: {n} bytes from {from}: {:02x?}", &buf[..n]);
        std::fs::write("tests/fixtures/icmp/echo_reply.bin", &buf[..n]).unwrap();
    }

    println!("Fixtures written to tests/fixtures/icmp/");
}
