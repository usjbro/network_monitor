//! Independently encoded mixed-endian sections; no production writer helpers.
use std::path::PathBuf;

pub struct CaptureFile(pub PathBuf);
impl Drop for CaptureFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}
fn u16_bytes(value: u16, be: bool) -> [u8; 2] { if be { value.to_be_bytes() } else { value.to_le_bytes() } }
fn u32_bytes(value: u32, be: bool) -> [u8; 4] { if be { value.to_be_bytes() } else { value.to_le_bytes() } }
fn block(out: &mut Vec<u8>, kind: u32, body: &[u8], be: bool) {
    let len = (body.len() + 12) as u32;
    out.extend(u32_bytes(kind, be)); out.extend(u32_bytes(len, be));
    out.extend(body); out.extend(u32_bytes(len, be));
}
fn section(out: &mut Vec<u8>, be: bool) {
    let mut body = Vec::new();
    body.extend(u32_bytes(0x1a2b3c4d, be)); body.extend(u16_bytes(1, be)); body.extend(u16_bytes(0, be));
    body.extend([0xff; 8]); block(out, 0x0a0d0d0a, &body, be);
}
fn interface(out: &mut Vec<u8>, link: u16, resolution: u8, be: bool) {
    let mut body = Vec::new();
    body.extend(u16_bytes(link, be)); body.extend([0; 2]); body.extend(u32_bytes(65535, be));
    body.extend(u16_bytes(9, be)); body.extend(u16_bytes(1, be)); body.extend([resolution, 0x42, 0x42, 0x42]);
    body.extend([0; 4]); block(out, 1, &body, be);
}
fn packet(out: &mut Vec<u8>, interface: u32, counter: u64, data: &[u8], be: bool) {
    let mut body = Vec::new();
    body.extend(u32_bytes(interface, be)); body.extend(u32_bytes((counter >> 32) as u32, be));
    body.extend(u32_bytes(counter as u32, be)); body.extend(u32_bytes(data.len() as u32, be));
    body.extend(u32_bytes(data.len() as u32, be)); body.extend(data);
    body.resize((body.len() + 3) & !3, 0x42); block(out, 6, &body, be);
}
fn datagram(index: u8) -> Vec<u8> {
    let mut data = Vec::new();
    etherparse::PacketBuilder::ipv4([192, 0, 2, index], [198, 51, 100, index], 64)
        .udp(3000 + u16::from(index), 4000 + u16::from(index))
        .write(&mut data, b"fixture").unwrap(); data
}
pub fn mixed_sections(label: &str) -> CaptureFile {
    let mut out = Vec::new(); section(&mut out, true);
    interface(&mut out, 1, 6, true); interface(&mut out, 101, 9, true);
    let mut ethernet = vec![0; 12]; ethernet.extend([8, 0]); ethernet.extend(datagram(1));
    packet(&mut out, 0, 1_000_000, &ethernet, true);
    block(&mut out, 4, &[0; 4], true); // NRB end record
    // A real-shaped TLS key-log DSB must be skipped without enabling decryption.
    let secrets = b"CLIENT_RANDOM fixture secret\n";
    let mut dsb = Vec::new(); dsb.extend(u32_bytes(0x544c534b, true));
    dsb.extend(u32_bytes(secrets.len() as u32, true)); dsb.extend(secrets);
    dsb.resize((dsb.len() + 3) & !3, 0); block(&mut out, 10, &dsb, true);
    block(&mut out, 0x40000bad, &[0; 4], true); // custom block
    packet(&mut out, 1, 2_000_000_000, &datagram(2), true);
    section(&mut out, false); interface(&mut out, 0, 0, false);
    let mut loopback = vec![2, 0, 0, 0]; loopback.extend(datagram(3));
    packet(&mut out, 0, 3, &loopback, false);
    write_capture(label, &out)
}
pub fn raw_classic(label: &str) -> CaptureFile {
    let data = datagram(4); let mut out = Vec::new();
    out.extend(0xa1b2c3d4u32.to_le_bytes()); out.extend(2u16.to_le_bytes()); out.extend(4u16.to_le_bytes());
    out.extend([0; 8]); out.extend(65535u32.to_le_bytes()); out.extend(101u32.to_le_bytes());
    out.extend(4u32.to_le_bytes()); out.extend(0u32.to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes()); out.extend((data.len() as u32).to_le_bytes()); out.extend(data);
    write_capture(label, &out)
}
pub fn write_capture(label: &str, bytes: &[u8]) -> CaptureFile {
    let path = std::env::temp_dir().join(format!("jam194-{label}-{}.capture", std::process::id()));
    std::fs::write(&path, bytes).unwrap(); CaptureFile(path)
}
