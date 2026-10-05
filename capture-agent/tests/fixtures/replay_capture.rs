//! Minimal independent classic-pcap and pcapng fixtures with real length metadata.
use std::path::PathBuf;

pub struct CaptureFile(pub PathBuf);
impl Drop for CaptureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let len = (body.len() + 12) as u32;
    out.extend(kind.to_le_bytes());
    out.extend(len.to_le_bytes());
    out.extend(body);
    out.extend(len.to_le_bytes());
}

pub fn fixture(format: &str, label: &str, data: &[u8], original_len: u32) -> CaptureFile {
    let path = std::env::temp_dir().join(format!("jam174-{label}-{}.{format}", std::process::id()));
    let mut out = Vec::new();
    let caplen = data.len() as u32;
    if format == "pcapng" {
        let mut shb = Vec::new();
        shb.extend(0x1a2b3c4du32.to_le_bytes());
        shb.extend(1u16.to_le_bytes());
        shb.extend(0u16.to_le_bytes());
        shb.extend((-1i64).to_le_bytes());
        block(&mut out, 0x0a0d0d0a, &shb);
        let mut idb = Vec::new();
        idb.extend(1u16.to_le_bytes()); // LINKTYPE_ETHERNET
        idb.extend(0u16.to_le_bytes());
        idb.extend(caplen.to_le_bytes()); // small recorded snaplen
        block(&mut out, 1, &idb);
        for timestamp in [0u32, 1] {
            let mut epb = Vec::new();
            epb.extend(0u32.to_le_bytes()); // interface ID
            epb.extend(0u32.to_le_bytes()); // timestamp high
            epb.extend(timestamp.to_le_bytes());
            epb.extend(caplen.to_le_bytes());
            epb.extend(original_len.to_le_bytes());
            epb.extend(data);
            epb.resize((epb.len() + 3) & !3, 0);
            block(&mut out, 6, &epb);
        }
    } else {
        out.extend(0xa1b2c3d4u32.to_le_bytes());
        out.extend(2u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.extend(0u32.to_le_bytes()); // timezone
        out.extend(0u32.to_le_bytes()); // sigfigs
        out.extend(caplen.to_le_bytes());
        out.extend(1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        for timestamp in [0u32, 1] {
            out.extend(0u32.to_le_bytes());
            out.extend(timestamp.to_le_bytes());
            out.extend(caplen.to_le_bytes());
            out.extend(original_len.to_le_bytes());
            out.extend(data);
        }
    }
    std::fs::write(&path, out).unwrap();
    CaptureFile(path)
}
