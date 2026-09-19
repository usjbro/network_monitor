//! A hand-rolled pcapng encoder and decoder (issue #70/#71, JAM-132/JAM-133).
//! Deliberately narrow: four block types (Section Header, Interface
//! Description, Enhanced Packet, Interface Statistics), no Name Resolution
//! or Decryption Secrets blocks, no per-packet comments. See
//! docs/superpowers/specs/2026-09-19-capture-files-design.md Components §1
//! for why this is hand-rolled rather than a new crate dependency.
use std::io::{self, Write};

const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const BT_SECTION_HEADER: u32 = 0x0A0D_0D0A;
const BT_INTERFACE_DESCRIPTION: u32 = 0x0000_0001;

const OPT_END_OF_OPT: u16 = 0;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;

/// Rounds `n` up to the next multiple of 4 — every pcapng block body, and
/// every option value, is padded to a 32-bit boundary.
fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Writes one option's TLV (code, length, value, padding) — shared by every
/// block type, since pcapng's option encoding is identical regardless of
/// which block or which option code is being written.
fn write_option(w: &mut impl Write, code: u16, value: &[u8]) -> io::Result<()> {
    w.write_all(&code.to_le_bytes())?;
    w.write_all(&(value.len() as u16).to_le_bytes())?;
    w.write_all(value)?;
    let padding = pad4(value.len()) - value.len();
    w.write_all(&vec![0u8; padding])
}

fn write_end_of_opt(w: &mut impl Write) -> io::Result<()> {
    w.write_all(&OPT_END_OF_OPT.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())
}

/// Writes one full block: type, length, body, length repeated. `body` must
/// already end on a 4-byte boundary — every block-body builder below
/// guarantees this by construction (every option is padded, and the
/// fixed-width fields before the options are all already multiples of 4).
fn write_block(w: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let total_len = 12 + body.len() as u32; // type + len + body + len
    w.write_all(&block_type.to_le_bytes())?;
    w.write_all(&total_len.to_le_bytes())?;
    w.write_all(body)?;
    w.write_all(&total_len.to_le_bytes())
}

/// Section Header Block — written once, at file open.
pub struct SectionHeaderBlock {
    pub hostname: String,
    pub agent_version: String,
}

impl SectionHeaderBlock {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major version
        body.extend_from_slice(&0u16.to_le_bytes()); // minor version
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown

        let userappl = format!("capture-agent/{} on {}", self.agent_version, self.hostname);
        write_option(&mut body, SHB_USERAPPL, userappl.as_bytes())?;
        write_end_of_opt(&mut body)?;

        write_block(w, BT_SECTION_HEADER, &body)
    }
}

/// pcapng LINKTYPE_* values this agent can produce — a small, closed
/// mapping from `parse::LinkType` (the agent's own internal link-type enum,
/// already resolved once at startup), not a general-purpose pcapng
/// linktype table.
fn pcapng_linktype(link_type: crate::parse::LinkType) -> u16 {
    match link_type {
        crate::parse::LinkType::Ethernet => 1,     // LINKTYPE_ETHERNET
        crate::parse::LinkType::NullLoopback => 0, // LINKTYPE_NULL
        crate::parse::LinkType::Raw => 101,        // LINKTYPE_RAW
    }
}

/// Interface Description Block — written once, at file open.
#[derive(Clone)]
pub struct InterfaceDescriptionBlock {
    pub interface_name: String,
    pub link_type: crate::parse::LinkType,
    pub snaplen: u32,
    /// Honest per the platform clock's actual resolution. `9` means
    /// nanosecond (10^-9); pcapng's `if_tsresol` encodes resolution as a
    /// power-of-ten exponent with the high bit clear, so a plain byte value
    /// of the exponent is correct here.
    pub timestamp_resolution_exponent: u8,
}

impl InterfaceDescriptionBlock {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcapng_linktype(self.link_type).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&self.snaplen.to_le_bytes());

        write_option(&mut body, IF_NAME, self.interface_name.as_bytes())?;
        write_option(&mut body, IF_TSRESOL, &[self.timestamp_resolution_exponent])?;
        write_end_of_opt(&mut body)?;

        write_block(w, BT_INTERFACE_DESCRIPTION, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_block_header(bytes: &[u8]) -> (u32, u32) {
        let block_type = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let total_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        (block_type, total_len)
    }

    #[test]
    fn every_written_block_has_matching_length_prefix_and_suffix() {
        let mut buf = Vec::new();
        SectionHeaderBlock {
            hostname: "test-host".into(),
            agent_version: "0.1.0".into(),
        }
        .write_to(&mut buf)
        .unwrap();
        let (block_type, total_len) = parse_block_header(&buf);
        assert_eq!(block_type, BT_SECTION_HEADER);
        assert_eq!(buf.len(), total_len as usize);
        let suffix = u32::from_le_bytes(buf[buf.len() - 4..].try_into().unwrap());
        assert_eq!(suffix, total_len);
    }

    #[test]
    fn block_length_is_always_a_multiple_of_four() {
        let mut buf = Vec::new();
        // An odd-length interface name forces the padding path — this is
        // exactly the case most likely to produce a misaligned block if
        // write_option's padding math is wrong.
        InterfaceDescriptionBlock {
            interface_name: "en0x".into(), // 4 bytes
            link_type: crate::parse::LinkType::Ethernet,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        }
        .write_to(&mut buf)
        .unwrap();
        assert_eq!(buf.len() % 4, 0);

        buf.clear();
        InterfaceDescriptionBlock {
            interface_name: "lo".into(), // 2 bytes — odd relative to 4-byte option padding
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 6,
        }
        .write_to(&mut buf)
        .unwrap();
        assert_eq!(buf.len() % 4, 0);
    }

    #[test]
    fn pcapng_linktype_maps_each_supported_link_type_to_a_distinct_value() {
        let values: Vec<u16> = [
            crate::parse::LinkType::Ethernet,
            crate::parse::LinkType::NullLoopback,
            crate::parse::LinkType::Raw,
        ]
        .into_iter()
        .map(pcapng_linktype)
        .collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len(), "each LinkType must map to a distinct pcapng LINKTYPE_*");
    }

    #[test]
    fn section_header_block_userappl_option_contains_hostname_and_version() {
        let mut buf = Vec::new();
        SectionHeaderBlock {
            hostname: "my-mac".into(),
            agent_version: "0.1.0".into(),
        }
        .write_to(&mut buf)
        .unwrap();
        let haystack = String::from_utf8_lossy(&buf);
        assert!(haystack.contains("my-mac"));
        assert!(haystack.contains("0.1.0"));
    }
}
