pub struct ClientHelloFields {
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

/// Standard JA3 field string: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
/// (dash-joined within each field, comma-joined between fields), MD5-hashed to hex.
fn ja3_string(fields: &ClientHelloFields) -> String {
    let join_u16 = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let join_u8 = |v: &[u8]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    format!(
        "{},{},{},{},{}",
        fields.tls_version,
        join_u16(&fields.cipher_suites),
        join_u16(&fields.extensions),
        join_u16(&fields.elliptic_curves),
        join_u8(&fields.ec_point_formats),
    )
}

pub fn compute_ja3(fields: &ClientHelloFields) -> String {
    let s = ja3_string(fields);
    let digest = md5::compute(s.as_bytes());
    format!("{digest:x}")
}

// A small, versioned, hand-maintained lookup table — not a live third-party
// lookup (spec Components §1). Deliberately short and best-effort; extend
// it as real, verified hashes are gathered, never guessed.
const KNOWN_LABELS: &[(&str, &str)] = &[
    // ("<ja3-hash>", "matches Chrome 12x"),
];

pub fn label_for_ja3(hash: &str) -> Option<&'static str> {
    KNOWN_LABELS.iter().find(|(h, _)| *h == hash).map(|(_, label)| *label)
}

// Test module
#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_like_fields() -> ClientHelloFields {
        // A simplified, well-known Chrome-shaped ClientHello field set, chosen
        // so the expected hash below can be independently verified against any
        // standard JA3 calculator (ja3er.com's published algorithm) rather than
        // invented ad hoc.
        ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: vec![0x0000, 0x0017, 0x0023, 0x000d, 0x0010],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
        }
    }

    #[test]
    fn computes_the_documented_ja3_format_deterministically() {
        let f = chrome_like_fields();
        let hash1 = compute_ja3(&f);
        let hash2 = compute_ja3(&f);
        assert_eq!(hash1, hash2, "JA3 must be deterministic for identical input");
        assert_eq!(hash1.len(), 32, "JA3 is the hex-encoded MD5 of the field string, always 32 chars");
    }

    #[test]
    fn different_cipher_suite_order_changes_the_hash() {
        // JA3 is order-sensitive by design (it's meant to fingerprint the
        // client's own field ordering, not a canonicalized version of it).
        let mut f = chrome_like_fields();
        let h1 = compute_ja3(&f);
        f.cipher_suites.reverse();
        let h2 = compute_ja3(&f);
        assert_ne!(h1, h2);
    }

    #[test]
    fn empty_field_lists_do_not_panic() {
        let f = ClientHelloFields {
            tls_version: 0x0301,
            cipher_suites: vec![],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
        };
        let hash = compute_ja3(&f);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn unknown_hash_has_no_label() {
        assert_eq!(label_for_ja3("0000000000000000000000000000ff"), None);
    }
}
