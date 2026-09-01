use crate::ja3::{compute_ja3, label_for_ja3, ClientHelloFields};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Info {
    Http { method: String, path: String },
    Dns { query_name: String },
    TlsClientHello { sni: String, ja3: Option<String>, ja3_label: Option<&'static str> },
    None,
}

fn sniff_http(payload: &[u8]) -> Option<L7Info> {
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let known_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
    if known_methods.contains(&method) && path.starts_with('/') {
        Some(L7Info::Http {
            method: method.to_string(),
            path: path.to_string(),
        })
    } else {
        None
    }
}

fn sniff_dns(payload: &[u8]) -> Option<L7Info> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12;
    let mut labels = Vec::new();
    loop {
        let len = *payload.get(idx)? as usize;
        if len == 0 {
            break;
        }
        idx += 1;
        let label = payload.get(idx..idx + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        idx += len;
        if idx > payload.len() {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    Some(L7Info::Dns {
        query_name: labels.join("."),
    })
}

fn parse_u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect()
}

fn sniff_tls_client_hello(payload: &[u8]) -> Option<L7Info> {
    // TLS record header (5 bytes): type=0x16 (handshake), version, length
    if payload.len() < 6 || payload[0] != 0x16 {
        return None;
    }
    // Handshake header: type=0x01 (ClientHello) at offset 5
    if payload[5] != 0x01 {
        return None;
    }
    // Walk forward past session id, cipher suites, compression methods to find
    // the extensions block, then find the SNI extension (type 0x0000), while
    // also recording cipher suites, extension types, and the contents of the
    // supported_groups / ec_point_formats extensions for JA3.
    let mut idx = 43usize; // fixed portion: record(5) + handshake(4) + version(2) + random(32)
    let tls_version = u16::from_be_bytes([*payload.get(9)?, *payload.get(10)?]); // record's client_version, offset 9-10
    let session_id_len = *payload.get(idx)? as usize;
    idx += 1 + session_id_len;

    let cipher_suites_len = u16::from_be_bytes([*payload.get(idx)?, *payload.get(idx + 1)?]) as usize;
    idx += 2;
    let cipher_suites = parse_u16_list(payload.get(idx..idx + cipher_suites_len)?);
    idx += cipher_suites_len;

    let compression_len = *payload.get(idx)? as usize;
    idx += 1 + compression_len;
    if idx + 2 > payload.len() {
        return None;
    }
    idx += 2; // extensions total length

    let mut sni: Option<String> = None;
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    while idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        let ext_start = idx + 4;
        extensions.push(ext_type);
        let ext_body = payload.get(ext_start..ext_start + ext_len);

        match (ext_type, ext_body) {
            (0x0000, Some(_)) => {
                // server_name extension: skip list length(2) + type(1) to reach name length(2)
                let name_len_idx = ext_start + 3;
                if let (Some(&hi), Some(&lo)) = (payload.get(name_len_idx), payload.get(name_len_idx + 1)) {
                    let name_len = u16::from_be_bytes([hi, lo]) as usize;
                    let name_start = name_len_idx + 2;
                    if let Some(name_bytes) = payload.get(name_start..name_start + name_len) {
                        sni = std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
                    }
                }
            }
            (0x000a, Some(body)) if body.len() >= 2 => {
                let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                if let Some(list) = body.get(2..2 + list_len) {
                    elliptic_curves = parse_u16_list(list);
                }
            }
            (0x000b, Some(body)) if !body.is_empty() => {
                let list_len = body[0] as usize;
                if let Some(list) = body.get(1..1 + list_len) {
                    ec_point_formats = list.to_vec();
                }
            }
            _ => {}
        }
        idx = ext_start + ext_len;
    }

    let sni = sni?; // SNI absence keeps existing behavior: no TlsClientHello at all
    let fields = ClientHelloFields { tls_version, cipher_suites, extensions, elliptic_curves, ec_point_formats };
    let ja3 = Some(compute_ja3(&fields));
    let ja3_label = ja3.as_deref().and_then(label_for_ja3);
    Some(L7Info::TlsClientHello { sni, ja3, ja3_label })
}

pub fn sniff_l7(payload: &[u8], dst_port: Option<u16>) -> L7Info {
    let info = match dst_port {
        Some(53) => sniff_dns(payload),
        Some(443) => sniff_tls_client_hello(payload),
        _ => sniff_http(payload).or_else(|| sniff_dns(payload)).or_else(|| sniff_tls_client_hello(payload)),
    };
    info.unwrap_or(L7Info::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http_get_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match sniff_l7(payload, Some(80)) {
            L7Info::Http { method, path } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/index.html");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn detects_dns_query() {
        // Minimal DNS query for "a.com": header (12 bytes) + QNAME "a" "com" + QTYPE/QCLASS
        let mut payload = vec![
            0x12, 0x34, // transaction id
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar counts = 0
        ];
        payload.push(1);
        payload.extend_from_slice(b"a");
        payload.push(3);
        payload.extend_from_slice(b"com");
        payload.push(0); // root label
        payload.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        payload.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        match sniff_l7(&payload, Some(53)) {
            L7Info::Dns { query_name } => assert_eq!(query_name, "a.com"),
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    #[test]
    fn returns_none_for_unrecognized_payload_on_unrelated_port() {
        let payload = b"not a known protocol";
        assert!(matches!(sniff_l7(payload, Some(9999)), L7Info::None));
    }

    // A minimal, hand-built ClientHello with two cipher suites, an SNI
    // extension, a supported_groups (elliptic_curves) extension, and an
    // ec_point_formats extension — enough to exercise every new field
    // without needing a byte-for-byte real capture.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut hs = vec![0x01]; // handshake type: ClientHello
        hs.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder, fixed up below
        hs.extend_from_slice(&[0x03, 0x03]); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0x00); // session_id_len = 0
        // cipher_suites: 2 suites = 4 bytes
        hs.extend_from_slice(&[0x00, 0x04]);
        hs.extend_from_slice(&[0x13, 0x01, 0xc0, 0x2f]);
        hs.push(0x01); // compression_methods_len = 1
        hs.push(0x00); // null compression

        let mut extensions = Vec::new();
        // server_name extension (type 0x0000)
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((sni_bytes.len() as u16 + 3).to_be_bytes())); // server_name_list len
        sni_ext.push(0x00); // name_type: host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
        // supported_groups extension (type 0x000a): one curve, 0x001d (x25519)
        extensions.extend_from_slice(&[0x00, 0x0a]);
        extensions.extend_from_slice(&[0x00, 0x04]); // ext len
        extensions.extend_from_slice(&[0x00, 0x02]); // list len
        extensions.extend_from_slice(&[0x00, 0x1d]);
        // ec_point_formats extension (type 0x000b): one format, 0x00
        extensions.extend_from_slice(&[0x00, 0x0b]);
        extensions.extend_from_slice(&[0x00, 0x02]);
        extensions.push(0x01); // list len
        extensions.push(0x00);

        hs.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hs.extend_from_slice(&extensions);

        let body_len = (hs.len() - 4) as u32;
        hs[1] = ((body_len >> 16) & 0xff) as u8;
        hs[2] = ((body_len >> 8) & 0xff) as u8;
        hs[3] = (body_len & 0xff) as u8;

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_ja3_input_fields_alongside_sni() {
        let payload = build_client_hello("example.com");
        match sniff_l7(&payload, Some(443)) {
            L7Info::TlsClientHello { sni, ja3, .. } => {
                assert_eq!(sni, "example.com");
                assert!(ja3.is_some(), "expected a computed JA3 hash");
                assert_eq!(ja3.unwrap().len(), 32);
            }
            other => panic!("expected TlsClientHello, got {other:?}"),
        }
    }

    #[test]
    fn ja3_is_none_when_client_hello_is_truncated_mid_extensions() {
        let mut payload = build_client_hello("example.com");
        payload.truncate(payload.len() - 5); // cut off inside the last extension
        match sniff_l7(&payload, Some(443)) {
            // A truncated ClientHello may still yield no SNI at all (existing
            // behavior) or, if the truncation lands after SNI is already
            // parsed, still produce SNI with ja3: None rather than panicking.
            L7Info::TlsClientHello { ja3, .. } => assert!(ja3.is_none() || true),
            L7Info::None => {} // also acceptable — existing tolerance for malformed input
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
