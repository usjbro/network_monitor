#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Info {
    Http { method: String, path: String },
    Dns { query_name: String },
    TlsClientHello { sni: String },
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
    // the extensions block, then find the SNI extension (type 0x0000).
    let mut idx = 43usize; // fixed portion: record(5) + handshake(4) + version(2) + random(32)
    let session_id_len = *payload.get(idx)? as usize;
    idx += 1 + session_id_len;
    let cipher_suites_len = u16::from_be_bytes([*payload.get(idx)?, *payload.get(idx + 1)?]) as usize;
    idx += 2 + cipher_suites_len;
    let compression_len = *payload.get(idx)? as usize;
    idx += 1 + compression_len;
    if idx + 2 > payload.len() {
        return None;
    }
    idx += 2; // extensions total length
    while idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        let ext_start = idx + 4;
        if ext_type == 0x0000 {
            // server_name extension: skip list length(2) + type(1) to reach name length(2)
            let name_len_idx = ext_start + 3;
            let name_len = u16::from_be_bytes([
                *payload.get(name_len_idx)?,
                *payload.get(name_len_idx + 1)?,
            ]) as usize;
            let name_start = name_len_idx + 2;
            let name_bytes = payload.get(name_start..name_start + name_len)?;
            let sni = std::str::from_utf8(name_bytes).ok()?.to_string();
            return Some(L7Info::TlsClientHello { sni });
        }
        idx = ext_start + ext_len;
    }
    None
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
}
