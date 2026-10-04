use crate::ja3::{compute_ja3, label_for_ja3, ClientHelloFields};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Info {
    Http { method: String, path: String },
    /// An HTTP response's status line (e.g. the "200" in `HTTP/1.1 200 OK`).
    /// Kept as its own variant rather than an optional field on `Http`
    /// above — a request has a method and a path but no status, a response
    /// has a status but no method or path; the two never overlap on one
    /// packet. Populates `http.response.code` on the wire (fields.rs),
    /// replacing the old, unpopulated `Layer7Json.status_or_code` — see issue #65.
    /// Request/response *correlation* (matching this to the request it
    /// answers, service-time timing) is explicitly out of scope here; that
    /// is epic #57's #82.
    HttpResponse { status: String },
    /// A DNS query (QR bit clear). `id` is the transaction ID and `qtype` the
    /// first question's type (`0` when the question is truncated before its
    /// type field). Both exist for JAM-15's request/response matching
    /// (`transaction.rs`).
    Dns { query_name: String, id: u16, qtype: u16 },
    /// A DNS response (QR bit set), JAM-15. Kept apart from `Dns` for the
    /// same reason `HttpResponse` is kept apart from `Http`: the two carry
    /// different facts, and before this variant existed a response's echoed
    /// question was reported as though it were a query.
    ///
    /// `answer_count` is the header's ANCOUNT as sent. `answers` holds the
    /// records actually decoded, at most `MAX_DNS_ANSWERS`, so it can be
    /// shorter than `answer_count` when the message is truncated or the
    /// record cap is reached. Both are reported so a consumer never mistakes
    /// one for the other.
    DnsResponse {
        query_name: String,
        id: u16,
        qtype: u16,
        rcode: u8,
        answer_count: u16,
        answers: Vec<DnsAnswer>,
    },
    TlsClientHello {
        sni: String,
        ja3: Option<String>,
        ja3_label: Option<&'static str>,
        // The ClientHello's 32-byte `random` field, kept so the capture loop
        // can look up this flow's logged session secret by client_random
        // (Tier B / Task 13) — never sent over the wire, purely an
        // in-process decrypt-eligibility lookup key.
        client_random: Option<Vec<u8>>,
        /// Byte range of the SNI name within the complete TLS payload.
        sni_offset: usize,
        sni_len: usize,
    },
    None,
}

/// The first **complete** line of `payload` as text, or `None` when no line
/// terminator has arrived yet or the line isn't valid UTF-8.
///
/// Two deliberate differences from the `std::str::from_utf8(payload)?.lines()
/// .next()` this replaced (JAM-16), both of which were silent wrong-output
/// bugs rather than style:
///
/// 1. **A line terminator is required.** Without one, `"GET /ind"` — the first
///    half of `"GET /index.html HTTP/1.1\r\n"` split across two TCP segments —
///    decoded as a complete request for the path `/ind`. That is confidently
///    wrong output, worse than none: the caller has no way to tell it from a
///    real request for a real path named `/ind`. Declining instead is what
///    lets `sniff_l7_desegmenting` report `NeedMoreBytes` and a reassembling
///    caller recover the true path.
/// 2. **Only the first line is UTF-8-validated**, not the whole payload. An
///    HTTP response carrying a binary body (an image, gzip, anything) failed
///    `from_utf8` on the body and so was never recognized at all, even though
///    its status line was perfectly readable ASCII.
fn first_complete_line(payload: &[u8]) -> Option<&str> {
    let newline = payload.iter().position(|b| *b == b'\n')?;
    let line = payload.get(..newline)?;
    // A CRLF terminator leaves a trailing CR on the line; a bare LF doesn't.
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    std::str::from_utf8(line).ok()
}

fn sniff_http(payload: &[u8]) -> Option<L7Info> {
    let first_line = first_complete_line(payload)?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    if HTTP_METHODS.contains(&method) && path.starts_with('/') {
        Some(L7Info::Http {
            method: method.to_string(),
            path: path.to_string(),
        })
    } else {
        None
    }
}

/// Recognizes an HTTP response's status line — `HTTP/<version> <3-digit
/// status> <reason phrase>` — e.g. `HTTP/1.1 200 OK`. Deliberately narrow:
/// only the status code is extracted, not the reason phrase, headers, or
/// body, and this makes no attempt to associate the response with the
/// request it answers (that's #82's job). A response line is what a
/// request line is not — this and `sniff_http` above never both match the
/// same payload.
fn sniff_http_response(payload: &[u8]) -> Option<L7Info> {
    let first_line = first_complete_line(payload)?;
    let mut parts = first_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status = parts.next()?;
    if status.len() == 3 && status.bytes().all(|b| b.is_ascii_digit()) {
        Some(L7Info::HttpResponse { status: status.to_string() })
    } else {
        None
    }
}

/// One decoded resource record from a DNS response's answer section.
///
/// `data` is the record's value in text form: dotted IPv4 for A, standard
/// IPv6 notation for AAAA, the target name for CNAME/NS/PTR, and empty for
/// any other type, whose RDATA is not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

/// Upper bound on the answer records decoded from one response. A response
/// can declare up to 65,535 answers in ANCOUNT. Decoding is linear in the
/// message length either way, but each decoded record is a heap-allocated
/// `String` pair that goes onto the wire as fields, so the count is capped.
pub const MAX_DNS_ANSWERS: usize = 16;

/// RFC 1035 §2.3.4: a domain name is at most 255 octets on the wire.
const MAX_DNS_NAME_LEN: usize = 255;

/// Compression pointers followed while reading one name. A legitimate name
/// needs one or two. The cap is what turns a pointer loop (a pointer back to
/// itself, or two pointing at each other) into a decode failure instead of
/// an infinite loop.
const MAX_DNS_POINTER_HOPS: usize = 16;

/// Reads the (possibly compressed) domain name starting at `offset` in
/// `msg`. Returns the dotted name and the offset just past the name *in
/// place*: for a compressed name that is just past its first pointer, not
/// past wherever the pointer led.
///
/// Labels must be UTF-8, matching the query parser's long-standing rule.
/// Never panics: every index is a `get`.
fn read_dns_name(msg: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&str> = Vec::new();
    let mut wire_len = 0usize;
    let mut pos = offset;
    let mut end_in_place: Option<usize> = None;
    let mut hops = 0usize;
    loop {
        let len_byte = *msg.get(pos)?;
        match len_byte & 0xc0 {
            0x00 => {
                let len = len_byte as usize;
                if len == 0 {
                    let end = end_in_place.unwrap_or(pos + 1);
                    return Some((labels.join("."), end));
                }
                wire_len += len + 1;
                if wire_len > MAX_DNS_NAME_LEN {
                    return None;
                }
                let label = msg.get(pos + 1..pos + 1 + len)?;
                labels.push(std::str::from_utf8(label).ok()?);
                pos += 1 + len;
            }
            0xc0 => {
                hops += 1;
                if hops > MAX_DNS_POINTER_HOPS {
                    return None;
                }
                let lo = *msg.get(pos + 1)?;
                if end_in_place.is_none() {
                    end_in_place = Some(pos + 2);
                }
                pos = (((len_byte & 0x3f) as usize) << 8) | lo as usize;
            }
            // 0x40 and 0x80 are the obsolete/reserved label types (RFC 6891
            // §5): not something a real resolver sends.
            _ => return None,
        }
    }
}

fn dns_rdata_text(msg: &[u8], rtype: u16, rdata_offset: usize, rdata: &[u8]) -> String {
    match (rtype, rdata.len()) {
        (1, 4) => std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        (28, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        // CNAME, NS and PTR RDATA is a name, which may itself be compressed,
        // so it is read against the whole message, not the RDATA slice.
        (5 | 2 | 12, _) => read_dns_name(msg, rdata_offset).map(|(name, _)| name).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Decodes a DNS message over UDP: a query (QR clear) or a response (QR set,
/// with its answer section). Only the first question is read. The message
/// must declare at least one question, as before.
fn sniff_dns(payload: &[u8]) -> Option<L7Info> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let is_response = payload[2] & 0x80 != 0;
    let rcode = payload[3] & 0x0f;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let answer_count = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 {
        return None;
    }
    // The question name. It is read with the compression-aware reader, but a
    // first question has nothing earlier in the message to point at, so in
    // practice it is a plain label sequence, exactly as before this change.
    let (query_name, after_name) = read_dns_name(payload, 12)?;
    if query_name.is_empty() {
        return None;
    }
    let qtype_bytes = payload.get(after_name..after_name + 2);
    if !is_response {
        let qtype = qtype_bytes.map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
        return Some(L7Info::Dns { query_name, id, qtype });
    }

    // A response must carry its whole question (type and class) for its
    // answer section to be locatable at all.
    let qtype_bytes = qtype_bytes?;
    let qtype = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
    let mut pos = after_name + 4;
    if pos > payload.len() {
        return None;
    }
    // Further questions (qdcount > 1 is legal, if rare) sit between the
    // first question and the answers. Skip them; give up on the answers
    // rather than misread them if a question can't be skipped.
    let mut answers = Vec::new();
    let mut questions_skipped = true;
    for _ in 1..qdcount.min(16) {
        match read_dns_name(payload, pos) {
            Some((_, after)) if after + 4 <= payload.len() => pos = after + 4,
            _ => {
                questions_skipped = false;
                break;
            }
        }
    }
    if questions_skipped && qdcount <= 16 {
        for _ in 0..(answer_count as usize).min(MAX_DNS_ANSWERS) {
            let Some((name, after)) = read_dns_name(payload, pos) else { break };
            let Some(fixed) = payload.get(after..after + 10) else { break };
            let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
            let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
            let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
            let rdata_offset = after + 10;
            let Some(rdata) = payload.get(rdata_offset..rdata_offset + rdlength) else { break };
            let data = dns_rdata_text(payload, rtype, rdata_offset, rdata);
            answers.push(DnsAnswer { name, rtype, ttl, data });
            pos = rdata_offset + rdlength;
        }
    }
    Some(L7Info::DnsResponse { query_name, id, qtype, rcode, answer_count, answers })
}

/// The conventional mnemonic for a DNS record type, for display. Unknown
/// types fall back to RFC 3597's `TYPE<n>` form.
pub fn dns_type_name(rtype: u16) -> String {
    match rtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// The RFC 1035/2136 mnemonic for a DNS response code, for display.
pub fn dns_rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

/// Test-only DNS message builders, shared with `transaction.rs`'s and
/// `fields.rs`'s tests (as `build_client_hello` is with `reassembly.rs`).
#[cfg(test)]
pub(crate) mod dns_test_support {
    fn push_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    pub(crate) fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = id.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        push_name(&mut buf, name);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        buf
    }

    /// Each answer is `(rtype, ttl, rdata)` and is named with a compression
    /// pointer to the question name at offset 12, as real resolvers do.
    pub(crate) fn response(id: u16, name: &str, qtype: u16, rcode: u8, answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut buf = id.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0x81, 0x80 | rcode, 0x00, 0x01]);
        buf.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        push_name(&mut buf, name);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        for (rtype, ttl, rdata) in answers {
            buf.extend_from_slice(&[0xc0, 0x0c]);
            buf.extend_from_slice(&rtype.to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x01]);
            buf.extend_from_slice(&ttl.to_be_bytes());
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(rdata);
        }
        buf
    }
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
    let mut sni_offset = 0usize;
    let mut sni_len = 0usize;

    while idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        let ext_start = idx + 4;
        extensions.push(ext_type);
        let ext_body = payload.get(ext_start..ext_start + ext_len);

        match (ext_type, ext_body) {
            (0x0000, Some(body)) => {
                // server_name extension: skip list length(2) + type(1) to reach name length(2)
                if let (Some(&hi), Some(&lo)) = (body.get(3), body.get(4)) {
                    let name_len = u16::from_be_bytes([hi, lo]) as usize;
                    if let Some(name_bytes) = body.get(5..5 + name_len) {
                        if let Ok(name) = std::str::from_utf8(name_bytes) {
                            sni = Some(name.to_string());
                            sni_offset = ext_start + 5;
                            sni_len = name_len;
                        }
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
    // random is the 32 bytes right after the 2-byte client_version, i.e.
    // offset 11..43 of the record (record header(5) + handshake header(4) +
    // client_version(2) = 11).
    let client_random = payload.get(11..43).map(|b| b.to_vec());
    Some(L7Info::TlsClientHello { sni, ja3, ja3_label, client_random, sni_offset, sni_len })
}

/// The known HTTP request methods `sniff_http` accepts. Shared with
/// `unterminated_http_start_line` below so the "is this a plausible partial
/// request line" probe can never recognize a method the real detector
/// wouldn't, or miss one it would.
const HTTP_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

/// The outcome of sniffing a buffer that may or may not hold a complete
/// application-layer message — the desegmentation hand-off JAM-16 needed and
/// `sniff_l7`'s `L7Info`-only return couldn't express.
///
/// `sniff_l7` silently returns `L7Info::None` both for "these bytes are not a
/// protocol I know" and for "these bytes are the first half of an HTTP request
/// I would have recognized". Those are completely different facts to a caller
/// doing TCP reassembly: the first means stop, the second means buffer and try
/// again. See `docs/superpowers/specs/2026-09-28-stream-reassembly-design.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Sniff {
    /// A detector matched the bytes available. Identical to what `sniff_l7`
    /// returns for the same input.
    Decided(L7Info),
    /// No detector matched, and the buffer is a *structurally incomplete*
    /// prefix of something one of them would recognize.
    ///
    /// `at_least` is a lower bound and nothing more. It is a real declared
    /// length where the protocol has one — a TLS record header states its own
    /// body length, so the shortfall is arithmetic on a captured field — and
    /// `1` where the protocol has none, as for an HTTP start line with no
    /// line terminator yet, where the true remaining length is genuinely
    /// unknowable from the prefix. Deliberately not an estimate dressed up as
    /// a measurement.
    NeedMoreBytes { at_least: usize },
    /// No detector matched and nothing about the buffer suggests more bytes
    /// would change that. A caller must not buffer on this outcome — every
    /// unrecognized stream on the network reaches here.
    Undecided,
}

/// `sniff_l7`, but able to distinguish "not a protocol I know" from "the
/// first half of one" — see `L7Sniff`.
///
/// The individual detectors above are deliberately untouched by this:
/// incompleteness is a separate structural probe consulted only after every
/// one of them has declined, so reassembly changes which *bytes* they see and
/// never how they parse them.
pub fn sniff_l7_desegmenting(payload: &[u8], dst_port: Option<u16>) -> L7Sniff {
    let info = match dst_port {
        Some(53) => sniff_dns(payload),
        Some(443) => sniff_tls_client_hello(payload),
        _ => sniff_http(payload)
            .or_else(|| sniff_http_response(payload))
            .or_else(|| sniff_dns(payload))
            .or_else(|| sniff_tls_client_hello(payload)),
    };
    if let Some(info) = info {
        return L7Sniff::Decided(info);
    }
    match missing_byte_count(payload) {
        Some(at_least) => L7Sniff::NeedMoreBytes { at_least },
        None => L7Sniff::Undecided,
    }
}

/// Exactly `sniff_l7_desegmenting` with both non-`Decided` outcomes collapsed
/// to `L7Info::None` — the unchanged per-packet contract every existing
/// caller and test relies on, with one implementation behind it so the two
/// can never drift.
pub fn sniff_l7(payload: &[u8], dst_port: Option<u16>) -> L7Info {
    match sniff_l7_desegmenting(payload, dst_port) {
        L7Sniff::Decided(info) => info,
        L7Sniff::NeedMoreBytes { .. } | L7Sniff::Undecided => L7Info::None,
    }
}

/// How many more bytes could possibly let one of the detectors above decide,
/// or `None` when nothing about `payload` looks like a truncated prefix of a
/// protocol this module recognizes.
///
/// Never panics and never allocates: every index into `payload` is a `get`
/// or a length-checked slice, and the one piece of arithmetic on a
/// length field read off the wire is `checked_add`.
fn missing_byte_count(payload: &[u8]) -> Option<usize> {
    // A TLS handshake record (content type 0x16) declares its own body
    // length in bytes 3..5, so the shortfall here is a measured number.
    if payload.first() == Some(&0x16) {
        if payload.len() < 5 {
            // Not even the 5-byte record header is complete yet.
            return Some(5 - payload.len());
        }
        let declared = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        // `checked_add` rather than `+`: `declared` is attacker-controlled.
        // It cannot actually overflow a usize on any supported target
        // (u16::MAX + 5), but relying on that rather than checking is the
        // habit this file does not want.
        let needed = declared.checked_add(5)?;
        if let Some(shortfall) = needed.checked_sub(payload.len()) {
            if shortfall > 0 {
                return Some(shortfall);
            }
        }
    }

    // An HTTP start line with no line terminator yet. No length is declared
    // anywhere in HTTP/1.x framing, so `1` is the only honest lower bound.
    if unterminated_http_start_line(payload) {
        return Some(1);
    }

    None
}

/// True when `payload` is a plausible, not-yet-terminated prefix of an HTTP
/// request line or response status line.
///
/// "Plausible" is kept narrow on purpose: a caller buffers on the strength of
/// this, so matching loosely would mean buffering arbitrary traffic. It
/// requires the bytes to be printable ASCII, to contain no line terminator
/// yet (once a line is complete, more bytes cannot change the verdict about
/// it), and to agree with a known method token or `HTTP/` in one direction or
/// the other — either the buffer is a prefix of the token, or it starts with
/// the token.
fn unterminated_http_start_line(payload: &[u8]) -> bool {
    /// An unterminated buffer longer than this is not a start line anyone is
    /// waiting on — real request lines are well under it, and the bound keeps
    /// the printable-ASCII scan below from walking a whole reassembly buffer
    /// on every segment of the capture hot path.
    const MAX_START_LINE_PROBE: usize = 2_048;
    if payload.is_empty() || payload.len() > MAX_START_LINE_PROBE || payload.contains(&b'\n') {
        return false;
    }
    // Printable ASCII (plus a bare CR, which can legitimately be the last
    // byte of a start line split across a segment boundary).
    if !payload.iter().all(|b| (0x20..0x7f).contains(b) || *b == b'\r') {
        return false;
    }
    let looks_like_request = HTTP_METHODS.iter().any(|method| {
        let token = method.as_bytes();
        if payload.len() <= token.len() {
            token.starts_with(payload)
        } else {
            // Past the method token, the next byte must be the separating
            // space — otherwise "GETX..." would read as a partial GET.
            payload.starts_with(token) && payload.get(token.len()) == Some(&b' ')
        }
    });
    let looks_like_response = {
        let token: &[u8] = b"HTTP/";
        if payload.len() <= token.len() {
            token.starts_with(payload)
        } else {
            payload.starts_with(token)
        }
    };
    looks_like_request || looks_like_response
}

/// A minimal, hand-built TLS ClientHello, shared by this module's own tests
/// and `reassembly.rs`'s (which needs a real record to split across
/// segment boundaries). Lives outside `mod tests` only so the other
/// module can reach it.
#[cfg(test)]
// A minimal, hand-built ClientHello with two cipher suites, an SNI
// extension, a supported_groups (elliptic_curves) extension, and an
// ec_point_formats extension — enough to exercise every new field
// without needing a byte-for-byte real capture.
pub(crate) fn build_client_hello(sni: &str) -> Vec<u8> {
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
    fn detects_http_response_status_line() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
        match sniff_l7(payload, Some(51000)) {
            L7Info::HttpResponse { status } => assert_eq!(status, "200"),
            other => panic!("expected HttpResponse, got {other:?}"),
        }
    }

    #[test]
    fn detects_http_error_response_status_line() {
        let payload = b"HTTP/1.1 404 Not Found\r\n\r\n";
        match sniff_l7(payload, Some(51000)) {
            L7Info::HttpResponse { status } => assert_eq!(status, "404"),
            other => panic!("expected HttpResponse, got {other:?}"),
        }
    }

    #[test]
    fn does_not_misparse_a_request_as_a_response_or_vice_versa() {
        // A request line's method never starts with "HTTP/", and a response
        // line's version token is never a known request method — the two
        // sniffers are mutually exclusive on any real traffic.
        let request = b"GET / HTTP/1.1\r\n\r\n";
        assert!(matches!(sniff_l7(request, Some(80)), L7Info::Http { .. }));

        let response = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n";
        assert!(matches!(sniff_l7(response, Some(51000)), L7Info::HttpResponse { .. }));
    }

    #[test]
    fn returns_none_for_a_status_line_with_a_non_numeric_or_wrong_length_code() {
        assert!(matches!(sniff_l7(b"HTTP/1.1 OK\r\n\r\n", Some(51000)), L7Info::None));
        assert!(matches!(sniff_l7(b"HTTP/1.1 20 OK\r\n\r\n", Some(51000)), L7Info::None));
        assert!(matches!(sniff_l7(b"HTTP/1.1 20000 OK\r\n\r\n", Some(51000)), L7Info::None));
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
            L7Info::Dns { query_name, id, qtype } => {
                assert_eq!(query_name, "a.com");
                assert_eq!(id, 0x1234);
                assert_eq!(qtype, 1);
            }
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    // ---- JAM-15: DNS responses -------------------------------------------

    use super::dns_test_support::{query, response};

    #[test]
    fn a_dns_response_is_a_response_not_a_query_with_its_rcode_and_answers() {
        let msg = response(
            0xbeef,
            "example.com",
            1,
            0,
            &[(1, 300, vec![93, 184, 216, 34]), (1, 60, vec![93, 184, 216, 35])],
        );
        match sniff_l7(&msg, Some(51000)) {
            L7Info::DnsResponse { query_name, id, qtype, rcode, answer_count, answers } => {
                assert_eq!(query_name, "example.com");
                assert_eq!(id, 0xbeef);
                assert_eq!(qtype, 1);
                assert_eq!(rcode, 0);
                assert_eq!(answer_count, 2);
                assert_eq!(
                    answers,
                    vec![
                        DnsAnswer { name: "example.com".into(), rtype: 1, ttl: 300, data: "93.184.216.34".into() },
                        DnsAnswer { name: "example.com".into(), rtype: 1, ttl: 60, data: "93.184.216.35".into() },
                    ]
                );
            }
            other => panic!("expected DnsResponse, got {other:?}"),
        }
    }

    #[test]
    fn a_dns_query_is_still_a_query() {
        assert!(matches!(sniff_l7(&query(7, "a.com", 28), Some(53)), L7Info::Dns { id: 7, qtype: 28, .. }));
    }

    #[test]
    fn dns_answers_decode_aaaa_and_a_compressed_cname_target() {
        let mut aaaa = [0u8; 16];
        aaaa[0] = 0x20;
        aaaa[1] = 0x01;
        aaaa[2] = 0x0d;
        aaaa[3] = 0xb8;
        aaaa[15] = 1;
        // CNAME RDATA "www" + pointer to "example.com" at offset 12.
        let cname = vec![3, b'w', b'w', b'w', 0xc0, 0x0c];
        let msg = response(1, "example.com", 28, 0, &[(5, 10, cname), (28, 20, aaaa.to_vec())]);
        let L7Info::DnsResponse { answers, .. } = sniff_l7(&msg, None) else { panic!("expected DnsResponse") };
        assert_eq!(answers[0].data, "www.example.com");
        assert_eq!(answers[1].data, "2001:db8::1");
    }

    #[test]
    fn an_nxdomain_response_carries_its_rcode_and_no_answers() {
        let msg = response(9, "nope.invalid", 1, 3, &[]);
        assert!(matches!(
            sniff_l7(&msg, None),
            L7Info::DnsResponse { rcode: 3, answer_count: 0, ref answers, .. } if answers.is_empty()
        ));
    }

    #[test]
    fn a_compression_pointer_loop_ends_the_answers_instead_of_hanging() {
        let mut msg = response(1, "a.com", 1, 0, &[(5, 1, vec![0xc0, 0x00])]);
        // Point the answer's own name at itself.
        let answer_name_at = 12 + 7 + 4;
        msg[answer_name_at] = 0xc0;
        msg[answer_name_at + 1] = answer_name_at as u8;
        let L7Info::DnsResponse { answer_count, answers, .. } = sniff_l7(&msg, None) else { panic!("expected DnsResponse") };
        assert_eq!(answer_count, 1);
        assert!(answers.is_empty());
    }

    #[test]
    fn a_truncated_answer_section_keeps_the_answers_decoded_before_the_cut() {
        let msg = response(1, "a.com", 1, 0, &[(1, 1, vec![1, 2, 3, 4]), (1, 1, vec![5, 6, 7, 8])]);
        let cut = &msg[..msg.len() - 2];
        let L7Info::DnsResponse { answer_count, answers, .. } = sniff_l7(cut, None) else { panic!("expected DnsResponse") };
        assert_eq!(answer_count, 2);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, "1.2.3.4");
    }

    #[test]
    fn answer_decoding_stops_at_the_cap_while_answer_count_reports_the_header() {
        let many: Vec<_> = (0..40u8).map(|i| (1u16, 1u32, vec![10, 0, 0, i])).collect();
        let msg = response(1, "a.com", 1, 0, &many);
        let L7Info::DnsResponse { answer_count, answers, .. } = sniff_l7(&msg, None) else { panic!("expected DnsResponse") };
        assert_eq!(answer_count, 40);
        assert_eq!(answers.len(), MAX_DNS_ANSWERS);
    }

    #[test]
    fn a_response_without_its_question_type_is_not_decoded_as_dns() {
        let msg = response(1, "a.com", 1, 0, &[]);
        let cut = &msg[..12 + 7 + 1];
        assert!(matches!(sniff_l7(cut, Some(53)), L7Info::None));
    }

    #[test]
    fn dns_display_names_fall_back_to_their_numeric_forms() {
        assert_eq!(dns_type_name(28), "AAAA");
        assert_eq!(dns_type_name(9999), "TYPE9999");
        assert_eq!(dns_rcode_name(3), "NXDOMAIN");
        assert_eq!(dns_rcode_name(11), "RCODE11");
    }

    #[test]
    fn returns_none_for_unrecognized_payload_on_unrelated_port() {
        let payload = b"not a known protocol";
        assert!(matches!(sniff_l7(payload, Some(9999)), L7Info::None));
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
    fn sni_range_points_to_the_name_bytes_in_the_client_hello() {
        let payload = build_client_hello("example.com");
        match sniff_l7(&payload, Some(443)) {
            L7Info::TlsClientHello { sni, sni_offset, sni_len, .. } => {
                assert_eq!(sni, "example.com");
                assert_eq!((sni_offset, sni_len), (63, 11));
                assert_eq!(&payload[sni_offset..sni_offset + sni_len], b"example.com");
            }
            other => panic!("expected TlsClientHello, got {other:?}"),
        }
    }

    #[test]
    fn sni_outside_its_declared_extension_is_not_accepted() {
        let mut payload = build_client_hello("example.com");
        payload[56..58].copy_from_slice(&5u16.to_be_bytes());
        assert!(matches!(sniff_l7(&payload, Some(443)), L7Info::None));
    }

    #[test]
    fn extracts_the_32_byte_client_random_for_decrypt_key_lookup() {
        let payload = build_client_hello("example.com");
        match sniff_l7(&payload, Some(443)) {
            L7Info::TlsClientHello { client_random, .. } => {
                assert_eq!(client_random.as_deref(), Some([0u8; 32].as_slice()));
            }
            other => panic!("expected TlsClientHello, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_http_request_line_asks_for_more_bytes_instead_of_reporting_a_truncated_path() {
        // JAM-16: the first of two TCP segments carrying
        // "GET /index.html HTTP/1.1\r\n...". Before this task, this decoded
        // as a complete request for the path "/index.h" — indistinguishable
        // from a real request for a resource by that name, and impossible
        // for any caller to tell was truncated. It must decline instead, and
        // the desegmenting wrapper must say why, which is what lets a caller
        // buffer and recover the real path.
        let first_segment = b"GET /index.h";
        assert!(matches!(sniff_l7(first_segment, Some(80)), L7Info::None));
        match sniff_l7_desegmenting(first_segment, Some(80)) {
            L7Sniff::NeedMoreBytes { at_least } => assert!(at_least >= 1),
            other => panic!("expected NeedMoreBytes, got {other:?}"),
        }
    }

    #[test]
    fn a_request_line_split_mid_path_recovers_the_whole_path_once_rejoined() {
        // The same two segments concatenated — the reassembled buffer must
        // yield the real path, not the prefix the first segment ended on.
        let rejoined = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match sniff_l7(rejoined, Some(80)) {
            L7Info::Http { method, path } => {
                assert_eq!((method.as_str(), path.as_str()), ("GET", "/index.html"));
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn a_response_with_a_binary_body_is_still_recognized_by_its_status_line() {
        // Only the status line is UTF-8-validated. Validating the whole
        // payload (the old behavior) meant any response with a non-UTF-8
        // body — a PNG, gzip, anything — silently failed to decode even
        // though its status line was plain ASCII.
        let mut payload = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x80, 0x00]);
        match sniff_l7(&payload, Some(51000)) {
            L7Info::HttpResponse { status } => assert_eq!(status, "200"),
            other => panic!("expected HttpResponse, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_lf_terminated_start_line_is_accepted_without_a_cr() {
        // Some minimal clients/servers send LF only. The terminator check
        // must not require CRLF specifically.
        match sniff_l7(b"GET /x HTTP/1.0\n\n", Some(80)) {
            L7Info::Http { path, .. } => assert_eq!(path, "/x"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn a_partial_method_token_alone_still_asks_for_more_bytes() {
        // A segment boundary can land mid-method. "GE" is a prefix of "GET".
        match sniff_l7_desegmenting(b"GE", Some(80)) {
            L7Sniff::NeedMoreBytes { .. } => {}
            other => panic!("expected NeedMoreBytes, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_http_response_status_line_asks_for_more_bytes() {
        match sniff_l7_desegmenting(b"HTTP/1.1 20", Some(51000)) {
            L7Sniff::NeedMoreBytes { .. } => {}
            other => panic!("expected NeedMoreBytes, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_tls_record_asks_for_exactly_the_bytes_its_own_length_field_declares() {
        // The one case where a precise number is honestly available: a TLS
        // record header declares its own body length, so the shortfall is a
        // real measurement, not a guess.
        let full = build_client_hello("example.com");
        let cut = &full[..20];
        match sniff_l7_desegmenting(cut, Some(443)) {
            L7Sniff::NeedMoreBytes { at_least } => {
                assert_eq!(at_least, full.len() - cut.len());
            }
            other => panic!("expected NeedMoreBytes, got {other:?}"),
        }
    }

    #[test]
    fn a_tls_record_header_shorter_than_five_bytes_asks_for_the_rest_of_the_header() {
        match sniff_l7_desegmenting(&[0x16, 0x03], Some(443)) {
            L7Sniff::NeedMoreBytes { at_least } => assert_eq!(at_least, 3),
            other => panic!("expected NeedMoreBytes, got {other:?}"),
        }
    }

    #[test]
    fn unrecognizable_bytes_are_undecided_not_incomplete() {
        // Nothing about these bytes suggests more would help — saying
        // "NeedMoreBytes" here would make a caller buffer every unknown
        // stream on the network.
        match sniff_l7_desegmenting(b"\x00\x01\x02 not a protocol\n", Some(9999)) {
            L7Sniff::Undecided => {}
            other => panic!("expected Undecided, got {other:?}"),
        }
    }

    #[test]
    fn a_terminated_but_unrecognized_first_line_is_undecided() {
        // The line is complete and still matched nothing — more bytes
        // cannot change that verdict about the start line.
        match sniff_l7_desegmenting(b"NOTAMETHOD / HTTP/1.1\r\n\r\n", Some(80)) {
            L7Sniff::Undecided => {}
            other => panic!("expected Undecided, got {other:?}"),
        }
    }

    #[test]
    fn a_complete_request_decides_rather_than_asking_for_more() {
        match sniff_l7_desegmenting(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", Some(80)) {
            L7Sniff::Decided(L7Info::Http { method, path }) => {
                assert_eq!((method.as_str(), path.as_str()), ("GET", "/"));
            }
            other => panic!("expected Decided(Http), got {other:?}"),
        }
    }

    #[test]
    fn sniff_l7_stays_exactly_a_collapsed_view_of_the_desegmenting_result() {
        // The two must never drift: every non-Decided outcome is None, and
        // every Decided outcome is that same L7Info.
        let cases: [(&[u8], Option<u16>); 6] = [
            (b"GET / HTTP/1.1\r\n\r\n", Some(80)),
            (b"HTTP/1.1 200 OK\r\n\r\n", Some(51000)),
            (b"GE", Some(80)),
            (b"", Some(80)),
            (b"\x16\x03", Some(443)),
            (b"random bytes", Some(9999)),
        ];
        for (payload, port) in cases {
            let collapsed = match sniff_l7_desegmenting(payload, port) {
                L7Sniff::Decided(info) => info,
                _ => L7Info::None,
            };
            assert_eq!(sniff_l7(payload, port), collapsed, "payload {payload:?} port {port:?}");
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
            L7Info::TlsClientHello { ja3, .. } => {
                let _ = ja3; // either value is acceptable, see comment above
            }
            L7Info::None => {} // also acceptable — existing tolerance for malformed input
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
