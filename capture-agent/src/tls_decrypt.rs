use crate::keylog::SessionSecret;
use ring::aead;
use ring::hkdf;

pub enum DecryptOutcome {
    Plaintext(Vec<u8>),
    Undecryptable { reason: &'static str },
}

/// RFC 8446 §7.1 HKDF-Expand-Label, restricted to the fixed-length outputs
/// this module needs (16-byte key, 12-byte IV) — a general-purpose
/// variable-length version is not needed here and would be untested dead
/// code for any length this call site never uses.
fn hkdf_expand_label(secret: &[u8], label: &str, out_len: usize) -> Option<Vec<u8>> {
    // RFC 8446 §7.1: HKDF-Expand-Label uses the given secret directly AS
    // the PRK for HKDF-Expand — there is no additional HKDF-Extract step
    // here (that already happened earlier in the key schedule, when this
    // traffic secret was itself derived). `Prk::new_less_safe` constructs a
    // PRK from raw bytes without re-extracting.
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    // HkdfLabel structure: length(2) || "tls13 " + label (1-byte len prefixed) || context (1-byte len prefixed, empty here)
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(out_len as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(0); // empty context

    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let info = [hkdf_label.as_slice()];
    let okm = prk.expand(&info, Len(out_len)).ok()?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

fn derive_key_and_iv(traffic_secret: &[u8]) -> Option<([u8; 16], [u8; 12])> {
    let key_bytes = hkdf_expand_label(traffic_secret, "key", 16)?;
    let iv_bytes = hkdf_expand_label(traffic_secret, "iv", 12)?;
    let key: [u8; 16] = key_bytes.try_into().ok()?;
    let iv: [u8; 12] = iv_bytes.try_into().ok()?;
    Some((key, iv))
}

/// Decrypts one captured TLS record using the client's application traffic
/// secret logged via `SSLKEYLOGFILE`. This derives the record's key/IV
/// straight from the given secret with no sequence-number tracking, so it
/// is only correct for the FIRST record encrypted under that secret
/// (sequence number 0) — matching how this module is currently wired
/// (Task 13: one decrypt-eligible record per observed secret). Every
/// failure path (truncation, wrong key, malformed padding) returns
/// `Undecryptable`, never panics — decrypted content is best-effort and
/// must always fail closed, per the spec's Security model.
pub fn decrypt_record(record: &[u8], secret: &SessionSecret) -> DecryptOutcome {
    // TLS record: type(1) version(2) length(2) || ciphertext+tag
    if record.len() < 5 || record[0] != 0x17 {
        return DecryptOutcome::Undecryptable { reason: "not an application_data record" };
    }
    let body = &record[5..];
    if body.len() < aead::AES_128_GCM.tag_len() {
        return DecryptOutcome::Undecryptable { reason: "record too short for AEAD tag" };
    }

    let Some((key_bytes, iv)) = derive_key_and_iv(&secret.secret) else {
        return DecryptOutcome::Undecryptable { reason: "key derivation failed" };
    };
    let Ok(unbound_key) = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes) else {
        return DecryptOutcome::Undecryptable { reason: "invalid key material" };
    };
    let nonce = aead::Nonce::assume_unique_for_key(iv);
    let key = aead::LessSafeKey::new(unbound_key);

    // RFC 8446 §5.2: the AEAD's additional authenticated data is the
    // 5-byte outer TLSCiphertext record header (opaque_type ||
    // legacy_record_version || length) — NOT empty. Getting this wrong
    // makes every real record fail the AEAD tag check.
    let aad = aead::Aad::from(&record[..5]);
    let mut buf = body.to_vec();
    match key.open_in_place(nonce, aad, &mut buf) {
        Ok(plaintext) => {
            // TLS 1.3 records end with a content-type byte after the real
            // plaintext, per RFC 8446 §5.2 — strip it and any trailing zero
            // padding before returning application data to the caller.
            let mut end = plaintext.len();
            while end > 0 && plaintext[end - 1] == 0 {
                end -= 1;
            }
            if end == 0 {
                return DecryptOutcome::Undecryptable { reason: "empty plaintext after padding strip" };
            }
            DecryptOutcome::Plaintext(plaintext[..end - 1].to_vec())
        }
        Err(_) => DecryptOutcome::Undecryptable { reason: "AEAD authentication failed" },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::SessionSecret;

    // Published RFC 8448 "Example Handshake Traces for TLS 1.3" test vector
    // fields (client hello random, derived client application traffic
    // secret, and the first encrypted client application_data record with
    // its known plaintext), checked into
    // capture-agent/tests/fixtures/tls13_rfc8446_vector.json — see that
    // file's "_source" field for exactly how each value was extracted from
    // the RFC's published trace, not invented.
    fn load_fixture() -> serde_json::Value {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls13_rfc8446_vector.json"
        ))
        .expect("fixture file present");
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn decrypts_a_known_tls13_application_data_record() {
        let fx = load_fixture();
        let secret = SessionSecret {
            client_random: hex::decode(fx["client_random"].as_str().unwrap()).unwrap(),
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: hex::decode(fx["client_traffic_secret_0"].as_str().unwrap()).unwrap(),
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let expected_plaintext = hex::decode(fx["expected_plaintext"].as_str().unwrap()).unwrap();

        match decrypt_record(&record, &secret) {
            DecryptOutcome::Plaintext(bytes) => assert_eq!(bytes, expected_plaintext),
            DecryptOutcome::Undecryptable { reason } => panic!("expected success, got: {reason}"),
        }
    }

    #[test]
    fn derives_the_documented_key_and_iv_from_the_traffic_secret() {
        // Cross-check against RFC 8448's own restated key/IV for this exact
        // step, independent of the AEAD decrypt succeeding — pins down that
        // a passing decrypt test above isn't accidentally passing for the
        // wrong reason.
        let fx = load_fixture();
        let secret = hex::decode(fx["client_traffic_secret_0"].as_str().unwrap()).unwrap();
        let (key, iv) = derive_key_and_iv(&secret).expect("derivation should succeed");
        assert_eq!(hex::encode(key), fx["expected_key"].as_str().unwrap());
        assert_eq!(hex::encode(iv), fx["expected_iv"].as_str().unwrap());
    }

    #[test]
    fn returns_undecryptable_not_a_panic_for_a_truncated_record() {
        let secret = SessionSecret { client_random: vec![0u8; 32], label: "x".into(), secret: vec![1u8; 32] };
        let outcome = decrypt_record(&[0x17, 0x03, 0x03], &secret); // header only, no body
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }));
    }

    #[test]
    fn returns_undecryptable_for_an_authentication_failure_wrong_key() {
        let fx = load_fixture();
        let wrong_secret = SessionSecret {
            client_random: hex::decode(fx["client_random"].as_str().unwrap()).unwrap(),
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: vec![0xAA; 32], // deliberately wrong key material
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let outcome = decrypt_record(&record, &wrong_secret);
        assert!(
            matches!(outcome, DecryptOutcome::Undecryptable { .. }),
            "AEAD tag check must fail closed, not return garbage plaintext"
        );
    }

    #[test]
    fn returns_undecryptable_for_a_non_application_data_record() {
        let secret = SessionSecret { client_random: vec![0u8; 32], label: "x".into(), secret: vec![1u8; 32] };
        // 0x16 = handshake record, not application_data (0x17).
        let outcome = decrypt_record(&[0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5], &secret);
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }));
    }
}
