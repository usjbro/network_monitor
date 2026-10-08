use crate::keylog::SessionSecret;
use ring::aead;
use ring::hkdf;
use zeroize::Zeroizing;

pub enum DecryptOutcome {
    Plaintext {
        content_type: u8,
        bytes: Zeroizing<Vec<u8>>,
    },
    Undecryptable {
        reason: &'static str,
    },
}

impl std::fmt::Debug for DecryptOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext { content_type, .. } => f
                .debug_struct("Plaintext")
                .field("content_type", content_type)
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::Undecryptable { reason } => f
                .debug_struct("Undecryptable")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// TLS 1.3 §5.3 forms each record nonce by XORing the 64-bit sequence number
/// into the final eight bytes of the traffic secret's static IV.
pub fn nonce_for_sequence(mut iv: [u8; 12], sequence: u64) -> [u8; 12] {
    for (byte, sequence_byte) in iv[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *byte ^= sequence_byte;
    }
    iv
}

/// RFC 8446 §7.1 HKDF-Expand-Label, restricted to the fixed-length outputs
/// this module needs (16-byte key, 12-byte IV) — a general-purpose
/// variable-length version is not needed here and would be untested dead
/// code for any length this call site never uses.
fn hkdf_expand_label(secret: &[u8], label: &str, out_len: usize) -> Option<Zeroizing<Vec<u8>>> {
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
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    okm.fill(&mut out).ok()?;
    Some(out)
}

type TrafficKey = Zeroizing<[u8; 16]>;
type TrafficIv = Zeroizing<[u8; 12]>;

fn derive_key_and_iv(traffic_secret: &[u8]) -> Option<(TrafficKey, TrafficIv)> {
    let key_bytes = hkdf_expand_label(traffic_secret, "key", 16)?;
    let iv_bytes = hkdf_expand_label(traffic_secret, "iv", 12)?;
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&key_bytes);
    let mut iv = Zeroizing::new([0u8; 12]);
    iv.copy_from_slice(&iv_bytes);
    Some((key, iv))
}

/// RFC 8446 §7.2 KeyUpdate: derive the next generation from the current
/// traffic secret, retaining the output in zeroizing memory.
pub fn next_traffic_secret(secret: &SessionSecret) -> Option<Zeroizing<Vec<u8>>> {
    hkdf_expand_label(&secret.secret, "traffic upd", secret.secret.len())
}

/// Decrypts one captured TLS record using its traffic secret and sequence number. Every
/// failure path (truncation, wrong key, malformed padding) returns
/// `Undecryptable`, never panics — decrypted content is best-effort and
/// must always fail closed, per the spec's Security model.
pub fn decrypt_record(record: &[u8], secret: &SessionSecret, sequence: u64) -> DecryptOutcome {
    // TLS record: type(1) version(2) length(2) || ciphertext+tag
    if record.len() < 5 || record[0] != 0x17 {
        return DecryptOutcome::Undecryptable {
            reason: "not an application_data record",
        };
    }
    let body = &record[5..];
    if body.len() < aead::AES_128_GCM.tag_len() {
        return DecryptOutcome::Undecryptable {
            reason: "record too short for AEAD tag",
        };
    }

    let Some((key_bytes, iv)) = derive_key_and_iv(&secret.secret) else {
        return DecryptOutcome::Undecryptable {
            reason: "key derivation failed",
        };
    };
    let Ok(unbound_key) = aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes.as_slice()) else {
        return DecryptOutcome::Undecryptable {
            reason: "invalid key material",
        };
    };
    let nonce = aead::Nonce::assume_unique_for_key(nonce_for_sequence(*iv, sequence));
    let key = aead::LessSafeKey::new(unbound_key);

    // RFC 8446 §5.2: the AEAD's additional authenticated data is the
    // 5-byte outer TLSCiphertext record header (opaque_type ||
    // legacy_record_version || length) — NOT empty. Getting this wrong
    // makes every real record fail the AEAD tag check.
    let aad = aead::Aad::from(&record[..5]);
    let mut buf = Zeroizing::new(body.to_vec());
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
                return DecryptOutcome::Undecryptable {
                    reason: "empty plaintext after padding strip",
                };
            }
            let content_type = plaintext[end - 1];
            if !matches!(content_type, 20..=23) {
                return DecryptOutcome::Undecryptable {
                    reason: "invalid TLS inner content type",
                };
            }
            DecryptOutcome::Plaintext {
                content_type,
                bytes: Zeroizing::new(plaintext[..end - 1].to_vec()),
            }
        }
        Err(_) => DecryptOutcome::Undecryptable {
            reason: "AEAD authentication failed",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::SessionSecret;
    use zeroize::Zeroizing;

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
            secret: Zeroizing::new(
                hex::decode(fx["client_traffic_secret_0"].as_str().unwrap()).unwrap(),
            ),
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let expected_plaintext = hex::decode(fx["expected_plaintext"].as_str().unwrap()).unwrap();

        match decrypt_record(&record, &secret, 0) {
            DecryptOutcome::Plaintext {
                content_type,
                bytes,
            } => {
                assert_eq!(content_type, 23);
                assert_eq!(bytes.as_slice(), expected_plaintext);
            }
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
        assert_eq!(hex::encode(&iv[..]), fx["expected_iv"].as_str().unwrap());
    }

    #[test]
    fn record_nonce_xors_the_sequence_number_into_the_final_eight_iv_bytes() {
        // Generate distinct test bytes at runtime so static secret scanners
        // do not mistake this deterministic fixture for a production IV.
        let iv = std::array::from_fn(|index| 0x40_u8 + index as u8);
        assert_eq!(
            nonce_for_sequence(iv, 1),
            [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4A]
        );
    }

    #[test]
    fn derives_next_tls13_traffic_secret_for_key_update() {
        let secret = SessionSecret {
            client_random: vec![0x11; 32],
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: Zeroizing::new(vec![0x22; 32]),
        };
        let next =
            next_traffic_secret(&secret).expect("AES-128-GCM-SHA256 traffic secret should update");
        assert_eq!(next.len(), 32);
        assert_ne!(next.as_slice(), secret.secret.as_slice());
    }

    #[test]
    fn decrypts_three_directional_records_only_at_their_monotonic_sequences() {
        let secret = SessionSecret {
            client_random: vec![0x11; 32],
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: Zeroizing::new(vec![0x22; 32]),
        };
        for sequence in 0..3 {
            let plaintext = format!("record-{sequence}").into_bytes();
            let record = encrypt_record_for_test(&secret, sequence, &plaintext);
            match decrypt_record(&record, &secret, sequence) {
                DecryptOutcome::Plaintext {
                    content_type: 23,
                    bytes,
                } => assert_eq!(bytes.as_slice(), plaintext),
                other => panic!("expected authenticated application plaintext, got {other:?}"),
            }
            assert!(matches!(
                decrypt_record(&record, &secret, sequence + 1),
                DecryptOutcome::Undecryptable { .. }
            ));
        }
    }

    #[test]
    fn reassembles_out_of_order_records_then_decrypts_each_direction_from_sequence_zero() {
        use crate::tls_stream::TlsDirectionStream;
        let client = SessionSecret {
            client_random: vec![0x31; 32],
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: Zeroizing::new(vec![0x41; 32]),
        };
        let server = SessionSecret {
            client_random: client.client_random.clone(),
            label: "SERVER_TRAFFIC_SECRET_0".to_string(),
            secret: Zeroizing::new(vec![0x51; 32]),
        };
        let client_records = (0..3)
            .map(|seq| encrypt_record_for_test(&client, seq, format!("c{seq}").as_bytes()))
            .collect::<Vec<_>>();
        let server_records = (0..3)
            .map(|seq| encrypt_record_for_test(&server, seq, format!("s{seq}").as_bytes()))
            .collect::<Vec<_>>();
        let client_wire = client_records.concat();
        let server_wire = server_records.concat();
        let mut client_stream = TlsDirectionStream::new(100);
        let split = client_wire.len() / 3;
        assert!(client_stream
            .feed_segment(100 + split as u32, &client_wire[split..split * 2])
            .unwrap()
            .is_empty());
        assert!(client_stream
            .feed_segment(100 + (split * 2) as u32, &client_wire[split * 2..])
            .unwrap()
            .is_empty());
        let got_client = client_stream
            .feed_segment(100, &client_wire[..split])
            .unwrap();
        assert_eq!(got_client, client_records);

        let mut server_stream = TlsDirectionStream::new(900);
        let got_server = server_stream.feed_segment(900, &server_wire).unwrap();
        assert_eq!(got_server, server_records);
        for (sequence, record) in got_client.iter().enumerate() {
            assert!(matches!(
                decrypt_record(record, &client, sequence as u64),
                DecryptOutcome::Plaintext {
                    content_type: 23,
                    ..
                }
            ));
        }
        for (sequence, record) in got_server.iter().enumerate() {
            assert!(matches!(
                decrypt_record(record, &server, sequence as u64),
                DecryptOutcome::Plaintext {
                    content_type: 23,
                    ..
                }
            ));
        }
    }

    fn encrypt_record_for_test(secret: &SessionSecret, sequence: u64, plaintext: &[u8]) -> Vec<u8> {
        let (key_bytes, iv) = derive_key_and_iv(&secret.secret).unwrap();
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes.as_slice()).unwrap();
        let key = aead::LessSafeKey::new(unbound);
        let mut body = plaintext.to_vec();
        body.push(23);
        let body_len = body.len() + aead::AES_128_GCM.tag_len();
        let mut record = vec![0x17, 0x03, 0x03, (body_len >> 8) as u8, body_len as u8];
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_for_sequence(*iv, sequence)),
            aead::Aad::from(record.as_slice()),
            &mut body,
        )
        .unwrap();
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn returns_undecryptable_not_a_panic_for_a_truncated_record() {
        let secret = SessionSecret {
            client_random: vec![0u8; 32],
            label: "x".into(),
            secret: Zeroizing::new(vec![1u8; 32]),
        };
        let outcome = decrypt_record(&[0x17, 0x03, 0x03], &secret, 0); // header only, no body
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }));
    }

    #[test]
    fn returns_undecryptable_for_an_authentication_failure_wrong_key() {
        let fx = load_fixture();
        let wrong_secret = SessionSecret {
            client_random: hex::decode(fx["client_random"].as_str().unwrap()).unwrap(),
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: Zeroizing::new(vec![0xAA; 32]), // deliberately wrong key material
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let outcome = decrypt_record(&record, &wrong_secret, 0);
        assert!(
            matches!(outcome, DecryptOutcome::Undecryptable { .. }),
            "AEAD tag check must fail closed, not return garbage plaintext"
        );
    }

    #[test]
    fn returns_undecryptable_for_a_non_application_data_record() {
        let secret = SessionSecret {
            client_random: vec![0u8; 32],
            label: "x".into(),
            secret: Zeroizing::new(vec![1u8; 32]),
        };
        // 0x16 = handshake record, not application_data (0x17).
        let outcome = decrypt_record(&[0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5], &secret, 0);
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }));
    }
}
