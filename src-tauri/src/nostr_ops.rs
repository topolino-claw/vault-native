use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Compute Nostr event ID (SHA-256 of serialized event array).
/// Format: [0, pubkey, created_at, kind, tags, content]
fn compute_event_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &serde_json::Value,
    content: &str,
) -> String {
    let serialized = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
    let hash = Sha256::digest(serialized.to_string().as_bytes());
    hex::encode(hash)
}

/// Sign a Nostr event with schnorr signature.
/// Takes partial event JSON (with kind, pubkey, created_at, tags, content),
/// computes id and sig, returns complete event JSON.
///
/// Uses the `nostr` crate's secp256k1 for signing — the same library relays
/// use for verification — so signatures are guaranteed to be accepted.
pub fn sign_event(event_json: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use nostr::secp256k1::{Secp256k1, Keypair, Message};

    let mut event: serde_json::Value =
        serde_json::from_str(event_json).map_err(|e| format!("Invalid event JSON: {}", e))?;

    let pubkey = event["pubkey"]
        .as_str()
        .unwrap_or(pk_hex);
    let created_at = event["created_at"]
        .as_u64()
        .ok_or("Missing created_at")?;
    let kind = event["kind"]
        .as_u64()
        .ok_or("Missing kind")? as u32;
    let tags = event["tags"].clone();
    let content = event["content"]
        .as_str()
        .ok_or("Missing content")?
        .to_string();

    // Compute event ID
    let id = compute_event_id(pubkey, created_at, kind, &tags, &content);
    event["id"] = serde_json::Value::String(id.clone());

    // Sign with secp256k1 schnorr (same lib as nostr relay verification)
    let secp = Secp256k1::signing_only();
    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK hex: {}", e))?;
    let keypair = Keypair::from_seckey_slice(&secp, &sk_bytes)
        .map_err(|e| format!("Invalid signing key: {}", e))?;
    sk_bytes.zeroize();

    let id_bytes = hex::decode(&id).map_err(|e| format!("Invalid event ID: {}", e))?;
    let message = Message::from_digest_slice(&id_bytes)
        .map_err(|e| format!("Invalid message: {}", e))?;
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let sig_hex = hex::encode(signature.as_ref());

    event["sig"] = serde_json::Value::String(sig_hex);
    event["pubkey"] = serde_json::Value::String(pk_hex.to_string());

    serde_json::to_string(&event).map_err(|e| format!("Serialize failed: {}", e))
}

/// NIP-44 encryption placeholder.
/// NIP-44 is complex (ChaCha20-Poly1305 with HKDF-SHA256, padding, versioning).
/// For now, this delegates to the nostr crate if available, otherwise returns an error
/// indicating the JS side should handle NIP-44 encryption.
///
/// In production, this should use a proper NIP-44 implementation.
pub fn nip44_encrypt(plaintext: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use nostr::nips::nip44;
    use nostr::SecretKey;

    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK: {}", e))?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;
    sk_bytes.zeroize();

    let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid PK: {}", e))?;
    let pk = nostr::PublicKey::from_slice(&pk_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    nip44::encrypt(&sk, &pk, plaintext, nip44::Version::V2)
        .map_err(|e| format!("NIP-44 encrypt failed: {}", e))
}

/// NIP-04 decryption (legacy format for kind:1 backup events).
pub fn nip04_decrypt(ciphertext: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use nostr::nips::nip04;
    use nostr::SecretKey;

    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK: {}", e))?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;
    sk_bytes.zeroize();

    let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid PK: {}", e))?;
    let pk = nostr::PublicKey::from_slice(&pk_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    nip04::decrypt(&sk, &pk, ciphertext)
        .map_err(|e| format!("NIP-04 decrypt failed: {}", e))
}

/// Compute NIP-44 v1 shared key: SHA-256(ECDH_x_coordinate(sk, pk)).
/// This matches nostr-tools v1.15.0: `sha256(getSharedSecret(sk, "02"+pk).subarray(1,33))`
fn nip44_v1_shared_key(sk_hex: &str, pk_hex: &str) -> Result<[u8; 32], String> {
    use k256::{SecretKey as K256SecretKey, PublicKey as K256PublicKey};
    use k256::ecdh::diffie_hellman;

    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK: {}", e))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid SK: {}", e))?;
    sk_bytes.zeroize();

    let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid PK: {}", e))?;
    let mut pk_sec1 = Vec::with_capacity(33);
    pk_sec1.push(0x02);
    pk_sec1.extend_from_slice(&pk_bytes);
    let pk = K256PublicKey::from_sec1_bytes(&pk_sec1).map_err(|e| format!("Invalid PK: {}", e))?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let x = shared.raw_secret_bytes();
    Ok(Sha256::digest(x).into())
}

/// NIP-44 v1 decryption (nostr-tools v1.15.0 XChaCha20 format).
/// Payload: version(0x01) || nonce(24) || xchacha20_ciphertext
fn nip44_v1_decrypt_raw(payload: &[u8], sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use chacha20::XChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    if payload.len() < 26 {
        return Err("NIP-44 v1: payload too short".to_string());
    }

    let nonce = &payload[1..25];
    let mut data = payload[25..].to_vec();

    let mut key = nip44_v1_shared_key(sk_hex, pk_hex)?;
    let mut cipher = XChaCha20::new_from_slices(&key, nonce)
        .map_err(|_| "NIP-44 v1: cipher init failed".to_string())?;
    key.zeroize();

    cipher.apply_keystream(&mut data);
    String::from_utf8(data).map_err(|e| format!("NIP-44 v1: invalid UTF-8: {}", e))
}

/// NIP-44 decryption with automatic v1/v2 version detection.
/// - v1: XChaCha20 stream cipher (nostr-tools v1.15.0 legacy format)
/// - v2: ChaCha20-Poly1305 + HKDF + padding (NIP-44 final spec, nostr crate)
pub fn nip44_decrypt(ciphertext: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let payload = STANDARD.decode(ciphertext)
        .map_err(|e| format!("NIP-44: invalid base64: {}", e))?;

    if payload.is_empty() {
        return Err("NIP-44: empty payload".to_string());
    }

    match payload[0] {
        2 => {
            use nostr::nips::nip44;
            use nostr::SecretKey;

            let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK: {}", e))?;
            let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;
            sk_bytes.zeroize();

            let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid PK: {}", e))?;
            let pk = nostr::PublicKey::from_slice(&pk_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

            nip44::decrypt(&sk, &pk, ciphertext)
                .map_err(|e| format!("NIP-44 v2 decrypt failed: {}", e))
        }
        1 => nip44_v1_decrypt_raw(&payload, sk_hex, pk_hex),
        v => Err(format!("NIP-44: unsupported version: {}", v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> crate::state::NostrKeyPair {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        crate::crypto::derive_nostr_keys_nip06(mnemonic, "").unwrap()
    }

    #[test]
    fn test_nip44_v1_decrypt_roundtrip() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let keys = test_keys();
        let plaintext = r#"{"users":{"alice":{"github.com":3}},"settings":{}}"#;

        // Manually construct a v1 ciphertext (mimicking nostr-tools v1.15.0)
        let key = nip44_v1_shared_key(&keys.sk_hex, &keys.pk_hex).unwrap();
        let nonce = [42u8; 24]; // deterministic nonce for test

        let mut ct = plaintext.as_bytes().to_vec();
        let mut cipher = XChaCha20::new_from_slices(&key, &nonce).unwrap();
        cipher.apply_keystream(&mut ct);

        let mut payload = Vec::with_capacity(1 + 24 + ct.len());
        payload.push(0x01); // version 1
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ct);

        let encoded = STANDARD.encode(&payload);

        // Decrypt through the main entry point (should auto-detect v1)
        let decrypted = nip44_decrypt(&encoded, &keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip44_v2_roundtrip() {
        let keys = test_keys();
        let plaintext = r#"{"users":{"bob":{"example.com":1}},"settings":{}}"#;

        let encrypted = nip44_encrypt(plaintext, &keys.sk_hex, &keys.pk_hex).unwrap();
        let decrypted = nip44_decrypt(&encrypted, &keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip44_version_detection() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let keys = test_keys();

        // v2 ciphertext starts with version byte 2
        let v2_ct = nip44_encrypt("test", &keys.sk_hex, &keys.pk_hex).unwrap();
        let v2_payload = STANDARD.decode(&v2_ct).unwrap();
        assert_eq!(v2_payload[0], 2, "nip44_encrypt should produce version 2");

        // Unsupported version 3
        let mut bad_payload = v2_payload.clone();
        bad_payload[0] = 3;
        let bad_ct = STANDARD.encode(&bad_payload);
        let err = nip44_decrypt(&bad_ct, &keys.sk_hex, &keys.pk_hex).unwrap_err();
        assert!(err.contains("unsupported version: 3"), "Should reject version 3: {}", err);

        // Empty payload
        let empty_ct = STANDARD.encode(&[]);
        let err = nip44_decrypt(&empty_ct, &keys.sk_hex, &keys.pk_hex).unwrap_err();
        assert!(err.contains("empty"), "Should reject empty payload: {}", err);
    }

    #[test]
    fn test_nip44_v1_shared_key_deterministic() {
        let keys = test_keys();

        // Same inputs should produce same key
        let key1 = nip44_v1_shared_key(&keys.sk_hex, &keys.pk_hex).unwrap();
        let key2 = nip44_v1_shared_key(&keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(key1, key2, "Shared key should be deterministic");
        assert_ne!(key1, [0u8; 32], "Shared key should not be zero");
    }

    #[test]
    fn test_sign_event_produces_valid_signature() {
        // Use the NIP-06 test vector key
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = crate::crypto::derive_nostr_keys_nip06(mnemonic, "").unwrap();

        let event_json = serde_json::json!({
            "kind": 30078,
            "pubkey": keys.pk_hex,
            "created_at": 1700000000u64,
            "tags": [["d", "vault-backup"]],
            "content": "test-encrypted-content"
        });

        let signed = sign_event(
            &serde_json::to_string(&event_json).unwrap(),
            &keys.sk_hex,
            &keys.pk_hex,
        ).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&signed).unwrap();
        
        // Verify ID was computed
        let id = parsed["id"].as_str().unwrap();
        assert_eq!(id.len(), 64, "Event ID should be 64 hex chars");
        
        // Verify signature was computed
        let sig = parsed["sig"].as_str().unwrap();
        assert_eq!(sig.len(), 128, "Signature should be 128 hex chars");

        // Re-compute the event ID and verify it matches
        let expected_id = compute_event_id(
            &keys.pk_hex,
            1700000000,
            30078,
            &serde_json::json!([["d", "vault-backup"]]),
            "test-encrypted-content",
        );
        assert_eq!(id, expected_id, "Event ID should match recomputed ID");

        // Verify the serialized array matches what JS JSON.stringify would produce
        let serialized = serde_json::json!([
            0,
            keys.pk_hex,
            1700000000u64,
            30078u32,
            [["d", "vault-backup"]],
            "test-encrypted-content"
        ]);
        let serialized_str = serialized.to_string();
        println!("Serialized event for ID: {}", serialized_str);
        println!("Event ID: {}", id);
        println!("Signature: {}", sig);

        // Verify with nostr crate
        use nostr::secp256k1::schnorr::Signature;
        use nostr::secp256k1::{XOnlyPublicKey, Secp256k1, Message};
        
        let secp = Secp256k1::verification_only();
        let sig_bytes = hex::decode(sig).unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        let id_bytes = hex::decode(id).unwrap();
        let message = Message::from_digest_slice(&id_bytes).unwrap();
        let pk_bytes = hex::decode(&keys.pk_hex).unwrap();
        let xonly_pk = XOnlyPublicKey::from_slice(&pk_bytes).unwrap();
        
        secp.verify_schnorr(&signature, &message, &xonly_pk)
            .expect("Signature should verify with nostr secp256k1");
    }

    #[test]
    fn test_event_id_matches_js_serialization() {
        // Verify the Rust serialization matches what JS JSON.stringify produces
        let id = compute_event_id(
            "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34",
            1700000000,
            30078,
            &serde_json::json!([["d", "vault-backup"]]),
            "hello world",
        );

        // The serialized form should be exactly:
        // [0,"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34",1700000000,30078,[["d","vault-backup"]],"hello world"]
        let expected_serialized = r#"[0,"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34",1700000000,30078,[["d","vault-backup"]],"hello world"]"#;
        let actual_serialized = serde_json::json!([
            0,
            "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34",
            1700000000u64,
            30078u32,
            [["d", "vault-backup"]],
            "hello world"
        ]).to_string();

        assert_eq!(actual_serialized, expected_serialized, "Rust JSON serialization must match JS JSON.stringify");
        println!("Serialized: {}", actual_serialized);
        println!("Event ID: {}", id);
    }

    // ── NIP-04 encrypt + decrypt roundtrip ─────────────────────────────

    #[test]
    fn test_nip04_self_encrypt_decrypt_roundtrip() {
        use nostr::nips::nip04;
        use nostr::SecretKey;

        let keys = test_keys();
        let plaintext = r#"{"users":{"alice":{"bank.com":5}}}"#;

        // Encrypt with NIP-04
        let mut sk_bytes = hex::decode(&keys.sk_hex).unwrap();
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        sk_bytes.zeroize();
        let pk_bytes = hex::decode(&keys.pk_hex).unwrap();
        let pk = nostr::PublicKey::from_slice(&pk_bytes).unwrap();

        let encrypted = nip04::encrypt(&sk, &pk, plaintext).unwrap();

        // Decrypt through our function
        let decrypted = nip04_decrypt(&encrypted, &keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip04_decrypt_invalid_ciphertext() {
        let keys = test_keys();
        let result = nip04_decrypt("not-valid-nip04-ciphertext", &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
    }

    // ── sign_event invalid inputs ──────────────────────────────────────

    #[test]
    fn test_sign_event_missing_kind() {
        let keys = test_keys();
        let event = serde_json::json!({
            "pubkey": keys.pk_hex,
            "created_at": 1700000000u64,
            "tags": [],
            "content": "test"
        });
        let result = sign_event(&serde_json::to_string(&event).unwrap(), &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing kind"));
    }

    #[test]
    fn test_sign_event_missing_created_at() {
        let keys = test_keys();
        let event = serde_json::json!({
            "kind": 30078,
            "pubkey": keys.pk_hex,
            "tags": [],
            "content": "test"
        });
        let result = sign_event(&serde_json::to_string(&event).unwrap(), &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing created_at"));
    }

    #[test]
    fn test_sign_event_missing_content() {
        let keys = test_keys();
        let event = serde_json::json!({
            "kind": 30078,
            "pubkey": keys.pk_hex,
            "created_at": 1700000000u64,
            "tags": []
        });
        let result = sign_event(&serde_json::to_string(&event).unwrap(), &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing content"));
    }

    #[test]
    fn test_sign_event_invalid_json() {
        let keys = test_keys();
        let result = sign_event("not json", &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid event JSON"));
    }

    #[test]
    fn test_sign_event_invalid_sk_hex() {
        let keys = test_keys();
        let event = serde_json::json!({
            "kind": 30078,
            "pubkey": keys.pk_hex,
            "created_at": 1700000000u64,
            "tags": [],
            "content": "test"
        });
        let result = sign_event(&serde_json::to_string(&event).unwrap(), "not_hex", &keys.pk_hex);
        assert!(result.is_err());
    }

    // ── sign_event deterministic ID ────────────────────────────────────

    #[test]
    fn test_sign_event_deterministic_id() {
        let keys = test_keys();
        let event = serde_json::json!({
            "kind": 30078,
            "pubkey": keys.pk_hex,
            "created_at": 1700000000u64,
            "tags": [["d", "vault-backup"]],
            "content": "hello"
        });
        let json = serde_json::to_string(&event).unwrap();

        let signed1: serde_json::Value = serde_json::from_str(&sign_event(&json, &keys.sk_hex, &keys.pk_hex).unwrap()).unwrap();
        let signed2: serde_json::Value = serde_json::from_str(&sign_event(&json, &keys.sk_hex, &keys.pk_hex).unwrap()).unwrap();

        // ID is deterministic (same event data → same hash)
        assert_eq!(signed1["id"], signed2["id"]);
        // Signatures may differ (schnorr can use aux randomness, but we use no_aux_rand so they should match)
        assert_eq!(signed1["sig"], signed2["sig"]);
    }

    // ── sign_event uses provided pubkey ────────────────────────────────

    #[test]
    fn test_sign_event_uses_pk_hex_param() {
        let keys = test_keys();
        let event = serde_json::json!({
            "kind": 1,
            "created_at": 1700000000u64,
            "tags": [],
            "content": "test"
        });
        let signed: serde_json::Value = serde_json::from_str(
            &sign_event(&serde_json::to_string(&event).unwrap(), &keys.sk_hex, &keys.pk_hex).unwrap()
        ).unwrap();
        assert_eq!(signed["pubkey"].as_str().unwrap(), keys.pk_hex);
    }

    // ── NIP-44 wrong key decryption ────────────────────────────────────

    #[test]
    fn test_nip44_v2_wrong_key_fails() {
        let keys = test_keys();
        let encrypted = nip44_encrypt("secret data", &keys.sk_hex, &keys.pk_hex).unwrap();

        // Use a different key pair to try decrypting
        let other_keys = crate::crypto::derive_nostr_keys_nip06(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            ""
        ).unwrap();
        let result = nip44_decrypt(&encrypted, &other_keys.sk_hex, &other_keys.pk_hex);
        assert!(result.is_err(), "Decrypting with wrong keys should fail");
    }

    #[test]
    fn test_nip44_invalid_base64() {
        let keys = test_keys();
        let result = nip44_decrypt("!!!not-base64!!!", &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64"));
    }

    #[test]
    fn test_nip44_invalid_sk() {
        let keys = test_keys();
        let result = nip44_encrypt("test", "zzzz", &keys.pk_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_invalid_pk() {
        let keys = test_keys();
        let result = nip44_encrypt("test", &keys.sk_hex, "zzzz");
        assert!(result.is_err());
    }

    // ── NIP-44 v1 edge cases ───────────────────────────────────────────

    #[test]
    fn test_nip44_v1_too_short_payload() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let keys = test_keys();
        // Version byte + only a few bytes (need at least 1 + 24 nonce + 1 data = 26)
        let short_payload = vec![0x01, 0x00, 0x00];
        let encoded = STANDARD.encode(&short_payload);
        let result = nip44_decrypt(&encoded, &keys.sk_hex, &keys.pk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    // ── compute_event_id determinism ───────────────────────────────────

    #[test]
    fn test_compute_event_id_deterministic() {
        let id1 = compute_event_id("pubkey1", 1000, 1, &serde_json::json!([]), "content");
        let id2 = compute_event_id("pubkey1", 1000, 1, &serde_json::json!([]), "content");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn test_compute_event_id_different_content() {
        let id1 = compute_event_id("pk", 1000, 1, &serde_json::json!([]), "hello");
        let id2 = compute_event_id("pk", 1000, 1, &serde_json::json!([]), "world");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_different_kind() {
        let id1 = compute_event_id("pk", 1000, 1, &serde_json::json!([]), "c");
        let id2 = compute_event_id("pk", 1000, 30078, &serde_json::json!([]), "c");
        assert_ne!(id1, id2);
    }

    // ── NIP-44 v2 large payload ────────────────────────────────────────

    #[test]
    fn test_nip44_v2_large_payload() {
        let keys = test_keys();
        // Build a large JSON payload (~10KB)
        let mut users = serde_json::Map::new();
        for i in 0..50 {
            let mut sites = serde_json::Map::new();
            for j in 0..20 {
                sites.insert(format!("site-{}.example.com", j), serde_json::Value::from(j as u64));
            }
            users.insert(format!("user{}@test.com", i), serde_json::Value::Object(sites));
        }
        let payload = serde_json::to_string(&users).unwrap();
        assert!(payload.len() > 5000);

        let encrypted = nip44_encrypt(&payload, &keys.sk_hex, &keys.pk_hex).unwrap();
        let decrypted = nip44_decrypt(&encrypted, &keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(payload, decrypted);
    }

    // ── NIP-44 v1 shared key with invalid keys ─────────────────────────

    #[test]
    fn test_nip44_v1_shared_key_invalid_sk() {
        let keys = test_keys();
        let result = nip44_v1_shared_key("not_hex", &keys.pk_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_v1_shared_key_invalid_pk() {
        let keys = test_keys();
        let result = nip44_v1_shared_key(&keys.sk_hex, "not_hex");
        assert!(result.is_err());
    }
}
