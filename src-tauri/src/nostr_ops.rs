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

/// NIP-44 decryption.
pub fn nip44_decrypt(ciphertext: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
    use nostr::nips::nip44;
    use nostr::SecretKey;

    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK: {}", e))?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;
    sk_bytes.zeroize();

    let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid PK: {}", e))?;
    let pk = nostr::PublicKey::from_slice(&pk_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    nip44::decrypt(&sk, &pk, ciphertext)
        .map_err(|e| format!("NIP-44 decrypt failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
