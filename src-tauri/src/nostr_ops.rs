use k256::schnorr::{SigningKey, signature::Signer};
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
pub fn sign_event(event_json: &str, sk_hex: &str, pk_hex: &str) -> Result<String, String> {
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

    // Sign with schnorr
    let mut sk_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid SK hex: {}", e))?;
    let signing_key = SigningKey::from_bytes(sk_bytes.as_slice().into())
        .map_err(|e| format!("Invalid signing key: {}", e))?;
    sk_bytes.zeroize();

    let id_bytes = hex::decode(&id).map_err(|e| format!("Invalid event ID: {}", e))?;
    let signature = signing_key.sign(&id_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

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
