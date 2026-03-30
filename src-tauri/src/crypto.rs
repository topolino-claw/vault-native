use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::Hmac;
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    Scalar, SecretKey,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::state::{LegacyNostrKeyPair, NostrKeyPair, VaultSecrets};

// BIP39 English wordlist (standard 2048 words)
const BIP39_WORDLIST: &str = include_str!("../../vault/bip39WordList.js");

/// Parse the BIP39 wordlist from the JS file.
fn get_wordlist() -> Vec<&'static str> {
    BIP39_WORDLIST
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            if trimmed.starts_with('"') && trimmed.ends_with('"') {
                Some(&trimmed[1..trimmed.len() - 1])
            } else {
                None
            }
        })
        .collect()
}

/// Generate a random 12-word BIP39 mnemonic.
pub fn generate_mnemonic() -> Result<String, String> {
    let wordlist = get_wordlist();
    if wordlist.len() != 2048 {
        return Err(format!("BIP39 wordlist has {} words, expected 2048", wordlist.len()));
    }

    // 128 bits of entropy
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);

    // SHA-256 checksum
    let hash = Sha256::digest(&entropy);
    let checksum_bits = 4; // 128/32 = 4 bits

    // Convert entropy + checksum to binary string, then to word indices
    let mut bits = Vec::with_capacity(132);
    for byte in &entropy {
        for j in (0..8).rev() {
            bits.push((byte >> j) & 1);
        }
    }
    for j in (8 - checksum_bits..8).rev() {
        bits.push((hash[0] >> j) & 1);
    }

    // Zero entropy
    entropy.zeroize();

    let mut words = Vec::with_capacity(12);
    for chunk in bits.chunks(11) {
        let mut index: u16 = 0;
        for &bit in chunk {
            index = (index << 1) | bit as u16;
        }
        words.push(wordlist[index as usize].to_string());
    }

    Ok(words.join(" "))
}

/// Verify a BIP39 seed phrase checksum.
pub fn verify_seed_phrase(phrase: &str) -> bool {
    let wordlist = get_wordlist();
    let normalized = phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>();

    let word_count = normalized.len();
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return false;
    }

    // Convert words to indices
    let indices: Vec<usize> = match normalized
        .iter()
        .map(|w| wordlist.iter().position(|&wl| wl == w.as_str()))
        .collect()
    {
        Some(v) => v,
        None => return false,
    };

    // Convert indices to bits
    let total_bits = word_count * 11;
    let checksum_bits = total_bits / 33; // total_bits % 32 for BIP39
    let entropy_bits = total_bits - checksum_bits;

    let mut bits = Vec::with_capacity(total_bits);
    for &idx in &indices {
        for j in (0..11).rev() {
            bits.push(((idx >> j) & 1) as u8);
        }
    }

    // Split into entropy and checksum
    let entropy_part = &bits[..entropy_bits];
    let checksum_part = &bits[entropy_bits..];

    // Convert entropy bits to bytes
    let mut entropy_bytes = vec![0u8; entropy_bits / 8];
    for (i, byte) in entropy_bytes.iter_mut().enumerate() {
        for j in 0..8 {
            *byte |= entropy_part[i * 8 + j] << (7 - j);
        }
    }

    // Compute SHA-256 of entropy
    let hash = Sha256::digest(&entropy_bytes);
    entropy_bytes.zeroize();

    // Compare checksum
    let hash_bits: Vec<u8> = (0..8)
        .map(|j| (hash[0] >> (7 - j)) & 1)
        .collect();

    checksum_part == &hash_bits[..checksum_bits]
}

/// Custom private key derivation matching the JS `derivePrivateKey()`.
/// Process: words → 4-digit padded indices → decimal string → hex via BigInt.
pub fn derive_private_key(seed_phrase: &str, wordlist: &[&str]) -> Result<String, String> {
    let normalized = seed_phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>();

    let mut decimal_str = String::new();
    for word in &normalized {
        let index = wordlist
            .iter()
            .position(|&w| w == word.as_str())
            .ok_or_else(|| format!("Word '{}' not found in BIP39 wordlist", word))?;
        decimal_str.push_str(&format!("{:04}", index));
    }

    // Remove leading zeros and convert decimal to hex
    let decimal_str = decimal_str.trim_start_matches('0');
    if decimal_str.is_empty() {
        return Ok("0".to_string());
    }

    // BigInt decimal-to-hex conversion
    decimal_to_hex(decimal_str)
}

/// Convert a decimal string to hex (matching JS BigInt behavior).
fn decimal_to_hex(dec: &str) -> Result<String, String> {
    // Process digit by digit using long division
    let mut digits: Vec<u8> = dec.bytes().map(|b| b - b'0').collect();
    let mut hex_chars = Vec::new();

    while !digits.is_empty() && !(digits.len() == 1 && digits[0] == 0) {
        let mut remainder = 0u32;
        let mut new_digits = Vec::new();
        for &d in &digits {
            let current = remainder * 10 + d as u32;
            let quotient = current / 16;
            remainder = current % 16;
            if !new_digits.is_empty() || quotient > 0 {
                new_digits.push(quotient as u8);
            }
        }
        hex_chars.push(
            std::char::from_digit(remainder, 16).unwrap_or('0'),
        );
        digits = new_digits;
    }

    hex_chars.reverse();
    let result: String = hex_chars.into_iter().collect();
    if result.is_empty() {
        Ok("0".to_string())
    } else {
        Ok(result)
    }
}

/// Derive Nostr keys via NIP-06: BIP39 → BIP32 → m/44'/1237'/0'/0/0.
pub fn derive_nostr_keys_nip06(
    mnemonic: &str,
    passphrase: &str,
) -> Result<NostrKeyPair, String> {
    // BIP39: mnemonic → seed via PBKDF2-SHA512 (2048 iterations)
    let mut seed = [0u8; 64];
    let mnemonic_nfkd = mnemonic; // Already normalized by caller
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac::<Sha512>(
        mnemonic_nfkd.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    );

    // BIP32: seed → master key via HMAC-SHA512("Bitcoin seed", seed)
    let (mut master_key, mut master_chain) = bip32_master(&seed)?;
    seed.zeroize();

    // Hardened derivation: 44', 1237', 0'
    for index in [44u32, 1237, 0] {
        let (new_key, new_chain) = bip32_hard_child(&master_key, &master_chain, index)?;
        master_key.zeroize();
        master_chain.zeroize();
        master_key = new_key;
        master_chain = new_chain;
    }

    // Normal derivation: 0, 0
    let (key1, chain1) = bip32_normal_child(&master_key, &master_chain, 0)?;
    master_key.zeroize();
    master_chain.zeroize();

    let (final_key, mut final_chain) = bip32_normal_child(&key1, &chain1, 0)?;
    // key1, chain1 dropped and zeroized at end of scope (they're arrays)

    let sk_hex = hex::encode(&final_key);
    final_chain.zeroize();

    // Derive public key
    let secret_key =
        SecretKey::from_slice(&final_key).map_err(|e| format!("Invalid secret key: {}", e))?;
    let public_key = secret_key.public_key();
    let pk_point = public_key.to_encoded_point(true);
    // Nostr uses x-only pubkey (32 bytes, no prefix)
    let pk_hex = hex::encode(&pk_point.as_bytes()[1..33]);

    Ok(NostrKeyPair {
        sk_hex,
        pk_hex,
        is_nip06: true,
    })
}

/// Derive legacy Nostr keys: SHA-256(vault_private_key) → Nostr secret key.
pub fn derive_nostr_keys_legacy(private_key: &str) -> Result<LegacyNostrKeyPair, String> {
    let hash = Sha256::digest(private_key.as_bytes());
    let sk_hex = hex::encode(hash);

    let sk_bytes: [u8; 32] = hash.into();
    let secret_key =
        SecretKey::from_slice(&sk_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;
    let public_key = secret_key.public_key();
    let pk_point = public_key.to_encoded_point(true);
    let pk_hex = hex::encode(&pk_point.as_bytes()[1..33]);

    Ok(LegacyNostrKeyPair { sk_hex, pk_hex })
}

/// BIP32: seed → master key via HMAC-SHA512("Bitcoin seed", seed).
fn bip32_master(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    use hmac::Mac;
    type HmacSha512 = Hmac<Sha512>;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(b"Bitcoin seed")
        .map_err(|e| format!("HMAC init failed: {}", e))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    Ok((key, chain))
}

/// BIP32 hardened child derivation (index' = index + 0x80000000).
fn bip32_hard_child(
    pk: &[u8; 32],
    cc: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    use hmac::Mac;
    type HmacSha512 = Hmac<Sha512>;

    let h = index + 0x80000000;
    let mut data = [0u8; 37];
    data[0] = 0x00;
    data[1..33].copy_from_slice(pk);
    data[33] = (h >> 24) as u8;
    data[34] = (h >> 16) as u8;
    data[35] = (h >> 8) as u8;
    data[36] = h as u8;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(cc)
        .map_err(|e| format!("HMAC init failed: {}", e))?;
    mac.update(&data);
    data.zeroize();
    let result = mac.finalize().into_bytes();

    let il = &result[..32];
    let ir = &result[32..];

    let child_key = secp256k1_mod_add(il, pk)?;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(ir);

    Ok((child_key, chain))
}

/// BIP32 normal (non-hardened) child derivation.
fn bip32_normal_child(
    pk: &[u8; 32],
    cc: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    use hmac::Mac;
    type HmacSha512 = Hmac<Sha512>;

    // Compute compressed public key from private key
    let comp_pub = priv_to_compressed_pub(pk)?;

    let mut data = [0u8; 37];
    data[..33].copy_from_slice(&comp_pub);
    data[33] = (index >> 24) as u8;
    data[34] = (index >> 16) as u8;
    data[35] = (index >> 8) as u8;
    data[36] = index as u8;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(cc)
        .map_err(|e| format!("HMAC init failed: {}", e))?;
    mac.update(&data);
    data.zeroize();
    let result = mac.finalize().into_bytes();

    let il = &result[..32];
    let ir = &result[32..];

    let child_key = secp256k1_mod_add(il, pk)?;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(ir);

    Ok((child_key, chain))
}

/// (a + b) mod N for secp256k1.
fn secp256k1_mod_add(a: &[u8], b: &[u8]) -> Result<[u8; 32], String> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;

    let a_scalar = <Scalar as Reduce<U256>>::reduce_bytes(a.into());
    let b_scalar = <Scalar as Reduce<U256>>::reduce_bytes(b.into());
    let sum = a_scalar + b_scalar;

    let bytes = sum.to_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Compute 33-byte compressed public key from 32-byte private key.
fn priv_to_compressed_pub(privkey: &[u8; 32]) -> Result<[u8; 33], String> {
    let secret_key =
        SecretKey::from_slice(privkey).map_err(|e| format!("Invalid private key: {}", e))?;
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(true);
    let mut result = [0u8; 33];
    result.copy_from_slice(point.as_bytes());
    Ok(result)
}

/// SHA-256 hash, returned as hex string.
pub fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Generate a deterministic password matching the JS `generatePassword()`.
pub fn generate_password(
    private_key: &str,
    user: &str,
    site: &str,
    nonce: u32,
    hash_length: u32,
) -> String {
    let concat = format!("{}/{}/{}/{}", private_key, user, site, nonce);
    let entropy = &sha256_hex(&concat)[..hash_length as usize];
    format!("PASS{}249+", entropy)
}

// ── AES-256-GCM Encryption (matching JS v3 format) ─────────────────────

const LOCAL_ENCRYPT_VERSION: u32 = 3;
const PBKDF2_ITERATIONS: u32 = 600_000;

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalEnvelope {
    v: u32,
    salt: String,
    iv: String,
    ciphertext: String,
}

/// Derive AES-256-GCM key from passphrase using PBKDF2-SHA256.
fn derive_local_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt plaintext with AES-256-GCM, returning a v3 JSON envelope string.
pub fn encrypt_local(plaintext: &str, passphrase: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut key_bytes = derive_local_key(passphrase.as_bytes(), &salt);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("AES key init failed: {}", e))?;
    key_bytes.zeroize();

    let mut iv_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let envelope = LocalEnvelope {
        v: LOCAL_ENCRYPT_VERSION,
        salt: base64_encode(&salt),
        iv: base64_encode(&iv_bytes),
        ciphertext: base64_encode(&ciphertext),
    };

    iv_bytes.zeroize();

    serde_json::to_string(&envelope).map_err(|e| format!("JSON serialize failed: {}", e))
}

/// Decrypt a v3 JSON envelope string with AES-256-GCM.
pub fn decrypt_local(envelope_str: &str, passphrase: &str) -> Result<String, String> {
    let envelope: LocalEnvelope =
        serde_json::from_str(envelope_str).map_err(|e| format!("Invalid envelope: {}", e))?;

    if envelope.v != LOCAL_ENCRYPT_VERSION {
        return Err(format!("Unknown encryption version: {}", envelope.v));
    }

    let salt = base64_decode(&envelope.salt)?;
    let iv = base64_decode(&envelope.iv)?;
    let ciphertext = base64_decode(&envelope.ciphertext)?;

    let mut key_bytes = derive_local_key(passphrase.as_bytes(), &salt);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("AES key init failed: {}", e))?;
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed (wrong password or corrupted data)".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode failed: {}", e))
}

// ── Backup encryption (Layer 1, matching JS backup password flow) ───────

const BACKUP_ENCRYPTED_VERSION: u32 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupEnvelope {
    v: u32,
    iv: String,
    ciphertext: String,
}

/// Encrypt with backup password (Layer 1). Uses npub_hex as PBKDF2 salt.
pub fn encrypt_with_backup_password(
    plaintext: &str,
    password: &str,
    npub_hex: &str,
) -> Result<String, String> {
    let mut key_bytes = derive_local_key(password.as_bytes(), npub_hex.as_bytes());

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("AES key init failed: {}", e))?;
    key_bytes.zeroize();

    let mut iv_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let envelope = BackupEnvelope {
        v: BACKUP_ENCRYPTED_VERSION,
        iv: base64_encode(&iv_bytes),
        ciphertext: base64_encode(&ciphertext),
    };

    iv_bytes.zeroize();

    serde_json::to_string(&envelope).map_err(|e| format!("JSON serialize failed: {}", e))
}

/// Decrypt Layer 1 backup envelope.
pub fn decrypt_with_backup_password(
    envelope_str: &str,
    password: &str,
    npub_hex: &str,
) -> Result<String, String> {
    let envelope: BackupEnvelope =
        serde_json::from_str(envelope_str).map_err(|e| format!("Invalid envelope: {}", e))?;

    if envelope.v != BACKUP_ENCRYPTED_VERSION {
        return Err(format!("Unknown backup version: {}", envelope.v));
    }

    let iv = base64_decode(&envelope.iv)?;
    let ciphertext = base64_decode(&envelope.ciphertext)?;

    let mut key_bytes = derive_local_key(password.as_bytes(), npub_hex.as_bytes());

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("AES key init failed: {}", e))?;
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Backup password incorrect".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode failed: {}", e))
}

// ── NIP-19 encoding ─────────────────────────────────────────────────────

/// Convert hex public key to npub bech32 string.
pub fn hex_to_npub(hex_pk: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_pk).map_err(|e| format!("Invalid hex: {}", e))?;
    bech32_encode("npub", &bytes)
}

/// Convert hex secret key to nsec bech32 string.
pub fn hex_to_nsec(hex_sk: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_sk).map_err(|e| format!("Invalid hex: {}", e))?;
    bech32_encode("nsec", &bytes)
}

/// Simple bech32 encoding (Nostr uses bech32, not bech32m).
fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String, String> {
    // Convert 8-bit data to 5-bit groups
    let mut bits = Vec::new();
    for &byte in data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    // Pad to 5-bit boundary
    while bits.len() % 5 != 0 {
        bits.push(0);
    }
    let data5: Vec<u8> = bits.chunks(5).map(|chunk| {
        chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b)
    }).collect();

    // Bech32 charset
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Compute checksum (bech32, not bech32m)
    let hrp_bytes: Vec<u8> = hrp.bytes().collect();
    let mut values = Vec::new();
    for &b in &hrp_bytes {
        values.push(b >> 5);
    }
    values.push(0);
    for &b in &hrp_bytes {
        values.push(b & 31);
    }
    values.extend_from_slice(&data5);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    let polymod = bech32_polymod(&values) ^ 1; // bech32 constant = 1
    let mut checksum = Vec::new();
    for i in 0..6 {
        checksum.push(((polymod >> (5 * (5 - i))) & 31) as u8);
    }

    let mut result = String::from(hrp);
    result.push('1');
    for &v in data5.iter().chain(checksum.iter()) {
        result.push(CHARSET[v as usize] as char);
    }
    Ok(result)
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, &g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

// ── Base64 helpers (matching JS btoa/atob) ──────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARSET[((triple >> 18) & 63) as usize] as char);
        result.push(CHARSET[((triple >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARSET[((triple >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARSET[(triple & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    const DECODE: [i8; 128] = {
        let mut table = [-1i8; 128];
        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[charset[i] as usize] = i as i8;
            i += 1;
        }
        table
    };

    let bytes: Vec<u8> = encoded.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = DECODE.get(chunk[0] as usize).copied().unwrap_or(-1);
        let b = DECODE.get(chunk[1] as usize).copied().unwrap_or(-1);
        let c = if chunk.len() > 2 && chunk[2] != b'=' {
            DECODE.get(chunk[2] as usize).copied().unwrap_or(-1)
        } else {
            0
        };
        let d = if chunk.len() > 3 && chunk[3] != b'=' {
            DECODE.get(chunk[3] as usize).copied().unwrap_or(-1)
        } else {
            0
        };
        if a < 0 || b < 0 {
            return Err("Invalid base64".to_string());
        }
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push((triple >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push(triple as u8);
        }
    }

    Ok(result)
}

/// Initialize vault secrets from seed phrase.
pub fn initialize_vault_secrets(
    seed_phrase: &str,
    passphrase: &str,
) -> Result<(VaultSecrets, NostrKeyPair, LegacyNostrKeyPair), String> {
    let wordlist = get_wordlist();
    let normalized = seed_phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let private_key = derive_private_key(&normalized, &wordlist)?;
    let nostr_keys = derive_nostr_keys_nip06(&normalized, passphrase)?;
    let legacy_nostr_keys = derive_nostr_keys_legacy(&private_key)?;

    let secrets = VaultSecrets {
        seed_phrase: normalized,
        private_key,
        passphrase: passphrase.to_string(),
    };

    Ok((secrets, nostr_keys, legacy_nostr_keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert!(verify_seed_phrase(&mnemonic));
    }

    #[test]
    fn test_nip06_test_vector() {
        // Standard NIP-06 test vector
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = derive_nostr_keys_nip06(mnemonic, "").unwrap();
        assert_eq!(
            keys.sk_hex,
            "5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731"
        );
    }

    #[test]
    fn test_custom_private_key_derivation() {
        let wordlist = get_wordlist();
        // "abandon" has index 0
        let key = derive_private_key("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", &wordlist).unwrap();
        // indices: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0003
        // decimal: "000000000000000000000000000000000000000000000003"
        // hex of 3 = "3"
        assert_eq!(key, "3");
    }

    #[test]
    fn test_password_generation() {
        // The password should match JS output for the same inputs
        let pass = generate_password("abc123", "user@test.com", "example.com", 0, 16);
        assert!(pass.starts_with("PASS"));
        assert!(pass.ends_with("249+"));
        assert_eq!(pass.len(), 4 + 16 + 4); // PASS + 16 hex chars + 249+
    }

    #[test]
    fn test_encrypt_decrypt_local() {
        let plaintext = r#"{"privateKey":"abc","seedPhrase":"test words"}"#;
        let password = "testpassword123";

        let encrypted = encrypt_local(plaintext, password).unwrap();
        let decrypted = decrypt_local(&encrypted, password).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_wrong_password() {
        let plaintext = "secret data";
        let encrypted = encrypt_local(plaintext, "correct").unwrap();
        let result = decrypt_local(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_bech32_npub() {
        // Test with a known public key
        let npub = hex_to_npub("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34").unwrap();
        assert!(npub.starts_with("npub1"));
    }

    #[test]
    fn test_envelope_format_compatibility() {
        // Verify the encrypted envelope matches JS v3 format
        let encrypted = encrypt_local("test data", "password123").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&encrypted).unwrap();

        assert_eq!(parsed["v"], 3);
        assert!(parsed["salt"].is_string());
        assert!(parsed["iv"].is_string());
        assert!(parsed["ciphertext"].is_string());

        // Verify base64 fields decode correctly
        let salt = base64_decode(parsed["salt"].as_str().unwrap()).unwrap();
        let iv = base64_decode(parsed["iv"].as_str().unwrap()).unwrap();
        assert_eq!(salt.len(), 16); // 128-bit salt
        assert_eq!(iv.len(), 12);   // 96-bit IV for GCM
    }

    #[test]
    fn test_full_vault_round_trip() {
        // Test the complete flow: mnemonic → keys → password → encrypt → decrypt
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let (secrets, nostr_keys, legacy_keys) =
            initialize_vault_secrets(mnemonic, "").unwrap();

        // Verify custom private key derivation
        assert_eq!(secrets.private_key, "3");

        // Verify NIP-06 key matches test vector
        assert_eq!(
            nostr_keys.sk_hex,
            "5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731"
        );
        assert!(nostr_keys.is_nip06);

        // Verify legacy keys are derived from private key
        let expected_legacy_sk = sha256_hex(&secrets.private_key);
        assert_eq!(legacy_keys.sk_hex, expected_legacy_sk);

        // Verify password generation is deterministic
        let pass1 = generate_password(&secrets.private_key, "user@test.com", "github.com", 0, 16);
        let pass2 = generate_password(&secrets.private_key, "user@test.com", "github.com", 0, 16);
        assert_eq!(pass1, pass2);
        assert!(pass1.starts_with("PASS"));
        assert!(pass1.ends_with("249+"));

        // Different nonce → different password
        let pass3 = generate_password(&secrets.private_key, "user@test.com", "github.com", 1, 16);
        assert_ne!(pass1, pass3);

        // Encrypt and decrypt vault data
        let vault_json = serde_json::json!({
            "privateKey": secrets.private_key,
            "seedPhrase": secrets.seed_phrase,
            "passphrase": "",
            "users": {"user@test.com": {"github.com": 0}},
            "settings": {"hashLength": 16}
        });
        let plaintext = serde_json::to_string(&vault_json).unwrap();
        let encrypted = encrypt_local(&plaintext, "master_password").unwrap();
        let decrypted = decrypt_local(&encrypted, "master_password").unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_backup_password_round_trip() {
        let plaintext = r#"{"users":{"alice":{"bank.com":2}}}"#;
        let password = "backup_pass_123";
        let npub_hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234f9d834e34";

        let encrypted = encrypt_with_backup_password(plaintext, password, npub_hex).unwrap();
        let decrypted = decrypt_with_backup_password(&encrypted, password, npub_hex).unwrap();
        assert_eq!(plaintext, decrypted);

        // Wrong password should fail
        let result = decrypt_with_backup_password(&encrypted, "wrong", npub_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_round_trip() {
        // Generate a key pair and verify NIP-44 self-encrypt/decrypt
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = derive_nostr_keys_nip06(mnemonic, "").unwrap();

        let plaintext = r#"{"users":{"test":{"site.com":5}}}"#;
        let encrypted = crate::nostr_ops::nip44_encrypt(plaintext, &keys.sk_hex, &keys.pk_hex).unwrap();
        let decrypted = crate::nostr_ops::nip44_decrypt(&encrypted, &keys.sk_hex, &keys.pk_hex).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_base64_round_trip() {
        // Verify base64 encode/decode matches JS btoa/atob behavior
        let test_data: &[u8] = &[0, 1, 2, 255, 128, 64, 32, 16, 8, 4, 2, 1];
        let encoded = base64_encode(test_data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(test_data, decoded.as_slice());

        // Test with various lengths (padding edge cases)
        for len in 1..=20 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(data, dec, "Failed for length {}", len);
        }
    }
}
