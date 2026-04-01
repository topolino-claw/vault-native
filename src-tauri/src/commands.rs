use crate::crypto;
use crate::state::{AppVault, VaultPublicInfo, VaultSettings};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::collections::HashMap;
use tauri::State;

// ── Mnemonic Operations ─────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_generate_mnemonic() -> Result<String, String> {
    crypto::generate_mnemonic()
}

#[tauri::command]
pub fn cmd_verify_seed_phrase(phrase: String) -> bool {
    crypto::verify_seed_phrase(&phrase)
}

// ── Vault Lifecycle ─────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_initialize_vault(
    seed_phrase: String,
    passphrase: String,
    vault: State<'_, AppVault>,
) -> Result<VaultPublicInfo, String> {
    if !crypto::verify_seed_phrase(&seed_phrase) {
        return Err("Invalid BIP39 seed phrase (bad checksum or unknown words)".to_string());
    }

    let (secrets, nostr_keys, legacy_nostr_keys) =
        crypto::initialize_vault_secrets(&seed_phrase, &passphrase)?;

    // Clear stale vault data from any previously loaded account
    *vault.data.lock() = crate::state::VaultData::default();

    *vault.secrets.lock() = Some(secrets);
    *vault.nostr_keys.lock() = Some(nostr_keys);
    *vault.legacy_nostr_keys.lock() = Some(legacy_nostr_keys);

    vault.mlock_secrets();

    vault
        .public_info()
        .ok_or_else(|| "Failed to get public info after init".to_string())
}

#[tauri::command]
pub fn cmd_lock_vault(vault: State<'_, AppVault>) {
    vault.lock();
}

#[tauri::command]
pub fn cmd_is_unlocked(vault: State<'_, AppVault>) -> bool {
    vault.is_unlocked()
}

#[tauri::command]
pub fn cmd_get_public_info(vault: State<'_, AppVault>) -> Result<VaultPublicInfo, String> {
    vault
        .public_info()
        .ok_or_else(|| "Vault is locked".to_string())
}

// ── Master Password ─────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_set_master_password(
    password: String,
    vault: State<'_, AppVault>,
) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    *vault.master_password.lock() = Some(SecretString::from(password));
    Ok(())
}

#[tauri::command]
pub fn cmd_has_master_password(vault: State<'_, AppVault>) -> bool {
    vault.master_password.lock().is_some()
}

// ── Password Generation ─────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_generate_password(
    user: String,
    site: String,
    nonce: u32,
    hash_length: u32,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let secrets = vault.secrets.lock();
    let secrets = secrets
        .as_ref()
        .ok_or("Vault is locked")?;

    Ok(crypto::generate_password(
        &secrets.private_key,
        &user,
        &site,
        nonce,
        hash_length,
    ))
}

// ── Vault Encryption (for localStorage) ─────────────────────────────────

/// Encrypt the full vault state for localStorage persistence.
/// Returns the encrypted envelope JSON string.
#[tauri::command]
pub fn cmd_encrypt_vault(vault: State<'_, AppVault>) -> Result<String, String> {
    let secrets = vault.secrets.lock();
    let secrets = secrets.as_ref().ok_or("Vault is locked")?;
    let master_pw = vault.master_password.lock();
    let master_pw = master_pw.as_ref().ok_or("No master password set")?;
    let data = vault.data.lock();

    // Build the save object matching JS format
    let save_obj = serde_json::json!({
        "privateKey": secrets.private_key,
        "seedPhrase": secrets.seed_phrase,
        "passphrase": secrets.passphrase,
        "users": data.users,
        "settings": data.settings,
    });

    let plaintext = serde_json::to_string(&save_obj)
        .map_err(|e| format!("Serialize failed: {}", e))?;

    crypto::encrypt_local(&plaintext, master_pw.expose_secret())
}

/// Encrypt nonce backup (users + settings) using private key as passphrase.
#[tauri::command]
pub fn cmd_encrypt_nonce_backup(vault: State<'_, AppVault>) -> Result<String, String> {
    let secrets = vault.secrets.lock();
    let secrets = secrets.as_ref().ok_or("Vault is locked")?;
    let data = vault.data.lock();

    let backup_obj = serde_json::json!({
        "users": data.users,
        "settings": data.settings,
    });

    let plaintext = serde_json::to_string(&backup_obj)
        .map_err(|e| format!("Serialize failed: {}", e))?;

    crypto::encrypt_local(&plaintext, &secrets.private_key)
}

/// Decrypt vault from localStorage envelope + password.
/// Loads the decrypted data into the Rust vault state.
#[tauri::command]
pub fn cmd_unlock_vault(
    encrypted: String,
    password: String,
    vault: State<'_, AppVault>,
) -> Result<VaultPublicInfo, String> {
    let plaintext = crypto::decrypt_local(&encrypted, &password)?;

    #[derive(Deserialize)]
    struct SavedVault {
        #[serde(rename = "privateKey", default)]
        private_key: String,
        #[serde(rename = "seedPhrase", default)]
        seed_phrase: String,
        #[serde(default)]
        passphrase: String,
        #[serde(default)]
        users: HashMap<String, HashMap<String, u64>>,
        #[serde(default)]
        settings: VaultSettings,
    }

    let saved: SavedVault =
        serde_json::from_str(&plaintext).map_err(|e| format!("Invalid vault data: {}", e))?;

    // Derive Nostr keys
    let nostr_keys = if !saved.seed_phrase.is_empty() {
        crypto::derive_nostr_keys_nip06(&saved.seed_phrase, &saved.passphrase)?
    } else {
        // Legacy: no seed phrase, derive from private key via SHA-256
        let legacy = crypto::derive_nostr_keys_legacy(&saved.private_key)?;
        crate::state::NostrKeyPair {
            sk_hex: legacy.sk_hex.clone(),
            pk_hex: legacy.pk_hex.clone(),
            is_nip06: false,
        }
    };

    let legacy_nostr_keys = if !saved.private_key.is_empty() {
        Some(crypto::derive_nostr_keys_legacy(&saved.private_key)?)
    } else {
        None
    };

    let secrets = crate::state::VaultSecrets {
        seed_phrase: saved.seed_phrase,
        private_key: saved.private_key,
        passphrase: saved.passphrase,
    };

    *vault.secrets.lock() = Some(secrets);
    *vault.nostr_keys.lock() = Some(nostr_keys);
    *vault.legacy_nostr_keys.lock() = legacy_nostr_keys;
    *vault.master_password.lock() = Some(SecretString::from(password));
    {
        let mut data = vault.data.lock();
        data.users = saved.users;
        data.settings = saved.settings;
    }

    vault.mlock_secrets();

    vault
        .public_info()
        .ok_or_else(|| "Failed to get public info after unlock".to_string())
}

/// Decrypt a nonce backup envelope using private key.
#[tauri::command]
pub fn cmd_decrypt_nonce_backup(
    encrypted: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let secrets = vault.secrets.lock();
    let secrets = secrets.as_ref().ok_or("Vault is locked")?;
    crypto::decrypt_local(&encrypted, &secrets.private_key)
}

// ── Vault Data Management (non-secret) ──────────────────────────────────

#[tauri::command]
pub fn cmd_set_vault_users(
    users_json: String,
    vault: State<'_, AppVault>,
) -> Result<(), String> {
    if !vault.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let users: HashMap<String, HashMap<String, u64>> =
        serde_json::from_str(&users_json).map_err(|e| format!("Invalid users JSON: {}", e))?;
    vault.data.lock().users = users;
    Ok(())
}

#[tauri::command]
pub fn cmd_set_vault_settings(
    settings_json: String,
    vault: State<'_, AppVault>,
) -> Result<(), String> {
    if !vault.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let settings: VaultSettings =
        serde_json::from_str(&settings_json)
            .map_err(|e| format!("Invalid settings JSON: {}", e))?;
    vault.data.lock().settings = settings;
    Ok(())
}

#[tauri::command]
pub fn cmd_get_vault_data(vault: State<'_, AppVault>) -> Result<String, String> {
    if !vault.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let data = vault.data.lock();
    serde_json::to_string(&*data).map_err(|e| format!("Serialize failed: {}", e))
}

#[tauri::command]
pub fn cmd_merge_users(
    remote_users_json: String,
    vault: State<'_, AppVault>,
) -> Result<(), String> {
    if !vault.is_unlocked() {
        return Err("Vault is locked".to_string());
    }
    let remote_users: HashMap<String, HashMap<String, u64>> =
        serde_json::from_str(&remote_users_json)
            .map_err(|e| format!("Invalid remote users JSON: {}", e))?;

    let mut data = vault.data.lock();
    // Merge: keep higher nonce for each user/site pair
    for (user, sites) in remote_users {
        let local_sites = data.users.entry(user).or_default();
        for (site, remote_nonce) in sites {
            let local_nonce = local_sites.entry(site).or_insert(0);
            if remote_nonce > *local_nonce {
                *local_nonce = remote_nonce;
            }
        }
    }
    Ok(())
}

// ── Nostr Key Access ────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_get_nostr_pubkey(vault: State<'_, AppVault>) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    Ok(keys.pk_hex.clone())
}

#[tauri::command]
pub fn cmd_get_npub(vault: State<'_, AppVault>) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    crypto::hex_to_npub(&keys.pk_hex)
}

#[tauri::command]
pub fn cmd_get_legacy_nostr_pubkey(vault: State<'_, AppVault>) -> Result<String, String> {
    let keys = vault.legacy_nostr_keys.lock();
    let keys = keys.as_ref().ok_or("No legacy keys available")?;
    Ok(keys.pk_hex.clone())
}

// ── Nostr Event Signing ─────────────────────────────────────────────────

/// Sign a Nostr event. Takes a partial event JSON (without id/sig),
/// computes the event hash (id) and schnorr signature.
#[tauri::command]
pub fn cmd_sign_nostr_event(
    event_json: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    crate::nostr_ops::sign_event(&event_json, &keys.sk_hex, &keys.pk_hex)
}

/// Sign a Nostr event with legacy keys.
#[tauri::command]
pub fn cmd_sign_nostr_event_legacy(
    event_json: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.legacy_nostr_keys.lock();
    let keys = keys.as_ref().ok_or("No legacy keys")?;
    crate::nostr_ops::sign_event(&event_json, &keys.sk_hex, &keys.pk_hex)
}

// ── NIP-44 Encryption/Decryption ────────────────────────────────────────

/// NIP-44 self-encrypt (sender == receiver) for Nostr backup.
#[tauri::command]
pub fn cmd_nip44_self_encrypt(
    plaintext: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    crate::nostr_ops::nip44_encrypt(&plaintext, &keys.sk_hex, &keys.pk_hex)
}

/// NIP-44 self-decrypt.
#[tauri::command]
pub fn cmd_nip44_self_decrypt(
    ciphertext: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    crate::nostr_ops::nip44_decrypt(&ciphertext, &keys.sk_hex, &keys.pk_hex)
}

/// NIP-44 decrypt with legacy keys (for restoring old backups).
#[tauri::command]
pub fn cmd_nip44_legacy_decrypt(
    ciphertext: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.legacy_nostr_keys.lock();
    let keys = keys.as_ref().ok_or("No legacy keys")?;
    crate::nostr_ops::nip44_decrypt(&ciphertext, &keys.sk_hex, &keys.pk_hex)
}

// ── NIP-04 Decryption (legacy kind:1 events) ────────────────────────────

/// NIP-04 decrypt with current keys.
#[tauri::command]
pub fn cmd_nip04_decrypt(
    ciphertext: String,
    pubkey: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.nostr_keys.lock();
    let keys = keys.as_ref().ok_or("Vault is locked")?;
    crate::nostr_ops::nip04_decrypt(&ciphertext, &keys.sk_hex, &pubkey)
}

/// NIP-04 decrypt with legacy keys.
#[tauri::command]
pub fn cmd_nip04_legacy_decrypt(
    ciphertext: String,
    pubkey: String,
    vault: State<'_, AppVault>,
) -> Result<String, String> {
    let keys = vault.legacy_nostr_keys.lock();
    let keys = keys.as_ref().ok_or("No legacy keys")?;
    crate::nostr_ops::nip04_decrypt(&ciphertext, &keys.sk_hex, &pubkey)
}

// ── Seed Phrase Access (for display) ────────────────────────────────────

#[tauri::command]
pub fn cmd_get_seed_phrase(vault: State<'_, AppVault>) -> Result<String, String> {
    let secrets = vault.secrets.lock();
    let secrets = secrets.as_ref().ok_or("Vault is locked")?;
    Ok(secrets.seed_phrase.clone())
}

// ── Backup Password Encryption ──────────────────────────────────────────

#[tauri::command]
pub fn cmd_encrypt_with_backup_password(
    plaintext: String,
    password: String,
    npub_hex: String,
) -> Result<String, String> {
    crypto::encrypt_with_backup_password(&plaintext, &password, &npub_hex)
}

#[tauri::command]
pub fn cmd_decrypt_with_backup_password(
    envelope_json: String,
    password: String,
    npub_hex: String,
) -> Result<String, String> {
    crypto::decrypt_with_backup_password(&envelope_json, &password, &npub_hex)
}

// ── SHA-256 Hash (for legacy compat) ────────────────────────────────────

#[tauri::command]
pub fn cmd_sha256(text: String) -> String {
    crypto::sha256_hex(&text)
}
