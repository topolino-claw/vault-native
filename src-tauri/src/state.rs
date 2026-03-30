use parking_lot::Mutex;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Best-effort mlock/munlock on a struct's memory region.
/// Prevents the OS from swapping secret data to disk.
fn mlock_struct<T>(ptr: &T, lock: bool) {
    let addr = ptr as *const T as *mut u8;
    let size = std::mem::size_of::<T>();
    if size == 0 {
        return;
    }
    unsafe {
        if lock {
            if !memsec::mlock(addr, size) {
                eprintln!("[harden] mlock failed for {} bytes — secrets may be swappable", size);
            }
        } else {
            memsec::munlock(addr, size);
        }
    }
}

/// Nostr key pair with zeroize-on-drop for secret key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NostrKeyPair {
    /// 64-char hex Nostr secret key
    pub sk_hex: String,
    /// 64-char hex Nostr public key (not secret, but zeroized with struct)
    pub pk_hex: String,
    /// Whether this was derived via NIP-06 (true) or legacy SHA-256 (false)
    #[zeroize(skip)]
    pub is_nip06: bool,
}

/// Legacy Nostr key pair (SHA-256 of vault private key).
/// Kept separately so we can look up old backups.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LegacyNostrKeyPair {
    pub sk_hex: String,
    pub pk_hex: String,
}

/// Core vault secrets, held in mlock'd memory with zeroize-on-drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSecrets {
    /// BIP39 mnemonic phrase
    pub seed_phrase: String,
    /// Custom hex private key (word-indices → decimal → hex)
    pub private_key: String,
    /// BIP39 passphrase (25th word), empty string if none
    pub passphrase: String,
}

/// Non-secret vault data (nonces, settings).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub users: HashMap<String, HashMap<String, u64>>,
    pub settings: VaultSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    #[serde(rename = "hashLength", default = "default_hash_length")]
    pub hash_length: u32,
    #[serde(rename = "debugMode", default)]
    pub debug_mode: bool,
    #[serde(rename = "lastBackupFailed", default)]
    pub last_backup_failed: bool,
}

fn default_hash_length() -> u32 {
    16
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            hash_length: 16,
            debug_mode: false,
            last_backup_failed: false,
        }
    }
}

/// Public info returned to the JS frontend (no secret material).
#[derive(Serialize)]
pub struct VaultPublicInfo {
    pub npub: String,
    pub npub_hex: String,
    pub has_seed: bool,
    pub has_password: bool,
    pub users: HashMap<String, HashMap<String, u64>>,
    pub settings: VaultSettings,
}

/// Thread-safe vault state managed by Tauri.
pub struct AppVault {
    pub secrets: Mutex<Option<VaultSecrets>>,
    pub nostr_keys: Mutex<Option<NostrKeyPair>>,
    pub legacy_nostr_keys: Mutex<Option<LegacyNostrKeyPair>>,
    pub data: Mutex<VaultData>,
    pub master_password: Mutex<Option<SecretString>>,
}

impl AppVault {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            nostr_keys: Mutex::new(None),
            legacy_nostr_keys: Mutex::new(None),
            data: Mutex::new(VaultData::default()),
            master_password: Mutex::new(None),
        }
    }

    /// Check if the vault is currently unlocked (has secrets loaded).
    pub fn is_unlocked(&self) -> bool {
        self.secrets.lock().is_some()
    }

    /// Apply mlock to all currently held secret buffers.
    /// Call this after storing secrets.
    pub fn mlock_secrets(&self) {
        if let Some(ref secrets) = *self.secrets.lock() {
            mlock_struct(secrets, true);
        }
        if let Some(ref keys) = *self.nostr_keys.lock() {
            mlock_struct(keys, true);
        }
        if let Some(ref keys) = *self.legacy_nostr_keys.lock() {
            mlock_struct(keys, true);
        }
    }

    /// Lock the vault: zero and drop all secret material.
    pub fn lock(&self) {
        // Drop secrets via `= None`, which triggers ZeroizeOnDrop to properly
        // zero each String field's heap buffer before deallocation.
        //
        // Note: we intentionally do NOT call memsec::munlock here because
        // munlock calls memzero on the struct in-place first, which corrupts
        // the String metadata (nulls pointers/lengths/capacities) before
        // ZeroizeOnDrop can properly zero the heap buffers — causing UB/crash.
        // The mlock'd pages stay locked (harmless, just zeros) until process exit.
        *self.secrets.lock() = None;
        *self.nostr_keys.lock() = None;
        *self.legacy_nostr_keys.lock() = None;
        *self.master_password.lock() = None;
        // Non-secret data is kept for potential re-lock scenarios,
        // but cleared for safety
        *self.data.lock() = VaultData::default();
    }

    /// Get public info for the JS frontend.
    pub fn public_info(&self) -> Option<VaultPublicInfo> {
        let nostr = self.nostr_keys.lock();
        let secrets = self.secrets.lock();
        let data = self.data.lock();
        let has_password = self.master_password.lock().is_some();

        let nostr = nostr.as_ref()?;
        let _secrets = secrets.as_ref()?;

        // Encode npub via bech32 (nip19)
        let npub = crate::crypto::hex_to_npub(&nostr.pk_hex).unwrap_or_default();

        Some(VaultPublicInfo {
            npub,
            npub_hex: nostr.pk_hex.clone(),
            has_seed: true,
            has_password,
            users: data.users.clone(),
            settings: data.settings.clone(),
        })
    }
}
