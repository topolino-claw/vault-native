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
/// Cached PBKDF2-derived key + salt to avoid re-deriving on every save.
/// Invalidated when the master password changes.
pub struct CachedLocalKey {
    pub key: [u8; 32],
    pub salt: [u8; 16],
}

impl Drop for CachedLocalKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

pub struct AppVault {
    pub secrets: Mutex<Option<VaultSecrets>>,
    pub nostr_keys: Mutex<Option<NostrKeyPair>>,
    pub legacy_nostr_keys: Mutex<Option<LegacyNostrKeyPair>>,
    pub data: Mutex<VaultData>,
    pub master_password: Mutex<Option<SecretString>>,
    pub cached_local_key: Mutex<Option<CachedLocalKey>>,
    /// Cached PBKDF2 key for nonce backup encryption (uses private_key as passphrase).
    pub cached_nonce_key: Mutex<Option<CachedLocalKey>>,
}

impl AppVault {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(None),
            nostr_keys: Mutex::new(None),
            legacy_nostr_keys: Mutex::new(None),
            data: Mutex::new(VaultData::default()),
            master_password: Mutex::new(None),
            cached_local_key: Mutex::new(None),
            cached_nonce_key: Mutex::new(None),
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
        *self.cached_local_key.lock() = None;
        *self.cached_nonce_key.lock() = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── AppVault::new defaults ─────────────────────────────────────────

    #[test]
    fn test_app_vault_new_is_locked() {
        let vault = AppVault::new();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn test_app_vault_new_no_master_password() {
        let vault = AppVault::new();
        assert!(vault.master_password.lock().is_none());
    }

    #[test]
    fn test_app_vault_new_no_keys() {
        let vault = AppVault::new();
        assert!(vault.nostr_keys.lock().is_none());
        assert!(vault.legacy_nostr_keys.lock().is_none());
        assert!(vault.secrets.lock().is_none());
    }

    #[test]
    fn test_app_vault_new_empty_data() {
        let vault = AppVault::new();
        let data = vault.data.lock();
        assert!(data.users.is_empty());
        assert_eq!(data.settings.hash_length, 16);
        assert!(!data.settings.debug_mode);
        assert!(!data.settings.last_backup_failed);
    }

    // ── AppVault unlock/lock lifecycle ─────────────────────────────────

    fn setup_unlocked_vault() -> AppVault {
        let vault = AppVault::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (secrets, nostr_keys, legacy_keys) =
            crate::crypto::initialize_vault_secrets(mnemonic, "").unwrap();
        *vault.secrets.lock() = Some(secrets);
        *vault.nostr_keys.lock() = Some(nostr_keys);
        *vault.legacy_nostr_keys.lock() = Some(LegacyNostrKeyPair {
            sk_hex: legacy_keys.sk_hex.clone(),
            pk_hex: legacy_keys.pk_hex.clone(),
        });
        *vault.master_password.lock() = Some(SecretString::from("test_password".to_string()));
        {
            let mut data = vault.data.lock();
            data.users.insert(
                "alice".to_string(),
                [("github.com".to_string(), 3u64)].into_iter().collect(),
            );
        }
        vault
    }

    #[test]
    fn test_app_vault_is_unlocked_after_setup() {
        let vault = setup_unlocked_vault();
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_app_vault_lock_clears_secrets() {
        let vault = setup_unlocked_vault();
        assert!(vault.is_unlocked());

        vault.lock();

        assert!(!vault.is_unlocked());
        assert!(vault.secrets.lock().is_none());
        assert!(vault.nostr_keys.lock().is_none());
        assert!(vault.legacy_nostr_keys.lock().is_none());
        assert!(vault.master_password.lock().is_none());
    }

    #[test]
    fn test_app_vault_lock_clears_data() {
        let vault = setup_unlocked_vault();
        assert!(!vault.data.lock().users.is_empty());

        vault.lock();

        assert!(vault.data.lock().users.is_empty());
    }

    #[test]
    fn test_app_vault_double_lock_is_safe() {
        let vault = setup_unlocked_vault();
        vault.lock();
        vault.lock(); // should not panic
        assert!(!vault.is_unlocked());
    }

    // ── AppVault::public_info ──────────────────────────────────────────

    #[test]
    fn test_public_info_none_when_locked() {
        let vault = AppVault::new();
        assert!(vault.public_info().is_none());
    }

    #[test]
    fn test_public_info_some_when_unlocked() {
        let vault = setup_unlocked_vault();
        let info = vault.public_info();
        assert!(info.is_some());

        let info = info.unwrap();
        assert!(info.npub.starts_with("npub1"));
        assert_eq!(info.npub_hex.len(), 64);
        assert!(info.has_seed);
        assert!(info.has_password);
        assert!(info.users.contains_key("alice"));
        assert_eq!(info.users["alice"]["github.com"], 3);
    }

    #[test]
    fn test_public_info_has_password_false_without_master() {
        let vault = setup_unlocked_vault();
        *vault.master_password.lock() = None;
        let info = vault.public_info().unwrap();
        assert!(!info.has_password);
    }

    #[test]
    fn test_public_info_none_after_lock() {
        let vault = setup_unlocked_vault();
        assert!(vault.public_info().is_some());
        vault.lock();
        assert!(vault.public_info().is_none());
    }

    // ── VaultSettings defaults and serialization ───────────────────────

    #[test]
    fn test_vault_settings_default() {
        let settings = VaultSettings::default();
        assert_eq!(settings.hash_length, 16);
        assert!(!settings.debug_mode);
        assert!(!settings.last_backup_failed);
    }

    #[test]
    fn test_vault_settings_serialization_roundtrip() {
        let settings = VaultSettings {
            hash_length: 32,
            debug_mode: true,
            last_backup_failed: true,
        };
        let json = serde_json::to_string(&settings).unwrap();
        let parsed: VaultSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hash_length, 32);
        assert!(parsed.debug_mode);
        assert!(parsed.last_backup_failed);
    }

    #[test]
    fn test_vault_settings_deserialization_camel_case() {
        // Frontend sends camelCase keys
        let json = r#"{"hashLength":24,"debugMode":false,"lastBackupFailed":true}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.hash_length, 24);
        assert!(!settings.debug_mode);
        assert!(settings.last_backup_failed);
    }

    #[test]
    fn test_vault_settings_deserialization_missing_fields() {
        // Should use defaults for missing fields
        let json = r#"{}"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.hash_length, 16);
        assert!(!settings.debug_mode);
        assert!(!settings.last_backup_failed);
    }

    // ── VaultData defaults ─────────────────────────────────────────────

    #[test]
    fn test_vault_data_default() {
        let data = VaultData::default();
        assert!(data.users.is_empty());
        assert_eq!(data.settings.hash_length, 16);
    }

    #[test]
    fn test_vault_data_serialization_roundtrip() {
        let mut data = VaultData::default();
        data.users.insert(
            "user@test.com".to_string(),
            [("site.com".to_string(), 5u64)].into_iter().collect(),
        );
        data.settings.hash_length = 24;

        let json = serde_json::to_string(&data).unwrap();
        let parsed: VaultData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.users["user@test.com"]["site.com"], 5);
        assert_eq!(parsed.settings.hash_length, 24);
    }

    // ── VaultPublicInfo serialization ──────────────────────────────────

    #[test]
    fn test_vault_public_info_serializes_to_json() {
        let info = VaultPublicInfo {
            npub: "npub1test".to_string(),
            npub_hex: "abcd".repeat(16),
            has_seed: true,
            has_password: false,
            users: HashMap::new(),
            settings: VaultSettings::default(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["npub"], "npub1test");
        assert_eq!(parsed["has_seed"], true);
        assert_eq!(parsed["has_password"], false);
    }

    // ── Thread safety smoke test ───────────────────────────────────────

    #[test]
    fn test_app_vault_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let vault = Arc::new(setup_unlocked_vault());
        let mut handles = vec![];

        // Spawn readers
        for _ in 0..4 {
            let v = Arc::clone(&vault);
            handles.push(thread::spawn(move || {
                assert!(v.is_unlocked());
                let _info = v.public_info();
            }));
        }

        // Spawn a writer
        {
            let v = Arc::clone(&vault);
            handles.push(thread::spawn(move || {
                let mut data = v.data.lock();
                data.users.insert(
                    "bob".to_string(),
                    [("test.com".to_string(), 1u64)].into_iter().collect(),
                );
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Verify writer's change persisted
        assert!(vault.data.lock().users.contains_key("bob"));
    }
}
