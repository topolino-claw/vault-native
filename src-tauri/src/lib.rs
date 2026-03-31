mod commands;
mod crypto;
mod harden;
mod nostr_ops;
mod state;

use state::AppVault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Apply process hardening before anything else
    harden::apply();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppVault::new())
        .invoke_handler(tauri::generate_handler![
            // Mnemonic
            commands::cmd_generate_mnemonic,
            commands::cmd_verify_seed_phrase,
            // Vault lifecycle
            commands::cmd_initialize_vault,
            commands::cmd_lock_vault,
            commands::cmd_is_unlocked,
            commands::cmd_get_public_info,
            // Master password
            commands::cmd_set_master_password,
            commands::cmd_has_master_password,
            // Password generation
            commands::cmd_generate_password,
            // Vault encryption
            commands::cmd_encrypt_vault,
            commands::cmd_encrypt_nonce_backup,
            commands::cmd_unlock_vault,
            commands::cmd_decrypt_nonce_backup,
            // Vault data (non-secret)
            commands::cmd_set_vault_users,
            commands::cmd_set_vault_settings,
            commands::cmd_get_vault_data,
            commands::cmd_merge_users,
            // Nostr keys (public only — secret keys never leave Rust)
            commands::cmd_get_nostr_pubkey,
            commands::cmd_get_npub,
            commands::cmd_get_legacy_nostr_pubkey,
            // Nostr event signing
            commands::cmd_sign_nostr_event,
            commands::cmd_sign_nostr_event_legacy,
            // NIP-44
            commands::cmd_nip44_self_encrypt,
            commands::cmd_nip44_self_decrypt,
            commands::cmd_nip44_legacy_decrypt,
            // NIP-04 (legacy)
            commands::cmd_nip04_decrypt,
            commands::cmd_nip04_legacy_decrypt,
            // Seed phrase access
            commands::cmd_get_seed_phrase,
            // Backup password
            commands::cmd_encrypt_with_backup_password,
            commands::cmd_decrypt_with_backup_password,
            // SHA-256
            commands::cmd_sha256,
        ])
        .run(tauri::generate_context!())
        .expect("error while running vault");
}
