# Biometric Unlock Implementation Guide (Android + macOS)

## Context

The Vault app currently requires typing a master password to unlock on every launch and after every auto-lock (5min inactivity / 2min hidden). The goal is to let Android and macOS users unlock with biometrics (fingerprint/Face ID/Touch ID) instead of retyping the password each time. The master password remains the actual encryption key — biometric just stores it securely in the platform keystore/keychain so the user doesn't have to retype it.

**No new UI screens needed** — both Android and macOS provide native biometric dialogs automatically.

## Approach: `tauri-plugin-biometry` (community plugin)

**Why this plugin**: The official `tauri-plugin-biometric` is mobile-only (Android/iOS). The community [`tauri-plugin-biometry`](https://github.com/Choochmeque/tauri-plugin-biometry) by Choochmeque supports **Android, iOS, macOS, and Windows** and bundles both biometric prompts AND secure storage (keystore/keychain) in a single plugin. One dependency solves both problems.

**API we'll use**:
| Function | Purpose |
|----------|---------|
| `checkStatus()` | Is biometric hardware available? |
| `setData({domain, name, data})` | Store master password in keystore/keychain |
| `getData({domain, name, reason})` | Retrieve password (triggers native biometric prompt) |
| `hasData({domain, name})` | Check if we previously stored a password |
| `removeData({domain, name})` | Clear stored password on delete/disable |

Since this is a vanilla JS project (no npm/bundler), all calls go through:
```javascript
window.__TAURI__.core.invoke('plugin:biometry|command_name', args)
```

## How It Works

```
SETUP (one-time, after setting master password):
  User sets master password -> vault encrypted as today
  -> If biometric available: native confirm() asks "Enable biometric unlock?"
  -> If yes: master password stored in Keystore/Keychain via setData()
  -> localStorage flag 'biometricEnabled' = 'true' (non-sensitive, needed pre-decryption)

UNLOCK (every app launch / re-lock):
  App starts -> encrypted vault exists -> show unlock screen
  -> If biometricEnabled flag is set:
     -> Auto-call getData() -> native biometric dialog appears
     -> Success: password retrieved -> decrypt vault as normal
     -> Cancel/Fail: user stays on unlock screen, types password manually
```

---

## Implementation Steps

### Step 1: Add plugin dependency and configuration

**`src-tauri/Cargo.toml`** — add dependency:
```toml
[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-opener = "2"
tauri-plugin-biometry = "0.2"   # ADD THIS
```

**`src-tauri/src/lib.rs`** — register plugin:
```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_biometry::init())  // ADD THIS
        .run(tauri::generate_context!())
        .expect("error while running vault");
}
```

**`src-tauri/tauri.conf.json`** — enable global Tauri API (change `false` to `true`):
```json
"withGlobalTauri": true
```

**`src-tauri/capabilities/default.json`** — add biometry permissions:
```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "description": "Default capabilities",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "opener:default",
    "biometry:default"
  ]
}
```

> **Note**: If `biometry:default` doesn't work, try explicit permissions:
> `"biometry:allow-check-status"`, `"biometry:allow-authenticate"`, `"biometry:allow-set-data"`, `"biometry:allow-get-data"`, `"biometry:allow-has-data"`, `"biometry:allow-remove-data"`

---

### Step 2: Add biometric helper functions to `vault/app.js`

Add these near the top of app.js (after state declarations, around line 60):

```javascript
// ============================================
// Biometric Unlock Helpers
// ============================================

function isTauriAvailable() {
    return !!(window.__TAURI__ && window.__TAURI__.core);
}

async function checkBiometricAvailability() {
    if (!isTauriAvailable()) return { isAvailable: false };
    try {
        return await window.__TAURI__.core.invoke('plugin:biometry|check_status');
        // Returns: { isAvailable: bool, biometryType: number }
        // biometryType: 0=None, 1=TouchID, 2=FaceID, 3=Iris, 4=Windows Hello
    } catch (e) {
        debugLog('checkBiometricAvailability error:', e);
        return { isAvailable: false };
    }
}

async function storeMasterPasswordBiometric(password) {
    try {
        await window.__TAURI__.core.invoke('plugin:biometry|set_data', {
            domain: 'com.topolino.vault',
            name: 'master_password',
            data: password
        });
        localStorage.setItem('biometricEnabled', 'true');
        return true;
    } catch (e) {
        debugLog('storeMasterPasswordBiometric error:', e);
        return false;
    }
}

async function retrieveMasterPasswordBiometric() {
    try {
        const result = await window.__TAURI__.core.invoke('plugin:biometry|get_data', {
            domain: 'com.topolino.vault',
            name: 'master_password',
            reason: 'Unlock your vault'
        });
        return result; // the password string
    } catch (e) {
        debugLog('retrieveMasterPasswordBiometric error:', e);
        return null;
    }
}

async function removeBiometricData() {
    try {
        await window.__TAURI__.core.invoke('plugin:biometry|remove_data', {
            domain: 'com.topolino.vault',
            name: 'master_password'
        });
    } catch (e) {
        debugLog('removeBiometricData error:', e);
    }
    localStorage.removeItem('biometricEnabled');
}

async function attemptBiometricUnlock() {
    if (!isTauriAvailable()) return;
    if (localStorage.getItem('biometricEnabled') !== 'true') return;

    try {
        const password = await retrieveMasterPasswordBiometric();
        if (password) {
            await unlockVaultWithPassword(password);
        }
        // If null/failed, user dismissed the biometric prompt — they see the password screen
    } catch (e) {
        debugLog('attemptBiometricUnlock error:', e);
        // Silent fallback to password entry
    }
}
```

---

### Step 3: Refactor `unlockVault()` in `vault/app.js`

Extract the core decryption logic (currently lines 1437-1517) into a new reusable function:

```javascript
/**
 * Core unlock logic: decrypt vault with a given password.
 * Used by both manual password entry and biometric unlock.
 *
 * @param {string} password - The master password to decrypt with
 * @returns {Promise<boolean>} - true if unlock succeeded
 */
async function unlockVaultWithPassword(password) {
    const stored = localStorage.getItem('vaultEncrypted');
    if (!stored) { showToast('No saved vault found'); return false; }

    let encrypted = stored;
    let isLegacy = false;

    // Detect legacy multi-password JSON format vs new raw AES string
    try {
        const parsed = JSON.parse(stored);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            const key = hash(password);
            const legacyStored = JSON.parse(localStorage.getItem('encryptedDataStorage') || '{}');
            const merged = { ...legacyStored, ...parsed };
            encrypted = merged[key];
            if (!encrypted) throw new Error('not found');
            isLegacy = true;
        }
    } catch (legacyErr) {
        if (isLegacy) throw legacyErr; // Legacy lookup failed — wrong password
        // Not JSON — new format, use stored directly
    }

    const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('decrypt failed');
    const data = JSON.parse(decrypted);

    // Handle both data shapes
    if (data.privateKey) {
        vault.privateKey = data.privateKey;
        vault.seedPhrase = data.seedPhrase || '';
        vault.passphrase = data.passphrase || '';
        vault.users = data.users || {};
        vault.settings = data.settings || { hashLength: 16 };
    } else {
        vault = data;
        vault.passphrase = vault.passphrase || '';
    }

    // Derive Nostr keys
    if (vault.seedPhrase) {
        nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, vault.passphrase || '');
    } else {
        nostrKeys = await deriveNostrKeys(vault.privateKey);
    }

    _masterPassword = password;
    unlockAttempts = 0;

    // Migrate legacy format
    if (isLegacy) {
        autoSaveVault();
        localStorage.removeItem('encryptedDataStorage');
    }

    resetInactivityTimer();
    showToast('Vault unlocked!');
    showScreen('mainScreen');
    return true;
}
```

Then simplify the existing `unlockVault()` to be a thin wrapper:

```javascript
/**
 * Unlock from the password input field (manual entry).
 */
async function unlockVault() {
    // Rate limiting
    const now = Date.now();
    if (now < unlockLockoutUntil) {
        const secs = Math.ceil((unlockLockoutUntil - now) / 1000);
        showToast(`Too many attempts. Wait ${secs}s`);
        return;
    }

    const password = document.getElementById('unlockPassword').value;
    if (!password) { showToast('Enter password'); return; }

    try {
        await unlockVaultWithPassword(password);
    } catch (e) {
        debugLog('unlockVault error:', e);
        unlockAttempts++;
        if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
            unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
            unlockAttempts = 0;
            showToast('Too many attempts. Locked for 30s');
        } else {
            showToast('Invalid password');
        }
    }
}
```

---

### Step 4: Modify `setMasterPassword()` (line 1368)

Add biometric enrollment after the password is set:

```javascript
async function setMasterPassword() {      // make async
    const p1 = document.getElementById('masterPass1').value;
    const p2 = document.getElementById('masterPass2').value;
    if (!p1) { showToast('Enter a password'); return; }
    if (p1 !== p2) { showToast('Passwords don\'t match'); return; }

    _masterPassword = p1;
    autoSaveVault();
    showToast('Password set!');

    // Offer biometric enrollment if available
    if (isTauriAvailable()) {
        const bioStatus = await checkBiometricAvailability();
        if (bioStatus.isAvailable) {
            if (confirm('Enable biometric unlock (fingerprint/Face ID)?')) {
                const stored = await storeMasterPasswordBiometric(p1);
                if (stored) {
                    showToast('Biometric unlock enabled!');
                } else {
                    showToast('Could not enable biometric');
                }
            }
        }
    }

    showScreen('mainScreen');
}
```

---

### Step 5: Modify DOMContentLoaded init (lines 2767-2774)

Add biometric auto-trigger after showing the unlock screen:

```javascript
// Auto-show unlock screen if encrypted vault exists
const storedVault = localStorage.getItem('vaultEncrypted');
const legacyVault = localStorage.getItem('encryptedDataStorage');
if (storedVault || legacyVault) {
    navigationStack = ['unlockScreen'];
    history.replaceState({ screen: 'unlockScreen' }, '');
    showScreen('unlockScreen');

    // Auto-trigger biometric unlock if previously enabled
    attemptBiometricUnlock();
}
```

---

### Step 6: Modify `deleteAllData()` (line 1391)

Add biometric cleanup:

```javascript
function deleteAllData() {
    if (!confirm('Delete ALL vault data from this device? This cannot be undone.')) return;
    if (!confirm('Are you sure? Your locally saved vault will be permanently erased. Cloud backups will NOT be affected.')) return;

    localStorage.removeItem('vaultEncrypted');
    localStorage.removeItem('vaultNonceBackup');
    localStorage.removeItem('encryptedDataStorage');
    localStorage.removeItem('biometricEnabled');         // ADD THIS

    // Clean up biometric-stored master password
    if (isTauriAvailable()) {                            // ADD THIS
        removeBiometricData();                           // ADD THIS
    }                                                    // ADD THIS

    _masterPassword = null;
    vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    _sessionBackupPassword = null;
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
    navigationStack = ['welcomeScreen'];

    document.querySelectorAll('input, textarea').forEach(el => { el.value = ''; });

    showScreen('welcomeScreen');
    showToast('All data deleted');
}
```

---

### Step 7: Add biometric toggle to Settings screen

**`vault/index.html`** — add inside `settingsScreen`, before the Lock Vault button, following the existing toggle pattern:

```html
<div class="settings-item" id="biometricSettingItem" style="display:none;">
    <div>
        <div class="settings-label">Biometric Unlock</div>
        <div class="settings-desc">Use fingerprint or Face ID to unlock</div>
    </div>
    <label class="toggle">
        <input type="checkbox" id="biometricToggle">
        <span class="toggle-slider"></span>
    </label>
</div>
```

**`vault/app.js`** — show/hide toggle when settings screen opens (add to `showScreen()` settingsScreen case):

```javascript
// Show biometric toggle if available
const bioItem = document.getElementById('biometricSettingItem');
if (bioItem && isTauriAvailable()) {
    checkBiometricAvailability().then(status => {
        if (status.isAvailable) {
            bioItem.style.display = '';
            document.getElementById('biometricToggle').checked =
                localStorage.getItem('biometricEnabled') === 'true';
        }
    });
}
```

**`vault/app.js`** — toggle handler (add in the DOMContentLoaded event listener bindings section):

```javascript
const biometricToggle = document.getElementById('biometricToggle');
if (biometricToggle) {
    biometricToggle.addEventListener('change', async () => {
        if (biometricToggle.checked) {
            if (_masterPassword) {
                const stored = await storeMasterPasswordBiometric(_masterPassword);
                if (stored) {
                    showToast('Biometric unlock enabled');
                } else {
                    biometricToggle.checked = false;
                    showToast('Could not enable biometric');
                }
            } else {
                biometricToggle.checked = false;
                showToast('Set a master password first');
            }
        } else {
            await removeBiometricData();
            showToast('Biometric unlock disabled');
        }
    });
}
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `src-tauri/Cargo.toml` | Add `tauri-plugin-biometry = "0.2"` |
| `src-tauri/src/lib.rs` | Register `.plugin(tauri_plugin_biometry::init())` |
| `src-tauri/tauri.conf.json` | Set `withGlobalTauri: true` |
| `src-tauri/capabilities/default.json` | Add `"biometry:default"` |
| `vault/app.js` | Add helper functions, refactor unlockVault, modify setMasterPassword, deleteAllData, DOMContentLoaded |
| `vault/index.html` | Add biometric toggle in settings screen |

---

## Edge Cases & Fallbacks

- **No biometric hardware**: All biometric code is no-op; app works exactly as today
- **Running as web app (no Tauri)**: `isTauriAvailable()` returns false; everything skipped gracefully
- **User cancels biometric prompt**: Returns null; stays on password screen with the input field ready
- **App reinstalled (localStorage gone, keychain persists)**: No `biometricEnabled` flag = no auto-trigger; stale keychain entry is harmless
- **Biometric enrollment changes (new fingerprint added)**: OS may invalidate keystore key; `getData` fails silently; user falls back to password; can re-enable biometric from settings
- **Master password changed**: Must re-call `storeMasterPasswordBiometric()` with new password to keep in sync

---

## Platform Notes

### Android
- **BiometricPrompt**: Native bottom-sheet dialog, no custom UI
- **minSdkVersion**: Already set to 24 (sufficient)
- **AndroidManifest**: May need `<uses-permission android:name="android.permission.USE_BIOMETRIC" />` if plugin doesn't add it automatically
- **Consider**: `allowDeviceCredential: true` option for PIN/pattern fallback

### macOS
- **Touch ID**: Dialog via LocalAuthentication framework
- **Availability**: Only Apple Silicon Macs and some Intel MacBooks with Touch ID keyboard
- **Code signing**: Keychain access requires the app to be code-signed; dev builds may need special entitlements
- **No Touch ID**: Toggle hidden automatically; app works with password only

---

## Difficulty Assessment

| Component | Difficulty | Time |
|-----------|-----------|------|
| Config files (Cargo.toml, lib.rs, tauri.conf.json, capabilities) | Easy | ~30min |
| JS helper functions (thin wrappers around invoke) | Easy | ~30min |
| Refactoring `unlockVault()` into `unlockVaultWithPassword()` | Moderate | ~1hr |
| Settings toggle (follows existing debugModeToggle pattern) | Easy | ~30min |
| Verifying exact IPC command names | Uncertain | test after build |
| Android Gradle integration | Uncertain | may need tweaks |
| **Total (both platforms, including device testing)** | | **~4-6 hours** |

---

## Verification Checklist

1. `cargo build` in `src-tauri/` — plugin compiles without errors
2. Run on macOS desktop — verify Touch ID prompt appears on unlock (if Touch ID available)
3. Build Android APK — deploy to physical device with fingerprint
4. Test: create vault -> set password -> enable biometric -> lock -> unlock with fingerprint
5. Test fallback: cancel biometric -> type password manually
6. Test settings: toggle biometric on/off from settings
7. Test delete: delete all data -> verify keychain entry removed
8. Test web: open `vault/index.html` in browser -> verify no errors (all biometric code skipped)

---

## References

- [tauri-plugin-biometry (GitHub)](https://github.com/Choochmeque/tauri-plugin-biometry) — Community plugin for Android, iOS, macOS, Windows
- [tauri-plugin-biometry (crates.io)](https://crates.io/crates/tauri-plugin-biometry) — Rust crate
- [Official Tauri Biometric Plugin](https://v2.tauri.app/plugin/biometric/) — Mobile-only (Android/iOS), does NOT support macOS
- [Tauri Calling Rust from Frontend](https://v2.tauri.app/develop/calling-rust/) — How to use `window.__TAURI__` for vanilla JS
- [Tauri Capabilities](https://v2.tauri.app/security/capabilities/) — Permission system
