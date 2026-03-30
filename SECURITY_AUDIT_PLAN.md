# Security Audit Plan: Vault Native — 3 Parallel Agents

## Context

Vault Native is a Tauri 2 deterministic password manager that holds BIP39 seed phrases, derived private keys, and Nostr signing keys. A security flaw here means total compromise of all generated passwords and the user's Nostr identity. This audit systematically covers every security-relevant file using 3 specialized agents running in parallel, each owning a distinct trust domain with zero overlap.

---

## Agent Architecture

### Agent 1: CRYPTO-CORE — Cryptographic Primitives & Memory Protection

**Scope:** All cryptographic operations, key derivation, entropy, memory security, process hardening.

**Files to audit:**
- `src-tauri/src/crypto.rs` — BIP39, BIP32/NIP-06, custom key derivation, AES-256-GCM, PBKDF2, bech32
- `src-tauri/src/state.rs` — AppVault, mlock/munlock, Zeroize+ZeroizeOnDrop, Mutex-wrapped secrets
- `src-tauri/src/harden.rs` — PT_DENY_ATTACH, PR_SET_DUMPABLE, RLIMIT_CORE
- `src-tauri/src/nostr_ops.rs` — Schnorr signing, NIP-44/NIP-04 encrypt/decrypt
- `src-tauri/Cargo.toml` — dependency versions, feature flags, release profile
- `vault/bip39WordList.js` — wordlist integrity

**Specific checks:**
1. **Entropy**: Verify `rand::thread_rng()` uses CSPRNG on all platforms; entropy zeroized after use
2. **BIP39**: Checksum validation correctness for 12/15/18/21/24 words; wordlist parsing yields exactly 2048 words
3. **Custom key derivation** (`derive_private_key`): Assess entropy loss from word-indices-to-decimal-to-hex; check for degenerate keys (all-zero indices producing key "0")
4. **BIP32/NIP-06**: Correct derivation path `m/44'/1237'/0'/0/0`; PBKDF2-SHA512 with 2048 iterations; hardened vs normal derivation; `secp256k1_mod_add` correctness (zero scalar risk)
5. **AES-256-GCM**: Fresh random salt (16B) and IV (12B) per encryption; 600K PBKDF2 iterations; backup password uses `npub_hex` as fixed salt (assess weakness)
6. **mlock flaw**: `mlock_struct()` locks the struct metadata (pointer/len/capacity), NOT the heap-allocated String data — the actual secret bytes are NOT mlock'd
7. **Legacy nostr keys not munlocked**: `AppVault::lock()` munlocks secrets and nostr_keys but skips `legacy_nostr_keys`
8. **Zeroize completeness**: All intermediate key bytes, `sk_bytes` in nostr_ops, BIP32 derivation intermediates
9. **Process hardening gaps**: No Windows hardening; no Android hardening (both are build targets)
10. **Password generation**: 64-bit entropy from 16 hex chars — assess collision risk; fixed prefix/suffix
11. **Dependency CVEs**: Check aes-gcm 0.10, k256 0.13, nostr 0.37, rand 0.8, pbkdf2 0.12

**Owns BUGS.md:** #14 (unverified seed in memory — crypto aspect)

**Output format:**
```
[CRYPTO-CORE-NNN] Severity: CRITICAL|HIGH|MEDIUM|LOW|INFO
Title: <description>
Location: <file:line>
Description: <technical detail>
Impact: <what an attacker can achieve>
Recommendation: <specific fix>
```

---

### Agent 2: IPC-BOUNDARY — Tauri Commands, Trust Boundary & Configuration

**Scope:** The JS-to-Rust IPC boundary, all 35 command handlers, input validation, CSP, Tauri permissions, service worker, third-party libs.

**Files to audit:**
- `src-tauri/src/commands.rs` — All 35 Tauri IPC command handlers
- `src-tauri/src/lib.rs` — Tauri builder, plugin init, command registration
- `src-tauri/src/main.rs` — Entry point
- `src-tauri/tauri.conf.json` — CSP (`connect-src 'self' wss: https:` is overly broad), `withGlobalTauri: true`
- `src-tauri/capabilities/default.json` — Permission grants
- `vault/index.html` — HTML CSP meta tag, DOM structure
- `vault/sw.js` — Service worker cache logic
- `vault/crypto-js.min.js` — CVE check only
- `vault/lib/nostr-tools.min.js` — CVE check only

**Specific checks:**
1. **Secret leakage via IPC**: 4 commands return raw secrets to JS — `cmd_get_seed_phrase`, `cmd_get_nsec`, `cmd_get_nostr_hex_sk`, `cmd_get_legacy_nostr_sk`. Catalogue all callers; assess necessity
2. **Input validation gaps**: `cmd_initialize_vault` accepts any string as seed_phrase (no BIP39 validation); `cmd_set_master_password` password `String` param not zeroized after conversion to `SecretString`; `cmd_unlock_vault` same issue with `password` param on the stack
3. **`withGlobalTauri: true`**: Exposes `window.__TAURI__` to all JS — any XSS gives full access to all 35 IPC commands including secret-returning ones
4. **CSP analysis**: Tauri CSP has `connect-src 'self' wss: https:` (any WebSocket/HTTPS endpoint reachable); HTML CSP is stricter but doesn't apply inside Tauri; neither has `object-src 'none'` or `frame-ancestors 'none'`
5. **Vault lock checks**: Verify ALL commands that access secrets check `is_unlocked()` — scan for commands that skip the check
6. **Service worker**: Bug #9 (cache never updates); assess if encrypted vault blobs could end up cached; stale cache attack vector
7. **Third-party lib versions**: Determine CryptoJS and nostr-tools versions; check for known CVEs
8. **Backup password commands**: `cmd_encrypt_with_backup_password` accepts password without length validation (unlike `cmd_set_master_password`)

**Owns BUGS.md:** #9, #12

**Output format:**
```
[IPC-BOUNDARY-NNN] Severity: CRITICAL|HIGH|MEDIUM|LOW|INFO
Title: <description>
Location: <file:line>
Description: <technical detail>
Attack Scenario: <concrete exploit path>
Recommendation: <specific fix>
```

---

### Agent 3: APP-LOGIC — Frontend Security & Data Integrity

**Scope:** All frontend application logic: vault lifecycle, backup/restore, merge integrity, authentication, clipboard, timers, navigation, debug exposure.

**Files to audit:**
- `vault/app.js` — All non-crypto application logic (~2,700 lines): vault init/lock, backup/restore, merge, UI, timers, auth, import/export
- `tests/deep-merge.test.js` — Test coverage assessment

**Specific checks:**
1. **JS global secrets**: `vault` object and `_masterPassword` are plaintext JS globals accessible via DevTools/XSS; assess exposure window
2. **Lock completeness**: Verify `lockVault()` wipes ALL sensitive state: `vault`, `nostrKeys`, `_masterPassword`, `_cachedLocalKey`, `_cachedLocalSalt`, `_cachedLocalPassphrase`, DOM elements displaying secrets
3. **Rate limiting**: Client-side unlock attempts (5/30s) resets on page reload — assess if PBKDF2 600K iterations alone provides adequate brute-force resistance
4. **Legacy CryptoJS path**: `CryptoJS.AES.decrypt` with MD5 key derivation — confirm only used for migration, never new encryptions
5. **Nostr backup integrity**: Verify `backupToNostr()` never includes secrets (privateKey, seedPhrase); verify `silentRestoreFromNostr()` uses `mergeUsers()` not direct assignment
6. **Import validation**: Bug #18 — nonces from JSON import/Nostr restore not validated as non-negative integers; `nonce: -1` or `nonce: NaN` would corrupt state
7. **Clipboard security**: Multiple rapid copies could conflict between `clipboardClearTimer` instances; `copySeedPhrase()` 15s timer may clear a subsequent password copy
8. **Debounce timer leak**: Bug #10 — `_backupDebounceTimer` not cleared on lock; trace what happens when timer fires post-lock
9. **Navigation security**: Bug #11 — `popstate` handler bypasses `showScreen()` setup; could show stale data or skip auth checks
10. **Debug exposure**: Catalogue all `debugLog()` arguments when debug mode is user-togglable; Bug #16 triggers relay publish
11. **DOM secret exposure**: Seed phrase in innerHTML (Bug #17); password in `textContent`; `dataset.indices`
12. **Race condition**: Bug #13 — remote restore during active use; assess data loss risk
13. **Test coverage gaps**: No tests for unlock, autoSave, encrypt/decrypt, backup, IPC interaction

**Owns BUGS.md:** #10, #11, #13, #14 (lifecycle aspect), #15, #16, #17, #18

**Output format:**
```
[APP-LOGIC-NNN] Severity: CRITICAL|HIGH|MEDIUM|LOW|INFO
Title: <description>
Location: <file:line>
Description: <technical detail>
Exploitation: <how this could be triggered>
Recommendation: <specific fix>
```

---

## Execution Steps

### Step 1: Launch 3 Agents in Parallel
Each agent runs in an isolated worktree, reads its assigned files, and produces findings in the format above.

### Step 2: Consolidate Results
After all 3 agents complete:
- Cross-reference findings that span domains (e.g., mlock flaw + secret returned to JS via IPC)
- Deduplicate overlapping findings (e.g., Bug #14 touched by both Agent 1 and Agent 3)
- Verify coverage: every security-relevant file was audited by exactly one agent

### Step 3: Produce Final Report
Unified report with:
1. **Executive summary** — finding counts by severity, top 3 critical issues, overall posture
2. **All findings** — ordered by severity, tagged by agent domain
3. **BUGS.md reconciliation** — status of all 18 known bugs + new findings discovered
4. **Recommendations** — prioritized fix list with code-level suggestions

---

## Severity Scale

| Level | Definition | Action |
|-------|-----------|--------|
| **CRITICAL** | Secrets extractable by remote/local attacker; broken crypto primitives; certain data loss | Must fix before any release |
| **HIGH** | Secrets extractable under realistic conditions (XSS + withGlobalTauri); significant crypto weakness | Fix before release |
| **MEDIUM** | Defense-in-depth gaps (broad CSP, missing validation); info disclosure via debug | Fix in next release cycle |
| **LOW** | Code hygiene, theoretical attacks, cosmetic timer leaks | Fix when convenient |
| **INFO** | Architecture observations, test coverage gaps | Document for reference |

---

## Coverage Matrix

| File | Agent | Criticality |
|------|-------|-------------|
| `src-tauri/src/crypto.rs` | CRYPTO-CORE | CRITICAL |
| `src-tauri/src/state.rs` | CRYPTO-CORE | CRITICAL |
| `src-tauri/src/harden.rs` | CRYPTO-CORE | HIGH |
| `src-tauri/src/nostr_ops.rs` | CRYPTO-CORE | HIGH |
| `src-tauri/Cargo.toml` | CRYPTO-CORE | MEDIUM |
| `vault/bip39WordList.js` | CRYPTO-CORE | MEDIUM |
| `src-tauri/src/commands.rs` | IPC-BOUNDARY | HIGH |
| `src-tauri/src/lib.rs` | IPC-BOUNDARY | MEDIUM |
| `src-tauri/src/main.rs` | IPC-BOUNDARY | LOW |
| `src-tauri/tauri.conf.json` | IPC-BOUNDARY | HIGH |
| `src-tauri/capabilities/default.json` | IPC-BOUNDARY | MEDIUM |
| `vault/index.html` | IPC-BOUNDARY | MEDIUM |
| `vault/sw.js` | IPC-BOUNDARY | LOW |
| `vault/crypto-js.min.js` | IPC-BOUNDARY | CVE check |
| `vault/lib/nostr-tools.min.js` | IPC-BOUNDARY | CVE check |
| `vault/app.js` | APP-LOGIC | CRITICAL |
| `tests/deep-merge.test.js` | APP-LOGIC | INFO |

---

## Known Issues to Verify (from BUGS.md)

| Bug | Agent | Status to Verify |
|-----|-------|-----------------|
| #1-3 (shallow merge) | APP-LOGIC | Confirm FIXED |
| #4 (CSP unsafe-inline) | IPC-BOUNDARY | Confirm FIXED |
| #5 (password min length) | IPC-BOUNDARY | Confirm FIXED |
| #6 (CryptoJS weak KDF) | APP-LOGIC | Confirm migration-only |
| #7 (WebSocket leak) | APP-LOGIC | Confirm FIXED |
| #8 (lock UX) | APP-LOGIC | Confirm FIXED |
| #9 (SW cache) | IPC-BOUNDARY | Confirm OPEN |
| #10 (debounce timer) | APP-LOGIC | Confirm OPEN |
| #11 (popstate) | APP-LOGIC | Confirm OPEN |
| #12 (HTML CSP) | IPC-BOUNDARY | Confirm OPEN |
| #13 (race condition) | APP-LOGIC | Confirm OPEN |
| #14 (unverified seed) | CRYPTO-CORE + APP-LOGIC | Confirm OPEN |
| #15 (dead code) | APP-LOGIC | Confirm OPEN |
| #16 (debug backup) | APP-LOGIC | Confirm OPEN |
| #17 (innerHTML) | APP-LOGIC | Confirm OPEN |
| #18 (nonce validation) | APP-LOGIC | Confirm OPEN |

---

## Post-Audit Verification

After fixes are applied:
1. `cargo test` — all Rust unit tests pass (crypto round-trips, edge cases)
2. `npm test` — deep-merge tests pass
3. `cargo build --release` — clean compile with no warnings
4. Manual smoke test: generate seed, set password, lock/unlock, backup to relay, restore, import JSON
5. Re-run each agent's checklist against the fixed code
