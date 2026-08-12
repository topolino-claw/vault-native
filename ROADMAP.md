# Security Roadmap

Audit of `vault/app.js`, `vault/envelope.js`, `src-tauri/src/lib.rs`, `src-tauri/tauri.conf.json`
(2026-08-09, branch `release/offline-vault-test`).

Ordering principle: **anything local-only has zero compatibility cost — do it first.**

**Update (2026-08-10): the Obsidian plugin is no longer a compatibility target.** The vault file
format therefore has exactly one other consumer — previously shipped versions of this app — and
the "reader-first on both sides" dance is gone. What still must not break: generated passwords
(byte-identical, forever) and the ability of an older build to open a file this one wrote.
`test/compat.test.mjs` enforces both by running the last released code out of git.

The practical consequence is large: **§2.5, §2.6 and §2.7 are now unblocked**, and the v3
envelope can be designed freely (Argon2id, AAD-bound header, VMK-encrypted rather than
password-encrypted) behind a version field that old builds simply refuse to read.

---

## 0. Threat model — read this before trusting the ordering

Two artifacts hold your secrets, and they are exposed very differently:

- **The synced vault file.** Most exposed by far: it is in a Syncthing folder, on every paired
  device, in whatever backs those up. Its *only* defense is master-password strength through
  PBKDF2-600k. Items 2.4 (secret key) and 2.7 (Argon2id) are what harden this, and both cost
  cross-implementation coordination.
- **The localStorage backup.** Less exposed — same-user processes on desktop, root or backup
  extraction on Android — but far weaker, because of 1.1.

And the highest-probability bad outcome is neither: it is **losing the vault** (§3, atomic
writes). The seed phrase exists only in that file and on whatever paper the user wrote. A
truncated write ends with every password gone permanently. Ranked by probability × severity,
that beats every cryptographic item here.

So: 1.1 is first among the *attacks* because it is free to fix and removes a ~10⁶ shortcut, not
because it is the likeliest breach path. If an attacker only ever gets the synced file, fixing
1.1 does nothing for you — that is what 2.4 and 2.7 are for.

**Verified clean** (checked, no action needed): seed entropy uses `crypto.getRandomValues`
(`app.js:332`), as do the envelope salt and IV. The lone `Math.random` (`app.js:483`) only picks
which 3 words to quiz during backup verification — not security-relevant.

---

## 1. Critical

### 1.1 Master-password cracking oracle in localStorage

`vault/app.js` — `saveEncryptedVault()` keys the `vaultEncrypted` map by raw, unsalted
`SHA-256(masterPassword)`:

```js
const key = hash(password);              // CryptoJS.SHA256 — 1 round, no salt
stored[key] = await encryptVaultPayload(password);
```

600k PBKDF2 iterations protect the payload, and then this key sits next to it as a free
verification oracle. Anyone who can read app data (adb / Android backup,
`~/.local/share/com.topolino.vault/`, a desktop backup, a sync folder that accidentally
includes it) brute-forces the master password at **one SHA-256 per guess** instead of one
PBKDF2-600k per guess — roughly a **10⁶× speedup**. The AES-GCM blob is only touched at the
last step.

**Fix:** single slot, or key by a random device-local UUID; identify the slot by attempting
decryption. Never appears in the vault file → **no compatibility impact**.

---

## 2. Design-level

### 2.1 `derivePrivateKey()` is a base conversion, not a derivation

BIP39 words → 4-digit indices → decimal → hex. No hash, no stretching, fully invertible.
`vault.privateKey` **is** the seed phrase in another encoding — everywhere the private key is
stored, logged, or held in memory, the seed phrase is. Real BIP39 uses PBKDF2-HMAC-SHA512,
2048 rounds, salt `"mnemonic" + passphrase`.

### 2.2 The passphrase is dead code

`vault.passphrase` is captured in `initializeVault()`, stored in the envelope, and **never
enters any derivation**. `generatePassword()` uses `privateKey/user/site/nonce` only, so a user
who set a "25th word" believing it protects them has zero extra protection.

**Resolution (non-critical, deferred):** make it the real BIP39 25th-word passphrase — fold it
into derivation as BIP39 does (PBKDF2-HMAC-SHA512, salt `"mnemonic"+passphrase`) behind the same
per-entry version flag as 2.1/2.3, so existing passwords do not change. Low priority: it affects
only users who deliberately set one. The interim honest state is that the field does nothing —
just don't advertise it as protection until it is wired in.

### 2.3 Site passwords: one unsalted SHA-256, truncated to 64 bits

`PASS + sha256(privateKey/user/site/nonce).slice(0,16) + 249+`.

**Corrected from the first draft, which overstated this.** 64 bits is not practically crackable
today: even against a site storing unsalted SHA-1, 2⁶⁴ at ~100 GH/s is millennia, and the known
fixed prefix/suffix don't shrink the search because they never vary. Nor does a leaked site
password expose the seed — recovering it means a preimage over the 2¹²⁸ mnemonic space.

The real objections are margin and direction of travel: 64 bits is below the 80-bit line people
design to, it never improves, and a vault minted today will still be issuing 64-bit passwords in
ten years. Raise the default to 20–24 hex chars for **new** entries (cheap, and it composes with
the per-entry versioning in §5). Low urgency — this is not a fire.

### 2.4 No secret-key / device-bound second factor

1Password mixes a 128-bit never-synced Secret Key into the KDF, so a stolen vault is
uncrackable regardless of master-password quality. This design targets Syncthing explicitly —
**a stolen file is the primary threat model** — and has no answer beyond password strength.

### 2.5 Envelope header is unauthenticated

`encryptEnvelope()` writes `kdf.iterations`, `kdf.salt`, `cipher.iv` outside the GCM tag with
no AAD. Not a direct break (wrong params → decrypt fails), but the header is attacker-malleable
and nothing in it can be trusted. Fix in a v3 envelope.

*Update (2026-08-10):* `decryptEnvelope()` and `keyslots.isSlot` now clamp `iterations` to
`[1, MAX_ITERATIONS]` and validate the `kdf`/`cipher` shape before deriving. Previously an absurd
iteration count in a file merely dropped into the synced folder would make `deriveVaultKey` run
for minutes and hang unlock/sync — a no-password CPU-exhaustion DoS the "wrong params → decrypt
fails" framing missed. The header is still unauthenticated; binding it via AAD stays a v3 item.

### 2.6 v1 acceptance is permanent

`decryptEnvelope()` falls back to `CryptoJS.AES.decrypt` — OpenSSL EVP_BytesToKey, **MD5, one
round**. Any surviving v1 file cracks near-instantly, with no sunset date.

### 2.7 PBKDF2-600k is the floor, not the bar

That is OWASP's *minimum* for PBKDF2-SHA256 — precisely the workload GPUs and ASICs are best
at. Bitwarden ships Argon2id. The envelope already carries `kdf.algo`, so this is negotiable.

---

## 3. Operational / platform

- **`write_vault_file` truncates before writing** (`src-tauri/src/lib.rs`, `.truncate(true)`).
  Crash, battery death, or a Syncthing race mid-write leaves the file empty or partial — and the
  seed phrase lives in that file. **Most likely real-world catastrophic loss, and it isn't
  crypto.** Write to `path.tmp`, fsync, atomic rename, keep N rotating backups.
- **Read-merge-write with no lock** (`writeSelectedVaultFile`). The nonce-max merge is correct;
  the file-level race is unhandled.
- **Nonce rollback** (missed in the first draft). `mergeUsers` only ever raises a nonce, which
  correctly defends against a *merge* carrying stale data — but nothing defends against the file
  itself being replaced with an older copy, whether by an attacker with sync-folder write access
  or by a well-meaning restore from backup. The user then regenerates a **previously retired
  password** for a site, and the app shows no sign anything moved backwards: rotation is exactly
  what you do after a breach, so this silently re-issues the password you rotated away from.
  Cheap mitigation: a monotonic counter in the envelope, and warn loudly on decrease.
- **`FLAG_SECURE` — done (2026-08-11).** Set in `MainActivity.onCreate`, so screenshots, the
  app-switcher thumbnail, and screen recorders are blocked app-wide. Caveat: `gen/android` is
  gitignored, so a clean `tauri android init` regenerates `MainActivity` and drops this — track
  `gen/android` (or add a template hook) to make it permanent.
- **Clipboard `EXTRA_IS_SENSITIVE` — deferred (needs a native bridge).** The 30s auto-clear is in
  place, but marking the clip sensitive requires Android's `ClipboardManager`: the Web Clipboard
  API (`navigator.clipboard`) cannot set `ClipDescription.EXTRA_IS_SENSITIVE`. That means native
  (Kotlin/JNI) code, and with `gen/android` gitignored it would be ephemeral, so it is parked until
  the clipboard path goes native. Until then the password still appears in the Android 13+
  paste-preview and clipboard history.
- **`withGlobalTauri: true`** exposes `__TAURI__` — including `read_vault_file` /
  `write_vault_file` — to any script in the webview. **Contained (2026-08-11):
  the file commands are now capability-scoped in Rust** (`src-tauri/src/scope.rs`).
  Only paths produced by a native dialog — a picked folder (becomes a scope
  root) or a picked file (authorized exactly) — are accepted; the renderer
  cannot widen its own authority, and the permit set is persisted by Rust, not
  by page state. The scope is containment, not a sandbox: the CSP
  (`script-src 'self'`, `connect-src 'none'`, no `unsafe-inline`, kept in
  parity between `tauri.conf.json` and the `index.html` `<meta>`) remains the
  outer boundary. Any script execution is still a real bug; it is just no
  longer *arbitrary filesystem access*.
- **Master password held in memory for the whole session** (`_sessionMasterPassword`), plus seed
  and private key as JS strings. JS strings are immutable and cannot be zeroed, so `lockVault()`
  nulls every reference (password, seed, store, rendered secrets, timers) and lets GC reclaim
  them — but copies linger until collection. True zeroing needs the native port (§6: `zeroize`,
  `CharArray`/`ByteArray`); in a WebView this is the best achievable.
- **The 5-attempt lockout is UI-only** — in-memory, resets on restart, irrelevant to the offline
  attack. Do not count it as a control.

---

## 4. Missing vs. mainstream password managers

Ranked for this threat model:

1. Secret Key / device-bound second factor — the direct answer to synced-file theft
2. Argon2id — memory-hard KDF
3. Atomic writes + versioned backups — one crash from total loss
4. Autofill (Android Autofill Service, browser extension) — its absence *forces* clipboard use,
   the leakiest channel available
5. Biometric / OS-keystore unlock — Android Keystore, macOS Keychain; hardware-backed
6. Emergency kit / recovery documentation
7. Breach monitoring (HIBP k-anonymity), password-age nudges
8. Duress or decoy vault

---

## 5. Compatibility strategy

The only consumers left are older builds of this app. Two things must hold:

1. **Generated passwords never change.** `generatePassword` is deterministic; altering it
   silently invalidates every account a user owns. This is the invariant with no escape hatch,
   and the only fix for the derivation weaknesses (2.1, 2.3) is *per-entry versioning*: store
   `{nonce, algo}` per site, keep `algo: 1` working forever, mint new entries with `algo: 2`,
   and add a "rotate this password" flow that upgrades an entry when the user is ready to change
   it on the site.
2. **An older build can still open the file**, so a downgrade or a stale device is not stranded.
   That constrains `topolino-vault.json` to the v2 envelope for as long as we care about it —
   and no longer.

Everything else is now free. A v3 envelope needs only a version bump: older builds see `v: 3`,
fail the structural check, and refuse rather than corrupt. Once no v2-era install remains, the
snapshot can be encrypted under the VMK instead of the password, which removes the last reason
the store holds the plaintext master password in memory at all (§3).

---

## 6. Native port (Kotlin / Rust)

Moderate effort; buys real things, but not most of the list above. Sequence it second.

- **Android (Kotlin/Compose): ~1–2 weeks.** Logic is small — wordlist, derivation, envelope,
  nonce merge; `javax.crypto` covers PBKDF2 + AES-GCM, Argon2id needs one dependency. Gains:
  Android Keystore (hardware-backed, biometric unlock), Autofill Service (kills the clipboard
  problem), `FLAG_SECURE`, `EXTRA_IS_SENSITIVE`, zeroable `CharArray`/`ByteArray`, real atomic
  writes, no WebView attack surface, ~7 MB smaller.
- **Desktop: ~2–3 weeks — refactor, not rewrite.** Move crypto and file I/O down into
  `src-tauri` (`argon2`, `aes-gcm`, `zeroize`); keep the HTML as a dumb view that never touches
  secrets. A full native GUI is a much bigger lift for much less benefit.
- **Cost:** three implementations of one format (Kotlin, Rust, plugin TypeScript) — exactly
  where crypto compatibility bugs breed. Before adding a third, turn
  `test/envelope-cross.test.mjs` into a language-agnostic fixture suite: fixed vectors on disk,
  every implementation reads and writes them.

---

## 6b. Delivered (2026-08-09/10)

Tier 0 and most of tier 1 are done, plus the storage rework. What shipped:

**Key management (1.1 — fixed).** `vault/core/keyslots.js`. A random 256-bit
Vault Master Key encrypts the data; the password only wraps it into a keyslot
with a random id and random salt. Nothing derived from the master password is
stored anywhere. Password change rewraps one blob instead of re-encrypting the
vault, so it cannot half-finish. Multiple slots can unlock one vault, which is
the hook 2.4's secret key will use.

**Durability (§3 — fixed).** `src-tauri/src/vaultfs.rs`. Temp file → fsync →
atomic rename → fsync parent dir, with three rotating backup generations and a
recovery read. `truncate(true)` is gone. Operation logs append-only with fsync.

**Conflicts (§3 — fixed by construction).** `vault/core/oplog.js` +
`store.js`. Each device appends only to `tv-<deviceId>.tvlog`, so Syncthing has
no shared file to conflict over on the data path. `topolino-vault.json` is
demoted to a *derived* snapshot kept for plugin compatibility — a consumer that
drops what it does not understand can no longer destroy anything, because the
logs still have it. Conflict files that do appear are absorbed losslessly, and
files we fail to decrypt are kept rather than deleted.

**Nonce rollback (§3 — fixed).** `nonce` is a grow-only maximum in the merge,
not last-write-wins, so a restored backup or a rolled-back plugin edit cannot
re-issue a retired password. Asserted continuously by the simulation.

**More than nonces (new).** `vault/core/records.js` — a CRDT record model with
per-field last-write-wins over a hybrid logical clock, tombstones, and
deterministic credential ids so concurrent creates converge. Notes, TOTP
secrets and custom records now ride along encrypted.

**Migration (new).** `vault/core/migrate-legacy.js` + `bootstrap.js`. One
quarantined file, one call site, a schema marker, and a removal checklist in
its header. Writes the replacement, verifies it through a fresh store, and only
then deletes the legacy artifacts; a wrong password leaves everything untouched.

**Storage engine decision.** Files, not SQLite. SQLite over Syncthing is a
known corruption source (binary, WAL, no merge), it cannot be read by the
Obsidian plugin, and it would block the Kotlin port from sharing one format.
JSON Lines gives self-healing (a torn line is skipped, not fatal) and stays
readable by every implementation.

**Web-layer + DoS hardening (2026-08-10).** `escapeHtml` now escapes quotes and is DOM-free,
closing an HTML attribute-injection breakout in `renderSiteList` (and the unescaped seed-word
grids); the app-wiring test double had been escaping quotes the real DOM does not, which hid the
bug. The `<meta>` CSP was aligned with `tauri.conf.json` (`connect-src`/`object-src` `'none'`).
KDF iteration counts read from files are bounded before use (2.5). A `..`-traversal guard was
added to the Rust file commands. New regression tests: `core.test.mjs` (KDF-cost guard),
`app-wiring.test.mjs` (quote escaping + attribute breakout), `cargo test` (traversal refusal).

**Feature surface + Android hardening (2026-08-11).** The record model's `totp` and `note` types
finally have UI: an RFC-6238 authenticator (`core/totp.js` — live codes, tap-to-copy) and secure
notes (add/edit/delete). CSV import/export (`core/porter.js`) bridges other managers — import
creates entries and keeps any old login as a note (this app *derives* passwords, so it cannot
adopt theirs); export is a plaintext-password CSV, behind a warning. `FLAG_SECURE` is set on the
Android activity (see §3 for the gitignore caveat). New tests: RFC-6238 vectors + CSV round-trip
(`core.test.mjs`), and notes/TOTP/CSV wiring through the Tauri mock (`app-wiring.test.mjs`).

### Verification

| Suite | What it covers | Result |
| --- | --- | --- |
| `test/core.test.mjs` | clock, CRDT laws, oplog, keyslots, store, TOTP/CSV, KDF-cost guard | 39 pass |
| `test/migrate.test.mjs` | legacy migration, including failure paths | 14 pass |
| `test/compat.test.mjs` | pinned released build (`REF_VERSION` `ba414b5`), both directions | 12 pass |
| `test/app-wiring.test.mjs` | real `app.js` against a headless DOM (incl. escaping + move) | 23 pass |
| `test/hostile.test.mjs` | attacker-shaped input: envelope, oplog, CSV/otpauth/b64 edge cases | 20 pass |
| `test/security-config.test.mjs` | CSP parity (index vs tauri.conf), no-network statics | 5 pass |
| `test/montecarlo.test.mjs` | 3 devices, random ops/sync/crash/plugin edits (see MONTECARLO.md) | 9 pass |
| `cargo test --lib` | atomic write, backups + JSON recovery, append, scope, `..`-traversal refusal | 16 pass |

`node test/run-all.mjs` runs everything.

**Bugs the Monte Carlo suite found that review had not:** a non-hex device id
silently invalidated every operation (vault appeared to work, saved nothing);
the store overwrote the snapshot without reading it first, losing plugin edits;
and log headers were never written, so logs only *appeared* to work because the
snapshot happened to carry the same data. The app-wiring suite caught that
creating a vault wiped the just-generated seed phrase.

### Still open

- **2.4 secret key** and **2.7 Argon2id** — the two that protect the most
  exposed artifact (§0). Keyslots are the prerequisite and now exist.
- **2.1 / 2.2 / 2.3** — derivation, the inert passphrase, and the 64-bit
  default. All need per-entry versioning (§5); none has shipped.
- **2.5 / 2.6** — AAD-bound envelope header and the v1 sunset. Note the *logs*
  already bind AAD (entries cannot be spliced between device logs); only the
  plugin-compatible envelope still lacks it.
- **§3 platform items** — `FLAG_SECURE`, clipboard sensitivity flag,
  `withGlobalTauri`, CSP.
- **Dropped:** Obsidian plugin compatibility is no longer a requirement
  (2026-08-10). `test/envelope-cross.test.mjs` is out of the default run and
  can be deleted. Making the snapshot derived state is still the right call —
  it is what lets any lossy consumer, including an older build of this app,
  rewrite the file without destroying record types it cannot model.

---

## 7. Execution order

**Tier 0 — hours of work, zero compatibility cost, no reason to wait**
1. Atomic writes + rotating backups (§3). *Highest probability × severity item in this document.*
2. localStorage slot keying (1.1).

**Tier 1 — cheap, local, but needs a decision**
3. Passphrase: wire into derivation behind a per-entry version flag, or delete the field (2.2).
   It is misleading users **today**, and either resolution beats leaving it.
4. `FLAG_SECURE`, clipboard sensitivity flag, Tauri `withGlobalTauri` + CSP hardening (§3).
5. Default `hashLength` → 20–24 for new entries (2.3).
6. Nonce rollback warning (§3).

**Tier 2 — format work, now unblocked (no second implementation to coordinate with)**
7. v3 envelope: Argon2id (2.7) + AAD-bound header (2.5) + v1 sunset (2.6). Gate it behind a
   version field; older builds refuse to read rather than corrupt.
8. Secret key / device-bound factor (2.4) — the real answer to a stolen synced file. The
   keyslot model already exists to carry it.

**Tier 3**
10. Kotlin Android, specifically for Autofill + Keystore (§6).
11. Per-entry versioned derivation + rotation flow (2.1, 2.3, §5) — the long tail.

Note the tension: tier 2 is what actually protects the **most exposed** artifact (§0), but it is
also the most expensive and the easiest to get wrong across three implementations. Tier 0 and 1
are strictly cheaper than tier 2 and should not be used as an excuse to skip it.

---

## Appendix: naming cleanups (no behavior change)

Names that actively mislead, fixed ahead of the logic work so the logic diffs stay readable:

| Before | After | Why |
| --- | --- | --- |
| `hash()` | `sha256Hex()` | Generic name hid that one fast unsalted hash serves both password entropy and the localStorage key (1.1) |
| `derivePrivateKey()` | `encodeSeedPhraseAsHex()` | It derives nothing (2.1) |
| `saveEncryptedVault()` | `saveLocalVaultBackup()` | Writes only to localStorage, not the vault file |
| `removeEncryptedVaultPassword()` | `removeLocalVaultBackupSlot()` | Removes a storage slot, not a password |
| `downloadData()` | `exportVaultFile()` | Nothing is downloaded; it writes via the native picker |
| `_sessionLocalPassword` | `_sessionMasterPassword` | It is the master password, held for the session |

The serialized field `privateKey` keeps its name — it is part of the shared file format and
cannot be renamed without breaking the plugin. Its misleading name is tracked as 2.1.
