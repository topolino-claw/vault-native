# Audit Guide

Where to look, in what order, and what each piece is supposed to guarantee.

The code is split so that **everything security-critical is small, pure and
DOM-free**. If you only have an hour, read the six files in §1 — about 1,100
lines — and you have seen every line that touches a key, a password or a
plaintext secret. Nothing in the UI layer can weaken them.

---

## 0. Threat model in one paragraph

Passwords are never stored. They are *derived* on demand from a BIP39 seed
phrase plus the site, user and a per-site counter (`nonce`). The only things
that persist are the seed phrase and those counters, encrypted into a file the
user syncs however they like (Syncthing, a shared folder, a USB stick). So the
assets are: **the seed phrase** (compromise = every account), **the master
password** (unlocks the file), and **the nonces** (losing or rolling one back
silently re-issues a password the user rotated away from). The app makes no
network calls and declares no network permission.

---

## 1. Security-critical code — read this first

Ordered by how much damage a bug in each would do.

| File | Lines | What it guarantees |
| --- | ---: | --- |
| `vault/core/derive.js` | ~230 | Turns a seed phrase into passwords. Pure functions, no I/O. **Two documented weaknesses live here** — read the header. |
| `vault/core/keyslots.js` | ~207 | The master password wraps a random 256-bit vault key; it never encrypts data directly. Nothing derived from the password is stored. |
| `vault/envelope.js` | ~201 | The on-disk file format: PBKDF2-600k → AES-256-GCM. Shared with previously shipped builds. |
| `vault/core/records.js` | ~302 | Merge rules. `nonce` is grow-only (never decreases); everything else is last-write-wins. Prototype-pollution guards. |
| `vault/core/oplog.js` | ~150 | Per-device append-only log. Each entry independently authenticated and bound to its own log via GCM AAD. |
| `vault/core/store.js` | ~481 | Orchestration. Contains the two rules that prevent data loss — see §3. |

Supporting, lower risk: `hlc.js` (ordering), `util.js` (base64/random),
`transports.js` (byte I/O per platform), `bootstrap.js` (open/upgrade),
`migrate-legacy.js` (**one-shot, deletable — see its header**).

`vault/app.js` (~1,840 lines) is UI. It holds no crypto: derivation moved to
`core/derive.js` precisely so the audit surface and the UI surface are
different files.

---

## 2. The invariants, and where they are enforced

Each is asserted by a named test — the test is the specification.

| Invariant | Enforced in | Proven by |
| --- | --- | --- |
| A generated password never changes, ever | `derive.js` | `compat.test.mjs` — 432 input combinations against the last released build |
| A nonce never decreases | `records.js` `GROW_ONLY_FIELDS` | `core.test.mjs`, and continuously in `montecarlo.test.mjs` |
| Nothing derived from the master password is stored | `keyslots.js` | `core.test.mjs` "leaks nothing derived from the password" |
| A wrong password never creates or replaces a vault | `bootstrap.js` `assertPasswordMatchesExisting` | `migrate.test.mjs` |
| A vault file we cannot decrypt is never overwritten | `store.js` `snapshotReadable` | `migrate.test.mjs` |
| A torn write costs at most the in-flight operation | `vaultfs.rs`, `transports.js` append contract | `core.test.mjs`, `cargo test` |
| Devices converge; acknowledged writes survive | `records.js` merge laws | `montecarlo.test.mjs` |
| The migration never deletes before verifying | `bootstrap.js` | `migrate.test.mjs` |

---

## 3. The two rules that exist because they were violated

Both were real, both were caught, both now have regression tests. They are the
first things to re-check after any change to `store.js` or `bootstrap.js`.

1. **Prove the password before creating keyslots.** A mistyped password used to
   mint a fresh empty vault, adopt the wrong password, and write that empty
   state over the user's file — destroying it and locking the real password out.
2. **Never overwrite a vault file you could not decrypt.** Whatever it is, it is
   the only copy of somebody's seed phrase. Skipping the write costs nothing:
   the operation log is already durable and the snapshot is derived state.

---

## 4. Attack surface

**Removed or absent:**

- No network code — no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`,
  `sendBeacon`. No external scripts, fonts, styles or images.
- **No `android.permission.INTERNET`** — the app cannot open a socket, rather
  than choosing not to.
- **`android:allowBackup="false"`** plus empty `data_extraction_rules.xml` —
  `adb backup`, cloud backup and device-to-device transfer cannot copy app data
  (which holds the keyslots) off the device. This defaults to *true*.
- `usesCleartextTraffic="false"`; AndroidTV `leanback` feature dropped.
- No runtime dependencies, no `package.json`, no build step. CryptoJS and the
  BIP39 word list are vendored files you can diff.
- CSP: `default-src 'self'; script-src 'self'; connect-src 'none'; object-src
  'none'; base-uri 'none'; form-action 'none'` — in both `index.html` and
  `tauri.conf.json`, so it does not depend on which one wins.

**Still present, deliberately:**

- `withGlobalTauri: true` exposes `window.__TAURI__` to page scripts. Needed
  because there is no bundler; mitigated by `script-src 'self'` and no remote
  content. **The blast radius of the exposed file commands is now contained by
  the Rust-side capability scope (`src-tauri/src/scope.rs`, 2026-08-11):** only
  paths that came out of a native dialog — the chosen vault folder, or a
  file the user picked — are accepted by `read/write/append/list/remove_vault_*`.
  A renderer bug is limited to locations the user already chose; it can no
  longer silently reach arbitrary absolute paths.
- CryptoJS (~48 KB, vendored) — used for SHA-256 in `derive.js` and for
  decrypting legacy v1 files. Removing it means either an async derivation
  (the signature is synchronous) or dropping v1 support. `ROADMAP.md` 2.6.
- The plaintext master password is held for the session, because the
  plugin-compatible snapshot is password-encrypted. A v3 envelope keyed by the
  vault master key removes the need. `ROADMAP.md` §3.
- Android `FLAG_SECURE` (no screenshots / no recents thumbnail) is set in
  `gen/android/.../MainActivity.kt`, but `gen/android` is gitignored, so a
  clean `tauri android init` regenerates it without the flag. Track
  `gen/android` or add a template hook before relying on it.

---

## 5. Known weaknesses that are NOT bugs

Documented, deliberate, and unfixable in place because the output is
deterministic — changing them changes every password every user has generated.
The fix is per-entry versioning plus a rotation flow (`ROADMAP.md` §5).

- **`encodeSeedPhraseAsHex` is not a key derivation** — it is an invertible base
  conversion, so `privateKey` *is* the seed phrase re-encoded (2.1).
- **Site passwords are 64 bits** — an unsalted single-round SHA-256 truncated to
  16 hex characters (2.3). Not practically crackable today; poor margin.
- **`vault.passphrase` protects nothing** — it is stored and enters no
  derivation (2.2). Decide: wire it in behind a version flag, or delete it.

---

## 6. Running the checks

```bash
node test/run-all.mjs              # all JS suites (122 tests)
cd src-tauri && cargo test --lib   # durability + scope tests
cargo clippy --all-targets -- -D warnings
```

Suites: `core` (CRDT/keyslots/store), `migrate` (one-shot upgrade), `compat`
(current vs the pinned released build `REF_VERSION`, see its header),
`app-wiring` (real `app.js` in a headless DOM), `hostile` (error-contract and
parser fuzzing), `security-config` (CSP parity + no-network statics), and
`montecarlo`. CI runs every one of them plus `cargo test`/`clippy`
(`.github/workflows/ci.yml`).

The one worth running against any storage or merge change is
`montecarlo.test.mjs`: three simulated devices, random actions, random sync
interleavings, crashes mid-write, clock skew, and foreign edits to the shared
file. A failure prints a seed that reproduces it exactly:

```bash
MC_SEEDS=12345 node test/montecarlo.test.mjs
MC_SEEDS=1 MC_TRACE=me/github.com node test/montecarlo.test.mjs   # trace one credential
```

It has found four bugs that code review did not: a non-hex device id silently
invalidating every operation, a lost-update on the shared snapshot, unwritten
log headers, and the torn-append bug in §2.
