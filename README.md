# Vault Native

Offline-first password manager built with Tauri 2. Vault data is encrypted with the master password and stored in a user-selected file that can be synced with tools like Syncthing.

## Platforms
- macOS (.dmg)
- Windows (.exe / .msi)
- Linux (.AppImage / .deb)
- Android (.apk / .aab)
- iOS (.ipa) — requires macOS + Xcode

## Build

Prerequisites: https://v2.tauri.app/start/prerequisites/

```bash
# Desktop
cargo tauri build

# Android (requires Android Studio)
cargo tauri android init
cargo tauri android build

# iOS (requires macOS + Xcode)
cargo tauri ios init
cargo tauri ios build
```

## Development

```bash
# Dev mode (opens webview with hot reload from ../vault/)
cargo tauri dev
```

## Source

The `vault/` directory contains the app UI and vault logic. `src-tauri/` contains the native shell and file commands. Generated Android output is intentionally not kept in the repo.

## Storage layout

The vault is a folder, not a single file. Pick the folder with Syncthing (or
any sync tool) and it replicates without conflicts:

```
topolino-vault.json         derived snapshot — v2 envelope, Obsidian-plugin compatible
topolino-vault.keys.json    keyslots: the vault master key, wrapped by your password
tv-<deviceId>.tvlog         this device's append-only operation log
```

Why it is shaped this way:

- **Each device writes only its own log**, so two devices never write the same
  file and Syncthing has nothing to conflict over on the data path. Merging is
  replaying the union of everyone's logs; the merge rules (`vault/core/records.js`)
  are a CRDT, so order, repeats and partial syncs all land on the same state.
- **`topolino-vault.json` is derived**, kept in the v2 envelope format that
  previously shipped versions of this app read and write. A consumer that drops
  record types it does not understand can no longer lose them — the logs still
  have them, and the next sync republishes.
- **Nonces merge by maximum, never by recency.** A restored backup or a
  rolled-back edit cannot re-issue a password you already rotated away from.
- **Logs are JSON Lines and append-only**, so a torn write damages at most the
  last line, and that line is skipped rather than fatal. Writes to the snapshot
  and keyslot files are temp-file + fsync + atomic rename, with three rotating
  backup generations.

Android hands back an opaque `content://` URI when you pick a *file*, which
cannot have siblings — that falls back to a single-file container with the same
operation log inside. Prefer granting a folder.

## Vault file format

Format v2: PBKDF2-SHA256 (600k iterations) → AES-256-GCM. Legacy v1 files
(CryptoJS EVP) are read-only and upgraded on first open.

Your master password does not encrypt the data directly. It wraps a random
256-bit vault master key into a keyslot (`vault/core/keyslots.js`), the way
LUKS and FileVault do. Changing your password rewraps that one small blob
instead of re-encrypting the vault, and several credentials can unlock the same
vault.

## Testing

```bash
node test/run-all.mjs      # everything
cd src-tauri && cargo test --lib   # atomic writes, backups, appends
```

| Suite | Covers |
| --- | --- |
| `core.test.mjs` | clock ordering, CRDT merge laws, oplog durability, keyslots |
| `migrate.test.mjs` | the one-shot legacy upgrade, including its failure paths |
| `app-wiring.test.mjs` | the real `app.js` against a headless DOM |
| `compat.test.mjs` | the previously shipped version, loaded out of git, read/written both ways |
| `montecarlo.test.mjs` | 3 devices, random actions, syncs, crashes, foreign edits |

`montecarlo.test.mjs` is the one worth running when changing anything about
merging or storage. It asserts convergence, that no nonce ever goes backwards,
that acknowledged writes survive crashes and restarts, and that the system
reaches a fixpoint instead of two devices fighting over writes. Failures print
a seed that reproduces them: `MC_SEEDS=12345 node test/montecarlo.test.mjs`.

`compat.test.mjs` is the one to keep green when touching `vault/envelope.js` or
the password derivation: it runs the last released code side by side with the
current code and asserts that generated passwords are byte-identical and that
each version can read the other's files.

See `ROADMAP.md` for the security audit and what remains open.
