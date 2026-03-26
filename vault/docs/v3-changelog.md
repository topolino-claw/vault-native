# Vault v3 — Changelog & Architecture Notes

## What Changed (v2 → v3)

### UI/UX Redesign
- **Dark mode** — Full dark theme, mobile-first
- **Phone-width container** (480px max) centered on desktop — identical experience everywhere
- **Simplified navigation** — 2 main flows (create/restore) vs 8+ screens in v2
- **Button stacks** — Consistent vertical layout with `.button-stack` wrappers
- **Toast notifications** — Replace alert() calls with non-blocking toasts
- **Site search** — Fuzzy search bar on main screen, Enter to add new sites
- **"Version"** replaces "nonce" — Users don't need to know what a nonce is

### BIP39 Autocomplete
- Predictive suggestions as user types each word in seed restore
- Filters 2048-word BIP39 list in real time
- Arrow keys + Tab/Enter to navigate and select
- Word count progress indicator (0/12)
- Prevents typos — only valid words can be entered

### Auto-Sync on Login
- After seed verification, shows loading modal with spinning 🔄
- Displays truncated npub while checking
- Silently queries Nostr relays for existing backups
- If found: merges data and shows "Synced from cloud backup!"
- If not found: proceeds with empty vault
- If offline: graceful fallback

### Debug Mode
- Toggle in Advanced settings
- After backup: prompt to view event on njump.me
- Backup history: clickable `nevent` links per entry
- Uses NIP-19 nevent encoding with relay hints

---

## Backwards Compatibility

### Password Derivation — IDENTICAL
```
privateKey = decimalToHex(wordsToIndices(seedPhrase))
password = "PASS" + SHA256(privateKey + "/" + user + "/" + site + "/" + nonce).slice(0, hashLength) + "249+"
```
No changes. Same inputs → same passwords.

### Nostr Key Derivation — IDENTICAL  
```
nostrSecretKey = SHA256(privateKey)
nostrPublicKey = getPublicKey(nostrSecretKey)
```

### Nostr Backup Format — COMPATIBLE
- Old backup payload: `{ users, settings, privateKey }`
- New backup payload: `{ users, settings }` (privateKey omitted — more secure)
- v3 reads old backups (ignores extra `privateKey` field)
- v2 reads new backups (derives privateKey from seed anyway)

### Local Encrypted Storage — COMPATIBLE
- v2 used `localStorage["encryptedDataStorage"]`
- v3 uses `localStorage["vaultEncrypted"]`
- v3 reads from BOTH keys for migration
- v3 writes only to new key
- Legacy format (with `privateKey` inside) handled correctly

### Seed Phrase in Storage
- v2 did NOT store seed phrase in local encrypted data
- v3 stores it (alongside privateKey for compat)
- Legacy unlocks: seed phrase unavailable but passwords still work

---

## File Structure

```
index.html          — v3 app (dark, mobile-first)
app.js              — v3 logic (all functions)
index-legacy.html   — v2 app (preserved)
script.js           — v2 logic (preserved)
bip39WordList.js    — BIP39 2048-word list
crypto-js.min.js    — SHA256 + AES
lib/nostr-tools.min.js — Nostr protocol
docs/
  how-it-works.md   — Technical overview
  v3-changelog.md   — This file
```

---

## Commit History (v3)

| Commit | Description |
|--------|-------------|
| `92ea289` | v3: Complete UI/UX redesign |
| `573663a` | fix: backwards compatibility with legacy local storage |
| `cedf89f` | feat: BIP39 autocomplete for seed phrase input |
| `bd913c9` | style: phone-width layout on all screens |
| `c12dc38` | fix: proper phone container with full-width buttons |
| `dcaa758` | fix: button-stack for consistent vertical layout |
| `a0f38d8` | feat: debug mode with njump.me event links |
| `401b03f` | feat: auto-check for remote backups on login |
