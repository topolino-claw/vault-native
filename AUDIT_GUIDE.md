# How to Audit This Codebase

You don't need to be a coder. You need to know what to look for, where to look, and what smells like trouble. This guide gets you there.

---

## What This App Is

A deterministic password manager. No stored passwords — it derives them from math (a BIP39 seed phrase + SHA-256 hashing). Nonces (password version numbers) sync via Nostr relays. Local storage is encrypted with a master password.

The security model depends on:
- The seed phrase never leaking
- The encryption being strong
- The sync/restore logic not silently destroying data

---

## What You're Actually Auditing

**~4,100 lines of meaningful code across 4 files.** That's it. The rest is icons, build config, and generated Android scaffolding.

| File | Lines | What It Does | Priority |
|------|-------|-------------|----------|
| `vault/app.js` | ~2,760 | ALL the logic — crypto, UI, backup, restore, everything | **AUDIT THIS FIRST** |
| `vault/index.html` | ~1,260 | UI layout, CSS, security headers (CSP) | Second |
| `vault/sw.js` | ~50 | Service worker (offline caching) | Quick pass |
| `src-tauri/tauri.conf.json` | ~50 | App permissions, security policy | Quick pass |

The Rust code (`src-tauri/src/main.rs` and `lib.rs`) is 13 lines of boilerplate. Nothing custom. Skip it.

`vault/bip39WordList.js` is a static list of 2,048 English words. It's a standard. Skip it unless you want to verify it matches the official BIP39 list.

`vault/crypto-js.min.js` and `vault/lib/nostr-tools.min.js` are third-party libraries (minified). You can't meaningfully audit minified code. What you CAN do: check if the versions have known vulnerabilities (search "CryptoJS CVE" and "nostr-tools CVE").

---

## At ~100 Lines Per Day: Your Schedule

### Week 1-2: The Danger Zone (lines 1-300 of app.js)

This is where the cryptographic foundation lives.

**What to look for:**
- How the seed phrase is handled — is it ever logged, sent over the network unencrypted, or stored in plain text?
- How the private key is derived — does it use proper algorithms (SHA-256, PBKDF2)?
- Are secrets cleared from memory when they should be?
- Global variables that hold sensitive data (`vault`, `nostrKeys`, `_masterPassword`)

**Key functions to scrutinize:**
| Function | ~Line | What It Does | What Could Go Wrong |
|----------|-------|-------------|-------------------|
| `derivePrivateKey()` | 290 | Seed phrase to private key | Weak hashing, key stored too long |
| `initializeVault()` | 396 | App startup, loads everything | Secrets exposed before user authenticates |
| `generatePassword()` | 526 | The core: derives a password from inputs | Weak entropy, predictable output |
| `generateNewSeed()` | 566 | Creates a new 12-word seed | Bad randomness source |
| `verifySeedBackup()` | 631 | Checks user wrote down their seed | Seed exposed in DOM before verification |

### Week 3-4: Backup & Restore (lines 750-1050 of app.js)

This is where the known critical bugs live. Three separate code paths do the same thing (merge remote data with local data) and all three are broken differently.

**What to look for:**
- Data being overwritten instead of merged (shallow merge vs deep merge)
- What happens when remote backup has older/different data than local
- Whether encrypted backups can be tampered with
- Whether decryption failures are handled or silently swallowed

**Key functions:**
| Function | ~Line | What It Does | Known Problem |
|----------|-------|-------------|---------------|
| `silentRestoreFromNostr()` | 783 | Auto-restores from cloud on startup | Shallow merge — loses local sites |
| `lockVault()` | 900 | Clears session on inactivity | Doesn't fully wipe memory |
| `saveLocalNonceBackup()` | 960 | Encrypts nonces to localStorage | Uses weak key derivation (MD5) |
| `autoSaveVault()` | 990 | Encrypts full vault to localStorage | Same weak key derivation |

### Week 5-6: User Interaction & Passwords (lines 1050-1500 of app.js)

UI logic, clipboard handling, password display, master password setup.

**What to look for:**
- Passwords visible in the DOM (can be scraped by browser extensions)
- Clipboard not being cleared after copy
- Master password validation (minimum length, complexity)
- Timing attacks on password comparison

**Key functions:**
| Function | ~Line | What It Does | What Could Go Wrong |
|----------|-------|-------------|-------------------|
| `copyPassword()` | 1229 | Copies password to clipboard | Clipboard not cleared, timer not reliable |
| `setMasterPassword()` | 1370 | Sets encryption password | No minimum length (accepts "a") |
| `unlockVault()` | 1423 | Decrypts vault with master password | Brute-force with only 5-attempt/5-sec lockout |
| `importData()` | 1540 | Import from JSON file | No validation on imported nonce values |

### Week 7-8: Nostr & Network (lines 1500-2000 of app.js)

The cloud sync layer. This is where your data leaves the device.

**What to look for:**
- What exactly is sent to relays (is it properly encrypted before sending?)
- Can relays see your data, identity, or usage patterns?
- Are WebSocket connections properly closed?
- What happens if a relay is malicious and sends garbage data?

**Key functions:**
| Function | ~Line | What It Does | What Could Go Wrong |
|----------|-------|-------------|-------------------|
| `showSeedPhrase()` | 1641 | Displays seed on screen | Seed visible in DOM, innerHTML usage |
| `connectRelay()` | 1719 | Opens WebSocket to relay | Leaks connections on timeout |
| `subscribeAndCollect()` | 1752 | Listens for backup events | No validation of incoming data |
| `backupToNostr()` | 1920 | Publishes encrypted backup | Is the encryption actually applied before send? |

### Week 9-10: Restore Paths & UI Navigation (lines 2000-2760 of app.js)

More restore logic, settings, screen navigation.

**What to look for:**
- The `restoreFromNostr()` and `restoreFromId()` functions — both have known critical bugs
- Screen transitions that skip security checks
- The back button handler that bypasses normal navigation
- Debug mode that can be toggled by the user

**Key functions:**
| Function | ~Line | What It Does | Known Problem |
|----------|-------|-------------|---------------|
| `restoreFromNostr()` | 2147 | Manual cloud restore | Same shallow merge bug as silent restore |
| `restoreFromId()` | 2307 | Restore specific backup | Replaces ALL data instead of merging |
| `popstate handler` | 2579 | Android back button | Skips screen setup, stale data shown |

### Week 11: index.html (~1,260 lines)

Mostly CSS and HTML structure. Focus on:
- **Line 5**: The `<meta>` CSP tag — does it properly restrict what scripts/connections are allowed?
- **Lines 1-50**: Security headers and script loading order
- **Inline event handlers**: Search for `onclick=`, `onsubmit=`, etc. — these bypass CSP
- **Hidden inputs or fields** that might store sensitive data in the DOM

### Week 12: Config & Service Worker

**`src-tauri/tauri.conf.json`** (~50 lines):
- CSP policy — does it match the HTML one? (Currently it doesn't — known bug #4)
- Permissions granted to the app
- Whether `unsafe-inline` or `unsafe-eval` are present (bad)

**`vault/sw.js`** (~50 lines):
- Cache update logic is broken (known bug #9) — verify it's still broken or if it's been fixed
- What files are cached and whether sensitive data could end up in the cache

---

## Red Flags Cheat Sheet

When you're reading code, these patterns should make you stop and investigate:

| Pattern | Why It's Suspicious |
|---------|-------------------|
| `innerHTML = ` | Can inject malicious HTML/scripts if the value isn't sanitized |
| `console.log(` with sensitive data | Secrets leaked to browser console |
| `localStorage.setItem(` without encryption | Sensitive data stored in plain text |
| `CryptoJS.AES.encrypt(data, stringPassword)` | Uses weak MD5 key derivation internally |
| `eval(`, `new Function(` | Code execution from strings — massive red flag |
| `...spread` on nested objects | Shallow merge — inner objects get replaced, not merged |
| `JSON.parse(` without try/catch | Crashes on malformed data instead of handling it |
| `vault.users = data.users` | Full replacement instead of merge — data loss |
| `setTimeout` / `setInterval` without cleanup | Timers that run after they should have stopped |
| Hardcoded URLs or keys | Things that should be configurable or rotatable |
| `'unsafe-inline'` in CSP | Allows inline script execution (XSS vector) |
| `.close()` never called on connections | Resource leaks |

---

## How to Read a Function (For Non-Coders)

Every function follows this pattern:

```
function doSomething(input1, input2) {   // NAME and INPUTS
    // ... stuff happens ...             // THE LOGIC
    return result;                        // THE OUTPUT
}
```

**Ask yourself:**
1. **What goes in?** — Are the inputs validated? Could someone pass garbage?
2. **What comes out?** — Is sensitive data being returned or exposed?
3. **What's the side effect?** — Does it write to storage, send data over the network, or modify global state?
4. **What if it fails?** — Is there error handling? Does a failure leave things in a broken state?

---

## Tools You'll Want

You don't need an IDE. But these help:

- **A text editor with line numbers** — VS Code, Sublime Text, even Notepad++. You need to reference specific lines.
- **Ctrl+F / Cmd+F** — Search within the file. Use it constantly.
- **Browser DevTools (F12)** — Run the app and watch the Console tab for logged secrets, the Network tab for outgoing requests, and the Application tab for localStorage contents.
- **`BUGS.md`** — Read this first. It already catalogs 18 known issues with severity ratings and exact line numbers.

---

## Your Audit Checklist

For each section you review, answer these questions:

- [ ] Are secrets (seed phrase, private key, master password) ever exposed in plain text outside of intentional display?
- [ ] Is user input validated before being used?
- [ ] Is data encrypted before being stored or transmitted?
- [ ] If encryption is used, is the key derivation strong (PBKDF2, not MD5)?
- [ ] When data is merged from an external source, is it a deep merge (preserving existing entries)?
- [ ] Are network connections properly closed after use?
- [ ] Are error cases handled without exposing sensitive information?
- [ ] Are timers and intervals cleaned up when no longer needed?
- [ ] Is the CSP (Content Security Policy) as restrictive as possible?
- [ ] Is there any dead code that could confuse future developers?

---

## Already Known Issues

Before you start, read `BUGS.md` thoroughly. 18 bugs are already documented with exact line numbers and severity ratings. Your job during audit is to:

1. **Verify** these bugs still exist (or if they've been fixed)
2. **Find new ones** that aren't in the list
3. **Assess** whether the severity ratings are accurate from your perspective
4. **Track** which sections you've reviewed and which you haven't

---

## Keeping Track of Your Progress

Create a simple log. Something like:

```
Day 1  - app.js lines 1-100    - Reviewed global state, timer setup. No new issues.
Day 2  - app.js lines 100-200  - Found: debugLog could log sensitive data if debugMode on.
Day 3  - app.js lines 200-300  - Reviewed derivePrivateKey. Uses SHA-256, looks correct.
...
```

This way you never lose your place and you have a record of what you've covered.
