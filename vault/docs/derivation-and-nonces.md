# Derivation and Nonce Workflow

This document details the full cryptographic pipeline used by PasswordManagerWeb: from BIP39 mnemonic to private key, from private key to Nostr identity, and from private key + credentials + nonce to a deterministic password.

---

## 1. BIP39 Mnemonic → Private Key

### Step 1 — Word indices

Each BIP39 word maps to a 0-based integer index in the 2048-word list.
Each index is zero-padded to exactly **4 decimal digits**.

```
"abandon" → index 0    → "0000"
"ability" → index 1    → "0001"
"about"   → index 2    → "0002"
"zoo"     → index 2047 → "2047"
```

### Step 2 — Concatenate to a decimal string

All the 4-digit indices are concatenated into a single decimal string.

Example with a 3-word phrase (for brevity — real phrases use 12+ words):

```
words:   "abandon about zoo"
indices: [0, 2, 2047]
padded:  ["0000", "0002", "2047"]
decimal: "000000022047"
```

A real 12-word phrase produces a 48-digit decimal string.

### Step 3 — Convert decimal → hexadecimal

The decimal string is treated as an arbitrary-precision integer and converted to hex using `BigInt`:

```js
BigInt("000000022047").toString(16)
// → "55ff"
```

For a real 12-word phrase this produces a hex string of roughly 20–40 characters (variable length, no leading "0x").

This hex string is the **vault private key**.

> **Security note:** The private key's entropy is bounded by the BIP39 mnemonic's entropy (128 bits for 12 words). The decimal→hex conversion is lossless.

---

## 2. Private Key + Credentials + Nonce → Password

### The generation formula

```
concat  = "<privateKey>/<user>/<site>/<nonce>"
entropy = SHA-256(concat).substring(0, hashLength)
password = "PASS" + entropy + "249+"
```

All inputs are treated as plain strings — no special encoding.

### Example (placeholder values)

```
privateKey = "a1b2c3d4e5f6..."  (hex, from seed phrase)
user       = "alice@example.com"
site       = "github.com"
nonce      = 0

concat  = "a1b2c3d4e5f6.../alice@example.com/github.com/0"
SHA-256 = "3f7a9b2e1c4d..." (64 hex chars)
entropy = "3f7a9b2e1c4d5e6f"  (first 16 chars, hashLength=16)
password = "PASS3f7a9b2e1c4d5e6f249+"
```

### Fixed prefix and suffix

| Segment    | Value   | Purpose                                            |
|------------|---------|----------------------------------------------------|
| Prefix     | `PASS`  | Uppercase letters — satisfies "must have uppercase"|
| Entropy    | hex str | Variable length (8–64 chars). Default: 16 chars.   |
| Suffix     | `249+`  | Digits + special char — satisfies complexity rules |

These fixed segments ensure the output passes most website password policies regardless of what the hex entropy happens to contain.

### Password strength

| hashLength | Entropy bits | Total length | Label     |
|------------|-------------|--------------|-----------|
| 8          | 32 bits     | 16 chars     | Weak      |
| 12         | 48 bits     | 20 chars     | Good      |
| 16         | 64 bits     | 24 chars     | Strong    |
| 20         | 80 bits     | 28 chars     | Excellent |
| 32         | 128 bits    | 40 chars     | Excellent |

Default hashLength is **16** (64-bit entropy, 24-char password).

---

## 3. Nonces (Password Versions)

A **nonce** is a non-negative integer (0, 1, 2, …) that acts as a version counter for a password.

### How they work

- Every `(user, site)` pair has its own nonce stored in `vault.users[user][site]`.
- The initial nonce is **0**.
- Incrementing the nonce and copying the password generates a **different, but still deterministic** password for the same site.
- Decrementing is possible (minimum 0) to retrieve previous passwords.

### When to increment

Increment the nonce when you need to rotate a password, for example:

1. A site forces a password change.
2. You suspect the password was compromised.
3. A site's password policy changed and the old password no longer validates.

### Example — password rotation

```
nonce=0: "PASSa1b2c3d4e5f60000249+"   ← current password
nonce=1: "PASSf9e8d7c6b5a40001249+"   ← after rotation
nonce=2: "PASS1122334455667002249+"   ← after second rotation
```

All of these can be reproduced from the same seed phrase at any time.

### Nonce persistence

Nonces are stored in `vault.users`:

```json
{
  "alice@example.com": {
    "github.com": 2,
    "google.com": 0
  }
}
```

This data is backed up encrypted to Nostr (see §5) and optionally to localStorage as an encrypted local backup (see §5).

---

## 4. Nostr Key Derivation

The Nostr identity is derived from the vault private key in a separate step to keep the two identities linked but distinct.

### Process

```
nostrHex = SHA-256(privateKey encoded as UTF-8)
nsec     = nip19.nsecEncode(nostrHex)   // bech32 "nsec1..."
npub     = getPublicKey(nostrHex)       // secp256k1 pubkey, hex
```

### Example (placeholder)

```
privateKey = "a1b2c3d4e5f6..."
UTF-8 bytes of privateKey → SHA-256 → "7c3a9f1e2b4d..."

nsec = "nsec1..."  (bech32-encoded Nostr secret key)
npub = "b8d2..."   (hex Nostr public key used to author events)
```

### Why SHA-256 of the private key?

- The vault private key is a hex string of variable length derived from BIP39 indices.
- Nostr requires a 32-byte (256-bit) secret key.
- SHA-256 normalises the input to exactly 32 bytes while maintaining determinism.
- The Nostr identity is separate from (but linked to) the vault's core identity.

---

## 5. Backup Encryption

### Nostr backup (primary)

Vault data (`{users, settings}`) is serialized to JSON and encrypted using **NIP-44** (nip44.encrypt) with a self-to-self shared secret derived from the Nostr key pair.

The encrypted blob is published as a **kind:30078** parameterized replaceable event with `d = "vault-backup"`, so relays automatically keep only the latest version.

### Local nonce backup (fallback)

After every Nostr restore and every `copyPassword()` call, the app saves an additional encrypted copy to `localStorage['vaultNonceBackup']`.

Encryption: `CryptoJS.AES.encrypt(JSON.stringify({users, settings}), privateKey)`.

The private key is the AES encryption key — the backup is only useful to someone who already possesses the seed phrase.

**Restore priority:**
1. Local backup is loaded first during `initializeVault()` as a low-priority seed.
2. Any subsequent Nostr restore overwrites it with the latest cloud data.

This ensures nonce data survives brief Nostr relay outages without compromising the "Nostr is source of truth" principle.

---

## 6. Full End-to-End Example

```
Seed phrase:  "abandon abandon abandon abandon abandon abandon
               abandon abandon abandon abandon abandon about"
                (test phrase — DO NOT USE IN PRODUCTION)

Word indices: [0,0,0,0,0,0,0,0,0,0,0,2]
Decimal str:  "000000000000000000000000000000000000000000000002"
Hex (privkey): "2"

Nostr secret: SHA-256("2") = ...
              (deterministic Nostr identity)

Password for (user="alice", site="github.com", nonce=0):
  concat   = "2/alice/github.com/0"
  SHA-256  = "dbc1b4c9..."
  entropy  = "dbc1b4c9" (hashLength=8 for this example)
  password = "PASSdbc1b4c9249+"
```

> **Warning:** The example above uses an all-zero entropy phrase. Never use this in production. Use a randomly generated phrase from the app.

---

## 7. Relevant Code

| File      | Function              | Description                                      |
|-----------|-----------------------|--------------------------------------------------|
| `app.js`  | `wordsToIndices()`    | BIP39 words → concatenated 4-digit decimal indices |
| `app.js`  | `decimalStringToHex()`| Decimal string → hex via BigInt                  |
| `app.js`  | `derivePrivateKey()`  | Full mnemonic → private key pipeline             |
| `app.js`  | `deriveNostrKeys()`   | Private key → Nostr nsec/npub                    |
| `app.js`  | `generatePassword()`  | Credential + nonce → deterministic password      |
| `app.js`  | `saveLocalNonceBackup()` | Encrypt nonce state to localStorage          |
| `app.js`  | `initializeVault()`   | Key derivation + local backup merge              |
