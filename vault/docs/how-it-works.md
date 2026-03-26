# How It Works

This document explains the key components behind Password Manager v3: password generation, seed phrase verification and key derivation, Nostr backup/restore, and the local nonce backup.

For a deep dive into the cryptographic derivation pipeline (BIP39 indices, hex key, nonces, Nostr key derivation), see **[derivation-and-nonces.md](./derivation-and-nonces.md)**.

---

## Password Generation Algorithm

1. After verifying or generating your seed phrase, the app builds a **private key** from the phrase.
2. When you request a password it concatenates `privateKey / username / site / nonce`.
3. The SHA-256 hash of that string is taken and the first 16 hex characters become the password entropy.
4. The final password is `PASS` + entropy + `249+`. Changing the nonce yields a new password for the same site.

See [derivation-and-nonces.md § 2](./derivation-and-nonces.md#2-private-key--credentials--nonce--password) for the full formula with examples.

---

## Seed Phrase Verification and Key Derivation

1. Each word in the seed phrase is validated against the BIP39 word list.
2. The words are translated to their numeric indices and combined into a long decimal string.
3. That decimal string is converted to hexadecimal and becomes the deterministic private key.
4. The private key is hashed once more with SHA-256 to derive a Nostr secret key (`nsec`), and NostrTools computes the corresponding public key (`npub`).

Full step-by-step derivation with examples: [derivation-and-nonces.md § 1–4](./derivation-and-nonces.md).

---

## Nonces (Password Versions)

Each saved site has a **nonce** — a version counter (starting at 0). Incrementing the nonce generates a completely different password for the same site, while the old one remains reproducible by setting the nonce back.

Use nonce rotation when a site forces a password change or you suspect a compromise.

See [derivation-and-nonces.md § 3](./derivation-and-nonces.md#3-nonces-password-versions) for details.

---

## Nostr Backup and Restore Flow

### Backup

1. The app derives a Nostr key pair from your private key.
2. Your session data (users + nonces + settings) is serialized to JSON and encrypted with **NIP-44** using a self-to-self shared secret.
3. The encrypted content is published as a **kind:30078** parameterized replaceable event tagged `d = "vault-backup"`. Relays automatically keep only the latest version.
4. The event is published to a list of relays. Success on any relay completes the backup.
5. Legacy format (kind:1 with NIP-04) is supported for restore to maintain backwards compatibility.

### Restore

1. Using the derived Nostr public key, the app queries the relays for the latest backup event (kind:30078 or legacy kind:1).
2. If an event is found, its content is decrypted (NIP-44 or NIP-04 depending on kind).
3. The decrypted JSON is merged into the application state, restoring your saved nonces.
4. After a successful restore, a local encrypted backup is saved automatically (see below).

---

## Local Nonce Backup (Fallback)

In addition to Nostr, the app maintains an encrypted local backup in `localStorage['vaultNonceBackup']`.

**When it is saved:**
- After every successful Nostr restore (manual or silent).
- After every `copyPassword()` call (which may update a nonce).

**How it is encrypted:**
`CryptoJS.AES.encrypt({users, settings}, privateKey)` — the vault's own private key is used as the AES encryption key. This means the backup is only useful to someone who already has the seed phrase.

**Restore priority:**
- On vault initialization, the local backup is merged first as a low-priority fallback.
- Any subsequent Nostr restore overwrites local data (Nostr is source of truth).

This ensures nonce state survives brief Nostr relay outages without losing recently-rotated passwords.

See [derivation-and-nonces.md § 5](./derivation-and-nonces.md#5-backup-encryption) for encryption details.
