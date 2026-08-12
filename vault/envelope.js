/**
 * Vault file envelope: encrypt/decrypt the vault snapshot with the master password.
 * Direct port of the Obsidian plugin's src/core/envelope.ts — the two apps MUST
 * stay byte-compatible on this format; the plugin side is the reference.
 *
 * v2 (written by both apps since 2026-07):
 *   PBKDF2-SHA256 (600k iterations, 16-byte random salt) → AES-256-GCM (12-byte random IV).
 *   The derived CryptoKey is cached for the session so saves don't re-run the KDF;
 *   the salt is kept stable across saves (fresh IV per write — that is what GCM needs).
 *
 * v1 (legacy, written by this app before the v2 port):
 *   CryptoJS.AES.encrypt(json, password) — OpenSSL EVP_BytesToKey (MD5, 1 round).
 *   Read-only: decrypting a v1 file upgrades it to v2 on the next save.
 */
(function (root) {
    'use strict';

    const VAULT_FILE_TYPE = 'topolino-vault';
    const V2_ITERATIONS = 600000;
    // Upper bound on the KDF cost we will honour from a file. The parameters
    // live outside the GCM tag, so a foreign or tampered file can set them to
    // anything; an unbounded iteration count makes deriveVaultKey run for
    // minutes and hangs unlock/sync on a file merely dropped into the synced
    // folder — a no-password CPU-exhaustion DoS. 10M is ~16x the current
    // default: generous headroom for raising the cost later, but bounded.
    const MAX_ITERATIONS = 10000000;
    const SALT_BYTES = 16;
    const IV_BYTES = 12;

    const subtle = (root.crypto || crypto).subtle;

    function toBase64(bytes) {
        let bin = '';
        bytes.forEach((b) => (bin += String.fromCharCode(b)));
        return btoa(bin);
    }

    function fromBase64(b64) {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    /** A KDF iteration count we are willing to run for a file we did not write. */
    function isValidIterations(n) {
        return Number.isInteger(n) && n >= 1 && n <= MAX_ITERATIONS;
    }

    async function deriveVaultKey(password, salt, iterations = V2_ITERATIONS) {
        const material = await subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return subtle.deriveKey(
            { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    function randomSalt() {
        const salt = new Uint8Array(SALT_BYTES);
        (root.crypto || crypto).getRandomValues(salt);
        return salt;
    }

    /**
     * Coerce a decrypted payload into the shape both apps agree on.
     *
     * Unknown top-level keys are PRESERVED. This used to drop them, which
     * quietly made the file format lossy: any record type one side did not
     * model was deleted the moment the other side saved. Forward compatibility
     * requires that an old reader hand back what it could not interpret.
     * The Obsidian plugin's normalizeVaultData needs the same change — until
     * it ships, treat the per-device logs as the durable home for anything
     * outside `users` (see core/store.js).
     *
     * Reserved keys are dropped rather than copied: a payload is attacker-
     * supplied until proven otherwise, and `__proto__` assigned through a
     * normal property write would reach Object.prototype.
     */
    const RESERVED_KEYS = ['__proto__', 'constructor', 'prototype'];

    function normalizeVaultData(data) {
        const src = data !== null && typeof data === 'object' ? data : {};
        const out = {};
        Object.keys(src).forEach((key) => {
            if (RESERVED_KEYS.indexOf(key) === -1) out[key] = src[key];
        });
        out.privateKey = src.privateKey || '';
        out.seedPhrase = src.seedPhrase || '';
        out.passphrase = src.passphrase || '';
        out.users = src.users || {};
        out.settings = Object.assign({ hashLength: 16 }, src.settings || {});
        return out;
    }

    /** Merge nonce maps without ever decreasing a password version. */
    function mergeUsers(target, imported) {
        let changed = false;
        Object.entries(imported || {}).forEach(([user, sites]) => {
            let targetSites = target[user];
            if (!targetSites) targetSites = target[user] = {};
            Object.entries(sites || {}).forEach(([site, nonce]) => {
                if (typeof nonce !== 'number' || !Number.isFinite(nonce)) return;
                const current = targetSites[site];
                if (current === undefined || nonce > current) {
                    targetSites[site] = nonce;
                    changed = true;
                }
            });
        });
        return changed;
    }

    // ---------- encrypt (always v2) ----------

    async function encryptEnvelope(data, key, salt, iterations = V2_ITERATIONS) {
        const iv = new Uint8Array(IV_BYTES);
        (root.crypto || crypto).getRandomValues(iv);
        const plaintext = new TextEncoder().encode(JSON.stringify(data));
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
        return JSON.stringify({
            v: 2,
            type: VAULT_FILE_TYPE,
            kdf: { algo: 'PBKDF2-SHA256', iterations, salt: toBase64(salt) },
            cipher: { algo: 'AES-256-GCM', iv: toBase64(iv) },
            payload: toBase64(new Uint8Array(ciphertext))
        });
    }

    // ---------- decrypt (v1 + v2 auto-detect) ----------

    function isVaultEnvelope(parsed) {
        return (
            typeof parsed === 'object' &&
            parsed !== null &&
            parsed.type === VAULT_FILE_TYPE &&
            typeof parsed.payload === 'string'
        );
    }

    /**
     * Decrypt a vault file with the master password. Detects v1 vs v2.
     * Throws on wrong password or malformed file. Returns
     * { data, key, salt, iterations, legacy } — cache key/salt for cheap saves;
     * legacy=true means the source was v1 and should be re-written as v2.
     */
    async function decryptEnvelope(fileContents, password) {
        let parsed;
        try {
            parsed = JSON.parse(fileContents);
        } catch (e) {
            throw new Error('Malformed vault file');
        }
        if (!isVaultEnvelope(parsed)) throw new Error('Not a topolino-vault file');

        if (parsed.v === 2) {
            // The KDF/cipher header is outside the GCM tag and therefore
            // attacker-malleable. Validate its shape and, crucially, bound the
            // iteration count BEFORE deriving: an unbounded value would hang
            // deriveVaultKey for minutes on a file dropped into the synced
            // folder, with no password required (ROADMAP 2.5).
            if (!parsed.kdf || typeof parsed.kdf !== 'object' ||
                !parsed.cipher || typeof parsed.cipher !== 'object' ||
                typeof parsed.kdf.salt !== 'string' ||
                typeof parsed.cipher.iv !== 'string' ||
                typeof parsed.payload !== 'string') {
                throw new Error('Malformed vault file');
            }
            const iterations = parsed.kdf.iterations;
            if (!isValidIterations(iterations)) throw new Error('Vault KDF iterations out of range');
            // Header fields live outside the GCM tag, so their base64 is
            // attacker-controlled too. Decode them under the malformed-file
            // contract rather than letting a raw DOMException escape and
            // distinguish this file's shape for the caller.
            let salt;
            let iv;
            try {
                salt = fromBase64(parsed.kdf.salt);
                iv = fromBase64(parsed.cipher.iv);
            } catch (e) {
                throw new Error('Malformed vault file');
            }
            const key = await deriveVaultKey(password, salt, iterations);
            let plaintext;
            try {
                plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, key, fromBase64(parsed.payload));
            } catch (e) {
                throw new Error('Wrong password');
            }
            let data;
            try {
                data = normalizeVaultData(JSON.parse(new TextDecoder().decode(plaintext)));
            } catch (e) {
                throw new Error('Malformed vault file');
            }
            return { data, key, salt, iterations, legacy: false };
        }

        // Legacy v1: CryptoJS AES (OpenSSL EVP KDF). Decrypt, then hand back a
        // fresh v2 key/salt so the caller re-writes the file upgraded.
        const CryptoJS = root.CryptoJS;
        let decrypted = '';
        try {
            decrypted = CryptoJS.AES.decrypt(parsed.payload, password).toString(CryptoJS.enc.Utf8);
        } catch (e) {
            throw new Error('Wrong password');
        }
        if (!decrypted) throw new Error('Wrong password');
        let data;
        try {
            data = normalizeVaultData(JSON.parse(decrypted));
        } catch (e) {
            throw new Error('Malformed vault file');
        }
        const salt = randomSalt();
        const key = await deriveVaultKey(password, salt);
        return { data, key, salt, iterations: V2_ITERATIONS, legacy: true };
    }

    /** Quick structural check without decrypting (any version). */
    function looksLikeVaultFile(fileContents) {
        try {
            return isVaultEnvelope(JSON.parse(fileContents));
        } catch (e) {
            return false;
        }
    }

    root.VaultEnvelope = {
        VAULT_FILE_TYPE,
        V2_ITERATIONS,
        MAX_ITERATIONS,
        isValidIterations,
        toBase64,
        fromBase64,
        deriveVaultKey,
        randomSalt,
        normalizeVaultData,
        mergeUsers,
        encryptEnvelope,
        decryptEnvelope,
        isVaultEnvelope,
        looksLikeVaultFile
    };
})(typeof window !== 'undefined' ? window : globalThis);
