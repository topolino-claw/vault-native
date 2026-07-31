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

    function normalizeVaultData(data) {
        return {
            privateKey: data.privateKey || '',
            seedPhrase: data.seedPhrase || '',
            passphrase: data.passphrase || '',
            users: data.users || {},
            settings: Object.assign({ hashLength: 16 }, data.settings || {})
        };
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
        const parsed = JSON.parse(fileContents);
        if (!isVaultEnvelope(parsed)) throw new Error('Not a topolino-vault file');

        if (parsed.v === 2) {
            const salt = fromBase64(parsed.kdf.salt);
            const iterations = parsed.kdf.iterations;
            const key = await deriveVaultKey(password, salt, iterations);
            const iv = fromBase64(parsed.cipher.iv);
            let plaintext;
            try {
                plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, key, fromBase64(parsed.payload));
            } catch (e) {
                throw new Error('Wrong password');
            }
            const data = normalizeVaultData(JSON.parse(new TextDecoder().decode(plaintext)));
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
        const data = normalizeVaultData(JSON.parse(decrypted));
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
        toBase64,
        fromBase64,
        deriveVaultKey,
        randomSalt,
        normalizeVaultData,
        encryptEnvelope,
        decryptEnvelope,
        isVaultEnvelope,
        looksLikeVaultFile
    };
})(typeof window !== 'undefined' ? window : globalThis);
