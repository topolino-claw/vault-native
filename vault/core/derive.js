/**
 * Password derivation — the security-critical heart of the app.
 *
 * Extracted from app.js so it can be audited on its own: no DOM, no storage,
 * no Tauri, no UI. Everything here is a pure function of its inputs.
 *
 * THE CHAIN, end to end:
 *
 *   BIP39 mnemonic
 *     -> encodeSeedPhraseAsHex()   word indices -> decimal -> hex   [NOT a KDF]
 *     -> generatePassword()        SHA-256(key/user/site/nonce), truncated
 *     -> "PASS" + <hex> + "249+"
 *
 * TWO WEAKNESSES ARE DELIBERATE AND DOCUMENTED, NOT OVERSIGHTS:
 *
 *   1. encodeSeedPhraseAsHex is an invertible base conversion, not a key
 *      derivation. `privateKey` IS the seed phrase in another encoding
 *      (ROADMAP.md 2.1).
 *   2. generatePassword truncates an unsalted single-round SHA-256 to 16 hex
 *      characters — 64 bits (ROADMAP.md 2.3).
 *
 * Neither can be fixed in place. The output is deterministic, so changing it
 * changes every password every user has ever generated. The fix is per-entry
 * versioning plus a rotation flow (ROADMAP.md 5), not an edit here.
 *
 * `vault.passphrase` is captured by the UI and enters NO derivation below.
 * It currently protects nothing (ROADMAP.md 2.2).
 *
 * WHAT MUST NEVER CHANGE: the exact bytes generatePassword returns.
 * test/compat.test.mjs pins this against the last released build across 432
 * input combinations. If that test fails, users are locked out of every
 * account they own.
 */
(function (root) {
    'use strict';

    const CryptoJS = root.CryptoJS;

    /**
     * The BIP39 word list.
     *
     * bip39WordList.js declares `words` with `const` at script top level, which
     * makes it a global *lexical* binding rather than a property of the global
     * object — so `root.words` is undefined even though `words` is in scope.
     * Resolved at call time so load order cannot bite, and so this module works
     * whether the list arrives lexically (browser script tags, vm context) or
     * as a global property.
     */
    function wordList() {
        if (typeof words !== 'undefined' && Array.isArray(words)) return words;
        if (Array.isArray(root.words)) return root.words;
        throw new Error('BIP39 word list not loaded');
    }


    /**
     * Convert a decimal string (arbitrary precision) to a hexadecimal string.
     * Used to transform the concatenated BIP39 word indices into the private key.
     *
     * @param {string} decStr - A string of decimal digits (e.g. "0234107220153...").
     * @returns {string} Hexadecimal representation without leading "0x".
     * @throws {Error} If decStr contains non-digit characters.
     */
    function decimalStringToHex(decStr) {
        if (!/^\d+$/.test(decStr)) throw new Error("Invalid decimal string");
        return BigInt(decStr).toString(16);
    }

    /**
     * Convert a space-separated list of BIP39 words into their concatenated
     * zero-padded 4-digit indices as a single decimal string.
     *
     * Example: "abandon abandon about" → "000000000002"
     * (indices 0, 0, 2 each padded to 4 digits)
     *
     * @param {string} inputWords - Space-separated BIP39 words (case-insensitive).
     * @returns {string} Concatenated decimal index string (each word = 4 chars).
     * @throws {Error} If any word is not found in the BIP39 word list.
     */
    function wordsToIndices(inputWords) {
        const wordsArray = inputWords.trim().split(/\s+/);
        return wordsArray.map(word => {
            const index = wordList().indexOf(word.toLowerCase());
            if (index === -1) throw new Error(`Word "${word}" not found`);
            return index.toString().padStart(4, '0');
        }).join('');
    }

    /**
     * Verify that a BIP39 seed phrase has a valid checksum.
     * Accepts 12, 15, 18, 21, or 24 word phrases.
     *
     * @param {string} seedPhrase - Space-separated BIP39 mnemonic.
     * @returns {Promise<boolean>} True if valid, false otherwise.
     */
    async function verifyBip39SeedPhrase(seedPhrase) {
        const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
        const seedWords = normalized.split(' ');

        if (![12, 15, 18, 21, 24].includes(seedWords.length)) return false;

        const invalid = seedWords.filter(w => !wordList().includes(w));
        if (invalid.length > 0) return false;

        const totalBits = seedWords.length * 11;
        const checksumBits = totalBits % 32;
        const entropyBits = totalBits - checksumBits;

        const binary = seedWords.map(w => wordList().indexOf(w).toString(2).padStart(11, '0')).join('');
        const entropy = binary.slice(0, entropyBits);
        const checksum = binary.slice(entropyBits);

        const entropyBytes = new Uint8Array(entropy.length / 8);
        for (let i = 0; i < entropy.length; i += 8) {
            entropyBytes[i / 8] = parseInt(entropy.slice(i, i + 8), 2);
        }

        const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
        const hashBinary = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(2).padStart(8, '0')).join('');

        return checksum === hashBinary.slice(0, checksumBits);
    }

    /**
     * Generate a random 12-word BIP39 mnemonic using 128 bits of entropy.
     * Uses the Web Crypto API for cryptographically secure randomness.
     *
     * @returns {Promise<string>} Space-separated 12-word mnemonic phrase.
     */
    async function generateMnemonic() {
        const entropy = new Uint8Array(16); // 128 bits
        crypto.getRandomValues(entropy);

        const entropyBinary = Array.from(entropy).map(b => b.toString(2).padStart(8, '0')).join('');
        const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
        const hashBinary = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(2).padStart(8, '0')).join('');
        // BIP39: checksum = first (entropyBits/32) bits of SHA-256(entropy)
        const checksumBits = entropyBinary.length / 32;

        const fullBinary = entropyBinary + hashBinary.slice(0, checksumBits);
        const mnemonic = [];
        // Split into 11-bit groups and map each to a BIP39 word
        for (let i = 0; i < fullBinary.length; i += 11) {
            mnemonic.push(wordList()[parseInt(fullBinary.slice(i, i + 11), 2)]);
        }

        return mnemonic.join(' ');
    }


    /**
     * Re-encode a BIP39 seed phrase as a hex string.
     * Process: normalize → word indices → decimal string → hex string.
     *
     * NOT a key derivation, despite what `vault.privateKey` is called: there is no
     * hashing and no stretching, so this transform is fully invertible and the
     * result IS the seed phrase in another base. Anywhere the "private key" is
     * stored, logged, or held in memory, the seed phrase is. Real BIP39 uses
     * PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic"+passphrase.
     * Tracked as ROADMAP.md 2.1; the fix changes every generated password, so it
     * has to ship behind a per-entry version flag.
     *
     * @param {string} seedPhrase - Valid BIP39 mnemonic (any case/spacing).
     * @returns {Promise<string>} Hex-encoded seed phrase (variable length, no 0x prefix).
     */
    async function encodeSeedPhraseAsHex(seedPhrase) {
        const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
        const indices = wordsToIndices(normalized);
        // Convert the big decimal number (concatenated 4-digit indices) to hex
        return decimalStringToHex(indices);
    }


    /**
     * Compute the SHA-256 hash of a string and return it as a lowercase hex string.
     *
     * FAST and UNSALTED — one round. That is fine for deriving deterministic
     * password entropy (generatePassword), and must never again be applied to the
     * master password: keying storage by sha256Hex(masterPassword) was a ~10^6x
     * brute-force shortcut around the KDF (ROADMAP.md 1.1, fixed by
     * core/keyslots.js). Key material belongs in a keyslot, never in a hash.
     *
     * @param {string} text - Input string.
     * @returns {string} 64-character lowercase hex SHA-256 digest.
     */
    function sha256Hex(text) {
        return CryptoJS.SHA256(text).toString();
    }

    /**
     * Generate a deterministic password for the given credentials.
     *
     * Algorithm:
     *   concat = "<privateKey>/<user>/<site>/<nonce>"
     *   entropy = SHA-256(concat).substring(0, hashLength)
     *   password = "PASS" + entropy + "249+"
     *
     * The fixed prefix "PASS" and suffix "249+" satisfy most complexity requirements
     * (uppercase, lowercase, digits, special characters) regardless of the hex portion.
     *
     * @param {string} privateKey  - Hex private key derived from seed phrase.
     * @param {string} user        - Username / email associated with the site.
     * @param {string} site        - Site name or domain (e.g. "github.com").
     * @param {number} nonce       - Version counter (0-based). Increment to rotate the password.
     * @param {number} [hashLength=16] - Number of hex characters to take from the SHA-256 output.
     * @returns {string} The generated password in the form "PASS<hex>249+".
     */
    function generatePassword(privateKey, user, site, nonce, hashLength = 16) {
        const concat = `${privateKey}/${user}/${site}/${nonce}`;
        const entropy = sha256Hex(concat).substring(0, hashLength);
        return 'PASS' + entropy + '249+';
    }

    /**
     * Calculate effective entropy bits of a generated password.
     * hex chars = 4 bits each. Fixed prefix/suffix add known charset expansion.
     *
     * @param {number} hashLength - Number of hex chars used in the password entropy portion.
     * @returns {{bits: number, label: string, color: string, len: number}}
     *   bits:  entropy bits from the hex portion
     *   label: human-readable strength label
     *   color: CSS color variable string
     *   len:   total password character count (prefix + entropy + suffix)
     */
    function getPasswordStrength(hashLength) {
        // Each hex character contributes 4 bits of entropy from SHA-256
        const hexBits = hashLength * 4;
        // Total length: "PASS" (4) + hex portion + "249+" (4)
        const totalLen = 4 + hashLength + 4;

        if (hexBits >= 80) return { bits: hexBits, label: 'Excellent', color: 'var(--success)', len: totalLen };
        if (hexBits >= 64) return { bits: hexBits, label: 'Strong', color: 'var(--success)', len: totalLen };
        if (hexBits >= 48) return { bits: hexBits, label: 'Good', color: 'var(--accent)', len: totalLen };
        return { bits: hexBits, label: 'Weak', color: 'var(--danger)', len: totalLen };
    }

    root.VaultDerive = {
        decimalStringToHex,
        wordsToIndices,
        verifyBip39SeedPhrase,
        generateMnemonic,
        encodeSeedPhraseAsHex,
        sha256Hex,
        generatePassword,
        getPasswordStrength
    };
})(typeof window !== 'undefined' ? window : globalThis);
