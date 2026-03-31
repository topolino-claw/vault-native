/**
 * Vault v3 - Deterministic Password Manager
 * Clean rewrite with simplified UX
 *
 * Architecture:
 *  - Passwords are deterministic: derived from privateKey + user + site + nonce via SHA-256.
 *  - The private key never changes — it is deterministically derived from the BIP39 seed phrase.
 *  - Nonces are the only mutable state: they are persisted to Nostr (encrypted) and optionally
 *    to localStorage as an encrypted local backup (see saveLocalNonceBackup).
 *  - debugMode gates all sensitive log output via debugLog().
 */

// ============================================
// State
// ============================================
let vault = {
    privateKey: '',
    seedPhrase: '',
    users: {},
    settings: { hashLength: 16, debugMode: false }
};

let nostrKeys = { nsec: '', npub: '' };
let currentNonce = 0;
let originalNonce = 0;
let passwordVisible = false;
let navigationStack = ['welcomeScreen'];
let debugMode = false;
let inactivityTimer = null;
let unlockAttempts = 0;
let unlockLockoutUntil = 0;
let clipboardClearTimer = null;
let _masterPassword = null;
let _vaultInitialized = false; // True when vault has been initialized/unlocked (Tauri or legacy)

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const VISIBILITY_LOCK_MS = 2 * 60 * 1000; // 2 minutes hidden = lock
const MAX_UNLOCK_ATTEMPTS = 5;
const UNLOCK_LOCKOUT_MS = 30 * 1000; // 30 seconds
const DEFAULT_HASH_LENGTH = 16;
const MIN_PASSWORD_LENGTH = 8;

// ============================================
// Tauri Backend Bridge
// ============================================
// When running inside Tauri, crypto operations are delegated to the Rust backend
// where secrets are held in mlock'd, zeroize-on-drop memory.
// The JS side only sees public keys, generated passwords, and encrypted blobs.

const invoke = (window.__TAURI__ && window.__TAURI__.core) ? window.__TAURI__.core.invoke : null;

/**
 * Deep-merge remote users into vault.users — higher nonce wins.
 * @param {Object} remoteUsers - { user: { site: nonce, ... }, ... }
 */
function mergeUsers(remoteUsers) {
    if (!remoteUsers) return;
    Object.entries(remoteUsers).forEach(([user, sites]) => {
        if (!vault.users[user]) vault.users[user] = {};
        Object.entries(sites).forEach(([site, nonce]) => {
            if (!Number.isInteger(nonce) || nonce < 0) return; // skip invalid nonces
            if (vault.users[user][site] === undefined || nonce > vault.users[user][site]) {
                vault.users[user][site] = nonce;
            }
        });
    });
}

const RELAYS = [
    "wss://relay.damus.io",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.snort.social",
    "wss://nos.lol"
];

// ============================================
// Debug Guard
// ============================================

/**
 * Conditional logger that only emits output when debugMode is enabled.
 * Use this for ANY log that could expose sensitive data: private keys,
 * seed phrases, encrypted blobs, decrypted vault content, or Nostr keys.
 * Safe (non-sensitive) errors — e.g. relay connection failures — may use
 * console.error directly so they always surface in production.
 *
 * @param {...*} args - Arguments forwarded to console.log when debugMode is true.
 */
function debugLog(...args) {
    if (debugMode) {
        console.log('[debug]', ...args);
    }
}

// ============================================
// Navigation
// ============================================

/**
 * Show a named screen by its DOM id, hiding all others.
 * Pushes the screenId onto the navigation stack unless it is already the top.
 * Triggers screen-specific setup (e.g. rendering the site list, generating a seed).
 *
 * @param {string} screenId - The id of the <div class="screen"> element to display.
 */
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
    const target = document.getElementById(screenId);
    if (target) {
        target.classList.remove('hidden');
        if (navigationStack[navigationStack.length - 1] !== screenId) {
            navigationStack.push(screenId);
            history.pushState({ screen: screenId }, '');
        }
    }

    // Screen-specific setup
    if (screenId === 'welcomeScreen') {
        const hasVault = localStorage.getItem('vaultEncrypted') || localStorage.getItem('encryptedDataStorage');
        if (hasVault) { showScreen('unlockScreen'); return; }
    } else if (screenId === 'mainScreen') {
        renderSiteList();
        updateNoPasswordBadge();
    } else if (screenId === 'newWalletScreen') {
        generateNewSeed(true);
    } else if (screenId === 'backupScreen') {
        // No per-screen setup needed — backup is seamless now
    } else if (screenId === 'settingsScreen') {
        updateBackupWarningIndicator();
    } else if (screenId === 'advancedScreen') {
        const hl = vault.settings.hashLength || 16;
        document.getElementById('hashLengthSetting').value = hl;
        document.getElementById('hashLengthDisplay').textContent = hl;
        debugMode = vault.settings.debugMode || false;
        document.getElementById('debugModeToggle').checked = debugMode;
    }
}

/**
 * Navigate back to the previous screen in the navigation stack.
 * Falls back to 'welcomeScreen' if the stack is empty.
 */
function goBack() {
    navigationStack.pop();
    const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
    showScreen(prev);
}


// ============================================
// Toast
// ============================================

/**
 * Display a brief status message at the bottom of the screen.
 * The toast automatically hides after 2 seconds.
 *
 * @param {string} message - The text to display.
 */
function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2000);
}

/**
 * Show an in-app confirmation dialog (replaces native confirm() which
 * may not work in Tauri / Android WebView).
 *
 * @param {string} message - The text to display.
 * @param {object} [options] - Optional button customization.
 * @param {string} [options.okLabel='OK'] - Label for the OK button.
 * @param {string} [options.cancelLabel='Cancel'] - Label for the Cancel button.
 * @param {boolean} [options.cancelDanger=false] - Style Cancel as a danger button.
 * @returns {Promise<boolean>} Resolves true for OK, false for Cancel.
 */
function showConfirm(message, options = {}) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        document.getElementById('confirmText').textContent = message;

        const okBtn = document.getElementById('confirmOk');
        const cancelBtn = document.getElementById('confirmCancel');

        okBtn.textContent = options.okLabel || 'OK';
        cancelBtn.textContent = options.cancelLabel || 'Cancel';

        if (options.cancelDanger) {
            cancelBtn.classList.add('btn-danger');
            cancelBtn.classList.remove('btn-ghost');
        }

        modal.classList.remove('hidden');

        const cleanup = (result) => {
            modal.classList.add('hidden');
            okBtn.textContent = 'OK';
            cancelBtn.textContent = 'Cancel';
            cancelBtn.classList.remove('btn-danger');
            cancelBtn.classList.add('btn-ghost');
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            resolve(result);
        };

        const onOk = () => cleanup(true);
        const onCancel = () => cleanup(false);

        okBtn.addEventListener('click', onOk);
        cancelBtn.addEventListener('click', onCancel);
    });
}

/**
 * Show the fullscreen loading modal with a status message.
 *
 * @param {string} text - Loading text shown inside the modal.
 */
function showLoading(text) {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingModal').classList.remove('hidden');
}

/**
 * Hide the fullscreen loading modal.
 */
function hideLoading() {
    document.getElementById('loadingModal').classList.add('hidden');
}

// ============================================
// BIP39 Seed Phrase Functions (preserved from original)
// ============================================

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
        const index = words.indexOf(word.toLowerCase());
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
    if (invoke) return invoke('cmd_verify_seed_phrase', { phrase: seedPhrase });

    const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    const seedWords = normalized.split(' ');

    if (![12, 15, 18, 21, 24].includes(seedWords.length)) return false;

    const invalid = seedWords.filter(w => !words.includes(w));
    if (invalid.length > 0) return false;

    const totalBits = seedWords.length * 11;
    const checksumBits = totalBits % 32;
    const entropyBits = totalBits - checksumBits;

    const binary = seedWords.map(w => words.indexOf(w).toString(2).padStart(11, '0')).join('');
    const entropy = binary.slice(0, entropyBits);
    const checksum = binary.slice(entropyBits);

    const entropyBytes = new Uint8Array(entropy.length / 8);
    for (let i = 0; i < entropy.length; i += 8) {
        entropyBytes[i / 8] = parseInt(entropy.slice(i, i + 8), 2);
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
    entropyBytes.fill(0);
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
    if (invoke) return invoke('cmd_generate_mnemonic');

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
        mnemonic.push(words[parseInt(fullBinary.slice(i, i + 11), 2)]);
    }

    entropy.fill(0);
    return mnemonic.join(' ');
}

// ============================================
// Key Derivation (preserved from original)
// ============================================

/**
 * Derive the deterministic private key from a BIP39 seed phrase.
 * Process: normalize → word indices → decimal string → hex string.
 *
 * @param {string} seedPhrase - Valid BIP39 mnemonic (any case/spacing).
 * @returns {Promise<string>} Hex-encoded private key (variable length, no 0x prefix).
 */
async function derivePrivateKey(seedPhrase) {
    const normalized = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    const indices = wordsToIndices(normalized);
    // Convert the big decimal number (concatenated 4-digit indices) to hex
    return decimalStringToHex(indices);
}

/**
 * LEGACY: Derive Nostr keys from the vault's private key via SHA-256.
 * Kept only for backward compat — used when unlocking from a locally-saved vault
 * that has no seed phrase stored (no seed = cannot use NIP-06 derivation).
 * New vaults use deriveNostrKeysNIP06() instead.
 *
 * @param {string} privateKey - Hex private key from derivePrivateKey().
 * @returns {Promise<{nsec: string, npub: string, hex: string}>}
 */
async function deriveNostrKeys(privateKey) {
    const { nip19, getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    // Nostr secret key = SHA-256 of the vault private key
    const hashBytes = new Uint8Array(hashBuffer);
    const nostrHex = Array.from(hashBytes)
        .map(b => b.toString(16).padStart(2, '0')).join('');
    hashBytes.fill(0);

    const nsec = nip19.nsecEncode(nostrHex);
    const npub = getPublicKey(nostrHex);
    return { nsec, npub, hex: nostrHex };
}

// ============================================
// NIP-06 Standard Nostr Key Derivation
// ============================================
// Derives Nostr keys via BIP39 → BIP32 → m/44'/1237'/0'/0/0
// Pure WebCrypto + BigInt EC math — no external dependencies.
//
// Test vector (empty passphrase):
//   mnemonic: "abandon abandon abandon abandon abandon abandon
//              abandon abandon abandon abandon abandon about"
//   private key: 5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731

const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

/** (a + b) mod N — for private key child derivation. */
function _secp256k1ModAdd(a, b) {
    const aBig = BigInt('0x' + Array.from(a).map(x => x.toString(16).padStart(2, '0')).join(''));
    const bBig = BigInt('0x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(''));
    const r = (aBig + bBig) % SECP256K1_N;
    const hex = r.toString(16).padStart(64, '0');
    return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

/** Modular inverse via extended Euclidean algorithm (BigInt). */
function _modInv(a, m) {
    let [or, r] = [((a % m) + m) % m, m];
    let [os, s] = [1n, 0n];
    while (r !== 0n) {
        const q = or / r;
        [or, r] = [r, or - q * r];
        [os, s] = [s, os - q * s];
    }
    return ((os % m) + m) % m;
}

/** secp256k1 EC point addition; null = point at infinity. */
function _ecAdd(p1, p2) {
    if (!p1) return p2;
    if (!p2) return p1;
    const [x1, y1] = p1, [x2, y2] = p2;
    if (x1 === x2) {
        if (y1 !== y2) return null;
        const lam = 3n * x1 * x1 % SECP256K1_P * _modInv(2n * y1, SECP256K1_P) % SECP256K1_P;
        const x3 = (lam * lam % SECP256K1_P - 2n * x1 % SECP256K1_P + 2n * SECP256K1_P) % SECP256K1_P;
        const y3 = (lam * ((x1 - x3 + SECP256K1_P) % SECP256K1_P) % SECP256K1_P - y1 + SECP256K1_P) % SECP256K1_P;
        return [x3, y3];
    }
    const lam = (y2 - y1 + SECP256K1_P) % SECP256K1_P * _modInv((x2 - x1 + SECP256K1_P) % SECP256K1_P, SECP256K1_P) % SECP256K1_P;
    const x3 = (lam * lam % SECP256K1_P - x1 - x2 + 2n * SECP256K1_P) % SECP256K1_P;
    const y3 = (lam * ((x1 - x3 + SECP256K1_P) % SECP256K1_P) % SECP256K1_P - y1 + SECP256K1_P) % SECP256K1_P;
    return [x3, y3];
}

/** secp256k1 scalar multiplication (double-and-add). */
function _ecMul(k, point) {
    let r = null, p = point;
    while (k > 0n) {
        if (k & 1n) r = _ecAdd(r, p);
        p = _ecAdd(p, p);
        k >>= 1n;
    }
    return r;
}

/**
 * Compute the 33-byte compressed public key from a 32-byte private key.
 * Uses full EC point multiplication for a correct 02/03 prefix.
 * @param {Uint8Array} privKey - 32-byte private key.
 * @returns {Uint8Array} 33-byte compressed public key.
 */
function _privToCompressedPub(privKey) {
    const k = BigInt('0x' + Array.from(privKey).map(b => b.toString(16).padStart(2, '0')).join(''));
    const [x, y] = _ecMul(k, [SECP256K1_Gx, SECP256K1_Gy]);
    const out = new Uint8Array(33);
    out[0] = (y % 2n === 0n) ? 0x02 : 0x03;
    const xHex = x.toString(16).padStart(64, '0');
    out.set(new Uint8Array(xHex.match(/.{2}/g).map(b => parseInt(b, 16))), 1);
    return out;
}

/**
 * BIP39: mnemonic + passphrase → 64-byte seed via PBKDF2-SHA512.
 */
async function _mnemonicToSeed(mnemonic, passphrase = '') {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey(
        'raw', enc.encode(mnemonic.normalize('NFKD')), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: enc.encode(('mnemonic' + passphrase).normalize('NFKD')),
        iterations: 2048, hash: 'SHA-512'
    }, km, 512);
    return new Uint8Array(bits);
}

/**
 * BIP32: 64-byte seed → master {privateKey, chainCode} via HMAC-SHA512("Bitcoin seed", seed).
 */
async function _bip32Master(seed) {
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode('Bitcoin seed'),
        { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
    );
    const r = new Uint8Array(await crypto.subtle.sign('HMAC', key, seed));
    const result = { privateKey: r.slice(0, 32), chainCode: r.slice(32) };
    r.fill(0);
    return result;
}

/**
 * BIP32 hardened child key derivation (index′ = index + 0x80000000).
 */
async function _bip32HardChild(pk, cc, index) {
    const h = index + 0x80000000;
    const data = new Uint8Array(37);
    data[0] = 0x00; data.set(pk, 1);
    data[33] = (h >>> 24) & 0xff; data[34] = (h >>> 16) & 0xff;
    data[35] = (h >>> 8) & 0xff;  data[36] = h & 0xff;
    const key = await crypto.subtle.importKey(
        'raw', cc, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
    );
    const r = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
    data.fill(0);
    const result = { privateKey: _secp256k1ModAdd(r.slice(0, 32), pk), chainCode: r.slice(32) };
    r.fill(0);
    return result;
}

/**
 * BIP32 normal (non-hardened) child key derivation.
 * Requires secp256k1 EC point multiplication to compute the compressed public key.
 */
async function _bip32NormalChild(pk, cc, index) {
    const compPub = _privToCompressedPub(pk);
    const data = new Uint8Array(37);
    data.set(compPub, 0);
    data[33] = (index >>> 24) & 0xff; data[34] = (index >>> 16) & 0xff;
    data[35] = (index >>> 8) & 0xff;  data[36] = index & 0xff;
    const key = await crypto.subtle.importKey(
        'raw', cc, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
    );
    const r = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
    data.fill(0);
    const result = { privateKey: _secp256k1ModAdd(r.slice(0, 32), pk), chainCode: r.slice(32) };
    r.fill(0);
    return result;
}

/**
 * NIP-06 key derivation: BIP39 → BIP32 → m/44'/1237'/0'/0/0
 * Compatible with Alby, nostr-wot-extension, and all major NIP-06 wallets.
 *
 * @param {string} mnemonic - Normalized BIP39 mnemonic.
 * @param {string} [passphrase=''] - Optional BIP39 passphrase (25th word).
 * @returns {Promise<string>} 64-char hex Nostr private key.
 */
async function deriveNostrKeyNIP06(mnemonic, passphrase = '') {
    const seed = await _mnemonicToSeed(mnemonic, passphrase);
    let { privateKey: pk, chainCode: cc } = await _bip32Master(seed);
    seed.fill(0);
    // Hardened: 44', 1237', 0'
    for (const i of [44, 1237, 0]) {
        const prev = pk;
        ({ privateKey: pk, chainCode: cc } = await _bip32HardChild(pk, cc, i));
        prev.fill(0);
    }
    // Non-hardened: 0, 0
    let prev = pk;
    ({ privateKey: pk, chainCode: cc } = await _bip32NormalChild(pk, cc, 0));
    prev.fill(0);
    prev = pk;
    ({ privateKey: pk } = await _bip32NormalChild(pk, cc, 0));
    prev.fill(0);
    cc.fill(0);
    const hex = Array.from(pk).map(b => b.toString(16).padStart(2, '0')).join('');
    pk.fill(0);
    return hex;
}

/**
 * Derive full Nostr key set (nsec, npub, hex) via NIP-06 standard derivation.
 * @param {string} mnemonic - BIP39 mnemonic phrase.
 * @param {string} [passphrase=''] - Optional BIP39 passphrase.
 * @returns {Promise<{nsec: string, npub: string, hex: string}>}
 */
async function deriveNostrKeysNIP06(mnemonic, passphrase = '') {
    const { nip19, getPublicKey } = window.NostrTools;
    const hex = await deriveNostrKeyNIP06(mnemonic, passphrase);
    return { nsec: nip19.nsecEncode(hex), npub: getPublicKey(hex), hex };
}

// ============================================
// Password Generation (preserved from original)
// ============================================

/**
 * Compute the SHA-256 hash of a string and return it as a lowercase hex string.
 *
 * @param {string} text - Input string.
 * @returns {Promise<string>} 64-character lowercase hex SHA-256 digest.
 */
async function hash(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
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
async function generatePassword(privateKey, user, site, nonce, hashLength = 16) {
    if (invoke) {
        return invoke('cmd_generate_password', {
            user, site, nonce, hashLength
        });
    }
    const concat = `${privateKey}/${user}/${site}/${nonce}`;
    const entropy = (await hash(concat)).substring(0, hashLength);
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

// ============================================
// Seed Phrase UI
// ============================================

/**
 * Generate a new random mnemonic and display it in the seed grid UI.
 * If a seed is already loaded and this is not the initial render, confirms
 * before replacing it.
 *
 * @param {boolean} [isInitial=false] - Skip confirmation when true (first display).
 */
async function generateNewSeed(isInitial = false) {
    // Only confirm if there's already a seed loaded (re-generating)
    if (!isInitial && (vault.seedPhrase || _vaultInitialized)) {
        if (!await showConfirm('Generate a new seed phrase? This will replace the current one.')) return;
    }
    const mnemonic = await generateMnemonic();
    vault.seedPhrase = mnemonic;

    const grid = document.getElementById('seedGrid');
    grid.innerHTML = '';

    mnemonic.split(' ').forEach((word, i) => {
        const div = document.createElement('div');
        div.className = 'seed-word';
        div.innerHTML = `<span>${i + 1}.</span>${word}`;
        grid.appendChild(div);
    });
}

/**
 * Begin the seed backup verification flow.
 * Picks 3 random word positions and renders text inputs for the user to fill in.
 * Transitions to the 'verifySeedScreen'.
 */
async function confirmSeedBackup() {
    // Setup verification
    const seedPhrase = (invoke && !vault.seedPhrase) ? await invoke('cmd_get_seed_phrase') : vault.seedPhrase;
    const seedWords = seedPhrase.split(' ');
    const indices = [];
    while (indices.length < 4) {
        const r = Math.floor(Math.random() * seedWords.length);
        if (!indices.includes(r)) indices.push(r);
    }
    indices.sort((a, b) => a - b);

    const container = document.getElementById('verifyInputs');
    container.innerHTML = '';
    container.dataset.indices = JSON.stringify(indices);

    indices.forEach(i => {
        const div = document.createElement('div');
        div.className = 'input-group';
        div.style.position = 'relative';
        div.innerHTML = `
            <label>Word #${i + 1}</label>
            <input type="text" class="verify-word" data-index="${i}" placeholder="Enter word ${i + 1}"
                   autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
            <div class="seed-suggestions hidden"></div>
        `;
        container.appendChild(div);
    });

    const verifyInputs = container.querySelectorAll('.verify-word');
    verifyInputs.forEach((input, position) => {
        const suggestionsEl = input.parentElement.querySelector('.seed-suggestions');

        attachBip39Autocomplete(input, suggestionsEl, {
            singleWord: true,
            onSelect: () => {
                const nextInput = verifyInputs[position + 1];
                if (nextInput) nextInput.focus();
            }
        });

        // Enter submits only when suggestions are hidden
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && suggestionsEl.classList.contains('hidden')) {
                verifySeedBackup();
            }
        });
    });

    showScreen('verifySeedScreen');
}

/**
 * Validate the user's seed verification inputs.
 * If all 4 words are correct, initialize the vault and proceed to the main screen.
 * On failure, highlights the incorrect fields and shows a toast.
 *
 * @returns {Promise<void>}
 */
async function verifySeedBackup() {
    const seedPhrase = (invoke && !vault.seedPhrase) ? await invoke('cmd_get_seed_phrase') : vault.seedPhrase;
    const seedWords = seedPhrase.split(' ');
    const inputs = document.querySelectorAll('.verify-word');
    let valid = true;

    inputs.forEach(input => {
        const idx = parseInt(input.dataset.index);
        if (input.value.trim().toLowerCase() !== seedWords[idx]) {
            input.style.borderColor = 'var(--danger)';
            valid = false;
        } else {
            input.style.borderColor = 'var(--success)';
        }
    });

    if (valid) {
        const passphrase = document.getElementById('newVaultPassphrase')?.value || '';
        if (passphrase) {
            const confirmed = confirm(
                'You have set an extra passphrase.\n\n' +
                'This passphrase is now permanently tied to your vault. ' +
                'You will need BOTH your 12 words AND this exact passphrase to restore your vault.\n\n' +
                'If you forget the passphrase, your vault is unrecoverable — no one can help you.\n\n' +
                'Are you sure you want to continue with this passphrase?'
            );
            if (!confirmed) return;
        }
        await initializeVault(seedPhrase, passphrase);
        await checkForRemoteBackups();
        showScreen('setMasterPasswordScreen');
    } else {
        showToast('Incorrect words. Try again.');
    }
}

/**
 * Validate and restore a vault from a user-entered seed phrase.
 * Validates BIP39 checksum, initializes the vault, checks for Nostr backups,
 * then navigates to the main screen.
 *
 * @returns {Promise<void>}
 */
async function restoreFromSeed() {
    const input = document.getElementById('restoreSeedInput').value;
    const valid = await verifyBip39SeedPhrase(input);

    if (!valid) {
        showToast('Invalid seed phrase');
        return;
    }

    const passphrase = document.getElementById('bip39Passphrase')?.value || '';
    await initializeVault(input, passphrase);
    await checkForRemoteBackups();

    // Clear sensitive seed phrase from the input fields
    document.getElementById('restoreSeedInput').value = '';
    const passphraseEl = document.getElementById('bip39Passphrase');
    if (passphraseEl) passphraseEl.value = '';
    document.getElementById('wordCount').textContent = '0';

    showScreen('setMasterPasswordScreen');
}

// ============================================
// Vault Management
// ============================================

/**
 * Initialize the vault from a seed phrase: derive keys, merge any local nonce backup.
 * After this call, vault.privateKey and nostrKeys are populated and the
 * inactivity timer is reset.
 *
 * Local backup merging: if a vaultNonceBackup exists in localStorage (written by
 * saveLocalNonceBackup), it is decrypted and merged as a low-priority fallback —
 * any data from a subsequent Nostr restore will win over local data.
 *
 * @param {string} seedPhrase - Valid BIP39 mnemonic.
 * @returns {Promise<void>}
 */
async function initializeVault(seedPhrase, passphrase = '') {
    if (invoke) {
        // Delegate to Rust backend — secrets stay in mlock'd memory
        const info = await invoke('cmd_initialize_vault', { seedPhrase, passphrase });
        vault.seedPhrase = ''; // Don't keep in JS
        vault.privateKey = ''; // Don't keep in JS
        vault.passphrase = '';
        nostrKeys = { nsec: '', npub: info.npub, hex: info.npub_hex };
        vault.users = info.users;
        vault.settings = info.settings;
    } else {
        vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
        vault.privateKey = await derivePrivateKey(vault.seedPhrase);
        nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, passphrase);
        vault.passphrase = passphrase;
    }

    // Attempt to load local nonce backup as a low-priority seed.
    // Nostr data (fetched later in checkForRemoteBackups) will overwrite this.
    try {
        const localBackupRaw = localStorage.getItem('vaultNonceBackup');
        if (localBackupRaw) {
            debugLog('initializeVault: local nonce backup found, attempting merge');
            let decrypted;
            if (isWebCryptoEnvelope(localBackupRaw)) {
                decrypted = await decryptLocal(localBackupRaw, vault.privateKey);
            } else {
                // Legacy CryptoJS format — decrypt and migrate
                decrypted = CryptoJS.AES.decrypt(localBackupRaw, vault.privateKey)
                    .toString(CryptoJS.enc.Utf8);
            }
            if (decrypted) {
                const localData = JSON.parse(decrypted);
                // Merge users — only adopt local nonces if not already present in vault
                if (localData.users) {
                    Object.entries(localData.users).forEach(([user, sites]) => {
                        if (!vault.users[user]) vault.users[user] = {};
                        Object.entries(sites).forEach(([site, nonce]) => {
                            // Local backup wins only if vault has no entry for this site
                            if (vault.users[user][site] === undefined) {
                                vault.users[user][site] = nonce;
                            }
                        });
                    });
                }
                if (localData.settings) {
                    // Only adopt settings not already set
                    vault.settings = { ...localData.settings, ...vault.settings };
                }
                debugLog('initializeVault: local backup merged');
                // Migrate legacy format to Web Crypto
                if (!isWebCryptoEnvelope(localBackupRaw)) {
                    await saveLocalNonceBackup();
                    debugLog('initializeVault: migrated nonce backup to Web Crypto');
                }
            }
        }
    } catch (e) {
        // Non-fatal: corrupted or missing local backup — just ignore
        debugLog('initializeVault: could not read local backup:', e);
    }

    _vaultInitialized = true;
    resetInactivityTimer();
}

/**
 * After vault initialization, silently check Nostr relays for an existing backup.
 * Shows a loading modal during the check. On success, notifies the user.
 *
 * @returns {Promise<void>}
 */
async function checkForRemoteBackups() {
    const npubShort = nostrKeys.npub.slice(0, 16) + '...';

    showLoading(`Looking for remote backups...\n${npubShort}`);

    try {
        const { found } = await silentRestoreFromNostr();
        hideLoading();

        if (found) {
            vault.settings.lastBackupFailed = false;
            setRelayStatus('synced');
            showToast('Synced from cloud backup!');
        } else {
            showToast('Vault ready');
        }
    } catch (e) {
        console.error('Backup check failed:', e);
        hideLoading();
        setRelayStatus('failed');
        showToast('Vault ready (offline)');
    }
}

/**
 * Silently attempt to restore vault data from Nostr relays without UI prompts.
 * Queries all configured relays for the latest backup event, decrypts it,
 * and merges users/settings into the current vault state.
 * After a successful restore, saves a local encrypted backup.
 *
 * @returns {Promise<{ found: boolean }>}
 *   found — true if a backup was found and applied
 */
async function silentRestoreFromNostr() {
    if (!_vaultInitialized && !vault.privateKey) return { found: false };

    const { sk, pk } = await getNostrKeyPair();

    // Helper: query all relays for backup events authored by a given pubkey
    async function fetchLatestFromRelays(authorPk) {
        let latest = null;
        for (const url of RELAYS) {
            try {
                debugLog(`silentRestoreFromNostr: connecting to ${url}`);
                const relay = await connectRelay(url);
                const events = await subscribeAndCollect(relay, [
                    { kinds: [30078], authors: [authorPk], "#d": [BACKUP_D_TAG], limit: 1 },
                    { kinds: [1], authors: [authorPk], "#t": ["nostr-pwd-backup"], limit: 1 }
                ], 6000);
                relay.close();
                if (events.length > 0) {
                    debugLog(`silentRestoreFromNostr: ${url} returned ${events.length} event(s)`);
                } else {
                    debugLog(`silentRestoreFromNostr: ${url} returned no events`);
                }
                for (const e of events) {
                    if (!latest || e.created_at > latest.created_at) latest = e;
                }
            } catch (e) {
                console.error(`silentRestoreFromNostr: relay error [${url}]`, e);
            }
        }
        return latest;
    }

    // Helper: attempt to decrypt and apply a backup event
    async function tryApplyBackup(event, decryptSk, decryptPk, useLegacy = false) {
        try {
            const decrypted = await decryptBackupEvent(event, decryptSk, decryptPk, false, useLegacy);
            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) {
                vault.settings = { ...vault.settings, ...data.settings };
                debugMode = vault.settings.debugMode || false;
            }
            await saveLocalNonceBackup();
            await autoSaveVault();
            return { found: true };
        } catch (e) {
            if (e.message && e.message.includes('password')) {
                try {
                    const decrypted = await decryptBackupEvent(event, decryptSk, decryptPk, true, useLegacy);
                    const data = JSON.parse(decrypted);
                    mergeUsers(data.users);
                    if (data.settings) {
                        vault.settings = { ...vault.settings, ...data.settings };
                        debugMode = vault.settings.debugMode || false;
                    }
                    await saveLocalNonceBackup();
                    await autoSaveVault();
                    return { found: true };
                } catch (e2) {
                    debugLog('silentRestoreFromNostr: interactive decrypt failed:', e2);
                }
            }
            debugLog('silentRestoreFromNostr: decrypt failed:', e);
        }
        return null;
    }

    // 1. Try NIP-06 key (current)
    let latest = await fetchLatestFromRelays(pk);
    if (latest) {
        const result = await tryApplyBackup(latest, sk, pk, false);
        if (result) return result;
    }

    // 2. Legacy fallback: try SHA-256 derived key if no NIP-06 backup found
    if (!vault.passphrase || vault.passphrase === '') {
        const legacy = await getLegacyNostrKeyPair();
        if (legacy.pk !== pk) { // Only if legacy key differs from current
            debugLog('silentRestoreFromNostr: trying legacy key fallback');
            latest = await fetchLatestFromRelays(legacy.pk);
            if (latest) {
                const result = await tryApplyBackup(latest, legacy.sk, legacy.pk, true);
                if (result) {
                    showToast('Legacy backup found — upgrading to NIP-06 key');
                    // Re-publish with new NIP-06 key
                    backupToNostrDebounced();
                    return result;
                }
            }
        }
    }

    return { found: false };
}

/**
 * Lock the vault, clearing all sensitive state from memory.
 * Clears the clipboard, cancels timers, resets navigation, and shows the welcome screen.
 *
 * @param {boolean} [skipConfirm=false] - If true, skip the confirmation dialog.
 */
async function lockVault(skipConfirm = false) {
    const isUnlocked = invoke ? await invoke('cmd_is_unlocked') : !!vault.privateKey;
    const hasPassword = invoke ? await invoke('cmd_has_master_password') : !!_masterPassword;
    // No-password sessions: vault lives only in memory and cannot be recovered.
    if (!hasPassword && isUnlocked) {
        if (skipConfirm) {
            // Auto-lock (inactivity / visibility): destroy the vault silently.
            var destroyed = true;
        } else {
            // Manual lock: offer to set a password first.
            const choice = await showConfirm(
                'No password is set!\n\n' +
                'Your vault exists only in memory and will be PERMANENTLY LOST if you lock now without password.\n\n' +
                'Set a password to protect your vault, or lock anyway (destroys vault).',
                { okLabel: 'Set Password', cancelLabel: 'Destroy Vault', cancelDanger: true }
            );
            if (choice) {
                showScreen('setMasterPasswordScreen');
                return;
            }
            var destroyed = true;
        }
    } else if (!skipConfirm && isUnlocked) {
        if (!await showConfirm('Lock vault? You\'ll need your password to unlock again.')) return;
    }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    if (_backupDebounceTimer) clearTimeout(_backupDebounceTimer);
    _backupDebounceTimer = null;
    try { navigator.clipboard.writeText('').catch(() => {}); } catch (_) {}
    // Zero secrets in Rust — must complete before we touch JS state
    if (invoke) {
        try { await invoke('cmd_lock_vault'); } catch (_) {}
    }
    _vaultInitialized = false;
    vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    _masterPassword = null;
    _cachedLocalKey = null;
    if (_cachedLocalSalt) _cachedLocalSalt.fill(0);
    _cachedLocalSalt = null;
    _cachedLocalPassphrase = null;

    // Wipe all sensitive data from DOM
    document.querySelectorAll('input, textarea').forEach(el => { el.value = ''; });
    document.querySelectorAll('[data-seed-word], .seed-word, .word-item, .word-display').forEach(el => {
        el.textContent = '';
    });
    // Wipe any containers that might show seed words
    ['seedPhraseDisplay','seedWords','mnemonicWords','seedBackupScreen','setupSeedScreen','verifyScreen','seedDisplay'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.querySelectorAll('input, span, div, p').forEach(child => {
            child.textContent = '';
            if ('value' in child) child.value = '';
        });
    });

    // Navigate directly to the right screen (avoid welcomeScreen → unlockScreen redirect)
    const hasVault = localStorage.getItem('vaultEncrypted') || localStorage.getItem('encryptedDataStorage');
    const targetScreen = hasVault ? 'unlockScreen' : 'welcomeScreen';
    navigationStack = [targetScreen];
    showScreen(targetScreen);
    showToast(destroyed ? 'Vault destroyed' : 'Vault locked');
}

// ============================================
// Local Nonce Backup (Issue #38)
// ============================================

/**
 * Encrypt and save the current vault nonce data to localStorage.
 *
 * This provides a local fallback so that nonce state (password versions) is not
 * lost if Nostr relays are temporarily unavailable. The backup is encrypted with
 * CryptoJS AES using the vault's private key as the encryption key, so it is
 * only useful to someone who already has the seed phrase.
 *
 * Priority on restore: Nostr > local backup. Local backup is merged first during
 * initializeVault(), and then any subsequent Nostr restore will overwrite it.
 *
 * Call this after:
 *   - Any successful Nostr restore (data changed)
 *   - copyPassword() (nonce may have changed)
 */
async function saveLocalNonceBackup() {
    if (invoke) {
        const isUnlocked = await invoke('cmd_is_unlocked');
        if (!isUnlocked) return;
        try {
            await invoke('cmd_set_vault_users', { usersJson: JSON.stringify(vault.users) });
            await invoke('cmd_set_vault_settings', { settingsJson: JSON.stringify(vault.settings) });
            const encrypted = await invoke('cmd_encrypt_nonce_backup');
            localStorage.setItem('vaultNonceBackup', encrypted);
            debugLog('saveLocalNonceBackup: saved (Tauri)');
        } catch (e) {
            debugLog('saveLocalNonceBackup: failed:', e);
        }
        return;
    }

    if (!vault.privateKey) return;
    try {
        const payload = JSON.stringify({ users: vault.users, settings: vault.settings });
        const encrypted = await encryptLocal(payload, vault.privateKey);
        localStorage.setItem('vaultNonceBackup', encrypted);
        debugLog('saveLocalNonceBackup: local backup saved');
    } catch (e) {
        // Non-fatal: if localStorage is full or unavailable, log and continue
        debugLog('saveLocalNonceBackup: failed to save local backup:', e);
    }
}

/**
 * Auto-save the full vault to localStorage, encrypted with the master password.
 * Called after every vault data mutation. No-op if the user skipped password setup.
 */
async function autoSaveVault() {
    if (invoke) {
        // In Tauri mode: Rust holds all secrets, encrypt from Rust
        const hasPassword = await invoke('cmd_has_master_password');
        const isUnlocked = await invoke('cmd_is_unlocked');
        if (!hasPassword || !isUnlocked) return;
        try {
            // Sync JS-side user/settings data to Rust before encrypting
            await invoke('cmd_set_vault_users', { usersJson: JSON.stringify(vault.users) });
            await invoke('cmd_set_vault_settings', { settingsJson: JSON.stringify(vault.settings) });
            const encrypted = await invoke('cmd_encrypt_vault');
            localStorage.setItem('vaultEncrypted', encrypted);
            debugLog('autoSaveVault: saved (Tauri)');
        } catch (e) {
            debugLog('autoSaveVault: failed:', e);
        }
        return;
    }

    if (!_masterPassword || !vault.privateKey) return;
    try {
        const saveData = {
            privateKey: vault.privateKey,
            seedPhrase: vault.seedPhrase,
            passphrase: vault.passphrase || '',
            users: vault.users,
            settings: vault.settings
        };
        const encrypted = await encryptLocal(JSON.stringify(saveData), _masterPassword);
        localStorage.setItem('vaultEncrypted', encrypted);
        debugLog('autoSaveVault: saved');
    } catch (e) {
        debugLog('autoSaveVault: failed:', e);
    }
}

// ============================================
// Site List & Search
// ============================================

/**
 * Render the list of saved sites in the main screen.
 * Filters by the current search term (site name or username).
 * Shows the empty state element when there are no sites and no active search.
 */
function renderSiteList() {
    const container = document.getElementById('siteList');
    const emptyState = document.getElementById('emptyState');
    const searchTerm = document.getElementById('siteSearch').value.toLowerCase();

    // Collect all sites across all users
    const sites = [];
    Object.entries(vault.users || {}).forEach(([user, userSites]) => {
        Object.entries(userSites).forEach(([site, nonce]) => {
            sites.push({ user, site, nonce });
        });
    });

    // Filter by site name or username
    const filtered = sites.filter(s =>
        s.site.toLowerCase().includes(searchTerm) ||
        s.user.toLowerCase().includes(searchTerm)
    );

    if (filtered.length === 0 && !searchTerm) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }

    emptyState.classList.add('hidden');
    container.innerHTML = filtered.map(s => `
        <div class="site-item" data-site="${escapeHtml(s.site)}" data-user="${escapeHtml(s.user)}" data-nonce="${s.nonce}">
            <div class="site-icon">${escapeHtml(s.site.charAt(0))}</div>
            <div class="site-info">
                <div class="site-name">${escapeHtml(s.site)}</div>
                <div class="site-user">${escapeHtml(s.user)}</div>
            </div>
            <button class="btn-delete" data-delete-site="${escapeHtml(s.site)}" data-delete-user="${escapeHtml(s.user)}" title="Delete">✕</button>
        </div>
    `).join('');
}

/**
 * Re-render the site list (called by the search input's oninput handler).
 */
function filterSites() {
    renderSiteList();
}

/**
 * Handle Enter key in the site search input.
 * If the search term matches no existing site, opens a new password generation
 * screen pre-filled with the search term as the site name.
 *
 * @param {KeyboardEvent} event - The keydown event from the search input.
 */
function handleSearchEnter(event) {
    if (event.key === 'Enter') {
        const term = document.getElementById('siteSearch').value.trim();
        if (term) {
            openSite(term, '', 0);
        }
    }
}

/**
 * Escape HTML special characters to prevent XSS when inserting user data into innerHTML.
 *
 * @param {string} str - Untrusted string.
 * @returns {string} HTML-escaped string safe for use in innerHTML.
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}



// ============================================
// Password Generation Screen
// ============================================

/**
 * Open the password generation screen for a given site/user combination.
 * Pre-fills the site and user fields, restores the nonce, and shows the
 * password strength indicator.
 *
 * @param {string} site  - Site name or domain.
 * @param {string} user  - Username / email.
 * @param {number} nonce - Current nonce (0-based version counter).
 */
function openSite(site, user, nonce) {
    document.getElementById('genSite').value = site;
    document.getElementById('genUser').value = user;
    currentNonce = nonce || 0;
    originalNonce = currentNonce;
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    passwordVisible = false;
    document.getElementById('genPassword').textContent = '••••••••••••';
    document.getElementById('visibilityIcon').textContent = '👁️';
    updateNonceIndicator();

    // Always show strength indicator
    const strengthEl = document.getElementById('passwordStrength');
    if (strengthEl) {
        const s = getPasswordStrength(vault.settings.hashLength || DEFAULT_HASH_LENGTH);
        strengthEl.innerHTML = `<span style="color:${s.color}">● ${s.label}</span> · ${s.bits}-bit · ${s.len} chars`;
    }

    if (site && user) {
        updatePassword();
    }

    showScreen('generateScreen');
}

/**
 * Update the nonce control's visual indicator.
 * Adds the 'nonce-changed' CSS class when the current nonce differs from the
 * saved (original) nonce, alerting the user that copying will update the stored version.
 */
function updateNonceIndicator() {
    const nonceControl = document.querySelector('.nonce-control');
    if (currentNonce !== originalNonce) {
        nonceControl.classList.add('nonce-changed');
    } else {
        nonceControl.classList.remove('nonce-changed');
    }
}

/**
 * Recompute and display the generated password based on the current
 * site, user, and nonce inputs. Only updates the display if the password
 * is currently visible.
 */
async function updatePassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    const strengthEl = document.getElementById('passwordStrength');

    if (!site || !user || (!_vaultInitialized && !vault.privateKey)) {
        document.getElementById('genPassword').textContent = '••••••••••••';
        if (strengthEl) strengthEl.textContent = '';
        return;
    }

    const hl = vault.settings.hashLength || DEFAULT_HASH_LENGTH;
    const pass = await generatePassword(vault.privateKey, user, site, currentNonce, hl);

    if (passwordVisible) {
        document.getElementById('genPassword').textContent = pass;
    }

    // Update strength indicator
    if (strengthEl) {
        const s = getPasswordStrength(hl);
        strengthEl.innerHTML = `<span style="color:${s.color}">● ${s.label}</span> · ${s.bits}-bit · ${s.len} chars`;
    }
}

/**
 * Toggle password visibility between the generated password and the masked placeholder.
 * Calls updatePassword() to reveal the current password when toggling on.
 */
function togglePasswordVisibility() {
    passwordVisible = !passwordVisible;
    document.getElementById('visibilityIcon').textContent = passwordVisible ? '🙈' : '👁️';

    if (passwordVisible) {
        updatePassword();
    } else {
        document.getElementById('genPassword').textContent = '••••••••••••';
    }
}

/**
 * Increment the nonce (password version) by 1.
 * Updates the display and regenerates the password if visible.
 */
function incrementNonce() {
    currentNonce++;
    document.getElementById('nonceDisplay').textContent = currentNonce + 1;
    updateNonceIndicator();
    if (passwordVisible) updatePassword();
}

/**
 * Decrement the nonce (password version) by 1, minimum 0.
 * Updates the display and regenerates the password if visible.
 */
function decrementNonce() {
    if (currentNonce > 0) {
        currentNonce--;
        document.getElementById('nonceDisplay').textContent = currentNonce + 1;
        updateNonceIndicator();
        if (passwordVisible) updatePassword();
    }
}

/**
 * Generate the current password, save the nonce to the vault, copy to clipboard,
 * save a local encrypted backup, and trigger a background Nostr sync.
 *
 * Saves the current nonce under vault.users[user][site] so the same password
 * can be reproduced later. The clipboard is auto-cleared after 30 seconds.
 */
async function copyPassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();

    if (!site || !user) {
        showToast('Enter site and username');
        return;
    }

    // Always save when copying — persist the current nonce
    if (!vault.users[user]) vault.users[user] = {};
    vault.users[user][site] = currentNonce;
    originalNonce = currentNonce;
    updateNonceIndicator();

    const pass = await generatePassword(
        vault.privateKey, user, site, currentNonce,
        vault.settings.hashLength || DEFAULT_HASH_LENGTH
    );

    navigator.clipboard.writeText(pass).then(() => {
        showToast('Saved & copied!');
        // Auto-clear clipboard after 30 seconds for security
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    }).catch(() => {
        showToast('Copy failed');
    });

    // Persist nonce changes to local backup immediately (nonce may have changed)
    await saveLocalNonceBackup();
    await autoSaveVault();

    // Background sync to Nostr
    backupToNostrDebounced();
}

/**
 * Copy the password and navigate back to the main site list screen.
 */
function saveAndCopy() {
    copyPassword();
    showScreen('mainScreen');
}

/**
 * Delete a site entry from the vault after user confirmation.
 * Removes the site from the user's entry, cleans up empty user objects,
 * and triggers a background Nostr sync.
 *
 * @param {string} site - Site name to delete.
 * @param {string} user - Username the site is associated with.
 */
async function deleteSite(site, user) {
    if (!await showConfirm(`Delete ${site} (${user})?`)) return;

    if (vault.users[user]) {
        delete vault.users[user][site];
        // Clean up empty user objects
        if (Object.keys(vault.users[user]).length === 0) {
            delete vault.users[user];
        }
    }

    showToast('Site deleted');
    renderSiteList();
    await saveLocalNonceBackup();
    await autoSaveVault();
    backupToNostrDebounced();
}

/**
 * Fire-and-forget wrapper for backupToNostr that suppresses UI feedback.
 * Used for background syncs triggered by user actions (copy, delete, import).
 */
function backupToNostrSilent() {
    backupToNostr(true).catch(e => console.error('Silent backup failed:', e));
}

/**
 * Debounced version of backupToNostrSilent.
 * Coalesces rapid vault mutations (e.g. multiple copies) into a single backup
 * after 3 seconds of inactivity.
 */
let _backupDebounceTimer = null;
function backupToNostrDebounced() {
    console.log('[relay] backupToNostrDebounced: queued (3s)');
    if (_backupDebounceTimer) clearTimeout(_backupDebounceTimer);
    setRelayStatus('syncing');
    _backupDebounceTimer = setTimeout(() => {
        console.log('[relay] backupToNostrDebounced: firing now');
        backupToNostrSilent();
        _backupDebounceTimer = null;
    }, 3000);
}

/**
 * Show or hide a subtle warning indicator on the Cloud Backup settings item
 * when the last silent backup failed (no relays confirmed the event).
 */
function updateBackupWarningIndicator() {
    const el = document.getElementById('backupWarningBadge');
    if (!el) return;
    if (vault.settings.lastBackupFailed) {
        el.classList.remove('hidden');
    } else {
        el.classList.add('hidden');
    }
}

/**
 * Update the relay status indicator dot in the main screen header.
 * @param {'synced'|'syncing'|'failed'|'idle'} status
 */
let _lastRelayStatus = 'idle';
let _lastSettledRelayStatus = 'idle';
function setRelayStatus(status) {
    const el = document.getElementById('relayStatus');
    if (!el) return;
    debugLog(`[relay-status] ${_lastRelayStatus} → ${status}`);
    _lastRelayStatus = status;
    if (status !== 'syncing') _lastSettledRelayStatus = status;
    el.dataset.status = status;
    const labels = {
        synced: 'Relay: synced',
        syncing: 'Relay: syncing…',
        failed: 'Relay: offline — local only',
        idle: 'Relay: idle'
    };
    el.title = labels[status] || '';
}

// ============================================
// Local Encryption
// ============================================

/**
 * Set the master password after vault creation, encrypt and save, then go to main screen.
 */
async function setMasterPassword() {
    const p1 = document.getElementById('masterPass1').value;
    const p2 = document.getElementById('masterPass2').value;
    if (!p1) { showToast('Enter a password'); return; }
    if (p1.length < MIN_PASSWORD_LENGTH) {
        showToast(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
        return;
    }
    if (p1 !== p2) { showToast('Passwords don\'t match'); return; }

    _masterPassword = p1;
    if (invoke) await invoke('cmd_set_master_password', { password: p1 });
    await autoSaveVault();
    showToast('Password set!');
    showScreen('mainScreen');
}

function skipMasterPassword() {
    _masterPassword = null;
    showScreen('mainScreen');
}

/**
 * Show/hide the "Unprotected" badge based on password state.
 */
function updateNoPasswordBadge() {
    const badge = document.getElementById('noPasswordBadge');
    if (!badge) return;
    badge.classList.toggle('hidden', !!_masterPassword);
}

/**
 * Delete all vault data from this device. Double confirmation required.
 */
async function deleteAllData() {
    if (!await showConfirm(
        'Delete all vault data from this device?\n\n' +
        'Your locally saved vault will be permanently erased. Cloud backups will NOT be affected.\n\n' +
        'You\'ll need your seed phrase to restore.'
    )) return;

    localStorage.removeItem('vaultEncrypted');
    localStorage.removeItem('vaultNonceBackup');
    localStorage.removeItem('encryptedDataStorage');

    _masterPassword = null;
    vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    try { navigator.clipboard.writeText('').catch(() => {}); } catch (_) {}
    navigationStack = ['welcomeScreen'];

    document.querySelectorAll('input, textarea').forEach(el => { el.value = ''; });

    showScreen('welcomeScreen');
    showToast('All data deleted');
}

/**
 * Unlock the vault from a locally encrypted backup stored in localStorage.
 * Supports the new single-string format and legacy multi-password JSON format.
 *
 * @returns {Promise<void>}
 */
async function unlockVault() {
    // Rate limiting
    const now = Date.now();
    if (now < unlockLockoutUntil) {
        const secs = Math.ceil((unlockLockoutUntil - now) / 1000);
        showToast(`Too many attempts. Wait ${secs}s`);
        return;
    }

    const password = document.getElementById('unlockPassword').value;
    if (!password) {
        showToast('Enter password');
        return;
    }

    try {
        const stored = localStorage.getItem('vaultEncrypted');
        if (!stored) { showToast('No saved vault found'); return; }

        // Tauri path: decrypt in Rust, secrets stay in Rust memory
        if (invoke && isWebCryptoEnvelope(stored)) {
            const info = await invoke('cmd_unlock_vault', { encrypted: stored, password });
            vault.privateKey = ''; // Don't keep in JS
            vault.seedPhrase = '';
            vault.passphrase = '';
            vault.users = info.users;
            vault.settings = info.settings;
            nostrKeys = { nsec: '', npub: info.npub, hex: info.npub_hex };
            _masterPassword = password; // Keep for UI checks only
            _vaultInitialized = true;
            unlockAttempts = 0;
            resetInactivityTimer();
            showToast('Vault unlocked!');
            showScreen('mainScreen');
            return;
        }

        let data;
        let needsMigration = false;

        if (isWebCryptoEnvelope(stored)) {
            // v3 Web Crypto format
            const decrypted = await decryptLocal(stored, password);
            if (!decrypted) throw new Error('decrypt failed');
            data = JSON.parse(decrypted);
        } else {
            // Legacy CryptoJS or multi-password JSON format
            needsMigration = true;
            let encrypted = stored;
            let isLegacy = false;

            try {
                const parsed = JSON.parse(stored);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) &&
                    parsed.v !== LOCAL_ENCRYPT_VERSION) {
                    // Legacy format: dictionary keyed by password hash
                    const key = await hash(password);
                    const legacyStored = JSON.parse(localStorage.getItem('encryptedDataStorage') || '{}');
                    const merged = { ...legacyStored, ...parsed };
                    encrypted = merged[key];
                    if (!encrypted) throw new Error('not found');
                    isLegacy = true;
                }
            } catch (legacyErr) {
                if (isLegacy) {
                    unlockAttempts++;
                    if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
                        unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
                        unlockAttempts = 0;
                        showToast('Too many attempts. Locked for 30s');
                    } else {
                        showToast(`Wrong password (${MAX_UNLOCK_ATTEMPTS - unlockAttempts} attempts left)`);
                    }
                    return;
                }
                // Not JSON — old CryptoJS raw format, use stored directly
            }

            const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
            if (!decrypted) throw new Error('decrypt failed');
            data = JSON.parse(decrypted);

            if (isLegacy) {
                localStorage.removeItem('encryptedDataStorage');
            }
        }

        // Handle both data shapes
        if (data.privateKey) {
            vault.privateKey = data.privateKey;
            vault.seedPhrase = data.seedPhrase || '';
            vault.passphrase = data.passphrase || '';
            vault.users = data.users || {};
            vault.settings = data.settings || { hashLength: 16 };
        } else {
            vault = data;
            vault.passphrase = vault.passphrase || '';
        }

        // Prefer NIP-06 derivation when seed phrase is available, fall back to legacy
        if (vault.seedPhrase) {
            nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, vault.passphrase || '');
        } else {
            nostrKeys = await deriveNostrKeys(vault.privateKey);
        }

        _masterPassword = password;
        _vaultInitialized = true;
        unlockAttempts = 0;

        // Migrate legacy format: push secrets into Rust backend if running in Tauri
        if (needsMigration && invoke) {
            if (vault.seedPhrase) {
                await invoke('cmd_initialize_vault', {
                    seedPhrase: vault.seedPhrase,
                    passphrase: vault.passphrase || ''
                });
                vault.privateKey = '';
                vault.seedPhrase = '';
                vault.passphrase = '';
            }
            await invoke('cmd_set_master_password', { password });
        }

        // Re-encrypt with Web Crypto (Rust-side if Tauri, JS-side otherwise)
        if (needsMigration) {
            await autoSaveVault();
            debugLog('unlockVault: migrated vault to Web Crypto');
        }

        resetInactivityTimer();
        showToast('Vault unlocked!');
        showScreen('mainScreen');
    } catch (e) {
        debugLog('unlockVault error:', e);
        unlockAttempts++;
        if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
            unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
            unlockAttempts = 0;
            showToast('Too many attempts. Locked for 30s');
        } else {
            showToast('Invalid password');
        }
    }
}



// ============================================
// Export & Import
// ============================================

/**
 * Download vault data (users + settings) as a JSON file.
 * Does NOT include the private key or seed phrase.
 */
function downloadData() {
    const data = { users: vault.users, settings: vault.settings };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vault-export.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Downloaded!');
}

/**
 * Open a file picker to import vault data from a JSON file.
 * Merges the imported users with the current vault, preferring higher nonces
 * (more recent password rotations). Triggers a background Nostr sync after import.
 */
function triggerImport() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
            const text = await file.text();
            const data = JSON.parse(text);
            if (!data.users || typeof data.users !== 'object') {
                showToast('Invalid vault file');
                return;
            }
            const siteCount = Object.values(data.users).reduce((n, u) => n + Object.keys(u).length, 0);
            if (!await showConfirm(`Import ${siteCount} site(s)? This will merge with your current vault.`)) return;
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            renderSiteList();
            await saveLocalNonceBackup();
            await autoSaveVault();
            backupToNostrDebounced();
            showToast(`Imported ${siteCount} site(s)!`);
        } catch (err) {
            // JSON parse errors are not sensitive
            console.error('triggerImport: failed to parse file:', err);
            showToast('Failed to import file');
        }
    };
    input.click();
}

// ============================================
// Settings
// ============================================

/**
 * Persist advanced settings (hash length, debug mode) and return to the settings screen.
 * Clamps hashLength to the range [8, 64].
 */
async function saveAdvancedSettings() {
    const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
    vault.settings.hashLength = Math.max(8, Math.min(64, len));
    vault.settings.debugMode = debugMode;
    await saveLocalNonceBackup();
    await autoSaveVault();
    backupToNostrDebounced();
    showToast('Settings saved');
    showScreen('settingsScreen');
}

/**
 * Toggle debug mode on/off from the advanced settings toggle.
 * Syncs the local debugMode variable and vault.settings.debugMode.
 */
function toggleDebugMode() {
    debugMode = document.getElementById('debugModeToggle').checked;
    vault.settings.debugMode = debugMode;
    // Debug mode is a UI preference — no need to backup to relays for this change
}

/**
 * Encode a Nostr event ID and optional relay hints as a bech32 nevent string.
 * Used for generating njump.me debug links.
 *
 * @param {string}   eventId        - Hex Nostr event ID.
 * @param {string[]} [relays=[]]    - Relay URLs to embed as hints (max 2).
 * @returns {string|null} bech32 nevent string, or null on error.
 */
function encodeNevent(eventId, relays = []) {
    const { nip19 } = window.NostrTools;
    try {
        return nip19.neventEncode({ id: eventId, relays: relays.slice(0, 2) });
    } catch (e) {
        return null;
    }
}

/**
 * Display the vault's seed phrase in the view seed screen.
 * Shows a toast if the seed phrase is not available (e.g. legacy unlock).
 */
async function showSeedPhrase() {
    let seedPhrase = vault.seedPhrase;
    if (invoke) {
        try { seedPhrase = await invoke('cmd_get_seed_phrase'); } catch (_) { seedPhrase = ''; }
    }
    if (!seedPhrase) {
        showToast('Seed phrase not available (unlocked from legacy storage)');
        return;
    }

    const grid = document.getElementById('viewSeedGrid');
    grid.innerHTML = '';

    seedPhrase.split(' ').forEach((word, i) => {
        const div = document.createElement('div');
        div.className = 'seed-word';
        div.innerHTML = `<span>${i + 1}.</span>${word}`;
        grid.appendChild(div);
    });

    showScreen('viewSeedScreen');
}

/**
 * Copy the vault's seed phrase to the clipboard and show a confirmation toast.
 */
async function copySeedPhrase() {
    const seedPhrase = invoke ? await invoke('cmd_get_seed_phrase') : vault.seedPhrase;
    navigator.clipboard.writeText(seedPhrase).then(() => {
        showToast('Seed phrase copied — clipboard clears in 15s');
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
            clipboardClearTimer = null;
        }, 15000);
    });
}

// ============================================
// Nostr Key Helpers
// ============================================

/**
 * Derive the Nostr (sk, pk) key pair from the vault's private key.
 * The Nostr secret key is SHA-256(vault.privateKey) as a hex string.
 *
 * @returns {Promise<{sk: string, pk: string}>}
 *   sk: hex Nostr secret key
 *   pk: hex Nostr public key
 */
async function getNostrKeyPair() {
    if (invoke) {
        // In Tauri mode, sk stays in Rust — only return pk
        const pk = await invoke('cmd_get_nostr_pubkey');
        return { sk: null, pk };
    }
    // Use NIP-06 derived keys if available, otherwise fall back to legacy SHA-256
    if (nostrKeys && nostrKeys.hex) {
        const { getPublicKey } = window.NostrTools;
        return { sk: nostrKeys.hex, pk: getPublicKey(nostrKeys.hex) };
    }
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const hashBytes = new Uint8Array(hashBuffer);
    const sk = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    hashBytes.fill(0);
    const pk = getPublicKey(sk);
    return { sk, pk };
}

/**
 * Get legacy Nostr key pair (SHA-256 of vault private key).
 * Used for fallback backup restoration from pre-NIP-06 backups.
 */
async function getLegacyNostrKeyPair() {
    if (invoke) {
        // In Tauri mode, sk stays in Rust — only return pk
        const pk = await invoke('cmd_get_legacy_nostr_pubkey');
        return { sk: null, pk };
    }
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const hashBytes = new Uint8Array(hashBuffer);
    const sk = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    hashBytes.fill(0);
    const pk = getPublicKey(sk);
    return { sk, pk };
}

/**
 * Connect to a Nostr relay with a configurable timeout.
 * Logs connection attempt and outcome via debugLog.
 *
 * @param {string} url                  - WebSocket URL of the relay.
 * @param {number} [timeoutMs=5000]     - Milliseconds before the connection attempt times out.
 * @returns {Promise<object>} Resolved relay object (from nostr-tools relayInit).
 * @throws {string} 'timeout' if the relay does not connect within timeoutMs.
 * @throws {*} Relay error event if the connection fails.
 */
async function connectRelay(url, timeoutMs = 5000) {
    const { relayInit } = window.NostrTools;
    debugLog(`connectRelay: attempting ${url} (timeout ${timeoutMs}ms)`);
    const relay = relayInit(url);
    await new Promise((resolve, reject) => {
        const t = setTimeout(() => {
            debugLog(`connectRelay: timeout — ${url}`);
            relay.close();
            reject('timeout');
        }, timeoutMs);
        relay.on('connect', () => {
            clearTimeout(t);
            debugLog(`connectRelay: connected — ${url}`);
            resolve();
        });
        relay.on('error', (err) => {
            clearTimeout(t);
            debugLog(`connectRelay: error — ${url}`, err);
            relay.close();
            reject(err);
        });
        relay.connect();
    });
    return relay;
}

/**
 * Subscribe to a relay with given filters and collect all received events.
 * Resolves when EOSE (End of Stored Events) is received or the timeout expires.
 *
 * @param {object}   relay          - Connected relay object from connectRelay().
 * @param {object[]} filters        - Array of Nostr filter objects.
 * @param {number}   [timeoutMs=8000] - Maximum wait time in milliseconds.
 * @returns {Promise<object[]>} Array of Nostr event objects.
 */
function subscribeAndCollect(relay, filters, timeoutMs = 8000) {
    return new Promise(resolve => {
        const events = [];
        const sub = relay.sub(filters);
        const t = setTimeout(() => { sub.unsub(); resolve(events); }, timeoutMs);
        sub.on('event', e => events.push(e));
        sub.on('eose', () => { clearTimeout(t); sub.unsub(); resolve(events); });
    });
}

// ============================================
// Double-Encrypted Backup — Layer 1: AES-256-GCM via WebCrypto
// ============================================

const BACKUP_PASSWORD_ITERATIONS = 600000; // OWASP 2023 recommendation for SHA-256
const BACKUP_ENCRYPTED_VERSION = 2;        // Version marker for double-encrypted backups

/**
 * Derive an AES-256 key from a user password using PBKDF2.
 * Uses the npub as salt (unique per vault, not secret).
 *
 * @param {string} password - User-chosen backup password.
 * @param {string} npubHex  - Hex-encoded Nostr public key (used as salt).
 * @returns {Promise<CryptoKey>} AES-256-GCM key.
 */
async function deriveBackupKey(password, npubHex) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode(npubHex),
            iterations: BACKUP_PASSWORD_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt vault data with AES-256-GCM using a password-derived key (Layer 1).
 * Returns a versioned envelope that can be detected on restore.
 *
 * @param {string} plaintext - JSON string of vault data.
 * @param {string} password  - User-chosen backup password.
 * @param {string} npubHex   - Hex Nostr public key (PBKDF2 salt).
 * @returns {Promise<object>} Envelope: { v, iv, ciphertext } (base64-encoded fields).
 */
async function encryptWithBackupPassword(plaintext, password, npubHex) {
    const key = await deriveBackupKey(password, npubHex);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
    const enc = new TextEncoder();
    const ciphertextBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(plaintext)
    );
    // Encode IV and ciphertext (includes auth tag) as base64
    const result = {
        v: BACKUP_ENCRYPTED_VERSION,
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf)))
    };
    iv.fill(0);
    return result;
}

/**
 * Decrypt a Layer 1 envelope using the backup password.
 *
 * @param {object} envelope  - { v, iv, ciphertext } from encryptWithBackupPassword.
 * @param {string} password  - User-chosen backup password.
 * @param {string} npubHex   - Hex Nostr public key (PBKDF2 salt).
 * @returns {Promise<string>} Decrypted plaintext JSON string.
 * @throws {DOMException} If password is incorrect (auth tag mismatch).
 */
async function decryptWithBackupPassword(envelope, password, npubHex) {
    const key = await deriveBackupKey(password, npubHex);
    const iv = Uint8Array.from(atob(envelope.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(envelope.ciphertext), c => c.charCodeAt(0));
    const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );
    iv.fill(0);
    ciphertext.fill(0);
    return new TextDecoder().decode(plaintextBuf);
}

/**
 * Check if a decrypted NIP-44 payload is a double-encrypted (v2) envelope.
 *
 * @param {string} decryptedContent - The NIP-44 decrypted string.
 * @returns {object|null} Parsed envelope if v2, null otherwise.
 */
function parseDoubleEncryptedEnvelope(decryptedContent) {
    try {
        const parsed = JSON.parse(decryptedContent);
        if (parsed && parsed.v === BACKUP_ENCRYPTED_VERSION && parsed.iv && parsed.ciphertext) {
            return parsed;
        }
    } catch (_) {}
    return null;
}

// ============================================
// Local Storage Encryption (Web Crypto API)
// ============================================

const LOCAL_ENCRYPT_VERSION = 3;
const LOCAL_ENCRYPT_ITERATIONS = 600000;

let _cachedLocalKey = null;
let _cachedLocalSalt = null;
let _cachedLocalPassphrase = null;

/**
 * Derive an AES-256-GCM key from a passphrase using PBKDF2.
 */
async function deriveLocalKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: LOCAL_ENCRYPT_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt plaintext with AES-256-GCM using PBKDF2-derived key.
 * Returns a versioned JSON envelope string for localStorage.
 */
async function encryptLocal(plaintext, passphrase) {
    let key, salt;
    if (_cachedLocalKey && _cachedLocalSalt && _cachedLocalPassphrase === passphrase) {
        key = _cachedLocalKey;
        salt = _cachedLocalSalt;
    } else {
        salt = crypto.getRandomValues(new Uint8Array(16));
        key = await deriveLocalKey(passphrase, salt);
        _cachedLocalKey = key;
        _cachedLocalSalt = salt;
        _cachedLocalPassphrase = passphrase;
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertextBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
    );
    const result = JSON.stringify({
        v: LOCAL_ENCRYPT_VERSION,
        salt: btoa(String.fromCharCode(...salt)),
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf)))
    });
    iv.fill(0);
    return result;
}

/**
 * Decrypt a v3 (Web Crypto) envelope from localStorage.
 */
async function decryptLocal(envelopeStr, passphrase) {
    const envelope = JSON.parse(envelopeStr);
    if (envelope.v !== LOCAL_ENCRYPT_VERSION) throw new Error('unknown encryption version');
    const salt = Uint8Array.from(atob(envelope.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(envelope.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(envelope.ciphertext), c => c.charCodeAt(0));

    let key;
    if (_cachedLocalKey && _cachedLocalSalt && _cachedLocalPassphrase === passphrase &&
        salt.length === _cachedLocalSalt.length && salt.every((b, i) => b === _cachedLocalSalt[i])) {
        key = _cachedLocalKey;
    } else {
        key = await deriveLocalKey(passphrase, salt);
        _cachedLocalKey = key;
        _cachedLocalSalt = salt;
        _cachedLocalPassphrase = passphrase;
    }

    const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, key, ciphertext
    );
    iv.fill(0);
    ciphertext.fill(0);
    return new TextDecoder().decode(plaintextBuf);
}

/**
 * Detect whether a stored string is a v3 (Web Crypto) envelope or legacy CryptoJS.
 */
function isWebCryptoEnvelope(stored) {
    try {
        const parsed = JSON.parse(stored);
        return parsed && parsed.v === LOCAL_ENCRYPT_VERSION && parsed.salt && parsed.iv && parsed.ciphertext;
    } catch {
        return false;
    }
}

// ============================================
// Backup Password UI Helpers
// ============================================

/**
 * Show a modal dialog and return a Promise that resolves with the result.
 * Used for backup password prompts (set and enter).
 *
 * @param {'set'|'enter'|'change'} mode - Dialog mode.
 * @returns {Promise<string|null>} The password entered, or null if cancelled.
 */
function showBackupPasswordModal(mode) {
    return new Promise((resolve) => {
        const modal = document.getElementById('backupPasswordModal');
        const title = document.getElementById('bpModalTitle');
        const desc = document.getElementById('bpModalDesc');
        const pass1 = document.getElementById('bpPass1');
        const pass2Group = document.getElementById('bpPass2Group');
        const pass2 = document.getElementById('bpPass2');
        const btnConfirm = document.getElementById('bpModalConfirm');
        const btnCancel = document.getElementById('bpModalCancel');

        pass1.value = '';
        pass2.value = '';

        if (mode === 'set' || mode === 'change') {
            title.textContent = mode === 'change' ? 'Change Backup Password' : 'Set Backup Password';
            desc.textContent = 'This password adds a second layer of encryption to your cloud backup. It is never stored anywhere — remember it or your backup is unrecoverable.';
            pass2Group.classList.remove('hidden');
            pass1.placeholder = 'Backup password';
            btnConfirm.textContent = mode === 'change' ? 'Change & Re-publish' : 'Set Password & Backup';
        } else {
            title.textContent = 'Enter Backup Password';
            desc.textContent = 'This backup is double-encrypted. Enter the backup password you set when creating it.';
            pass2Group.classList.add('hidden');
            pass1.placeholder = 'Backup password';
            btnConfirm.textContent = 'Decrypt';
        }

        modal.classList.remove('hidden');
        setTimeout(() => pass1.focus(), 100);

        function cleanup() {
            modal.classList.add('hidden');
            btnConfirm.removeEventListener('click', onConfirm);
            btnCancel.removeEventListener('click', onCancel);
            pass1.removeEventListener('keydown', onKeydown);
            pass2.removeEventListener('keydown', onKeydown);
        }

        function onConfirm() {
            const p1 = pass1.value;
            if (!p1) { showToast('Password required'); return; }
            if ((mode === 'set' || mode === 'change') && p1.length < MIN_PASSWORD_LENGTH) {
                showToast(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
                return;
            }
            if ((mode === 'set' || mode === 'change') && p1 !== pass2.value) {
                showToast('Passwords don\'t match');
                return;
            }
            cleanup();
            resolve(p1);
        }

        function onCancel() {
            cleanup();
            resolve(null);
        }

        function onKeydown(e) {
            if (e.key === 'Enter') onConfirm();
            if (e.key === 'Escape') onCancel();
        }

        btnConfirm.addEventListener('click', onConfirm);
        btnCancel.addEventListener('click', onCancel);
        pass1.addEventListener('keydown', onKeydown);
        pass2.addEventListener('keydown', onKeydown);
    });
}

// ============================================
// Nostr Backup — NIP-44 + kind:30078 (with NIP-04 legacy fallback)
// ============================================
const BACKUP_D_TAG = 'vault-backup';

/**
 * Encrypt and publish vault data to all configured Nostr relays.
 *
 * Double-encryption flow:
 * NIP-44 self-encryption using the seed-derived Nostr key pair.
 * Falls back gracefully: success on any relay is sufficient.
 *
 * @param {boolean} [silent=false] - If true, suppresses toast notifications.
 * @returns {Promise<void>}
 */
async function backupToNostr(silent = false) {
    const { nip44, getEventHash, signEvent, getPublicKey } = window.NostrTools;

    console.log(`[relay] backupToNostr: called (silent=${silent})`);

    if (!_vaultInitialized && !vault.privateKey) {
        console.log('[relay] backupToNostr: vault not initialized, aborting');
        if (!silent) showToast('Vault not initialized');
        return;
    }

    try {
        let event;
        const vaultData = JSON.stringify({ users: vault.users, settings: vault.settings });

        if (invoke) {
            // Tauri mode: encrypt with JS NIP-44 (for cross-implementation compat), sign in Rust
            const pk = await invoke('cmd_get_nostr_pubkey');
            const encrypted = await invoke('cmd_nip44_self_encrypt', { plaintext: vaultData });
            const unsignedEvent = {
                kind: 30078,
                pubkey: pk,
                created_at: Math.floor(Date.now() / 1000),
                tags: [["d", BACKUP_D_TAG]],
                content: encrypted,
            };
            const signedJson = await invoke('cmd_sign_nostr_event', { eventJson: JSON.stringify(unsignedEvent) });
            event = JSON.parse(signedJson);
        } else {
            const { sk, pk } = await getNostrKeyPair();
            const sharedSecret = nip44.getSharedSecret(sk, pk);
            const encrypted = nip44.encrypt(sharedSecret, vaultData);
            event = {
                kind: 30078,
                pubkey: pk,
                created_at: Math.floor(Date.now() / 1000),
                tags: [["d", BACKUP_D_TAG]],
                content: encrypted,
            };
            event.id = getEventHash(event);
            event.sig = await signEvent(event, sk);
        }

        console.log(`[relay] backupToNostr: starting parallel publish to ${RELAYS.length} relays`);
        setRelayStatus('syncing');

        if (debugMode) {
            const nevent = encodeNevent(event.id, RELAYS);
            const link = nevent ? `https://njump.me/${nevent}` : null;
            console.log('[debug] [relay] Event created & broadcasting:', {
                id: event.id,
                kind: event.kind,
                pubkey: event.pubkey,
                created_at: event.created_at,
                tags: event.tags,
                link
            });
        }

        let success = 0;
        let successRelays = [];
        const results = await Promise.allSettled(RELAYS.map(async (url) => {
            const relay = await connectRelay(url);
            await Promise.race([
                relay.publish(event),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
            ]);
            relay.close();
            return url;
        }));
        for (const r of results) {
            if (r.status === 'fulfilled') {
                success++;
                successRelays.push(r.value);
                debugLog(`backupToNostr: published to ${r.value}`);
            } else {
                debugLog(`backupToNostr: relay failed:`, r.reason);
            }
        }

        debugLog(`backupToNostr: succeeded on ${success}/${RELAYS.length} relays`, successRelays);

        if (success > 0) {
            vault.settings.lastBackupFailed = false;
            updateBackupWarningIndicator();
            setRelayStatus('synced');
            if (!silent) showToast(`Backed up to ${success} relays`);

            if (debugMode) {
                const nevent = encodeNevent(event.id, successRelays);
                if (nevent) {
                    const link = `https://njump.me/${nevent}`;
                    setTimeout(async () => {
                        if (await showConfirm(`Debug: View event on njump.me?\n\n${event.id.slice(0, 32)}...`)) {
                            window.open(link, '_blank');
                        }
                    }, 500);
                }
            }
        } else {
            vault.settings.lastBackupFailed = true;
            updateBackupWarningIndicator();
            setRelayStatus('failed');
            if (!silent) showToast('Backup failed');
        }
    } catch (e) {
        debugLog('backupToNostr: unexpected error:', e);
        setRelayStatus('failed');
        if (!silent) showToast('Backup error');
    }
}

/**
 * Decrypt a backup event, auto-detecting format:
 *   1. NIP-44 decrypt (kind:30078) or NIP-04 decrypt (legacy kind:1)
 *   2. Check if inner payload is a v2 double-encrypted envelope
 *   3. If v2: prompt for backup password and AES-256-GCM decrypt
 *   4. If plain JSON: return directly (legacy single-layer)
 *
 * @param {object}  event                - Nostr event object with kind and content.
 * @param {string}  sk                   - Hex Nostr secret key.
 * @param {string}  pk                   - Hex Nostr public key.
 * @param {boolean} [interactive=true]   - If true, prompt user for backup password.
 *                                         If false and password is needed, throws.
 * @returns {Promise<string>} Decrypted plaintext JSON string.
 */
async function decryptBackupEvent(event, sk, pk, interactive = true, useLegacy = false) {
    let layer2Decrypted;

    if (invoke) {
        // Tauri mode: all decryption happens in Rust (secret keys never leave Rust)
        if (event.kind === 30078) {
            const cmd = useLegacy ? 'cmd_nip44_legacy_decrypt' : 'cmd_nip44_self_decrypt';
            layer2Decrypted = await invoke(cmd, { ciphertext: event.content });
        } else {
            const cmd = useLegacy ? 'cmd_nip04_legacy_decrypt' : 'cmd_nip04_decrypt';
            layer2Decrypted = await invoke(cmd, { ciphertext: event.content, pubkey: event.pubkey });
        }
    } else {
        const { nip44, nip04 } = window.NostrTools;
        if (event.kind === 30078) {
            const sharedSecret = nip44.getSharedSecret(sk, pk);
            layer2Decrypted = nip44.decrypt(sharedSecret, event.content);
        } else {
            layer2Decrypted = await nip04.decrypt(sk, event.pubkey, event.content);
        }
    }

    // Check for double-encrypted v2 envelope
    const envelope = parseDoubleEncryptedEnvelope(layer2Decrypted);
    if (!envelope) {
        // Legacy single-layer backup — return as-is
        return layer2Decrypted;
    }

    // Legacy double-encrypted backup: need backup password to decrypt Layer 1
    let backupPwd = null;
    if (interactive) {
        backupPwd = await showBackupPasswordModal('enter');
        if (!backupPwd) throw new Error('Backup password required but cancelled');
    }
    if (!backupPwd) {
        throw new Error('Double-encrypted backup requires password');
    }

    try {
        const decrypted = await decryptWithBackupPassword(envelope, backupPwd, pk);
        return decrypted;
    } catch (e) {
        // Auth tag mismatch = wrong password
        if (interactive) {
            showToast('Wrong backup password');
        }
        throw new Error('Backup password incorrect');
    }
}

/**
 * Restore vault data from the latest Nostr backup event with user feedback.
 * Queries all configured relays for the latest backup (kind:30078 or legacy kind:1),
 * decrypts it, merges into the vault, and saves a local encrypted backup.
 *
 * Logs which relays returned events via debugLog.
 *
 * @returns {Promise<void>}
 */
async function restoreFromNostr() {
    if (!_vaultInitialized && !vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }

    try {
        const { sk, pk } = await getNostrKeyPair();

        async function fetchLatest(authorPk) {
            let latest = null;
            for (const url of RELAYS) {
                try {
                    const relay = await connectRelay(url);
                    const events = await subscribeAndCollect(relay, [
                        { kinds: [30078], authors: [authorPk], "#d": [BACKUP_D_TAG], limit: 1 },
                        { kinds: [1], authors: [authorPk], "#t": ["nostr-pwd-backup"], limit: 1 }
                    ]);
                    relay.close();
                    if (events.length > 0) debugLog(`restoreFromNostr: ${url} returned ${events.length} event(s)`);
                    for (const e of events) {
                        if (!latest || e.created_at > latest.created_at) latest = e;
                    }
                } catch (e) {
                    console.error(`restoreFromNostr: relay error [${url}]`, e);
                }
            }
            return latest;
        }

        // Try NIP-06 key first
        let latest = await fetchLatest(pk);
        let usedLegacy = false, legacySk, legacyPk;

        if (!latest) {
            // Fallback: try legacy SHA-256 key
            const legacy = await getLegacyNostrKeyPair();
            if (legacy.pk !== pk) {
                debugLog('restoreFromNostr: trying legacy key fallback...');
                latest = await fetchLatest(legacy.pk);
                if (latest) { usedLegacy = true; legacySk = legacy.sk; legacyPk = legacy.pk; }
            }
        }

        if (latest) {
            const decryptSk = usedLegacy ? legacySk : sk;
            const decryptPk = usedLegacy ? legacyPk : pk;
            const decrypted = await decryptBackupEvent(latest, decryptSk, decryptPk, true, usedLegacy);
            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            await saveLocalNonceBackup();
            await autoSaveVault();
            if (usedLegacy) {
                showToast('Found backup from previous version — upgrading key derivation');
                backupToNostrDebounced();
            } else {
                showToast('Restored from Nostr!');
            }
            renderSiteList();
        } else {
            showToast('No backup found');
        }
    } catch (e) {
        if (e.message && e.message.includes('cancelled')) {
            showToast('Restore cancelled');
        } else {
            console.error('restoreFromNostr: error:', e);
            showToast(`Restore error: ${e.message || e}`);
        }
    }
}

/**
 * Fetch and display backup history from Nostr relays.
 * Shows all backup events (kind:30078 + legacy kind:1) sorted by timestamp.
 * Tapping a history item calls restoreFromId() to restore from that specific event.
 * Logs relay query results via debugLog.
 *
 * @returns {Promise<void>}
 */
async function openNostrHistory() {
    if (!_vaultInitialized && !vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }

    const container = document.getElementById('nostrHistoryContainer');
    container.innerHTML = '<p class="text-muted">Loading...</p>';
    container.classList.remove('hidden');

    try {
        const { sk, pk } = await getNostrKeyPair();

        const allEvents = [];
        // Include legacy key author so history shows pre-NIP-06 backups too
        const legacyKeys = await getLegacyNostrKeyPair();
        const authors = [pk];
        if (legacyKeys.pk !== pk) authors.push(legacyKeys.pk);

        for (const url of RELAYS) {
            try {
                const relay = await connectRelay(url);

                // Fetch both new and legacy backup events from both key identities
                const events = await subscribeAndCollect(relay, [
                    { kinds: [30078], authors, "#d": [BACKUP_D_TAG] },
                    { kinds: [1], authors, "#t": ["nostr-pwd-backup"] }
                ]);

                relay.close();

                debugLog(`openNostrHistory: ${url} returned ${events.length} event(s)`);
                events.forEach(e => allEvents.push({ ...e, relay: url }));
            } catch (e) {
                console.error(`openNostrHistory: relay error [${url}]`, e);
            }
        }

        // Deduplicate by event id and sort newest-first
        const unique = [...new Map(allEvents.map(e => [e.id, e])).values()]
            .sort((a, b) => b.created_at - a.created_at);

        debugLog(`openNostrHistory: ${unique.length} unique event(s) found`);

        if (unique.length === 0) {
            container.innerHTML = '<p class="text-muted">No backups found</p>';
            return;
        }

        container.innerHTML = `<h3 class="mb-8">${unique.length} backup(s)</h3>` +
            unique.map(e => {
                const kindLabel = e.kind === 30078 ? '🔒 NIP-44' : '⚠️ NIP-04 (legacy)';
                const nevent = encodeNevent(e.id, [e.relay]);
                const debugLink = debugMode && nevent
                    ? `<a class="debug-link" href="https://njump.me/${nevent}" target="_blank" data-debug-link="true">🔗 njump.me/${nevent.slice(0, 20)}...</a>`
                    : '';
                return `
                <div class="site-item" data-restore-id="${e.id}" data-restore-kind="${e.kind}">
                    <div class="site-info">
                        <div class="site-name">${new Date(e.created_at * 1000).toLocaleString()}</div>
                        <div class="site-user">${kindLabel} · ${e.id.slice(0, 16)}...</div>
                        ${debugLink}
                    </div>
                </div>
            `}).join('');

        // Bind event delegation for history items
        container.querySelectorAll('[data-restore-id]').forEach(item => {
            item.addEventListener('click', (e) => {
                // Don't trigger restore when clicking debug links
                if (e.target.closest('[data-debug-link]')) return;
                restoreFromId(item.dataset.restoreId, parseInt(item.dataset.restoreKind));
            });
        });
    } catch (e) {
        // May include key material context — guard
        debugLog('openNostrHistory: error:', e);
        container.innerHTML = '<p class="text-muted">Error loading history</p>';
    }
}

/**
 * Restore the vault from a specific Nostr event by ID.
 * Queries relays until the event is found, decrypts it, and applies it to the vault.
 * After a successful restore, saves a local encrypted backup.
 *
 * @param {string} eventId   - Hex event ID to fetch.
 * @param {number} eventKind - Event kind (30078 for NIP-44, 1 for legacy NIP-04).
 * @returns {Promise<void>}
 */
async function restoreFromId(eventId, eventKind) {
    try {
        const { sk, pk } = await getNostrKeyPair();

        let found = null;

        for (const url of RELAYS) {
            if (found) break;
            try {
                const relay = await connectRelay(url);
                const events = await subscribeAndCollect(relay, [{ ids: [eventId] }], 5000);
                relay.close();
                if (events.length > 0) {
                    debugLog(`restoreFromId: found event ${eventId.slice(0, 16)}... on ${url}`);
                    found = events[0];
                } else {
                    debugLog(`restoreFromId: event not found on ${url}`);
                }
            } catch (e) {
                console.error(`restoreFromId: relay error [${url}]`, e);
            }
        }

        if (found) {
            // Try NIP-06 key first, then legacy
            let decrypted;
            try {
                decrypted = await decryptBackupEvent(found, sk, pk, true, false);
            } catch (e1) {
                const legacy = await getLegacyNostrKeyPair();
                if (legacy.pk !== pk) {
                    debugLog('restoreFromId: NIP-06 key failed, trying legacy...');
                    decrypted = await decryptBackupEvent(found, legacy.sk, legacy.pk, true, true);
                } else {
                    throw e1;
                }
            }
            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            await saveLocalNonceBackup();
            await autoSaveVault();
            showToast('Restored!');
            showScreen('mainScreen');
        } else {
            showToast('Backup not found');
        }
    } catch (e) {
        if (e.message && e.message.includes('cancelled')) {
            showToast('Restore cancelled');
        } else {
            console.error('restoreFromId: error:', e);
            showToast(`Restore error: ${e.message || e}`);
        }
    }
}

// ============================================
// Seed Phrase Autocomplete
// ============================================

/**
 * Attach BIP39 autocomplete to any input or textarea element.
 * Each call creates isolated state so multiple inputs can have independent suggestions.
 *
 * @param {HTMLInputElement|HTMLTextAreaElement} inputEl
 * @param {HTMLElement} suggestionsEl - Container to render suggestion items into.
 * @param {Object} [options]
 * @param {boolean} [options.singleWord] - Treat entire value as one word (for single-word inputs).
 * @param {Function} [options.onWordCountUpdate] - Called with current word count on input.
 * @param {Function} [options.onSelect] - Called after a suggestion is accepted.
 */
function attachBip39Autocomplete(inputEl, suggestionsEl, options = {}) {
    let activeSuggestionIndex = -1;
    let currentSuggestions = [];

    function getTypedWord() {
        if (options.singleWord) return inputEl.value.trim().toLowerCase();
        const cursorPos = inputEl.selectionStart;
        const beforeCursor = inputEl.value.slice(0, cursorPos);
        const match = beforeCursor.match(/[a-z]+$/i);
        return match ? match[0].toLowerCase() : '';
    }

    function render(typed) {
        suggestionsEl.innerHTML = currentSuggestions.map((word, i) => {
            const matchPart = word.slice(0, typed.length);
            const restPart = word.slice(typed.length);
            return `<div class="seed-suggestion ${i === activeSuggestionIndex ? 'active' : ''}"
                         data-suggestion="${word}">
                <span class="seed-suggestion-match">${matchPart}</span>${restPart}
            </div>`;
        }).join('');

        suggestionsEl.querySelectorAll('[data-suggestion]').forEach(el => {
            // Prevent blur on the input so the click can fire (critical on mobile)
            el.addEventListener('mousedown', e => e.preventDefault());
            el.addEventListener('click', () => selectWord(el.dataset.suggestion));
        });
    }

    function selectWord(word) {
        if (options.singleWord) {
            inputEl.value = word;
        } else {
            const cursorPos = inputEl.selectionStart;
            const value = inputEl.value;
            const beforeCursor = value.slice(0, cursorPos);
            const match = beforeCursor.match(/[a-z]+$/i);
            const wordStart = match ? cursorPos - match[0].length : cursorPos;
            const newValue = value.slice(0, wordStart) + word + ' ' + value.slice(cursorPos);
            inputEl.value = newValue;
            const newCursorPos = wordStart + word.length + 1;
            inputEl.setSelectionRange(newCursorPos, newCursorPos);
        }

        inputEl.focus();
        suggestionsEl.classList.add('hidden');
        currentSuggestions = [];

        if (options.onWordCountUpdate && !options.singleWord) {
            const count = inputEl.value.trim().split(/\s+/).filter(w => w.length > 0).length;
            options.onWordCountUpdate(count);
        }
        if (options.onSelect) options.onSelect(word);
    }

    inputEl.addEventListener('input', () => {
        const currentWord = getTypedWord();

        if (options.onWordCountUpdate && !options.singleWord) {
            const count = inputEl.value.trim().split(/\s+/).filter(w => w.length > 0).length;
            options.onWordCountUpdate(count);
        }

        if (currentWord.length < 1) {
            suggestionsEl.classList.add('hidden');
            currentSuggestions = [];
            return;
        }

        currentSuggestions = words.filter(w => w.startsWith(currentWord)).slice(0, 6);

        if (currentSuggestions.length === 0 ||
            (currentSuggestions.length === 1 && currentSuggestions[0] === currentWord)) {
            suggestionsEl.classList.add('hidden');
            return;
        }

        activeSuggestionIndex = 0;
        render(currentWord);
        suggestionsEl.classList.remove('hidden');
    });

    inputEl.addEventListener('keydown', (event) => {
        if (suggestionsEl.classList.contains('hidden') || currentSuggestions.length === 0) return;

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            activeSuggestionIndex = (activeSuggestionIndex + 1) % currentSuggestions.length;
            render(getTypedWord());
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            activeSuggestionIndex = activeSuggestionIndex <= 0
                ? currentSuggestions.length - 1
                : activeSuggestionIndex - 1;
            render(getTypedWord());
        } else if (event.key === 'Tab' || event.key === 'Enter') {
            event.preventDefault();
            selectWord(currentSuggestions[activeSuggestionIndex]);
        } else if (event.key === 'Escape') {
            suggestionsEl.classList.add('hidden');
        }
    });

    // Dismiss suggestions when input loses focus (delayed so click/tap can fire first)
    inputEl.addEventListener('blur', () => {
        setTimeout(() => suggestionsEl.classList.add('hidden'), 200);
    });
}

// ============================================
// Inactivity Auto-Lock
// ============================================

/**
 * Reset the inactivity auto-lock timer.
 * Clears any existing timer and sets a new one to lock the vault after
 * INACTIVITY_TIMEOUT_MS milliseconds of inactivity. Only active when the vault
 * is unlocked (vault.privateKey is set).
 */
function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    // Lock vault after inactivity — with or without a master password.
    // No-password sessions are destroyed (the user accepted ephemerality).
    if (_vaultInitialized || vault.privateKey) {
        inactivityTimer = setTimeout(() => {
            lockVault(true);
        }, INACTIVITY_TIMEOUT_MS);
    }
}

let hiddenAt = null;

/**
 * Attach event listeners to reset the inactivity timer on user interaction
 * and to lock the vault if the tab has been hidden for too long.
 *
 * Visibility-based locking: if the tab is hidden for >= VISIBILITY_LOCK_MS,
 * the vault is locked when the user returns.
 */
function setupInactivityListeners() {
    const events = ['click', 'keydown', 'touchstart', 'scroll', 'mousemove'];
    events.forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer, { passive: true });
    });

    // Lock vault when tab is hidden for too long (e.g. user switches app).
    // No-password sessions are destroyed — the user accepted ephemerality.
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            hiddenAt = Date.now();
        } else if (hiddenAt && (_vaultInitialized || vault.privateKey)) {
            const elapsed = Date.now() - hiddenAt;
            hiddenAt = null;
            if (elapsed >= VISIBILITY_LOCK_MS) {
                lockVault(true);
            } else {
                resetInactivityTimer();
            }
        }
    });
}

// ============================================
// Keyboard Shortcuts
// ============================================

/**
 * Attach global keyboard shortcuts:
 *   Enter → submit/advance current screen
 *   Escape → navigate back (generate screen only)
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            // Don't interfere with textareas
            if (e.target.tagName === 'TEXTAREA') return;

            const screen = document.querySelector('.screen:not(.hidden)');
            if (!screen) return;

            switch (screen.id) {
                case 'unlockScreen':
                    e.preventDefault();
                    unlockVault();
                    break;
                case 'setMasterPasswordScreen':
                    e.preventDefault();
                    if (e.target.id === 'masterPass1') {
                        document.getElementById('masterPass2').focus();
                    } else {
                        setMasterPassword();
                    }
                    break;
                case 'verifySeedScreen':
                    e.preventDefault();
                    verifySeedBackup();
                    break;
                case 'restoreSeedScreen':
                    e.preventDefault();
                    restoreFromSeed();
                    break;
                case 'generateScreen':
                    if (e.target.id === 'genSite') {
                        e.preventDefault();
                        document.getElementById('genUser').focus();
                    } else if (e.target.id === 'genUser') {
                        e.preventDefault();
                        saveAndCopy();
                    } else if (e.target.tagName !== 'INPUT') {
                        e.preventDefault();
                        copyPassword();
                    }
                    break;
                case 'advancedScreen':
                    if (e.target.id === 'hashLengthSetting') {
                        e.preventDefault();
                        saveAdvancedSettings();
                    }
                    break;
            }
            return;
        }

        // Escape → back to site list (generate screen only)
        if (e.key === 'Escape') {
            const genScreen = document.getElementById('generateScreen');
            if (!genScreen.classList.contains('hidden') &&
                e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
                e.preventDefault();
                showScreen('mainScreen');
            }
        }
    });
}

// ============================================
// Init
// ============================================
document.addEventListener('DOMContentLoaded', async () => {
    // BIP39 wordlist integrity check — detect tampering
    const wlHash = Array.from(new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(words.join('\n')))
    )).map(b => b.toString(16).padStart(2, '0')).join('');
    if (wlHash !== '187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae') {
        document.body.innerHTML = '<h1 style="color:red;padding:2em">SECURITY ERROR: BIP39 wordlist integrity check failed. The application has been tampered with.</h1>';
        throw new Error('BIP39 wordlist integrity check failed');
    }

    setupInactivityListeners();
    setupKeyboardShortcuts();

    // Android back button support via browser history
    history.replaceState({ screen: 'welcomeScreen' }, '');
    window.addEventListener('popstate', (e) => {
        if (navigationStack.length > 1) {
            navigationStack.pop();
            const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
            showScreen(prev);
        }
    });

    // ── Delegated screen navigation ──
    document.addEventListener('click', (e) => {
        const screenEl = e.target.closest('[data-screen]');
        if (screenEl) {
            showScreen(screenEl.dataset.screen);
            return;
        }
        const backEl = e.target.closest('[data-action="back"]');
        if (backEl) {
            goBack();
            return;
        }
        const seedPhraseEl = e.target.closest('[data-action="showSeedPhrase"]');
        if (seedPhraseEl) {
            showSeedPhrase();
            return;
        }
    });

    // ── Delegated site list events ──
    document.getElementById('siteList').addEventListener('click', (e) => {
        const deleteBtn = e.target.closest('.btn-delete[data-delete-site]');
        if (deleteBtn) {
            e.stopPropagation();
            deleteSite(deleteBtn.dataset.deleteSite, deleteBtn.dataset.deleteUser);
            return;
        }
        const siteItem = e.target.closest('.site-item[data-site]');
        if (siteItem) {
            openSite(siteItem.dataset.site, siteItem.dataset.user, parseInt(siteItem.dataset.nonce));
        }
    });

    // ── Individual button bindings ──
    const btnBindings = {
        btnGenerateNewSeed: () => generateNewSeed(),
        btnConfirmSeedBackup: () => confirmSeedBackup(),
        btnVerifySeedBackup: () => verifySeedBackup(),
        btnRestoreFromSeed: () => restoreFromSeed(),
        btnUnlockVault: () => unlockVault(),
        btnLockVault: () => lockVault(),
        btnDecrementNonce: () => decrementNonce(),
        btnIncrementNonce: () => incrementNonce(),
        btnToggleVisibility: () => togglePasswordVisibility(),
        btnSaveAndCopy: () => saveAndCopy(),
        btnBackupToNostr: () => backupToNostr(),
        btnRestoreFromNostr: () => restoreFromNostr(),
        btnOpenNostrHistory: () => openNostrHistory(),
        btnSetMasterPassword: () => setMasterPassword(),
        btnSkipMasterPassword: () => skipMasterPassword(),
        noPasswordBadge: () => showScreen('setMasterPasswordScreen'),
        btnDeleteAllData: () => deleteAllData(),
        btnDeleteAllDataUnlock: () => deleteAllData(),
        btnDownloadData: () => downloadData(),
        btnTriggerImport: () => triggerImport(),
        btnSaveAdvancedSettings: () => saveAdvancedSettings(),
        btnCopySeedPhrase: () => copySeedPhrase(),
    };

    Object.entries(btnBindings).forEach(([id, handler]) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', handler);
    });

    // ── Input event listeners ──
    // Note: Enter key handling is done globally in setupKeyboardShortcuts()
    const restoreSeedInput = document.getElementById('restoreSeedInput');
    const seedSuggestions = document.getElementById('seedSuggestions');
    if (restoreSeedInput && seedSuggestions) {
        attachBip39Autocomplete(restoreSeedInput, seedSuggestions, {
            singleWord: false,
            onWordCountUpdate: (count) => {
                document.getElementById('wordCount').textContent = count;
            }
        });
    }

    const siteSearch = document.getElementById('siteSearch');
    if (siteSearch) {
        siteSearch.addEventListener('input', () => filterSites());
        siteSearch.addEventListener('keydown', (e) => handleSearchEnter(e));
    }

    function updateHashLength(delta) {
        const input = document.getElementById('hashLengthSetting');
        const display = document.getElementById('hashLengthDisplay');
        let val = Math.min(64, Math.max(8, (parseInt(input.value) || 16) + delta));
        input.value = val;
        display.textContent = val;
    }
    document.getElementById('btnDecrementHash')?.addEventListener('click', () => updateHashLength(-1));
    document.getElementById('btnIncrementHash')?.addEventListener('click', () => updateHashLength(1));

    const debugModeToggle = document.getElementById('debugModeToggle');
    if (debugModeToggle) {
        debugModeToggle.addEventListener('change', () => toggleDebugMode());
    }

    // ── Service worker registration ──
    if ('serviceWorker' in navigator && !window.__TAURI__) {
        navigator.serviceWorker.register('sw.js').catch(() => {});
    }

    // If a saved vault exists, go straight to unlock screen
    const hasVault = localStorage.getItem('vaultEncrypted') || localStorage.getItem('encryptedDataStorage');
    if (hasVault) showScreen('unlockScreen');
});
