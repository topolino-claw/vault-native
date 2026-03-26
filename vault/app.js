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

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const VISIBILITY_LOCK_MS = 2 * 60 * 1000; // 2 minutes hidden = lock
const MAX_UNLOCK_ATTEMPTS = 5;
const UNLOCK_LOCKOUT_MS = 30 * 1000; // 30 seconds
const DEFAULT_HASH_LENGTH = 16;

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
        }
    }

    // Screen-specific setup
    if (screenId === 'mainScreen') {
        renderSiteList();
    } else if (screenId === 'newWalletScreen') {
        generateNewSeed(true);
    } else if (screenId === 'backupScreen') {
        const statusEl = document.getElementById('backupPasswordStatus');
        if (statusEl) {
            const hasPassword = vault.settings.hasBackupPassword || false;
            statusEl.innerHTML = hasPassword
                ? '<span>🔒 Backup password: ✅ set</span>'
                : '<span>🔒 Backup password: not set</span>';
        }
    } else if (screenId === 'settingsScreen') {
        updateBackupWarningIndicator();
    } else if (screenId === 'advancedScreen') {
        document.getElementById('hashLengthSetting').value = vault.settings.hashLength || 16;
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
        mnemonic.push(words[parseInt(fullBinary.slice(i, i + 11), 2)]);
    }

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
    const nostrHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');

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
    return { privateKey: r.slice(0, 32), chainCode: r.slice(32) };
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
    return { privateKey: _secp256k1ModAdd(r.slice(0, 32), pk), chainCode: r.slice(32) };
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
    return { privateKey: _secp256k1ModAdd(r.slice(0, 32), pk), chainCode: r.slice(32) };
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
    // Hardened: 44', 1237', 0'
    for (const i of [44, 1237, 0]) {
        ({ privateKey: pk, chainCode: cc } = await _bip32HardChild(pk, cc, i));
    }
    // Non-hardened: 0, 0
    ({ privateKey: pk, chainCode: cc } = await _bip32NormalChild(pk, cc, 0));
    ({ privateKey: pk } = await _bip32NormalChild(pk, cc, 0));
    return Array.from(pk).map(b => b.toString(16).padStart(2, '0')).join('');
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
 * @returns {string} 64-character lowercase hex SHA-256 digest.
 */
function hash(text) {
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
    const entropy = hash(concat).substring(0, hashLength);
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
    if (!isInitial && vault.seedPhrase && vault.privateKey) {
        if (!confirm('Generate a new seed phrase? This will replace the current one.')) return;
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
function confirmSeedBackup() {
    // Setup verification
    const seedWords = vault.seedPhrase.split(' ');
    const indices = [];
    while (indices.length < 3) {
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
        div.innerHTML = `
            <label>Word #${i + 1}</label>
            <input type="text" class="verify-word" data-index="${i}" placeholder="Enter word ${i + 1}">
        `;
        container.appendChild(div);
    });

    // Bind Enter key on dynamically created verify inputs
    container.querySelectorAll('.verify-word').forEach(input => {
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') verifySeedBackup();
        });
    });

    showScreen('verifySeedScreen');
}

/**
 * Validate the user's seed verification inputs.
 * If all 3 words are correct, initialize the vault and proceed to the main screen.
 * On failure, highlights the incorrect fields and shows a toast.
 *
 * @returns {Promise<void>}
 */
async function verifySeedBackup() {
    const seedWords = vault.seedPhrase.split(' ');
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
        await initializeVault(vault.seedPhrase, passphrase);
        await checkForRemoteBackups();
        showScreen('mainScreen');
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
    showScreen('mainScreen');
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
    vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    vault.privateKey = await derivePrivateKey(vault.seedPhrase);
    nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, passphrase);
    vault.passphrase = passphrase;

    // Attempt to load local nonce backup as a low-priority seed.
    // Nostr data (fetched later in checkForRemoteBackups) will overwrite this.
    try {
        const localBackupRaw = localStorage.getItem('vaultNonceBackup');
        if (localBackupRaw) {
            debugLog('initializeVault: local nonce backup found, attempting merge');
            const decrypted = CryptoJS.AES.decrypt(localBackupRaw, vault.privateKey)
                .toString(CryptoJS.enc.Utf8);
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
            }
        }
    } catch (e) {
        // Non-fatal: corrupted or missing local backup — just ignore
        debugLog('initializeVault: could not read local backup:', e);
    }

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
        const { found, isLegacy } = await silentRestoreFromNostr();
        hideLoading();

        if (found) {
            showToast('Synced from cloud backup!');
            // If backup was single-layer (legacy), nudge user to set a backup password
            if (isLegacy && !vault.settings.hasBackupPassword) {
                showBackupPasswordNudge();
            }
            // If vault has a backup password but session cache is empty, prompt early
            // so silent backups don't pile up as pending
            if (vault.settings.hasBackupPassword && !_sessionBackupPassword) {
                const pwd = await showBackupPasswordModal('enter');
                if (pwd) {
                    _sessionBackupPassword = pwd;
                }
            }
        } else {
            showToast('Vault ready');
            // No backup on relays and no backup password set — nudge to set one
            if (!vault.settings.hasBackupPassword) {
                showBackupPasswordNudge();
            }
        }
    } catch (e) {
        console.error('Backup check failed:', e);
        hideLoading();
        showToast('Vault ready (offline)');
    }
}

/**
 * Show a non-blocking nudge banner suggesting the user set a backup password.
 * Shown once per session. Inserts a dismissible banner in the settings screen
 * and shows a brief actionable toast on the main screen.
 */
function showBackupPasswordNudge(pendingMsg) {
    if (_backupPasswordNudgeShown) return;
    _backupPasswordNudgeShown = true;

    // Show an actionable toast on the main screen
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.innerHTML = '';
    const text = document.createElement('span');
    text.textContent = pendingMsg || '🔒 Backup not password-protected. ';

    const btn = document.createElement('button');
    btn.textContent = 'Set now';
    btn.style.cssText = 'background:none;border:none;color:var(--accent,#7c5cff);cursor:pointer;text-decoration:underline;font-size:inherit;padding:0;margin-left:4px;';
    btn.addEventListener('click', async () => {
        toast.classList.remove('show');
        const mode = vault.settings.hasBackupPassword ? 'enter' : 'set';
        const pwd = await showBackupPasswordModal(mode);
        if (pwd) {
            _sessionBackupPassword = pwd;
            vault.settings.hasBackupPassword = true;
            if (_pendingBackupAfterPassword) {
                _pendingBackupAfterPassword = false;
                showToast('Syncing backup...');
                await backupToNostr(false, pwd);
            } else {
                showToast('Re-encrypting backup...');
                await backupToNostr(false, pwd);
            }
        }
    });

    toast.appendChild(text);
    toast.appendChild(btn);
    toast.classList.add('show');
    setTimeout(() => {
        if (toast.classList.contains('show')) {
            toast.classList.remove('show');
            toast.innerHTML = ''; // Reset for normal showToast usage
        }
    }, 10000);
}

/** Whether the backup password nudge has been shown this session. @type {boolean} */
let _backupPasswordNudgeShown = false;

/** Whether a backup is pending because no backup password was available. @type {boolean} */
let _pendingBackupAfterPassword = false;

/**
 * Silently attempt to restore vault data from Nostr relays without UI prompts.
 * Queries all configured relays for the latest backup event, decrypts it,
 * and merges users/settings into the current vault state.
 * After a successful restore, saves a local encrypted backup.
 *
 * @returns {Promise<{ found: boolean, isLegacy: boolean }>}
 *   found    — true if a backup was found and applied
 *   isLegacy — true if the backup was single-layer (no v2 envelope)
 */
async function silentRestoreFromNostr() {
    if (!vault.privateKey) return { found: false, isLegacy: false };

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
    async function tryApplyBackup(event, decryptSk, decryptPk) {
        try {
            const decrypted = await decryptBackupEvent(event, decryptSk, decryptPk, false);
            const data = JSON.parse(decrypted);
            vault.users = { ...vault.users, ...data.users };
            if (data.settings) {
                vault.settings = { ...vault.settings, ...data.settings };
                debugMode = vault.settings.debugMode || false;
            }
            saveLocalNonceBackup();
            return { found: true, isLegacy: !vault.settings.hasBackupPassword };
        } catch (e) {
            if (e.message && e.message.includes('password')) {
                try {
                    const decrypted = await decryptBackupEvent(event, decryptSk, decryptPk, true);
                    const data = JSON.parse(decrypted);
                    vault.users = { ...vault.users, ...data.users };
                    if (data.settings) {
                        vault.settings = { ...vault.settings, ...data.settings };
                        debugMode = vault.settings.debugMode || false;
                    }
                    saveLocalNonceBackup();
                    return { found: true, isLegacy: false };
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
        const result = await tryApplyBackup(latest, sk, pk);
        if (result) return result;
    }

    // 2. Legacy fallback: try SHA-256 derived key if no NIP-06 backup found
    if (!vault.passphrase || vault.passphrase === '') {
        const legacy = await getLegacyNostrKeyPair();
        if (legacy.pk !== pk) { // Only if legacy key differs from current
            debugLog('silentRestoreFromNostr: trying legacy key fallback');
            latest = await fetchLatestFromRelays(legacy.pk);
            if (latest) {
                const result = await tryApplyBackup(latest, legacy.sk, legacy.pk);
                if (result) {
                    showToast('Legacy backup found — upgrading to NIP-06 key');
                    // Re-publish with new NIP-06 key
                    backupToNostrDebounced();
                    return result;
                }
            }
        }
    }

    return { found: false, isLegacy: false };
}

/**
 * Lock the vault, clearing all sensitive state from memory.
 * Clears the clipboard, cancels timers, resets navigation, and shows the welcome screen.
 *
 * @param {boolean} [skipConfirm=false] - If true, skip the confirmation dialog.
 */
function lockVault(skipConfirm = false) {
    if (!skipConfirm && vault.privateKey) {
        if (!confirm('Lock vault? Make sure you have your seed phrase saved.')) return;
    }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
    // Wipe all sensitive data from memory
    vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16 } };
    nostrKeys = { nsec: '', npub: '' };
    _sessionBackupPassword = null;
    navigationStack = ['welcomeScreen'];

    // Wipe all sensitive data from DOM
    document.querySelectorAll('input').forEach(el => { el.value = ''; });
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

    showScreen('welcomeScreen');
    showToast('Vault locked');
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
function saveLocalNonceBackup() {
    if (!vault.privateKey) return;
    try {
        const payload = JSON.stringify({ users: vault.users, settings: vault.settings });
        // Encrypt with the private key — only someone with the seed phrase can decrypt
        const encrypted = CryptoJS.AES.encrypt(payload, vault.privateKey).toString();
        localStorage.setItem('vaultNonceBackup', encrypted);
        debugLog('saveLocalNonceBackup: local backup saved');
    } catch (e) {
        // Non-fatal: if localStorage is full or unavailable, log and continue
        debugLog('saveLocalNonceBackup: failed to save local backup:', e);
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

/** Escape a string for safe use inside a JS string literal in an HTML attribute (onclick, etc.) */
function escapeJsString(str) {
    return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
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
function updatePassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();
    const strengthEl = document.getElementById('passwordStrength');

    if (!site || !user || !vault.privateKey) {
        document.getElementById('genPassword').textContent = '••••••••••••';
        if (strengthEl) strengthEl.textContent = '';
        return;
    }

    const hl = vault.settings.hashLength || DEFAULT_HASH_LENGTH;
    const pass = generatePassword(vault.privateKey, user, site, currentNonce, hl);

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
function copyPassword() {
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

    const pass = generatePassword(
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
    saveLocalNonceBackup();

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
function deleteSite(site, user) {
    if (!confirm(`Delete ${site} (${user})?`)) return;

    if (vault.users[user]) {
        delete vault.users[user][site];
        // Clean up empty user objects
        if (Object.keys(vault.users[user]).length === 0) {
            delete vault.users[user];
        }
    }

    showToast('Site deleted');
    renderSiteList();
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
    if (_backupDebounceTimer) clearTimeout(_backupDebounceTimer);
    _backupDebounceTimer = setTimeout(() => {
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

// ============================================
// Local Encryption
// ============================================

/**
 * Unlock the vault from a locally encrypted backup stored in localStorage.
 * Enforces rate limiting: after MAX_UNLOCK_ATTEMPTS failures, locks out for
 * UNLOCK_LOCKOUT_MS milliseconds.
 *
 * Supports both the new 'vaultEncrypted' storage key and the legacy
 * 'encryptedDataStorage' key for backwards compatibility.
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
        const key = hash(password);
        // Check both new and legacy storage keys for backwards compatibility
        let stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
        const legacy = JSON.parse(localStorage.getItem('encryptedDataStorage') || '{}');
        stored = { ...legacy, ...stored };
        const encrypted = stored[key];

        if (!encrypted) {
            unlockAttempts++;
            if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
                unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
                unlockAttempts = 0;
                showToast(`Too many attempts. Locked for 30s`);
            } else {
                showToast(`Wrong password (${MAX_UNLOCK_ATTEMPTS - unlockAttempts} attempts left)`);
            }
            return;
        }

        const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
        const data = JSON.parse(decrypted);

        // Handle both new format (users/settings/seedPhrase) and legacy format (privateKey/users)
        if (data.privateKey) {
            // Legacy format — privateKey was stored directly
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
        unlockAttempts = 0;

        resetInactivityTimer();
        showToast('Vault unlocked!');
        showScreen('mainScreen');
    } catch (e) {
        // Decrypt errors may include stack traces — guard with debugLog
        debugLog('unlockVault error:', e);
        unlockAttempts++;
        if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
            unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
            unlockAttempts = 0;
            showToast(`Too many attempts. Locked for 30s`);
        } else {
            showToast('Invalid password');
        }
    }
}

/**
 * Encrypt and save the vault to localStorage with a user-chosen password.
 * The vault is keyed by SHA-256(password), allowing multiple password slots.
 * After saving, triggers a background Nostr sync.
 */
function saveEncrypted() {
    const pass1 = document.getElementById('encryptPass1').value;
    const pass2 = document.getElementById('encryptPass2').value;

    if (!pass1 || pass1 !== pass2) {
        showToast('Passwords don\'t match');
        return;
    }

    const key = hash(pass1);
    // Include privateKey for backwards compatibility with legacy unlock
    const saveData = {
        privateKey: vault.privateKey,
        seedPhrase: vault.seedPhrase,
        passphrase: vault.passphrase || '',
        users: vault.users,
        settings: vault.settings
    };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(saveData), pass1).toString();

    const stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
    stored[key] = encrypted;
    localStorage.setItem('vaultEncrypted', JSON.stringify(stored));

    showToast('Vault saved!');
    backupToNostrDebounced();
    showScreen('settingsScreen');
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
            if (!confirm(`Import ${siteCount} site(s)? This will merge with your current vault.`)) return;
            // Merge users — higher nonce wins (more recent password rotation)
            Object.entries(data.users).forEach(([user, sites]) => {
                if (!vault.users[user]) vault.users[user] = {};
                Object.entries(sites).forEach(([site, nonce]) => {
                    // Only overwrite if imported nonce is higher (newer version)
                    if (vault.users[user][site] === undefined || nonce > vault.users[user][site]) {
                        vault.users[user][site] = nonce;
                    }
                });
            });
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            renderSiteList();
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
function saveAdvancedSettings() {
    const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
    vault.settings.hashLength = Math.max(8, Math.min(64, len));
    vault.settings.debugMode = debugMode;
    saveLocalNonceBackup();
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
    backupToNostrDebounced();
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
function showSeedPhrase() {
    if (!vault.seedPhrase) {
        showToast('Seed phrase not available (unlocked from legacy storage)');
        return;
    }

    const grid = document.getElementById('viewSeedGrid');
    grid.innerHTML = '';

    vault.seedPhrase.split(' ').forEach((word, i) => {
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
function copySeedPhrase() {
    navigator.clipboard.writeText(vault.seedPhrase).then(() => {
        showToast('Seed phrase copied — clipboard clears in 15s');
        setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 15000);
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
    // Use NIP-06 derived keys if available, otherwise fall back to legacy SHA-256
    if (nostrKeys && nostrKeys.hex) {
        const { getPublicKey } = window.NostrTools;
        return { sk: nostrKeys.hex, pk: getPublicKey(nostrKeys.hex) };
    }
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    const pk = getPublicKey(sk);
    return { sk, pk };
}

/**
 * Get legacy Nostr key pair (SHA-256 of vault private key).
 * Used for fallback backup restoration from pre-NIP-06 backups.
 */
async function getLegacyNostrKeyPair() {
    const { getPublicKey } = window.NostrTools;
    const utf8 = new TextEncoder().encode(vault.privateKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const sk = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
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
    return {
        v: BACKUP_ENCRYPTED_VERSION,
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf)))
    };
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
 *   Layer 1: AES-256-GCM with PBKDF2(backupPassword, npub) — if backup password is set
 *   Layer 2: NIP-44 self-encrypt (same as before)
 *
 * If no backup password has been set yet, prompts the user to create one (unless silent).
 * Silent backups (background syncs) use the cached backup password from the current session.
 *
 * Falls back gracefully: success on any relay is sufficient.
 *
 * @param {boolean} [silent=false] - If true, suppresses toast notifications and password prompts.
 * @param {string}  [overridePassword=null] - Use this password instead of prompting (for change flow).
 * @returns {Promise<void>}
 */
async function backupToNostr(silent = false, overridePassword = null) {
    const { nip44, getEventHash, signEvent, getPublicKey } = window.NostrTools;

    if (!vault.privateKey) {
        if (!silent) showToast('Vault not initialized');
        return;
    }

    try {
        const { sk, pk } = await getNostrKeyPair();
        const sharedSecret = nip44.getSharedSecret(sk, pk);

        const vaultData = JSON.stringify({ users: vault.users, settings: vault.settings });

        // Determine backup password — NEVER fall back to single-layer
        let backupPwd = overridePassword || _sessionBackupPassword;
        if (!backupPwd) {
            if (silent) {
                // Queue backup for when password becomes available — do NOT send single-layer
                _pendingBackupAfterPassword = true;
                const msg = vault.settings.hasBackupPassword
                    ? '🔒 Backup pending — re-enter backup password. '
                    : '🔒 Backup pending — set password to sync. ';
                showBackupPasswordNudge(msg);
                return;
            } else {
                // Interactive — show modal
                const mode = vault.settings.hasBackupPassword ? 'enter' : 'set';
                backupPwd = await showBackupPasswordModal(mode);
                if (!backupPwd) {
                    showToast('Backup cancelled');
                    return;
                }
                _sessionBackupPassword = backupPwd;
                vault.settings.hasBackupPassword = true;
            }
        }

        // Layer 1: AES-256-GCM with password-derived key (always — no single-layer fallback)
        const envelope = await encryptWithBackupPassword(vaultData, backupPwd, pk);
        const layer1Payload = JSON.stringify(envelope);

        // Layer 2: NIP-44 encryption (always)
        const encrypted = nip44.encrypt(sharedSecret, layer1Payload);

        const event = {
            kind: 30078,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["d", BACKUP_D_TAG]],
            content: encrypted,
        };
        event.id = getEventHash(event);
        event.sig = await signEvent(event, sk);

        let success = 0;
        let successRelays = [];
        for (const url of RELAYS) {
            try {
                const relay = await connectRelay(url);
                await Promise.race([
                    relay.publish(event),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
                ]);
                relay.close();
                success++;
                successRelays.push(url);
                debugLog(`backupToNostr: published to ${url}`);
            } catch (e) {
                console.error(`backupToNostr: failed on relay [${url}]`, e);
            }
        }

        debugLog(`backupToNostr: succeeded on ${success}/${RELAYS.length} relays`, successRelays);

        if (success > 0) {
            vault.settings.lastBackupFailed = false;
            updateBackupWarningIndicator();
            if (!silent) showToast(`Backed up to ${success} relays`);

            if (debugMode) {
                const nevent = encodeNevent(event.id, successRelays);
                if (nevent) {
                    const link = `https://njump.me/${nevent}`;
                    setTimeout(() => {
                        if (confirm(`Debug: View event on njump.me?\n\n${event.id.slice(0, 32)}...`)) {
                            window.open(link, '_blank');
                        }
                    }, 500);
                }
            }
        } else {
            if (silent) {
                vault.settings.lastBackupFailed = true;
                updateBackupWarningIndicator();
            }
            if (!silent) showToast('Backup failed');
        }
    } catch (e) {
        debugLog('backupToNostr: unexpected error:', e);
        if (!silent) showToast('Backup error');
    }
}

/**
 * Change the backup password: prompt for new password, re-encrypt, and re-publish.
 */
async function changeBackupPassword() {
    if (!vault.privateKey) {
        showToast('Vault not initialized');
        return;
    }
    const newPassword = await showBackupPasswordModal('change');
    if (!newPassword) return;

    _sessionBackupPassword = newPassword;
    vault.settings.hasBackupPassword = true;
    showToast('Re-encrypting...');
    await backupToNostr(false, newPassword);
}

// Session-only backup password cache — never persisted to storage
let _sessionBackupPassword = null;

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
async function decryptBackupEvent(event, sk, pk, interactive = true) {
    const { nip44, nip04 } = window.NostrTools;

    let layer2Decrypted;
    if (event.kind === 30078) {
        const sharedSecret = nip44.getSharedSecret(sk, pk);
        layer2Decrypted = nip44.decrypt(sharedSecret, event.content);
    } else {
        layer2Decrypted = await nip04.decrypt(sk, event.pubkey, event.content);
    }

    // Check for double-encrypted v2 envelope
    const envelope = parseDoubleEncryptedEnvelope(layer2Decrypted);
    if (!envelope) {
        // Legacy single-layer backup — return as-is
        return layer2Decrypted;
    }

    // Double-encrypted: need backup password
    let backupPwd = _sessionBackupPassword;
    if (!backupPwd && interactive) {
        backupPwd = await showBackupPasswordModal('enter');
        if (!backupPwd) throw new Error('Backup password required but cancelled');
    }
    if (!backupPwd) {
        throw new Error('Double-encrypted backup requires password');
    }

    try {
        const decrypted = await decryptWithBackupPassword(envelope, backupPwd, pk);
        // Cache the successful password for this session
        _sessionBackupPassword = backupPwd;
        vault.settings.hasBackupPassword = true;
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
    if (!vault.privateKey) {
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
            const decrypted = await decryptBackupEvent(latest, decryptSk, decryptPk, true);
            const data = JSON.parse(decrypted);
            vault.users = { ...vault.users, ...data.users };
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            saveLocalNonceBackup();
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
            debugLog('restoreFromNostr: error:', e);
            showToast('Restore error');
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
    if (!vault.privateKey) {
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
                decrypted = await decryptBackupEvent(found, sk, pk, true);
            } catch (e1) {
                const legacy = await getLegacyNostrKeyPair();
                if (legacy.pk !== pk) {
                    debugLog('restoreFromId: NIP-06 key failed, trying legacy...');
                    decrypted = await decryptBackupEvent(found, legacy.sk, legacy.pk, true);
                } else {
                    throw e1;
                }
            }
            const data = JSON.parse(decrypted);
            vault.users = data.users || vault.users;
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            saveLocalNonceBackup();
            showToast('Restored!');
            showScreen('mainScreen');
        } else {
            showToast('Backup not found');
        }
    } catch (e) {
        if (e.message && e.message.includes('cancelled')) {
            showToast('Restore cancelled');
        } else {
            debugLog('restoreFromId: error:', e);
            showToast('Restore error');
        }
    }
}

// ============================================
// Seed Phrase Autocomplete
// ============================================
let activeSuggestionIndex = -1;
let currentSuggestions = [];

/**
 * Handle input events on the seed phrase textarea.
 * Extracts the current word being typed, queries the BIP39 word list for prefix
 * matches, and displays up to 6 suggestions.
 *
 * @param {InputEvent} event - The input event from the seed phrase textarea.
 */
function onSeedInput(event) {
    const textarea = event.target;
    const value = textarea.value;
    const cursorPos = textarea.selectionStart;

    // Extract the word currently being typed (letters only, before the cursor)
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const currentWord = wordMatch ? wordMatch[0].toLowerCase() : '';

    // Update word count display
    const wordCount = value.trim().split(/\s+/).filter(w => w.length > 0).length;
    document.getElementById('wordCount').textContent = wordCount;

    const suggestions = document.getElementById('seedSuggestions');

    if (currentWord.length < 1) {
        suggestions.classList.add('hidden');
        currentSuggestions = [];
        return;
    }

    // Find BIP39 words that start with the typed prefix
    currentSuggestions = words
        .filter(w => w.startsWith(currentWord))
        .slice(0, 6);

    if (currentSuggestions.length === 0) {
        suggestions.classList.add('hidden');
        return;
    }

    // Hide suggestions if there's an exact single match (word is complete)
    if (currentSuggestions.length === 1 && currentSuggestions[0] === currentWord) {
        suggestions.classList.add('hidden');
        return;
    }

    activeSuggestionIndex = 0;
    renderSuggestions(currentWord);
    suggestions.classList.remove('hidden');
}

/**
 * Render the autocomplete suggestion list, highlighting the currently typed prefix
 * in bold and marking the active suggestion.
 *
 * @param {string} typed - The current typed prefix to highlight in each suggestion.
 */
function renderSuggestions(typed) {
    const suggestions = document.getElementById('seedSuggestions');
    suggestions.innerHTML = currentSuggestions.map((word, i) => {
        const matchPart = word.slice(0, typed.length);
        const restPart = word.slice(typed.length);
        return `<div class="seed-suggestion ${i === activeSuggestionIndex ? 'active' : ''}" 
                     data-suggestion="${word}">
            <span class="seed-suggestion-match">${matchPart}</span>${restPart}
        </div>`;
    }).join('');

    // Bind click events on suggestions
    suggestions.querySelectorAll('[data-suggestion]').forEach(el => {
        el.addEventListener('click', () => selectSuggestion(el.dataset.suggestion));
    });
}

/**
 * Handle keyboard navigation within the seed phrase autocomplete suggestions.
 * Supports ArrowUp/ArrowDown to move selection, Tab/Enter to confirm, Escape to dismiss.
 *
 * @param {KeyboardEvent} event - The keydown event from the seed phrase textarea.
 */
function onSeedKeydown(event) {
    const suggestions = document.getElementById('seedSuggestions');

    if (suggestions.classList.contains('hidden') || currentSuggestions.length === 0) {
        return;
    }

    if (event.key === 'ArrowDown') {
        event.preventDefault();
        activeSuggestionIndex = (activeSuggestionIndex + 1) % currentSuggestions.length;
        renderSuggestions(getCurrentTypedWord());
    } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        activeSuggestionIndex = activeSuggestionIndex <= 0
            ? currentSuggestions.length - 1
            : activeSuggestionIndex - 1;
        renderSuggestions(getCurrentTypedWord());
    } else if (event.key === 'Tab' || event.key === 'Enter') {
        if (currentSuggestions.length > 0) {
            event.preventDefault();
            selectSuggestion(currentSuggestions[activeSuggestionIndex]);
        }
    } else if (event.key === 'Escape') {
        suggestions.classList.add('hidden');
    }
}

/**
 * Get the word currently being typed at the cursor position in the seed textarea.
 *
 * @returns {string} The current partial word (lowercase), or empty string if none.
 */
function getCurrentTypedWord() {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const beforeCursor = textarea.value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    return wordMatch ? wordMatch[0].toLowerCase() : '';
}

/**
 * Insert a selected suggestion word into the seed textarea, replacing the
 * current partial word and appending a space.
 *
 * @param {string} word - The BIP39 word to insert.
 */
function selectSuggestion(word) {
    const textarea = document.getElementById('restoreSeedInput');
    const cursorPos = textarea.selectionStart;
    const value = textarea.value;

    // Find where the current partial word starts
    const beforeCursor = value.slice(0, cursorPos);
    const wordMatch = beforeCursor.match(/[a-z]+$/i);
    const wordStart = wordMatch ? cursorPos - wordMatch[0].length : cursorPos;

    // Replace current partial word with the selected word + a trailing space
    const newValue = value.slice(0, wordStart) + word + ' ' + value.slice(cursorPos);
    textarea.value = newValue;

    // Place cursor after the inserted word and space
    const newCursorPos = wordStart + word.length + 1;
    textarea.setSelectionRange(newCursorPos, newCursorPos);
    textarea.focus();

    // Hide suggestions and update word count
    document.getElementById('seedSuggestions').classList.add('hidden');
    currentSuggestions = [];

    const wordCount = newValue.trim().split(/\s+/).filter(w => w.length > 0).length;
    document.getElementById('wordCount').textContent = wordCount;
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
    // Only set timer if vault is unlocked (privateKey present)
    if (vault.privateKey) {
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

    // Lock vault when tab is hidden for too long (e.g. user switches app)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            hiddenAt = Date.now();
        } else if (hiddenAt && vault.privateKey) {
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
 * Attach global keyboard shortcuts active on the password generation screen:
 *   Enter → copyPassword()
 *   Escape → navigate back to main screen
 *
 * Shortcuts are suppressed when focus is inside an input or textarea.
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Only active on generate screen
        const genScreen = document.getElementById('generateScreen');
        if (genScreen.classList.contains('hidden')) return;

        // Don't trigger if typing in an input
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        // Enter → copy password
        if (e.key === 'Enter') {
            e.preventDefault();
            copyPassword();
        }
        // Escape → back to site list
        if (e.key === 'Escape') {
            e.preventDefault();
            showScreen('mainScreen');
        }
    });
}

// ============================================
// Init
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    setupInactivityListeners();
    setupKeyboardShortcuts();

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
        btnSaveEncrypted: () => saveEncrypted(),
        btnDownloadData: () => downloadData(),
        btnTriggerImport: () => triggerImport(),
        btnSaveAdvancedSettings: () => saveAdvancedSettings(),
        btnCopySeedPhrase: () => copySeedPhrase(),
        btnChangeBackupPassword: () => changeBackupPassword(),
    };

    Object.entries(btnBindings).forEach(([id, handler]) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', handler);
    });

    // ── Input event listeners ──
    const restoreSeedInput = document.getElementById('restoreSeedInput');
    if (restoreSeedInput) {
        restoreSeedInput.addEventListener('input', (e) => onSeedInput(e));
        restoreSeedInput.addEventListener('keydown', (e) => onSeedKeydown(e));
    }

    const unlockPassword = document.getElementById('unlockPassword');
    if (unlockPassword) {
        unlockPassword.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') unlockVault();
        });
    }

    const siteSearch = document.getElementById('siteSearch');
    if (siteSearch) {
        siteSearch.addEventListener('input', () => filterSites());
        siteSearch.addEventListener('keydown', (e) => handleSearchEnter(e));
    }

    const genSite = document.getElementById('genSite');
    if (genSite) {
        genSite.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') document.getElementById('genUser').focus();
        });
    }

    const genUser = document.getElementById('genUser');
    if (genUser) {
        genUser.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveAndCopy();
        });
    }

    const encryptPass1 = document.getElementById('encryptPass1');
    if (encryptPass1) {
        encryptPass1.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') document.getElementById('encryptPass2').focus();
        });
    }

    const encryptPass2 = document.getElementById('encryptPass2');
    if (encryptPass2) {
        encryptPass2.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveEncrypted();
        });
    }

    const hashLengthSetting = document.getElementById('hashLengthSetting');
    if (hashLengthSetting) {
        hashLengthSetting.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveAdvancedSettings();
        });
    }

    const debugModeToggle = document.getElementById('debugModeToggle');
    if (debugModeToggle) {
        debugModeToggle.addEventListener('change', () => toggleDebugMode());
    }

    // ── Service worker registration ──
    if ('serviceWorker' in navigator && !window.__TAURI__) {
        navigator.serviceWorker.register('sw.js').catch(() => {});
    }

    // Check if there's saved encrypted data
    const stored = localStorage.getItem('vaultEncrypted');
    const legacy = localStorage.getItem('encryptedDataStorage');
    if ((stored && Object.keys(JSON.parse(stored)).length > 0) ||
        (legacy && Object.keys(JSON.parse(legacy)).length > 0)) {
        // Could highlight unlock option
    }
});
