/**
 * Vault v3 - Deterministic Password Manager
 * Clean rewrite with simplified UX
 *
 * Architecture:
 *  - Passwords are deterministic: derived from privateKey + user + site + nonce via SHA-256.
 *  - The private key never changes — it is deterministically derived from the BIP39 seed phrase.
 *  - Nonces are the only mutable state: they are stored in an encrypted local vault
 *    and can be exported as a file for Syncthing or Android file pickers.
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

let currentNonce = 0;
let originalNonce = 0;
let passwordVisible = false;
let navigationStack = [hasSavedEncryptedVault() ? 'unlockScreen' : 'welcomeScreen'];
let debugMode = false;
let inactivityTimer = null;
let unlockAttempts = 0;
let unlockLockoutUntil = 0;
let clipboardClearTimer = null;
let toastTimer = null;

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const VISIBILITY_LOCK_MS = 2 * 60 * 1000; // 2 minutes hidden = lock
const MAX_UNLOCK_ATTEMPTS = 5;
const UNLOCK_LOCKOUT_MS = 30 * 1000; // 30 seconds
const DEFAULT_HASH_LENGTH = 16;

let _sessionLocalPassword = null;
let vaultFilePath = localStorage.getItem('vaultFilePath') || '';

// ============================================
// Debug Guard
// ============================================

/**
 * Conditional logger that only emits output when debugMode is enabled.
 * Use this for ANY log that could expose sensitive data: private keys,
 * seed phrases, encrypted blobs, decrypted vault content, or encrypted vault data.
 * Safe (non-sensitive) errors — e.g. file write failures — may use
 * console.error directly so they always surface in production.
 *
 * @param {...*} args - Arguments forwarded to console.log when debugMode is true.
 */
function hasTauri() {
    return Boolean(window.__TAURI__?.core?.invoke);
}

function tauriInvoke(command, args = {}) {
    return window.__TAURI__.core.invoke(command, args);
}

function setVaultFilePath(path) {
    vaultFilePath = path || '';
    if (vaultFilePath) localStorage.setItem('vaultFilePath', vaultFilePath);
    updateVaultPathLabel();
}

function updateVaultPathLabel() {
    const label = document.getElementById('vaultPathLabel');
    if (label) label.textContent = vaultFilePath || 'No vault file selected';
}

async function chooseVaultFilePath() {
    if (!hasTauri()) {
        showToast('File picker unavailable');
        return null;
    }
    showLoading('Choose vault file');
    try {
        const path = await tauriInvoke('choose_vault_file');
        if (path) setVaultFilePath(path);
        return path;
    } finally {
        hideLoading();
    }
}

async function writeSelectedVaultFile(password) {
    if (!vaultFilePath || !hasTauri()) return false;
    const contents = encryptVaultPayload(password);
    await tauriInvoke('write_vault_file', { path: vaultFilePath, contents });
    const saved = await tauriInvoke('read_vault_file', { path: vaultFilePath });
    if (saved !== contents) throw new Error('Vault file write verification failed');
    return true;
}

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
function showScreen(screenId, push = true) {
    document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
    const target = document.getElementById(screenId);
    if (target) {
        target.classList.remove('hidden');
        if (push && screenId === 'mainScreen') {
            navigationStack = ['mainScreen'];
        } else if (push && navigationStack[navigationStack.length - 1] !== screenId) {
            navigationStack = navigationStack.filter(id => id !== screenId);
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
        if (statusEl) statusEl.innerHTML = '<span>Encrypted file, no cloud account</span>';
    } else if (screenId === 'settingsScreen') {
        updateBackupWarningIndicator();
        const hashLengthSetting = document.getElementById('hashLengthSetting');
        if (hashLengthSetting) hashLengthSetting.value = vault.settings.hashLength || 16;
    }
}

/**
 * Navigate back to the previous screen in the navigation stack.
 * Falls back to 'welcomeScreen' if the stack is empty.
 */
function goBack() {
    navigationStack.pop();
    const prev = navigationStack[navigationStack.length - 1] || 'welcomeScreen';
    showScreen(prev, false);
}

function setupAndroidBackButton() {
    const onBackButtonPress = window.__TAURI__?.app?.onBackButtonPress;
    if (!onBackButtonPress) return;

    onBackButtonPress(() => {
        if (navigationStack.length > 1) {
            goBack();
        } else {
            tauriInvoke('plugin:app|exit').catch(() => {});
        }
    }).catch(e => console.error('Android back button setup failed:', e));
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
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
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
        showScreen('storageSetupScreen');
    } else {
        showToast('Incorrect words. Try again.');
    }
}

/**
 * Validate and restore a vault from a user-entered seed phrase.
 * Validates BIP39 checksum, initializes the vault,
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
    showScreen('storageSetupScreen');
}

// ============================================
// Vault Management
// ============================================

/**
 * Initialize the vault from a seed phrase.
 *
 *  {string} seedPhrase - Valid BIP39 mnemonic.
 *  {string} [passphrase=''] - Optional BIP39 passphrase kept with the vault.
 *  {Promise<void>}
 */
async function initializeVault(seedPhrase, passphrase = '') {
    vault.seedPhrase = seedPhrase.replace(/\s+/g, ' ').trim().toLowerCase();
    vault.privateKey = await derivePrivateKey(vault.seedPhrase);
    vault.passphrase = passphrase;
    resetInactivityTimer();
}

function hasSavedEncryptedVault() {
    const stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
    return Object.keys(stored).length > 0;
}

function lockVault(skipConfirm = false) {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
    vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: DEFAULT_HASH_LENGTH } };
    navigationStack = [hasSavedEncryptedVault() ? 'unlockScreen' : 'welcomeScreen'];

    document.querySelectorAll('input').forEach(el => { el.value = ''; });
    document.querySelectorAll('[data-seed-word], .seed-word, .word-item, .word-display').forEach(el => {
        el.textContent = '';
    });
    ['seedPhraseDisplay','seedWords','mnemonicWords','seedBackupScreen','setupSeedScreen','verifyScreen','seedDisplay'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.querySelectorAll('input, span, div, p').forEach(child => {
            child.textContent = '';
            if ('value' in child) child.value = '';
        });
    });

    showScreen(navigationStack[0]);
    showToast('Vault locked');
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
function addSiteFromSearch() {
    const site = document.getElementById('siteSearch')?.value.trim() || '';
    openSite(site, '', 0);
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
    document.getElementById('visibilityIcon').textContent = 'Show';
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
    document.getElementById('visibilityIcon').textContent = passwordVisible ? 'Hide' : 'Show';

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
 * save a local encrypted backup.
 *
 * Saves the current nonce under vault.users[user][site] so the same password
 * can be reproduced later. The clipboard is auto-cleared after 30 seconds.
 */
function copyPassword() {
    const site = document.getElementById('genSite').value.trim();
    const user = document.getElementById('genUser').value.trim();

    if (!site || !user) {
        showToast('Enter site and username');
        return false;
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

    saveUnlockedVaultSnapshot();
    return true;
}

/**
 * Copy the password and navigate back to the main site list screen.
 */
function saveAndCopy() {
    if (copyPassword()) showScreen('mainScreen');
}

/**
 * Delete a site entry from the vault after user confirmation.
 * Removes the site from the user's entry, cleans up empty user objects,
 * and writes the encrypted vault snapshot.
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
    saveUnlockedVaultSnapshot();
}

// ============================================
// Local Encryption
// ============================================

/**
 * Unlock the vault from a locally encrypted backup stored in localStorage.
 * Enforces rate limiting: after MAX_UNLOCK_ATTEMPTS failures, locks out for
 * UNLOCK_LOCKOUT_MS milliseconds.
 *
 * Uses the local 'vaultEncrypted' storage key.
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
        let stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
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

        _sessionLocalPassword = password;
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
 * After saving, writes the encrypted vault snapshot.
 */
function vaultSnapshot() {
    return {
        privateKey: vault.privateKey,
        seedPhrase: vault.seedPhrase,
        passphrase: vault.passphrase || '',
        users: vault.users,
        settings: vault.settings
    };
}

function encryptVaultPayload(password) {
    return JSON.stringify({
        v: 1,
        type: 'topolino-vault',
        payload: CryptoJS.AES.encrypt(JSON.stringify(vaultSnapshot()), password).toString()
    });
}

function saveEncryptedVault(password) {
    const key = hash(password);
    const stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
    stored[key] = CryptoJS.AES.encrypt(JSON.stringify(vaultSnapshot()), password).toString();
    localStorage.setItem('vaultEncrypted', JSON.stringify(stored));
}

function removeEncryptedVaultPassword(password) {
    const stored = JSON.parse(localStorage.getItem('vaultEncrypted') || '{}');
    delete stored[hash(password)];
    localStorage.setItem('vaultEncrypted', JSON.stringify(stored));
}

function saveUnlockedVaultSnapshot() {
    if (!_sessionLocalPassword || !vault.privateKey) return;
    saveEncryptedVault(_sessionLocalPassword);
    writeSelectedVaultFile(_sessionLocalPassword).catch(e => {
        console.error('vault file write failed:', e);
        showToast('Could not write vault file');
    });
}

function applyVaultSnapshot(data) {
    vault.privateKey = data.privateKey || vault.privateKey || '';
    vault.seedPhrase = data.seedPhrase || vault.seedPhrase || '';
    vault.passphrase = data.passphrase || '';
    vault.users = data.users || {};
    vault.settings = data.settings || { hashLength: DEFAULT_HASH_LENGTH };
    debugMode = vault.settings.debugMode || false;
}

// ============================================
// Export & Import
// ============================================

/**
 * Export the complete vault as one encrypted file. Android routes this through
 * its document/download UI, so the app does not need broad storage permission.
 */
async function downloadData() {
    if (!vault.privateKey) {
        showToast('Unlock vault first');
        return;
    }

    const password = _sessionLocalPassword || prompt('Password for encrypted vault file');
    if (!password) return;

    _sessionLocalPassword = password;
    saveEncryptedVault(password);

    const contents = encryptVaultPayload(password);

    if (hasTauri()) {
        showLoading('Choose export file');
        try {
            const path = await tauriInvoke('choose_vault_file');
            if (!path) return;
            await tauriInvoke('write_vault_file', { path, contents });
            const saved = await tauriInvoke('read_vault_file', { path });
            if (saved !== contents) throw new Error('Export verification failed');
            showToast('Encrypted vault exported');
            return;
        } catch (e) {
            console.error('downloadData export failed:', e);
            showToast('Could not export vault file');
            return;
        } finally {
            hideLoading();
        }
    }

    showToast('Native export unavailable');
}

function mergeUsers(importedUsers) {
    Object.entries(importedUsers || {}).forEach(([user, sites]) => {
        if (!vault.users[user]) vault.users[user] = {};
        Object.entries(sites || {}).forEach(([site, nonce]) => {
            if (vault.users[user][site] === undefined || nonce > vault.users[user][site]) {
                vault.users[user][site] = nonce;
            }
        });
    });
}

async function checkVaultFileHealth() {
    if (!vaultFilePath || !_sessionLocalPassword) { showToast('No vault file selected'); return; }
    try {
        await writeSelectedVaultFile(_sessionLocalPassword);
        showToast('Vault file healthy');
    } catch (e) {
        console.error('checkVaultFileHealth failed:', e);
        showToast('Vault file check failed');
    }
}

async function moveVaultFile() {
    if (!_sessionLocalPassword || !vault.privateKey) { showToast('Unlock vault first'); return; }
    const previousPath = vaultFilePath;
    const nextPath = await chooseVaultFilePath();
    if (!nextPath) return;
    try {
        await writeSelectedVaultFile(_sessionLocalPassword);
        showToast('Vault file moved');
    } catch (e) {
        if (previousPath) setVaultFilePath(previousPath);
        console.error('moveVaultFile failed:', e);
        showToast('Could not move vault file');
    }
}

async function setupVaultStorage() {
    const pass1 = document.getElementById('storagePass1').value;
    const pass2 = document.getElementById('storagePass2').value;
    if (!pass1 || pass1 !== pass2) {
        showToast('Passwords do not match');
        return;
    }
    if (!vaultFilePath && !(await chooseVaultFilePath())) return;

    try {
        _sessionLocalPassword = pass1;
        saveEncryptedVault(pass1);
        await writeSelectedVaultFile(pass1);
        showToast('Vault file saved');
        showScreen('mainScreen');
    } catch (e) {
        console.error('setupVaultStorage failed:', e);
        showToast('Could not write vault file');
    }
}

async function importVaultFile() {
    if (!hasTauri()) {
        showToast('Native file picker unavailable');
        return;
    }

    showLoading('Import vault file');
    try {
        const path = await tauriInvoke('open_vault_file');
        if (!path) return;

        const parsed = JSON.parse(await tauriInvoke('read_vault_file', { path }));
        if (parsed.type !== 'topolino-vault' || !parsed.payload) throw new Error('invalid vault file');

        const password = prompt('Password for this vault file');
        if (!password) return;

        const decrypted = CryptoJS.AES.decrypt(parsed.payload, password).toString(CryptoJS.enc.Utf8);
        if (!decrypted) throw new Error('decrypt failed');
        const data = JSON.parse(decrypted);
        if (!data.users || typeof data.users !== 'object') throw new Error('invalid vault data');

        if (!vault.privateKey) {
            applyVaultSnapshot(data);
            setVaultFilePath(path);
            _sessionLocalPassword = password;
            saveEncryptedVault(password);
        } else {
            const siteCount = Object.values(data.users).reduce((n, u) => n + Object.keys(u || {}).length, 0);
            if (!confirm('Import ' + siteCount + ' site(s)? This will merge with your current vault.')) return;
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            saveUnlockedVaultSnapshot();
        }

        resetInactivityTimer();
        renderSiteList();
        showToast('Vault file imported');
        showScreen('mainScreen');
    } catch (e) {
        console.error('importVaultFile failed:', e);
        showToast('Could not import vault file');
    } finally {
        hideLoading();
    }
}
// ============================================
// Settings
// ============================================

/**
 * Persist advanced settings (hash length, debug mode) and return to the settings screen.
 * Clamps hashLength to the range [8, 64].
 */
function saveAdvancedSettings(silent = false) {
    const len = parseInt(document.getElementById('hashLengthSetting').value) || 16;
    vault.settings.hashLength = Math.max(8, Math.min(64, len));
    vault.settings.debugMode = debugMode;
    saveUnlockedVaultSnapshot();
    if (!silent) showToast('Settings saved');
}

async function changeMasterPassword() {
    const current = document.getElementById('currentMasterPassword').value;
    const next = document.getElementById('newMasterPassword').value;
    const confirm = document.getElementById('confirmMasterPassword').value;
    if (!current || !next || !confirm) { showToast('Fill all password fields'); return; }
    if (current !== _sessionLocalPassword) { showToast('Current password is wrong'); return; }
    if (next.length < 8) { showToast('Use at least 8 characters'); return; }
    if (next !== confirm) { showToast('New passwords do not match'); return; }

    try {
        await writeSelectedVaultFile(next);
        saveEncryptedVault(next);
        removeEncryptedVaultPassword(current);
        _sessionLocalPassword = next;
        document.getElementById('currentMasterPassword').value = '';
        document.getElementById('newMasterPassword').value = '';
        document.getElementById('confirmMasterPassword').value = '';
        showToast('Password changed');
        showScreen('settingsScreen');
    } catch (e) {
        console.error('changeMasterPassword failed:', e);
        showToast('Could not update vault file');
    }
}

/**
 * Display the vault's seed phrase in the view seed screen.
 */
function showSeedPhrase() {
    if (!vault.seedPhrase) {
        showToast('Seed phrase not available');
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
    setupAndroidBackButton();
    updateVaultPathLabel();

    // ── Delegated screen navigation ──
    document.addEventListener('click', (e) => {
        const backEl = e.target.closest('[data-action="back"], [aria-label="Back"]');
        if (backEl) {
            goBack();
            return;
        }
        const screenEl = e.target.closest('[data-screen]');
        if (screenEl) {
            showScreen(screenEl.dataset.screen);
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
        btnChooseVaultPath: () => chooseVaultFilePath(),
        btnSetupVaultStorage: () => setupVaultStorage(),
        btnCheckVaultFile: () => checkVaultFileHealth(),
        btnMoveVaultFile: () => moveVaultFile(),
        btnChangeMasterPassword: () => changeMasterPassword(),
        btnAddSite: () => addSiteFromSearch(),
        btnLockVault: () => lockVault(),
        btnUnlockVault: () => unlockVault(),
        btnDecrementNonce: () => decrementNonce(),
        btnIncrementNonce: () => incrementNonce(),
        btnToggleVisibility: () => togglePasswordVisibility(),
        btnSaveAndCopy: () => saveAndCopy(),
        btnExportVaultFile: () => downloadData(),
        btnImportVaultFile: () => importVaultFile(),
        btnCopySeedPhrase: () => copySeedPhrase(),
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

    const hashLengthSetting = document.getElementById('hashLengthSetting');
    if (hashLengthSetting) {
        hashLengthSetting.addEventListener('input', () => saveAdvancedSettings(true));
        hashLengthSetting.addEventListener('change', () => saveAdvancedSettings());
    }

    // Check if there's saved encrypted data
    if (hasSavedEncryptedVault()) {
        navigationStack = ['unlockScreen'];
        showScreen('unlockScreen', false);
    }
});
