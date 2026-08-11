/**
 * Vault v3 - Deterministic Password Manager
 * Clean rewrite with simplified UX
 *
 * Architecture:
 *  - Passwords are deterministic: derived from privateKey + user + site + nonce via SHA-256.
 *  - `privateKey` is the BIP39 seed phrase re-encoded as hex — an invertible base
 *    conversion, not a derivation (see encodeSeedPhraseAsHex and ROADMAP.md 2.1).
 *  - `vault.passphrase` is stored but enters NO derivation — it currently protects
 *    nothing (ROADMAP.md 2.2).
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
let totpTimer = null;

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const VISIBILITY_LOCK_MS = 2 * 60 * 1000; // 2 minutes hidden = lock
const MAX_UNLOCK_ATTEMPTS = 5;
const UNLOCK_LOCKOUT_MS = 30 * 1000; // 30 seconds
const DEFAULT_HASH_LENGTH = 16;

let _sessionMasterPassword = null;

// ============================================
// Native Bridge
// ============================================

function hasTauri() {
    return Boolean(window.__TAURI__?.core?.invoke);
}

function tauriInvoke(command, args = {}) {
    return window.__TAURI__.core.invoke(command, args);
}

// ============================================
// Store Integration
// ============================================
//
// The vault itself lives in vault/core/ — keyslots, the per-device operation
// log, the CRDT merge and the durable transports. app.js keeps only the UI's
// view of it (`vault`) and pushes changes through the store, so the logic that
// can lose data stays in the part that has tests.

let vaultStore = null;
let vaultDirPath = localStorage.getItem('vaultDirPath') || '';
// Retained for the Android single-file (SAF) layout and for installs that
// selected a file before folder support existed.
let vaultFilePath = localStorage.getItem('vaultFilePath') || '';

function setVaultDirPath(path) {
    vaultDirPath = path || '';
    if (vaultDirPath) localStorage.setItem('vaultDirPath', vaultDirPath);
    else localStorage.removeItem('vaultDirPath');
    updateVaultPathLabel();
}

/**
 * Pick the storage layout for this device.
 *
 * A folder is strongly preferred: it is what lets the app write its own
 * per-device log beside the shared snapshot, which is what makes Syncthing
 * conflicts impossible rather than merely survivable. A single file (an
 * Android SAF grant) still works, with conflicts possible but lossless. With
 * neither, the vault stays device-local in browser storage.
 */
function buildTransport() {
    if (hasTauri() && vaultDirPath) return VaultTransports.tauriDirectory(tauriInvoke, vaultDirPath);
    if (hasTauri() && vaultFilePath) {
        return VaultTransports.tauriSingleFile(tauriInvoke, vaultFilePath, localStorage);
    }
    return VaultTransports.localStorageTransport(localStorage, 'tvfs:');
}

/**
 * Wipe this device's vault state and return to the welcome screen.
 *
 * The escape hatch for a device that cannot open its vault — a forgotten
 * password, a half-finished setup, a keyslot file that no longer matches.
 * It clears only DEVICE-LOCAL state; the synced vault files are left exactly
 * as they are, so another device (or a re-import with the right password) can
 * still recover everything. Deleting the user's actual vault is never
 * something an error path should do on their behalf.
 */
function resetThisDevice() {
    if (!confirm(
        'Reset this device?\n\n' +
        'Clears the vault from THIS DEVICE only: the master password, keys and ' +
        'local cache. Your synced vault files are NOT deleted, and other devices ' +
        'are unaffected.\n\n' +
        'If you cannot unlock and have no backup of your seed phrase, this will ' +
        'lose access to your passwords.'
    )) return;
    if (!confirm('Last check — reset this device and start over?')) return;

    const doomed = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key) continue;
        if (
            key === 'vaultEncrypted' ||
            key === 'vaultDirPath' ||
            key === 'vaultFilePath' ||
            key === 'tvDeviceId' ||
            key === 'tvSchema' ||
            key.startsWith('tvfs:')
        ) {
            doomed.push(key);
        }
    }
    doomed.forEach((key) => localStorage.removeItem(key));

    vaultStore = null;
    vaultDirPath = '';
    vaultFilePath = '';
    _sessionMasterPassword = null;
    pendingSeedForVerification = null;
    vault = {
        privateKey: '',
        seedPhrase: '',
        passphrase: '',
        users: {},
        settings: { hashLength: DEFAULT_HASH_LENGTH }
    };
    navigationStack = ['welcomeScreen'];
    updateVaultPathLabel();
    showToast(`Device reset (${doomed.length} item(s) cleared)`);
    showScreen('welcomeScreen', false);
}

/**
 * Which kind of setup the user is doing:
 *   'new'      — this location has no vault; we create one and the password is
 *                being chosen now, so it is asked for twice.
 *   'existing' — the location already holds a vault; the password is the one
 *                that already protects it, so it is asked for once and must
 *                match. Confirming a password you are not choosing is
 *                meaningless, and worse, it invites the user to "confirm" a
 *                typo into a password that will simply be rejected.
 */
let vaultSetupMode = 'new';

function setVaultSetupMode(mode) {
    vaultSetupMode = mode === 'existing' ? 'existing' : 'new';
    const existing = vaultSetupMode === 'existing';

    const hint = document.getElementById('storageSetupHint');
    if (hint) {
        hint.textContent = existing
            ? 'Enter the master password of the vault you selected. Its contents will be merged with anything on this device.'
            : 'Choose where this vault lives, then set the password that encrypts it.';
    }
    const label = document.getElementById('storagePass1Label');
    if (label) label.textContent = existing ? 'Existing Vault Password' : 'Vault Password';

    const confirmGroup = document.getElementById('storagePass2Group');
    if (confirmGroup) confirmGroup.classList[existing ? 'add' : 'remove']('hidden');

    const submit = document.getElementById('btnSetupVaultStorage');
    if (submit) submit.textContent = existing ? 'Open Vault' : 'Save Encrypted Vault';
}

/**
 * Point at a vault that already exists, rather than creating one.
 *
 * The other half of "restore from seed": a returning user types their seed
 * phrase and then needs to attach it to the vault file they already have,
 * not mint an empty one beside it.
 *
 * A folder is tried first because that is the layout with no sync conflicts;
 * Android has no folder picker, so it falls back to selecting the file.
 */
async function chooseExistingVaultLocation() {
    if (!hasTauri()) {
        showToast('File picker unavailable');
        return false;
    }

    const dir = await chooseVaultFolder();
    if (!dir) {
        showLoading('Select vault file');
        try {
            const file = await tauriInvoke('open_vault_file');
            if (!file) return false;
            setVaultFilePath(file);
            setVaultDirPath('');
        } catch (e) {
            debugLog('existing vault pick failed:', e);
            showToast('Could not open that location');
            return false;
        } finally {
            hideLoading();
        }
    }

    setVaultSetupMode('existing');
    updateVaultPathLabel();
    showToast('Enter the password for this vault');
    return true;
}

/** Pick a location for a NEW vault: folder where possible, file otherwise. */
async function chooseNewVaultLocation() {
    const dir = await chooseVaultFolder();
    if (!dir && !(await chooseVaultFilePath())) return false;
    if (dir) setVaultFilePath('');
    setVaultSetupMode('new');
    return true;
}

/** Refresh the UI's view from the store. The store is the source of truth. */
function syncVaultFromStore() {
    if (!vaultStore) return;
    const payload = vaultStore.snapshotPayload();
    // Preserve what the UI already holds when the store has nothing to say.
    // A brand-new store is empty, and blanking these would discard a seed
    // phrase that has been generated but not yet written — which is the one
    // value in this app that cannot be recovered from anywhere.
    vault.privateKey = payload.privateKey || vault.privateKey || '';
    vault.seedPhrase = payload.seedPhrase || vault.seedPhrase || '';
    vault.passphrase = payload.passphrase || vault.passphrase || '';
    vault.users = payload.users || {};
    vault.settings = Object.assign(
        { hashLength: DEFAULT_HASH_LENGTH, debugMode: debugMode },
        payload.settings || {}
    );
}

async function openVaultStore(password, create) {
    const result = await VaultBootstrap.open({
        transport: buildTransport(),
        password,
        storage: localStorage,
        create: Boolean(create)
    });
    vaultStore = result.store;
    syncVaultFromStore();
    if (result.migration) {
        debugLog('legacy migration:', result.migration);
        if (result.migration.migrated) {
            showToast(`Vault upgraded (${result.migration.credentials} sites)`);
        }
    }
    return result;
}

function setVaultFilePath(path) {
    vaultFilePath = path || '';
    if (vaultFilePath) localStorage.setItem('vaultFilePath', vaultFilePath);
    else localStorage.removeItem('vaultFilePath');
    updateVaultPathLabel();
}

/**
 * Warn when the vault has no synced home.
 *
 * Was referenced by showScreen('settingsScreen') but never defined, so opening
 * Settings threw a ReferenceError. Predates this change; fixed here because
 * the screen is now where a user checks where their vault lives.
 */
function updateBackupWarningIndicator() {
    const el = document.getElementById('backupWarning');
    if (!el) return;
    if (!vaultDirPath && !vaultFilePath) {
        el.textContent = 'This vault is only on this device — choose a folder to sync and back it up.';
        el.classList.remove('hidden');
    } else {
        el.textContent = '';
        el.classList.add('hidden');
    }
}

function updateVaultPathLabel() {
    const text = vaultDirPath || vaultFilePath || 'No vault location selected';
    // The path is shown in several places (setup, settings, sync-file screen);
    // update every one that exists rather than only the setup screen's label.
    ['vaultPathLabel', 'vaultPathSettings', 'vaultPathBackup'].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    });
}

/**
 * Prefer a folder — that is the layout with no conflicts.
 *
 * Returns null when the platform has no folder picker (Android: the dialog
 * plugin only offers single-document SAF URIs). Callers fall back to picking a
 * file, which uses the single-file container instead.
 */
async function chooseVaultFolder() {
    if (!hasTauri()) {
        showToast('Folder picker unavailable');
        return null;
    }
    showLoading('Choose vault folder');
    try {
        const dir = await tauriInvoke('choose_vault_dir');
        if (dir) setVaultDirPath(dir);
        return dir;
    } catch (e) {
        debugLog('folder picker unavailable on this platform:', e);
        return null;
    } finally {
        hideLoading();
    }
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

/**
 * Publish the vault. The store handles merging other devices, absorbing
 * foreign snapshots, and writing atomically; this just triggers it.
 */
async function writeSelectedVaultFile() {
    if (!vaultStore) return false;
    await vaultStore.sync();
    syncVaultFromStore();
    return true;
}

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

    // Leaving the authenticator screen stops its per-second code refresh.
    if (screenId !== 'totpScreen' && totpTimer) {
        clearInterval(totpTimer);
        totpTimer = null;
    }

    // Screen-specific setup
    if (screenId === 'mainScreen') {
        renderSiteList();
    } else if (screenId === 'newWalletScreen') {
        // Only mint a seed when there isn't one pending. This screen used to
        // regenerate on every visit with the confirmation suppressed, so
        // navigating back replaced a phrase the user had already written down
        // — and the verification step then asked for words from the NEW seed.
        if (!vault.seedPhrase) generateNewSeed(true);
    } else if (screenId === 'backupScreen') {
        const statusEl = document.getElementById('backupPasswordStatus');
        if (statusEl) statusEl.innerHTML = '<span>Encrypted file, no cloud account</span>';
        updateVaultPathLabel();
        updateBackupWarningIndicator();
    } else if (screenId === 'storageSetupScreen') {
        setVaultSetupMode(vaultSetupMode);
        updateVaultPathLabel();
    } else if (screenId === 'settingsScreen') {
        updateVaultPathLabel();
        updateBackupWarningIndicator();
        const hashLengthSetting = document.getElementById('hashLengthSetting');
        if (hashLengthSetting) hashLengthSetting.value = vault.settings.hashLength || 16;
    } else if (screenId === 'notesScreen') {
        renderNotesList();
    } else if (screenId === 'totpScreen') {
        renderTotpList();
        totpTimer = setInterval(renderTotpList, 1000);
    } else if (screenId === 'csvExportScreen') {
        renderCsvExport();
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
// Derivation (vault/core/derive.js)
// ============================================
//
// Password derivation lives in its own DOM-free module so it can be audited
// without reading the UI. Bound into scope here so call sites read unchanged.

const {
    verifyBip39SeedPhrase,
    generateMnemonic,
    encodeSeedPhraseAsHex,
    generatePassword,
    getPasswordStrength
} = VaultDerive;

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
        div.innerHTML = `<span>${i + 1}.</span>${escapeHtml(word)}`;
        grid.appendChild(div);
    });
}

/**
 * Begin the seed backup verification flow.
 * Picks 3 random word positions and renders text inputs for the user to fill in.
 * Transitions to the 'verifySeedScreen'.
 */
// The exact phrase the verification questions were generated from. Pinned so
// that whatever else happens to `vault.seedPhrase` in between, the answers are
// checked against the words the user was actually shown.
let pendingSeedForVerification = null;

function confirmSeedBackup() {
    pendingSeedForVerification = vault.seedPhrase;
    const seedWords = pendingSeedForVerification.split(' ');
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
    const seed = pendingSeedForVerification || vault.seedPhrase;
    const seedWords = seed.split(' ');
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
        await initializeVault(seed, passphrase);
        pendingSeedForVerification = null;
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
    // Default to creating a vault; "Open Existing Vault" switches modes. A
    // restoring user usually wants their existing file, so the screen offers
    // both rather than assuming.
    setVaultSetupMode('new');
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
    vault.privateKey = await encodeSeedPhraseAsHex(vault.seedPhrase);
    vault.passphrase = passphrase;
    resetInactivityTimer();
}

/**
 * Does this device already have a vault to unlock? Checked synchronously at
 * startup to choose the first screen, so it looks at markers rather than
 * opening anything: a configured location, a device-local keyslot file, or an
 * un-migrated legacy backup.
 */
function hasSavedEncryptedVault() {
    if (localStorage.getItem('vaultDirPath') || localStorage.getItem('vaultFilePath')) return true;
    if (localStorage.getItem('tvfs:topolino-vault.keys.json')) return true;
    try {
        return Object.keys(JSON.parse(localStorage.getItem('vaultEncrypted') || '{}')).length > 0;
    } catch (e) {
        return false;
    }
}

function lockVault(skipConfirm = false) {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = null;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = null;
    if (totpTimer) clearInterval(totpTimer);
    totpTimer = null;
    navigator.clipboard.writeText('').catch(() => {});
    _sessionMasterPassword = null;
    pendingSeedForVerification = null;
    vaultStore = null;
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
        <div class="site-item" data-site="${escapeHtml(s.site)}" data-user="${escapeHtml(s.user)}" data-nonce="${Number(s.nonce) || 0}">
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
 * Escape HTML special characters so untrusted text is safe in BOTH element
 * and attribute contexts.
 *
 * The previous implementation set `textContent` and read back `innerHTML`.
 * That escapes `& < >` but NOT quotes — text-node serialization never escapes
 * `"` or `'` — so any value placed inside a double-quoted attribute (which
 * renderSiteList does) could break out of it. A credential named
 * `x" onpointerover="…` injected attributes onto the site row. Escaping the
 * quotes here closes that; it is also DOM-free, so the browser and the test
 * harness now escape identically.
 *
 * @param {string} str - Untrusted string.
 * @returns {string} HTML-escaped string safe for element and attribute contexts.
 */
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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

    // Always save when copying — persist the current nonce through the store,
    // which merges by maximum so a stale device can never lower it.
    if (!vault.users[user]) vault.users[user] = {};
    vault.users[user][site] = currentNonce;
    originalNonce = currentNonce;
    if (vaultStore) {
        vaultStore.setNonce(user, site, currentNonce).catch((e) => {
            console.error('nonce save failed:', e);
            showToast('Could not save');
        });
    }
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
        if (Object.keys(vault.users[user]).length === 0) delete vault.users[user];
    }

    // A tombstone, not an absence: a plain local delete would be undone by the
    // next sync with a device that still has the record.
    if (vaultStore) {
        vaultStore
            .removeRecord(VaultRecords.credentialId(user, site))
            .then(syncVaultFromStore)
            .then(renderSiteList)
            .catch((e) => {
                console.error('delete failed:', e);
                showToast('Could not delete');
            });
    }

    showToast('Site deleted');
    renderSiteList();
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
/**
 * Unlock with the master password.
 *
 * The store does the work: it tries each keyslot, replays every device's
 * operation log, absorbs anything foreign (a plugin edit, a restored backup,
 * a Syncthing conflict file), and — on an install still carrying the old
 * layout — runs the one-shot migration.
 */
async function unlockVault() {
    const now = Date.now();
    if (now < unlockLockoutUntil) {
        showToast(`Too many attempts. Wait ${Math.ceil((unlockLockoutUntil - now) / 1000)}s`);
        return;
    }

    const password = document.getElementById('unlockPassword').value;
    if (!password) {
        showToast('Enter password');
        return;
    }

    showLoading('Unlocking vault');
    try {
        await openVaultStore(password, false);
        _sessionMasterPassword = password;
        unlockAttempts = 0;

        document.getElementById('unlockPassword').value = '';
        resetInactivityTimer();
        showToast('Vault unlocked!');
        showScreen('mainScreen');
    } catch (e) {
        // Guarded: decrypt errors can carry stack traces.
        debugLog('unlockVault error:', e);
        unlockAttempts++;
        if (unlockAttempts >= MAX_UNLOCK_ATTEMPTS) {
            unlockLockoutUntil = Date.now() + UNLOCK_LOCKOUT_MS;
            unlockAttempts = 0;
            showToast('Too many attempts. Locked for 30s');
        } else {
            showToast(`Wrong password (${MAX_UNLOCK_ATTEMPTS - unlockAttempts} attempts left)`);
        }
    } finally {
        hideLoading();
    }
}

/** The plaintext object that gets encrypted into the vault envelope. */
function vaultSnapshot() {
    return {
        privateKey: vault.privateKey,
        seedPhrase: vault.seedPhrase,
        passphrase: vault.passphrase || '',
        users: vault.users,
        settings: vault.settings
    };
}

/** Encrypt the current vault into a standalone, plugin-readable file. */
async function encryptVaultPayload(password) {
    const salt = VaultEnvelope.randomSalt();
    const key = await VaultEnvelope.deriveVaultKey(password, salt);
    const payload = vaultStore ? vaultStore.snapshotPayload() : vaultSnapshot();
    return VaultEnvelope.encryptEnvelope(payload, key, salt);
}

/**
 * Push the UI's current view into the store and publish it.
 *
 * Replaces the old saveLocalVaultBackup()/writeSelectedVaultFile() pair. Both
 * are gone: there is no longer a localStorage map keyed by
 * sha256Hex(masterPassword) (ROADMAP.md 1.1), and the store owns durability.
 */
function saveUnlockedVaultSnapshot() {
    if (!vaultStore || !vault.privateKey) return Promise.resolve();
    return vaultStore
        .setSettings({ hashLength: vault.settings.hashLength || DEFAULT_HASH_LENGTH })
        .then(() => vaultStore.sync())
        .then(syncVaultFromStore)
        .catch((e) => {
            console.error('vault save failed:', e);
            showToast('Could not save vault');
        });
}

// ============================================
// Export & Import
// ============================================

/**
 * Export the whole vault as one standalone encrypted file — the format the
 * Obsidian plugin reads, and the thing to hand someone as a cold backup.
 * Android routes this through its document UI, so no broad storage permission
 * is needed.
 */
async function exportVaultFile() {
    if (!vault.privateKey) {
        showToast('Unlock vault first');
        return;
    }
    if (!hasTauri()) {
        showToast('Native export unavailable');
        return;
    }

    const password = _sessionMasterPassword || prompt('Password for the exported file');
    if (!password) return;

    showLoading('Choose export file');
    try {
        const contents = await encryptVaultPayload(password);
        const path = await tauriInvoke('choose_vault_file');
        if (!path) return;
        await tauriInvoke('write_vault_file', { path, contents, keepBackups: false });
        const saved = await tauriInvoke('read_vault_file', { path });
        if (saved !== contents) throw new Error('Export verification failed');
        showToast('Encrypted vault exported');
    } catch (e) {
        console.error('exportVaultFile failed:', e);
        showToast('Could not export vault');
    } finally {
        hideLoading();
    }
}

/**
 * Absorb Syncthing conflict files.
 *
 * With a folder layout the store already does this automatically on every
 * sync, and per-device logs mean conflicts should not appear at all. This
 * stays for the single-file layout and for files that landed outside the
 * vault folder — merging is lossless either way, taking the highest nonce and
 * the newest edit per field.
 */
async function mergeSyncConflictFiles() {
    if (!vaultStore || !vault.privateKey) {
        showToast('Unlock the vault first');
        return;
    }

    showLoading('Select sync conflict files');
    try {
        const paths = await tauriInvoke('open_vault_files');
        if (!paths || !paths.length) return;

        let merged = 0;
        let changed = 0;
        for (const path of paths) {
            try {
                const contents = await tauriInvoke('read_vault_file', { path });
                const result = await VaultEnvelope.decryptEnvelope(contents, _sessionMasterPassword);
                if (result.data.privateKey !== vault.privateKey) throw new Error('different vault');
                const ops = VaultRecords.opsFromSnapshotPayload(
                    result.data,
                    vaultStore.clock,
                    vaultStore.state
                );
                changed += await vaultStore.apply(ops);
                merged++;
            } catch (e) {
                debugLog('sync conflict merge failed:', path, e);
            }
        }

        if (!merged) {
            showToast('No matching conflict files selected');
            return;
        }
        syncVaultFromStore();
        renderSiteList();
        showToast(changed ? `Merged ${merged} file(s)` : `Checked ${merged}; vault already current`);
    } catch (e) {
        console.error('mergeSyncConflictFiles failed:', e);
        showToast('Could not merge sync conflict files');
    } finally {
        hideLoading();
    }
}

async function checkVaultFileHealth() {
    if (!vaultStore) { showToast('Unlock vault first'); return; }
    try {
        const result = await vaultStore.sync();
        syncVaultFromStore();
        if (result.skipped) {
            showToast(`Vault readable; ${result.skipped} damaged log line(s) skipped`);
        } else if (result.unreadable) {
            showToast(`${result.unreadable} file(s) could not be read — kept for recovery`);
        } else {
            showToast('Vault healthy');
        }
    } catch (e) {
        console.error('checkVaultFileHealth failed:', e);
        showToast('Vault check failed');
    }
}

/**
 * Relocate the vault to a place this device can write to.
 *
 * Desktop gets a folder (the conflict-free layout); Android has no folder
 * picker, so it falls back to a single file via the save dialog — the same
 * split every other storage flow uses. That fallback is the fix for the button
 * doing nothing on Android, where the folder picker always fails.
 *
 * The new location gets its own fresh keyslots, and the seed plus every
 * credential are copied in from the CURRENT store — captured before repointing,
 * because re-opening at an empty location refreshes the UI from an empty vault.
 * The old files are left untouched: a synced copy must never be yanked out from
 * under another device.
 */
async function moveVaultFile() {
    if (!vaultStore || !vault.privateKey) { showToast('Unlock vault first'); return; }
    if (!hasTauri()) { showToast('Native storage unavailable'); return; }

    const payload = vaultStore.snapshotPayload();
    const previousDir = vaultDirPath;
    const previousFile = vaultFilePath;

    const dir = await chooseVaultFolder();
    if (dir) {
        setVaultFilePath('');
    } else {
        const file = await chooseVaultFilePath();
        if (!file) return; // cancelled, or no picker on this platform
        setVaultDirPath('');
    }

    showLoading('Moving vault');
    try {
        await openVaultStore(_sessionMasterPassword, true);
        await vaultStore.apply(
            VaultRecords.opsFromSnapshotPayload(payload, vaultStore.clock, vaultStore.state)
        );
        await ensureWritableVaultPath();
        await saveUnlockedVaultSnapshot();
        syncVaultFromStore();
        renderSiteList();
        showToast('Vault moved');
    } catch (e) {
        // A failed move must not leave the app pointing at a location it could
        // not populate — restore the previous one exactly.
        setVaultDirPath(previousDir);
        setVaultFilePath(previousFile);
        console.error('moveVaultFile failed:', e);
        showToast('Could not move vault');
    } finally {
        hideLoading();
    }
}

async function setupVaultStorage() {
    const pass1 = document.getElementById('storagePass1').value;
    const pass2 = document.getElementById('storagePass2').value;
    const opening = vaultSetupMode === 'existing';

    if (!pass1) {
        showToast('Enter the vault password');
        return;
    }
    if (!opening) {
        if (pass1 !== pass2) {
            showToast('Passwords do not match');
            return;
        }
        if (pass1.length < 8) {
            showToast('Use at least 8 characters');
            return;
        }
    }
    if (!vaultDirPath && !vaultFilePath && hasTauri()) {
        const chosen = opening ? await chooseExistingVaultLocation() : await chooseNewVaultLocation();
        if (!chosen) return;
    }

    // Read the identity BEFORE opening the store: opening refreshes the UI's
    // view from what is on disk, so anything read afterwards is the vault's,
    // not the seed phrase the user just typed.
    const typed = {
        privateKey: vault.privateKey,
        seedPhrase: vault.seedPhrase,
        passphrase: vault.passphrase || ''
    };
    if (!opening && !typed.privateKey) {
        showToast('Set up a seed phrase first');
        return;
    }

    showLoading(opening ? 'Opening vault' : 'Creating vault');
    try {
        await openVaultStore(pass1, !opening);
        _sessionMasterPassword = pass1;

        const stored = vaultStore.getRecord(VaultRecords.IDENTITY_ID);
        const storedKey = stored && stored.privateKey;

        if (!storedKey) {
            // Empty vault (new, or an existing one with no identity yet).
            await vaultStore.setIdentity(typed);
            await vaultStore.setSettings({
                hashLength: vault.settings.hashLength || DEFAULT_HASH_LENGTH
            });
        } else if (typed.privateKey && storedKey !== typed.privateKey) {
            // The vault holds a DIFFERENT seed than the one just entered.
            // Its own seed wins: every password already in it was derived from
            // that seed, and overwriting it would silently change all of them.
            showToast('This vault has its own seed phrase — keeping it');
        }

        syncVaultFromStore();
        await ensureWritableVaultPath();
        setVaultSetupMode('new');
        document.getElementById('storagePass1').value = '';
        document.getElementById('storagePass2').value = '';
        showToast(opening ? 'Vault opened' : 'Vault saved');
        showScreen('mainScreen');
    } catch (e) {
        console.error('setupVaultStorage failed:', e);
        if (/Wrong password/.test(String(e && e.message))) {
            showToast('Wrong password for that vault');
        } else if (/No vault found/.test(String(e && e.message))) {
            showToast('No vault at that location — use New Vault Location');
        } else {
            showToast(opening ? 'Could not open vault' : 'Could not create vault');
        }
    } finally {
        hideLoading();
    }
}

/**
 * Android only: the open-file picker (ACTION_OPEN_DOCUMENT) grants a READ-only
 * persistable URI, so every later save to it fails. The save dialog
 * (ACTION_CREATE_DOCUMENT) is what grants persistable read+WRITE and can target
 * the file that is already there, so route the user through it once and verify
 * with a real write. A folder grant would avoid this entirely, but Android's
 * dialog plugin has no folder picker. Desktop paths have full access already.
 */
async function ensureWritableVaultPath() {
    if (!vaultFilePath.startsWith('content://') || vaultDirPath) return;
    try {
        await writeSelectedVaultFile();
        return; // already writable
    } catch (e) {
        debugLog('adopted vault URI is read-only, requesting a writable handle:', e);
    }

    alert(
        'One more step: Android needs write access to your vault.\n\n' +
        'In the next dialog select the SAME file again and confirm overwriting it. ' +
        'Your data is not replaced — this only grants permission to save.'
    );
    const writable = await tauriInvoke('choose_vault_file').catch(() => null);
    if (!writable) {
        showToast('Vault is read-only: saves will fail until you re-select the file');
        return;
    }
    setVaultFilePath(writable);
    await writeSelectedVaultFile();
}

/** Import a standalone vault file, merging it into the current vault. */
async function importVaultFile() {
    if (!hasTauri()) {
        showToast('Native file picker unavailable');
        return;
    }

    showLoading('Import vault file');
    try {
        const path = await tauriInvoke('open_vault_file');
        if (!path) return;

        const contents = await tauriInvoke('read_vault_file', { path });
        if (!VaultEnvelope.looksLikeVaultFile(contents)) throw new Error('invalid vault file');

        const password = prompt('Password for this vault file');
        if (!password) return;

        const result = await VaultEnvelope.decryptEnvelope(contents, password);
        const data = result.data;
        if (!data.users || typeof data.users !== 'object') throw new Error('invalid vault data');

        if (!vault.privateKey) {
            // Adopting a vault on a fresh install.
            if (hasTauri() && !vaultDirPath) await chooseVaultFolder();
            await openVaultStore(password, true);
            _sessionMasterPassword = password;
            await vaultStore.apply(
                VaultRecords.opsFromSnapshotPayload(data, vaultStore.clock, vaultStore.state)
            );
        } else {
            const siteCount = Object.values(data.users).reduce(
                (n, u) => n + Object.keys(u || {}).length,
                0
            );
            if (!confirm('Import ' + siteCount + ' site(s)? This merges with your current vault.')) return;
            await vaultStore.apply(
                VaultRecords.opsFromSnapshotPayload(data, vaultStore.clock, vaultStore.state)
            );
        }

        syncVaultFromStore();
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

/**
 * Change the master password.
 *
 * Keyslots make this cheap and safe: the vault master key is rewrapped under
 * the new password and the data is never re-encrypted, so the operation cannot
 * leave the vault half-converted.
 */
async function changeMasterPassword() {
    const current = document.getElementById('currentMasterPassword').value;
    const next = document.getElementById('newMasterPassword').value;
    const repeat = document.getElementById('confirmMasterPassword').value;
    if (!current || !next || !repeat) { showToast('Fill all password fields'); return; }
    if (next.length < 8) { showToast('Use at least 8 characters'); return; }
    if (next !== repeat) { showToast('New passwords do not match'); return; }
    if (!vaultStore) { showToast('Unlock vault first'); return; }

    showLoading('Changing password');
    try {
        // Verified by attempting the unwrap, not by comparing against a copy
        // of the password held in memory.
        await vaultStore.changePassword(current, next);
        _sessionMasterPassword = next;
        ['currentMasterPassword', 'newMasterPassword', 'confirmMasterPassword'].forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        showToast('Password changed — other devices update on next sync');
        showScreen('settingsScreen');
    } catch (e) {
        console.error('changeMasterPassword failed:', e);
        showToast(/Wrong password/.test(String(e && e.message)) ? 'Current password is wrong' : 'Could not change password');
    } finally {
        hideLoading();
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
        div.innerHTML = `<span>${i + 1}.</span>${escapeHtml(word)}`;
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
// Secure Notes
// ============================================

function renderNotesList() {
    const list = document.getElementById('notesList');
    const empty = document.getElementById('notesEmpty');
    if (!list) return;
    const notes = vaultStore ? vaultStore.listRecords(VaultRecords.TYPES.NOTE) : [];
    if (!notes.length) {
        list.innerHTML = '';
        if (empty) empty.classList.remove('hidden');
        return;
    }
    if (empty) empty.classList.add('hidden');
    list.innerHTML = notes
        .map(
            (n) => `
        <div class="site-item" data-note-id="${escapeHtml(n.id)}">
            <div class="site-info">
                <div class="site-name">${escapeHtml(n.title || '(untitled)')}</div>
                <div class="site-user">${escapeHtml((n.body || '').split('\n')[0].slice(0, 60))}</div>
            </div>
            <span class="chevron">›</span>
        </div>`
        )
        .join('');
}

function openNoteEdit(id) {
    const rec = id && vaultStore ? vaultStore.getRecord(id) : null;
    document.getElementById('noteEditId').value = rec ? rec.id : '';
    document.getElementById('noteTitle').value = rec ? rec.title || '' : '';
    document.getElementById('noteBody').value = rec ? rec.body || '' : '';
    document.getElementById('noteEditTitle').textContent = rec ? 'Edit Note' : 'New Note';
    const del = document.getElementById('btnDeleteNote');
    if (del) del.classList[rec ? 'remove' : 'add']('hidden');
    showScreen('noteEditScreen');
}

async function saveNote() {
    if (!vaultStore) { showToast('Unlock vault first'); return; }
    const title = document.getElementById('noteTitle').value.trim();
    const body = document.getElementById('noteBody').value;
    if (!title && !body.trim()) { showToast('Nothing to save'); return; }
    const id = document.getElementById('noteEditId').value || 'note:' + VaultUtil.randomHex(8);
    try {
        await vaultStore.putRecord(VaultRecords.TYPES.NOTE, id, { title, body });
        syncVaultFromStore();
        showToast('Note saved');
        showScreen('notesScreen');
    } catch (e) {
        console.error('saveNote failed:', e);
        showToast('Could not save note');
    }
}

async function deleteNote() {
    const id = document.getElementById('noteEditId').value;
    if (!id || !vaultStore) { showScreen('notesScreen'); return; }
    if (!confirm('Delete this note?')) return;
    try {
        await vaultStore.removeRecord(id);
        syncVaultFromStore();
        showToast('Note deleted');
    } catch (e) {
        console.error('deleteNote failed:', e);
        showToast('Could not delete note');
    }
    showScreen('notesScreen');
}

// ============================================
// Authenticator (TOTP)
// ============================================

async function renderTotpList() {
    const list = document.getElementById('totpList');
    const empty = document.getElementById('totpEmpty');
    if (!list) return;
    const tokens = vaultStore ? vaultStore.listRecords(VaultRecords.TYPES.TOTP) : [];
    if (!tokens.length) {
        list.innerHTML = '';
        if (empty) empty.classList.remove('hidden');
        return;
    }
    if (empty) empty.classList.add('hidden');
    const rows = await Promise.all(
        tokens.map(async (tk) => {
            let raw = '';
            let shown = '------';
            let remaining = 0;
            try {
                const r = await VaultTotp.generate(tk.secret, {
                    period: tk.period,
                    digits: tk.digits,
                    algorithm: tk.algorithm
                });
                raw = r.code;
                shown = r.code.replace(/(\d{3})(\d.*)/, '$1 $2');
                remaining = r.secondsRemaining;
            } catch (e) {
                shown = 'bad secret';
            }
            const label = [tk.issuer, tk.account].filter(Boolean).join(' · ') || '(unnamed)';
            return `
        <div class="site-item" data-totp-id="${escapeHtml(tk.id)}" data-code="${escapeHtml(raw)}">
            <div class="site-info">
                <div class="site-name">${escapeHtml(label)}</div>
                <div class="site-user">expires in ${remaining}s · tap to copy</div>
            </div>
            <div class="password-value" style="font-size:1.1rem">${escapeHtml(shown)}</div>
        </div>`;
        })
    );
    list.innerHTML = rows.join('');
}

function openAddTotp() {
    ['totpUri', 'totpIssuer', 'totpAccount', 'totpSecret'].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    showScreen('totpAddScreen');
}

async function addTotp() {
    if (!vaultStore) { showToast('Unlock vault first'); return; }
    const uri = document.getElementById('totpUri').value.trim();
    let issuer = document.getElementById('totpIssuer').value.trim();
    let account = document.getElementById('totpAccount').value.trim();
    let secret = document.getElementById('totpSecret').value.trim();
    let digits = 6;
    let period = 30;
    let algorithm = 'SHA1';

    if (uri) {
        const p = VaultTotp.parseOtpauth(uri);
        if (!p) { showToast('Not a valid otpauth:// link'); return; }
        issuer = issuer || p.issuer;
        account = account || p.account;
        secret = p.secret;
        digits = p.digits;
        period = p.period;
        algorithm = p.algorithm;
    }
    if (!secret) { showToast('Enter a secret or otpauth link'); return; }
    try {
        VaultTotp.base32Decode(secret);
    } catch (e) {
        showToast('Secret is not valid base32');
        return;
    }
    try {
        await vaultStore.putRecord(VaultRecords.TYPES.TOTP, 'totp:' + VaultUtil.randomHex(8), {
            issuer, account, secret, digits, period, algorithm
        });
        showToast('2FA code added');
        showScreen('totpScreen');
    } catch (e) {
        console.error('addTotp failed:', e);
        showToast('Could not add code');
    }
}

// ============================================
// CSV import / export (other password managers)
// ============================================

async function importCsvText() {
    if (!vaultStore) { showToast('Unlock vault first'); return; }
    const text = document.getElementById('csvImportText').value;
    const entries = VaultPorter.importCsv(text);
    if (!entries.length) {
        showToast('No rows found — need a site/username column');
        return;
    }
    const ops = [];
    let notes = 0;
    for (const e of entries) {
        ops.push(
            vaultStore.opFor(VaultRecords.credentialId(e.user, e.site), VaultRecords.TYPES.CREDENTIAL, {
                user: e.user,
                site: e.site
            })
        );
        if (e.password || e.note) {
            const body = [
                e.user && 'Username: ' + e.user,
                e.password && 'Old password: ' + e.password,
                e.note
            ]
                .filter(Boolean)
                .join('\n');
            ops.push(
                vaultStore.opFor('note:' + VaultUtil.randomHex(8), VaultRecords.TYPES.NOTE, {
                    title: 'Imported: ' + e.site + (e.user ? ' (' + e.user + ')' : ''),
                    body
                })
            );
            notes++;
        }
    }
    try {
        await vaultStore.apply(ops);
        syncVaultFromStore();
        document.getElementById('csvImportText').value = '';
        renderSiteList();
        showToast(`Imported ${entries.length} site(s)` + (notes ? `, ${notes} note(s)` : ''));
        showScreen('mainScreen');
    } catch (e) {
        console.error('importCsvText failed:', e);
        showToast('Import failed');
    }
}

function renderCsvExport() {
    const ta = document.getElementById('csvExportText');
    if (!ta) return;
    const hl = vault.settings.hashLength || DEFAULT_HASH_LENGTH;
    const rows = [];
    Object.entries(vault.users || {}).forEach(([user, sites]) => {
        Object.entries(sites || {}).forEach(([site, nonce]) => {
            rows.push({
                name: site,
                url: site,
                username: user,
                password: generatePassword(vault.privateKey, user, site, Number(nonce) || 0, hl)
            });
        });
    });
    ta.value = VaultPorter.exportCsv(rows);
}

async function copyCsvExport() {
    const ta = document.getElementById('csvExportText');
    if (!ta || !ta.value) { showToast('Nothing to export'); return; }
    try {
        await navigator.clipboard.writeText(ta.value);
        showToast('CSV copied — it holds plaintext passwords, handle with care');
    } catch (e) {
        showToast('Copy failed');
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

    // ── Delegated notes + authenticator list events ──
    const notesList = document.getElementById('notesList');
    if (notesList) {
        notesList.addEventListener('click', (e) => {
            const item = e.target.closest('[data-note-id]');
            if (item) openNoteEdit(item.dataset.noteId);
        });
    }
    const totpList = document.getElementById('totpList');
    if (totpList) {
        totpList.addEventListener('click', (e) => {
            const item = e.target.closest('[data-totp-id]');
            if (item && item.dataset.code) {
                navigator.clipboard
                    .writeText(item.dataset.code)
                    .then(() => showToast('Code copied'))
                    .catch(() => {});
            }
        });
    }

    // ── Individual button bindings ──
    const btnBindings = {
        btnGenerateNewSeed: () => generateNewSeed(),
        btnConfirmSeedBackup: () => confirmSeedBackup(),
        btnVerifySeedBackup: () => verifySeedBackup(),
        btnRestoreFromSeed: () => restoreFromSeed(),
        btnChooseVaultPath: () => chooseNewVaultLocation(),
        btnOpenExistingVault: () => chooseExistingVaultLocation(),
        btnSetupVaultStorage: () => setupVaultStorage(),
        btnCheckVaultFile: () => checkVaultFileHealth(),
        btnMoveVaultFile: () => moveVaultFile(),
        btnChangeMasterPassword: () => changeMasterPassword(),
        btnAddSite: () => addSiteFromSearch(),
        btnLockVault: () => lockVault(),
        btnResetDevice: () => resetThisDevice(),
        btnResetDeviceUnlock: () => resetThisDevice(),
        btnUnlockVault: () => unlockVault(),
        btnDecrementNonce: () => decrementNonce(),
        btnIncrementNonce: () => incrementNonce(),
        btnToggleVisibility: () => togglePasswordVisibility(),
        btnSaveAndCopy: () => saveAndCopy(),
        btnExportVaultFile: () => exportVaultFile(),
        btnImportVaultFile: () => importVaultFile(),
        btnMergeSyncConflicts: () => mergeSyncConflictFiles(),
        btnCopySeedPhrase: () => copySeedPhrase(),
        btnAddNote: () => openNoteEdit(null),
        btnSaveNote: () => saveNote(),
        btnDeleteNote: () => deleteNote(),
        btnAddTotp: () => openAddTotp(),
        btnSaveTotp: () => addTotp(),
        btnDoImportCsv: () => importCsvText(),
        btnCopyCsvExport: () => copyCsvExport(),
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
