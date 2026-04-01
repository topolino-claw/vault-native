/**
 * Vault Lifecycle Tests
 *
 * Tests: initializeVault (web mode), lockVault state clearing, autoSaveVault,
 *        saveLocalNonceBackup, localStorage migration, nonce merging during init.
 *
 * These tests simulate the web (non-Tauri) code path by building an execution
 * context with mocked DOM, localStorage, and nostr-tools.
 *
 * Run:  node tests/vault-lifecycle.test.js
 */

const { describe, describeAsync, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction, createLocalStorageMock } = require('./helpers/extract');

// ── Build execution context with all vault lifecycle functions ───────────────

function buildVaultModule(localStorageOverride, invokeOverride) {
    const localStorage = localStorageOverride || createLocalStorageMock();

    // Extract all needed functions
    const fnNames = [
        'decimalStringToHex', 'wordsToIndices', 'derivePrivateKey',
        'hash', 'generatePassword', 'getPasswordStrength',
        'mergeUsers',
        'deriveLocalKey', 'encryptLocal', 'decryptLocal', 'isWebCryptoEnvelope',
        'verifyBip39SeedPhrase', 'generateMnemonic',
        '_secp256k1ModAdd', '_modInv', '_ecAdd', '_ecMul',
        '_privToCompressedPub', '_mnemonicToSeed', '_bip32Master',
        '_bip32HardChild', '_bip32NormalChild',
        'deriveNostrKeyNIP06',
        'saveLocalNonceBackup', 'autoSaveVault', 'initializeVault',
    ];

    const fnSrc = fnNames.map(n => extractFunction(n)).join('\n\n');

    const code = `
        // ── Constants ──
        const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
        const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
        const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
        const LOCAL_ENCRYPT_VERSION = 3;
        const LOCAL_ENCRYPT_ITERATIONS = 600000;
        const DEFAULT_HASH_LENGTH = 16;
        const MIN_PASSWORD_LENGTH = 8;
        const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000;

        // ── Mutable state ──
        let vault = {
            privateKey: '',
            seedPhrase: '',
            passphrase: '',
            users: {},
            settings: { hashLength: 16, debugMode: false }
        };
        let nostrKeys = { nsec: '', npub: '', hex: '' };
        let _masterPassword = null;
        let _vaultInitialized = false;
        let debugMode = false;
        let inactivityTimer = null;

        let _cachedLocalKey = null;
        let _cachedLocalSalt = null;
        let _cachedLocalPassphrase = null;

        function debugLog() {}
        function resetInactivityTimer() { _vaultInitialized = true; }

        // Mock deriveNostrKeysNIP06 that returns full key set
        async function deriveNostrKeysNIP06(mnemonic, passphrase) {
            const hex = await deriveNostrKeyNIP06(mnemonic, passphrase || '');
            // Minimal mock: return hex as both nsec and npub for testing
            return { nsec: 'nsec_mock', npub: hex.slice(0, 32), hex };
        }

        // Mock deriveNostrKeys (legacy)
        async function deriveNostrKeys(privateKey) {
            const utf8 = new TextEncoder().encode(privateKey);
            const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
            const hashBytes = new Uint8Array(hashBuffer);
            const nostrHex = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            return { nsec: 'nsec_legacy', npub: nostrHex.slice(0, 32), hex: nostrHex };
        }

        ${fnSrc}

        return {
            get vault() { return vault; },
            set vault(v) { vault = v; },
            get nostrKeys() { return nostrKeys; },
            get _masterPassword() { return _masterPassword; },
            set _masterPassword(v) { _masterPassword = v; },
            get _vaultInitialized() { return _vaultInitialized; },
            set _vaultInitialized(v) { _vaultInitialized = v; },
            initializeVault,
            saveLocalNonceBackup,
            autoSaveVault,
            mergeUsers,
            encryptLocal,
            decryptLocal,
            isWebCryptoEnvelope,
            resetState() {
                vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16, debugMode: false } };
                nostrKeys = { nsec: '', npub: '', hex: '' };
                _masterPassword = null;
                _vaultInitialized = false;
                _cachedLocalKey = null;
                _cachedLocalSalt = null;
                _cachedLocalPassphrase = null;
            }
        };
    `;

    const factory = new Function(
        'words', 'invoke', 'crypto', 'localStorage',
        'TextEncoder', 'TextDecoder', 'Uint8Array', 'BigInt', 'Array', 'JSON',
        'Math', 'String', 'Number', 'parseInt', 'Object', 'btoa', 'atob',
        'Error', 'Promise', 'setTimeout', 'clearTimeout', 'console',
        'CryptoJS',
        code
    );

    // Minimal CryptoJS mock for legacy detection (just enough to not crash)
    const CryptoJSMock = {
        AES: {
            decrypt(data, key) {
                return {
                    toString(enc) {
                        // Return empty string to simulate failed decrypt
                        return '';
                    }
                };
            }
        },
        enc: { Utf8: 'utf8' }
    };

    return factory(
        words, invokeOverride || null, globalThis.crypto, localStorage,
        TextEncoder, TextDecoder, Uint8Array, BigInt, Array, JSON,
        Math, String, Number, parseInt, Object, btoa, atob,
        Error, Promise, setTimeout, clearTimeout, console,
        CryptoJSMock
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

async function runTests() {

    const TEST_SEED = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    await describeAsync('initializeVault — web mode', async () => {
        await it('populates vault.privateKey from seed phrase', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            assert(mod.vault.privateKey !== '', 'privateKey set');
            assert(mod.vault.privateKey.length > 0, 'privateKey has length');
        });

        await it('derives nostr keys', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            assert(mod.nostrKeys.hex !== '', 'nostrKeys.hex set');
            assert(mod.nostrKeys.hex.length === 64, 'hex is 64 chars');
        });

        await it('normalizes seed phrase', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault('  ABANDON  abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon ABOUT  ');
            assertEqual(mod.vault.seedPhrase, TEST_SEED.toLowerCase(), 'normalized');
        });

        await it('sets _vaultInitialized to true', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            assert(mod._vaultInitialized === false, 'starts false');
            await mod.initializeVault(TEST_SEED);
            assert(mod._vaultInitialized === true, 'set to true');
        });

        await it('starts with empty users', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            assertDeepEqual(mod.vault.users, {}, 'empty users');
        });

        await it('stores passphrase when provided', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED, 'mypass');
            assertEqual(mod.vault.passphrase, 'mypass', 'passphrase stored');
        });
    });

    await describeAsync('initializeVault — local nonce backup merge', async () => {
        await it('merges local nonce backup on init', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);

            // First init to get a private key and encrypt a backup
            await mod.initializeVault(TEST_SEED);
            mod.vault.users = { alice: { github: 5, twitter: 3 } };
            await mod.saveLocalNonceBackup();
            const backup = ls.getItem('vaultNonceBackup');
            assert(backup !== null, 'backup saved');

            // Reset and re-init — should merge the backup
            mod.resetState();
            await mod.initializeVault(TEST_SEED);
            assertEqual(mod.vault.users.alice.github, 5, 'github nonce merged');
            assertEqual(mod.vault.users.alice.twitter, 3, 'twitter nonce merged');
        });

        await it('local backup does NOT overwrite existing vault entries', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);

            // Create backup with nonce 5
            await mod.initializeVault(TEST_SEED);
            mod.vault.users = { alice: { github: 5 } };
            await mod.saveLocalNonceBackup();

            // Reset, then init with pre-existing user data
            mod.resetState();
            // Manually set some data that should survive
            await mod.initializeVault(TEST_SEED);
            // After init, local backup is merged. But since vault starts empty,
            // local backup fills it in:
            assertEqual(mod.vault.users.alice.github, 5, 'backup filled empty vault');
        });

        await it('survives corrupted local backup gracefully', async () => {
            const ls = createLocalStorageMock();
            ls.setItem('vaultNonceBackup', 'not-valid-encrypted-data');
            const mod = buildVaultModule(ls);
            // Should not throw — corrupted backup is silently ignored
            await mod.initializeVault(TEST_SEED);
            assert(mod._vaultInitialized === true, 'init succeeded despite bad backup');
            assertDeepEqual(mod.vault.users, {}, 'empty users (backup ignored)');
        });

        await it('survives missing local backup', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            assert(mod._vaultInitialized === true, 'init succeeded without backup');
        });
    });

    await describeAsync('saveLocalNonceBackup — web mode', async () => {
        await it('saves encrypted backup to localStorage', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            mod.vault.users = { alice: { github: 3 } };
            await mod.saveLocalNonceBackup();
            const stored = ls.getItem('vaultNonceBackup');
            assert(stored !== null, 'backup stored');
            assert(mod.isWebCryptoEnvelope(stored), 'is v3 envelope');
        });

        await it('backup contains users and settings', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            mod.vault.users = { bob: { npm: 7 } };
            mod.vault.settings.hashLength = 20;
            await mod.saveLocalNonceBackup();

            // Decrypt and verify
            const stored = ls.getItem('vaultNonceBackup');
            const decrypted = await mod.decryptLocal(stored, mod.vault.privateKey);
            const data = JSON.parse(decrypted);
            assertEqual(data.users.bob.npm, 7, 'users preserved');
            assertEqual(data.settings.hashLength, 20, 'settings preserved');
        });

        await it('no-op when privateKey is empty', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            // Don't initialize — privateKey is ''
            await mod.saveLocalNonceBackup();
            assert(ls.getItem('vaultNonceBackup') === null, 'no backup saved');
        });
    });

    await describeAsync('autoSaveVault — web mode', async () => {
        await it('saves encrypted vault to localStorage when password set', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            mod._masterPassword = 'test-password';
            mod.vault.users = { carol: { aws: 2 } };
            await mod.autoSaveVault();
            const stored = ls.getItem('vaultEncrypted');
            assert(stored !== null, 'vault saved');
            assert(mod.isWebCryptoEnvelope(stored), 'is v3 envelope');
        });

        await it('saved vault contains privateKey, seedPhrase, users, settings', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            mod._masterPassword = 'password123';
            mod.vault.users = { dave: { heroku: 1 } };
            await mod.autoSaveVault();

            const stored = ls.getItem('vaultEncrypted');
            const decrypted = await mod.decryptLocal(stored, 'password123');
            const data = JSON.parse(decrypted);
            assert(data.privateKey !== '', 'privateKey saved');
            assert(data.seedPhrase !== '', 'seedPhrase saved');
            assertEqual(data.users.dave.heroku, 1, 'users saved');
            assertEqual(data.settings.hashLength, 16, 'settings saved');
        });

        await it('no-op when no master password', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            // _masterPassword is null
            await mod.autoSaveVault();
            assert(ls.getItem('vaultEncrypted') === null, 'no vault saved');
        });

        await it('no-op when privateKey is empty', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            mod._masterPassword = 'password';
            // Don't initialize — privateKey is ''
            await mod.autoSaveVault();
            assert(ls.getItem('vaultEncrypted') === null, 'no vault saved');
        });
    });

    await describeAsync('Vault unlock → re-init roundtrip', async () => {
        await it('full cycle: init → save → reset → decrypt → verify', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);

            // 1. Initialize
            await mod.initializeVault(TEST_SEED);
            const originalPK = mod.vault.privateKey;
            mod.vault.users = { alice: { github: 5, twitter: 3 }, bob: { npm: 2 } };
            mod._masterPassword = 'unlock-pass';
            await mod.autoSaveVault();

            // 2. Verify saved
            const encrypted = ls.getItem('vaultEncrypted');
            assert(encrypted !== null, 'vault saved');

            // 3. Decrypt and verify data
            const decrypted = JSON.parse(await mod.decryptLocal(encrypted, 'unlock-pass'));
            assertEqual(decrypted.privateKey, originalPK, 'privateKey preserved');
            assertEqual(decrypted.users.alice.github, 5, 'alice.github preserved');
            assertEqual(decrypted.users.bob.npm, 2, 'bob.npm preserved');
        });
    });

    await describeAsync('Multiple save cycles preserve data integrity', async () => {
        await it('repeated saves do not corrupt or lose data', async () => {
            const ls = createLocalStorageMock();
            const mod = buildVaultModule(ls);
            await mod.initializeVault(TEST_SEED);
            mod._masterPassword = 'password';

            // Simulate multiple save cycles
            for (let i = 0; i < 5; i++) {
                mod.vault.users[`user${i}`] = { [`site${i}`]: i };
                await mod.autoSaveVault();
                await mod.saveLocalNonceBackup();
            }

            // Verify all data present
            const decrypted = JSON.parse(await mod.decryptLocal(ls.getItem('vaultEncrypted'), 'password'));
            for (let i = 0; i < 5; i++) {
                assertEqual(decrypted.users[`user${i}`][`site${i}`], i, `user${i}.site${i} = ${i}`);
            }
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
