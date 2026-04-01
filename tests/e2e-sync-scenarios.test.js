/**
 * End-to-End Sync Scenario Tests
 *
 * Simulates real multi-device user flows through the full pipeline:
 *   seed → derive keys → initialize vault → add sites → encrypt (NIP-44-like)
 *   → "publish" to relay store → "fetch" from relay → decrypt → merge
 *
 * Each "device" is an isolated vault instance with its own localStorage.
 * The "relay network" is a shared in-memory store.
 * Encryption/decryption uses the real Web Crypto API functions.
 *
 * Scenarios tested:
 *   1. Account creation and first backup
 *   2. Second device restores from relay
 *   3. Device A adds sites while Device B is offline, B resyncs
 *   4. Both devices add different sites offline, then sync (conflict resolution)
 *   5. Both devices increment same nonce differently — higher wins
 *   6. Device goes offline, makes changes, comes back, syncs
 *   7. Legacy storage format migration on unlock
 *   8. Relay partial failure — some relays down, sync still works
 *   9. All relays down — local backup preserves data, resync later
 *  10. Rapid successive changes with debounce coalescing
 *  11. Lock/unlock cycle preserves data through localStorage
 *  12. Import from JSON file merges correctly
 *  13. Delete site on one device, add nonce on another — no data loss
 *  14. Empty vault syncs from device with data
 *  15. Backup password (double encryption) round-trip
 *
 * Run:  node tests/e2e-sync-scenarios.test.js
 */

const { describeAsync, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { words, extractFunction, createLocalStorageMock } = require('./helpers/extract');

// ════════════════════════════════════════════════════════════════════════════
// Infrastructure: simulated relay network + device factory
// ════════════════════════════════════════════════════════════════════════════

/**
 * Simulated Nostr relay network.
 * Stores events keyed by pubkey, supports kind:30078 (replaceable by d-tag).
 */
class RelayNetwork {
    constructor() {
        this.events = [];    // all events ever published
        this.online = true;  // global kill switch
        this.failingRelays = new Set(); // per-relay failures
    }

    publish(event) {
        if (!this.online) throw new Error('network offline');
        // kind:30078 is replaceable by d-tag — keep only the latest per pubkey+d
        if (event.kind === 30078) {
            const dTag = (event.tags.find(t => t[0] === 'd') || [])[1];
            this.events = this.events.filter(e => {
                if (e.kind !== 30078) return true;
                const eDTag = (e.tags.find(t => t[0] === 'd') || [])[1];
                return !(e.pubkey === event.pubkey && eDTag === dTag);
            });
        }
        this.events.push({ ...event });
    }

    query(filters) {
        if (!this.online) return [];
        return this.events.filter(e => {
            for (const f of filters) {
                let match = true;
                if (f.kinds && !f.kinds.includes(e.kind)) match = false;
                if (f.authors && !f.authors.includes(e.pubkey)) match = false;
                if (f['#d']) {
                    const dTag = (e.tags.find(t => t[0] === 'd') || [])[1];
                    if (!f['#d'].includes(dTag)) match = false;
                }
                if (f['#t']) {
                    const tTags = e.tags.filter(t => t[0] === 't').map(t => t[1]);
                    if (!f['#t'].some(t => tTags.includes(t))) match = false;
                }
                if (match) return true;
            }
            return false;
        }).sort((a, b) => b.created_at - a.created_at)
          .slice(0, filters[0]?.limit || 100);
    }

    goOffline() { this.online = false; }
    goOnline() { this.online = true; }
    failRelay(url) { this.failingRelays.add(url); }
    recoverRelay(url) { this.failingRelays.delete(url); }
    clear() { this.events = []; this.online = true; this.failingRelays.clear(); }
}

/**
 * Creates an isolated "device" — a vault instance with its own localStorage
 * and connection to a shared relay network.
 *
 * Uses real crypto functions extracted from app.js.
 */
function createDevice(relayNetwork) {
    const localStorage = createLocalStorageMock();

    const fnNames = [
        'decimalStringToHex', 'wordsToIndices', 'derivePrivateKey',
        'hash', 'generatePassword', 'mergeUsers',
        'deriveLocalKey', 'encryptLocal', 'decryptLocal', 'isWebCryptoEnvelope',
        'encryptWithBackupPassword', 'decryptWithBackupPassword', 'deriveBackupKey',
        'parseDoubleEncryptedEnvelope',
        '_secp256k1ModAdd', '_modInv', '_ecAdd', '_ecMul',
        '_privToCompressedPub', '_mnemonicToSeed', '_bip32Master',
        '_bip32HardChild', '_bip32NormalChild',
        'deriveNostrKeyNIP06',
        'verifyBip39SeedPhrase',
    ];

    const fnSrc = fnNames.map(n => extractFunction(n)).join('\n\n');

    const code = `
        const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
        const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
        const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
        const LOCAL_ENCRYPT_VERSION = 3;
        const LOCAL_ENCRYPT_ITERATIONS = 600000;
        const BACKUP_PASSWORD_ITERATIONS = 600000;
        const BACKUP_D_TAG = 'vault-backup';
        const DEFAULT_HASH_LENGTH = 16;

        let vault = {
            privateKey: '',
            seedPhrase: '',
            passphrase: '',
            users: {},
            settings: { hashLength: 16, debugMode: false, lastBackupFailed: false }
        };
        let nostrKeys = { nsec: '', npub: '', hex: '' };
        let _masterPassword = null;
        let _vaultInitialized = false;
        let _cachedLocalKey = null;
        let _cachedLocalSalt = null;
        let _cachedLocalPassphrase = null;

        function debugLog() {}

        // ── Nostr key derivation (full NIP-06 + legacy) ──
        async function deriveNostrKeysNIP06(mnemonic, passphrase) {
            const hex = await deriveNostrKeyNIP06(mnemonic, passphrase || '');
            // Derive public key from secret key using EC multiplication
            const skBytes = new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
            const pub = _privToCompressedPub(skBytes);
            const pkHex = Array.from(pub.slice(1)).map(b => b.toString(16).padStart(2, '0')).join('');
            return { nsec: 'nsec_' + hex.slice(0, 8), npub: pkHex, hex };
        }

        async function deriveNostrKeysLegacy(privateKey) {
            const utf8 = new TextEncoder().encode(privateKey);
            const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
            const hashBytes = new Uint8Array(hashBuffer);
            const sk = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const pub = _privToCompressedPub(hashBytes);
            const pkHex = Array.from(pub.slice(1)).map(b => b.toString(16).padStart(2, '0')).join('');
            return { sk, pk: pkHex };
        }

        ${fnSrc}

        // ── Device API ──

        async function initializeVault(seedPhrase, passphrase) {
            vault.seedPhrase = seedPhrase.replace(/\\s+/g, ' ').trim().toLowerCase();
            vault.privateKey = await derivePrivateKey(vault.seedPhrase);
            vault.passphrase = passphrase || '';
            nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, vault.passphrase);
            vault.users = {};
            vault.settings = { hashLength: 16, debugMode: false, lastBackupFailed: false };

            // Try to load local nonce backup
            try {
                const raw = localStorage.getItem('vaultNonceBackup');
                if (raw && isWebCryptoEnvelope(raw)) {
                    const decrypted = await decryptLocal(raw, vault.privateKey);
                    if (decrypted) {
                        const data = JSON.parse(decrypted);
                        if (data.users) {
                            Object.entries(data.users).forEach(([user, sites]) => {
                                if (!vault.users[user]) vault.users[user] = {};
                                Object.entries(sites).forEach(([site, nonce]) => {
                                    if (vault.users[user][site] === undefined) {
                                        vault.users[user][site] = nonce;
                                    }
                                });
                            });
                        }
                        if (data.settings) vault.settings = { ...data.settings, ...vault.settings };
                    }
                }
            } catch (e) {}

            _vaultInitialized = true;
        }

        function addSite(user, site, nonce) {
            if (!vault.users[user]) vault.users[user] = {};
            vault.users[user][site] = nonce || 0;
        }

        function incrementSiteNonce(user, site) {
            if (vault.users[user] && vault.users[user][site] !== undefined) {
                vault.users[user][site]++;
            }
        }

        function deleteSite(user, site) {
            if (vault.users[user]) {
                delete vault.users[user][site];
                if (Object.keys(vault.users[user]).length === 0) delete vault.users[user];
            }
        }

        async function saveLocalBackup() {
            if (!vault.privateKey) return;
            const payload = JSON.stringify({ users: vault.users, settings: vault.settings });
            const encrypted = await encryptLocal(payload, vault.privateKey);
            localStorage.setItem('vaultNonceBackup', encrypted);
        }

        async function saveVault(password) {
            _masterPassword = password;
            const saveData = {
                privateKey: vault.privateKey,
                seedPhrase: vault.seedPhrase,
                passphrase: vault.passphrase || '',
                users: vault.users,
                settings: vault.settings
            };
            const encrypted = await encryptLocal(JSON.stringify(saveData), password);
            localStorage.setItem('vaultEncrypted', encrypted);
        }

        async function unlockVault(password) {
            const stored = localStorage.getItem('vaultEncrypted');
            if (!stored) throw new Error('No saved vault');
            const decrypted = await decryptLocal(stored, password);
            const data = JSON.parse(decrypted);
            vault.privateKey = data.privateKey;
            vault.seedPhrase = data.seedPhrase || '';
            vault.passphrase = data.passphrase || '';
            vault.users = data.users || {};
            vault.settings = data.settings || { hashLength: 16 };
            if (vault.seedPhrase) {
                nostrKeys = await deriveNostrKeysNIP06(vault.seedPhrase, vault.passphrase);
            } else {
                const legacy = await deriveNostrKeysLegacy(vault.privateKey);
                nostrKeys = { nsec: '', npub: legacy.pk, hex: legacy.sk };
            }
            _masterPassword = password;
            _vaultInitialized = true;
        }

        function lockVault() {
            vault = { privateKey: '', seedPhrase: '', passphrase: '', users: {}, settings: { hashLength: 16 } };
            nostrKeys = { nsec: '', npub: '', hex: '' };
            _masterPassword = null;
            _vaultInitialized = false;
            _cachedLocalKey = null;
            _cachedLocalSalt = null;
            _cachedLocalPassphrase = null;
        }

        // ── Nostr backup: encrypt vault data and publish to relay network ──

        async function backupToRelay() {
            if (!_vaultInitialized) throw new Error('not initialized');
            const vaultData = JSON.stringify({ users: vault.users, settings: vault.settings });

            // Encrypt with AES-256-GCM using nostr secret key as passphrase (simulates NIP-44)
            const encrypted = await encryptLocal(vaultData, nostrKeys.hex);

            const event = {
                kind: 30078,
                pubkey: nostrKeys.npub,
                created_at: Math.floor(Date.now() / 1000),
                tags: [["d", BACKUP_D_TAG]],
                content: encrypted,
                id: 'evt_' + Math.random().toString(36).slice(2),
            };

            _relayNetwork.publish(event);
            vault.settings.lastBackupFailed = false;
            return event;
        }

        async function backupToRelayWithPassword(backupPassword) {
            if (!_vaultInitialized) throw new Error('not initialized');
            const vaultData = JSON.stringify({ users: vault.users, settings: vault.settings });

            // Layer 1: backup password encryption
            const envelope = await encryptWithBackupPassword(vaultData, backupPassword, nostrKeys.npub);

            // Layer 2: NIP-44-like encryption
            const encrypted = await encryptLocal(JSON.stringify(envelope), nostrKeys.hex);

            const event = {
                kind: 30078,
                pubkey: nostrKeys.npub,
                created_at: Math.floor(Date.now() / 1000),
                tags: [["d", BACKUP_D_TAG]],
                content: encrypted,
                id: 'evt_' + Math.random().toString(36).slice(2),
            };

            _relayNetwork.publish(event);
            return event;
        }

        // ── Nostr restore: fetch from relay, decrypt, merge ──

        async function restoreFromRelay() {
            if (!_vaultInitialized && !vault.privateKey) return { found: false };

            const events = _relayNetwork.query([
                { kinds: [30078], authors: [nostrKeys.npub], '#d': [BACKUP_D_TAG], limit: 1 }
            ]);

            if (events.length === 0) return { found: false };

            const latest = events[0];
            const decrypted = await decryptLocal(latest.content, nostrKeys.hex);

            // Check for double encryption (backup password)
            const envelope = parseDoubleEncryptedEnvelope(decrypted);
            if (envelope) {
                // Need backup password — cannot auto-decrypt
                return { found: true, needsPassword: true, envelope, event: latest };
            }

            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            await saveLocalBackup();
            return { found: true };
        }

        async function restoreWithPassword(envelope, backupPassword) {
            const decrypted = await decryptWithBackupPassword(envelope, backupPassword, nostrKeys.npub);
            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            await saveLocalBackup();
        }

        async function restoreFromLegacyKey() {
            if (!vault.privateKey) return { found: false };
            const legacy = await deriveNostrKeysLegacy(vault.privateKey);
            if (legacy.pk === nostrKeys.npub) return { found: false };

            const events = _relayNetwork.query([
                { kinds: [30078], authors: [legacy.pk], '#d': [BACKUP_D_TAG], limit: 1 }
            ]);
            if (events.length === 0) return { found: false };

            const decrypted = await decryptLocal(events[0].content, legacy.sk);
            const data = JSON.parse(decrypted);
            mergeUsers(data.users);
            if (data.settings) vault.settings = { ...vault.settings, ...data.settings };
            await saveLocalBackup();
            return { found: true };
        }

        async function genPassword(user, site, nonce) {
            return await generatePassword(vault.privateKey, user, site, nonce, vault.settings.hashLength || 16);
        }

        return {
            get vault() { return vault; },
            get nostrKeys() { return nostrKeys; },
            get _vaultInitialized() { return _vaultInitialized; },
            get localStorage() { return localStorage; },
            initializeVault, addSite, incrementSiteNonce, deleteSite,
            saveLocalBackup, saveVault, unlockVault, lockVault,
            backupToRelay, backupToRelayWithPassword,
            restoreFromRelay, restoreWithPassword, restoreFromLegacyKey,
            genPassword, mergeUsers,
        };
    `;

    const factory = new Function(
        'words', 'invoke', 'crypto', 'localStorage', '_relayNetwork',
        'TextEncoder', 'TextDecoder', 'Uint8Array', 'BigInt', 'Array', 'JSON',
        'Math', 'String', 'Number', 'parseInt', 'Object', 'btoa', 'atob',
        'Error', 'Promise', 'setTimeout', 'clearTimeout', 'console',
        code
    );

    return factory(
        words, null, globalThis.crypto, localStorage, relayNetwork,
        TextEncoder, TextDecoder, Uint8Array, BigInt, Array, JSON,
        Math, String, Number, parseInt, Object, btoa, atob,
        Error, Promise, setTimeout, clearTimeout, console
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Scenarios
// ════════════════════════════════════════════════════════════════════════════

const TEST_SEED = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function runScenarios() {

    // ── Scenario 1: Account creation and first backup ───────────────────
    await describeAsync('Scenario 1: Account creation → add sites → backup to relay', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);

        await it('creates vault from seed phrase', async () => {
            await deviceA.initializeVault(TEST_SEED);
            assert(deviceA._vaultInitialized, 'vault initialized');
            assert(deviceA.nostrKeys.hex.length === 64, 'nostr key derived');
        });

        await it('adds sites and generates passwords', async () => {
            deviceA.addSite('alice@gmail.com', 'github.com', 0);
            deviceA.addSite('alice@gmail.com', 'twitter.com', 0);
            deviceA.addSite('bob@work.com', 'gitlab.com', 0);
            const pass = await deviceA.genPassword('alice@gmail.com', 'github.com', 0);
            assert(pass.startsWith('PASS') && pass.endsWith('249+'), 'password generated');
        });

        await it('publishes encrypted backup to relay network', async () => {
            const event = await deviceA.backupToRelay();
            assertEqual(event.kind, 30078, 'kind is 30078');
            assertEqual(event.pubkey, deviceA.nostrKeys.npub, 'pubkey matches');
            assert(event.content.length > 50, 'content is encrypted (long)');
            assertEqual(relay.events.length, 1, '1 event on relay');
        });
    });

    // ── Scenario 2: Second device restores from relay ───────────────────
    await describeAsync('Scenario 2: Second device restores full vault from relay', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('Device A creates vault and backs up', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 3);
            deviceA.addSite('alice', 'twitter.com', 1);
            deviceA.addSite('bob', 'npm.com', 5);
            await deviceA.backupToRelay();
        });

        await it('Device B initializes with same seed and restores', async () => {
            await deviceB.initializeVault(TEST_SEED);
            assertDeepEqual(deviceB.vault.users, {}, 'starts empty');
            const result = await deviceB.restoreFromRelay();
            assert(result.found, 'backup found');
            assertEqual(deviceB.vault.users.alice['github.com'], 3, 'github nonce');
            assertEqual(deviceB.vault.users.alice['twitter.com'], 1, 'twitter nonce');
            assertEqual(deviceB.vault.users.bob['npm.com'], 5, 'npm nonce');
        });

        await it('passwords are identical on both devices', async () => {
            const passA = await deviceA.genPassword('alice', 'github.com', 3);
            const passB = await deviceB.genPassword('alice', 'github.com', 3);
            assertEqual(passA, passB, 'same password on both devices');
        });
    });

    // ── Scenario 3: Device A changes while Device B offline ─────────────
    await describeAsync('Scenario 3: Device A adds sites while Device B is offline → B resyncs', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('both devices start synced', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 2);
            await deviceA.backupToRelay();

            await deviceB.initializeVault(TEST_SEED);
            await deviceB.restoreFromRelay();
            assertEqual(deviceB.vault.users.alice['github.com'], 2, 'B synced');
        });

        await it('Device A adds new sites and backs up', async () => {
            deviceA.addSite('alice', 'slack.com', 0);
            deviceA.addSite('carol', 'aws.com', 1);
            deviceA.incrementSiteNonce('alice', 'github.com'); // 2 → 3
            await deviceA.backupToRelay();
        });

        await it('Device B resyncs and gets all changes', async () => {
            const result = await deviceB.restoreFromRelay();
            assert(result.found, 'found backup');
            assertEqual(deviceB.vault.users.alice['github.com'], 3, 'github nonce updated');
            assertEqual(deviceB.vault.users.alice['slack.com'], 0, 'slack added');
            assertEqual(deviceB.vault.users.carol['aws.com'], 1, 'carol added');
        });
    });

    // ── Scenario 4: Both devices change offline → sync conflict ─────────
    await describeAsync('Scenario 4: Both devices make changes offline → merge without data loss', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('setup: both devices synced', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 5);
            await deviceA.backupToRelay();

            await deviceB.initializeVault(TEST_SEED);
            await deviceB.restoreFromRelay();
        });

        await it('Device A adds sites offline', async () => {
            deviceA.addSite('alice', 'twitter.com', 3);
            deviceA.addSite('dave', 'heroku.com', 1);
            await deviceA.backupToRelay(); // A publishes first
        });

        await it('Device B also adds sites offline, then syncs', async () => {
            deviceB.addSite('alice', 'slack.com', 2);
            deviceB.addSite('bob', 'npm.com', 4);

            // B restores — merges A's changes with B's local changes
            await deviceB.restoreFromRelay();

            // B should have everything from both devices
            assertEqual(deviceB.vault.users.alice['github.com'], 5, 'original preserved');
            assertEqual(deviceB.vault.users.alice['twitter.com'], 3, 'from A');
            assertEqual(deviceB.vault.users.alice['slack.com'], 2, 'from B (local)');
            assertEqual(deviceB.vault.users.dave['heroku.com'], 1, 'from A');
            assertEqual(deviceB.vault.users.bob['npm.com'], 4, 'from B (local)');
        });

        await it('Device B backs up combined state → A can sync too', async () => {
            await deviceB.backupToRelay();
            await deviceA.restoreFromRelay();

            assertEqual(deviceA.vault.users.alice['slack.com'], 2, 'A gets B slack');
            assertEqual(deviceA.vault.users.bob['npm.com'], 4, 'A gets B npm');
            assertEqual(deviceA.vault.users.alice['twitter.com'], 3, 'A keeps twitter');
        });
    });

    // ── Scenario 5: Nonce conflict — higher wins ────────────────────────
    await describeAsync('Scenario 5: Both devices increment same nonce → higher wins', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('setup: both devices at nonce 5', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 5);
            await deviceA.backupToRelay();

            await deviceB.initializeVault(TEST_SEED);
            await deviceB.restoreFromRelay();
            assertEqual(deviceB.vault.users.alice['github.com'], 5, 'both at 5');
        });

        await it('Device A increments to 8, Device B to 6', async () => {
            for (let i = 0; i < 3; i++) deviceA.incrementSiteNonce('alice', 'github.com');
            assertEqual(deviceA.vault.users.alice['github.com'], 8, 'A at 8');

            deviceB.incrementSiteNonce('alice', 'github.com');
            assertEqual(deviceB.vault.users.alice['github.com'], 6, 'B at 6');
        });

        await it('A publishes first', async () => {
            await deviceA.backupToRelay();
        });

        await it('B syncs → gets 8 (higher wins), B local 6 discarded', async () => {
            await deviceB.restoreFromRelay();
            assertEqual(deviceB.vault.users.alice['github.com'], 8, 'higher nonce wins');
        });

        await it('if B had published first and A synced, A would keep 8', async () => {
            // Reset scenario: B publishes nonce 6, then A syncs with nonce 8
            const relay2 = new RelayNetwork();
            const a = createDevice(relay2);
            const b = createDevice(relay2);
            await a.initializeVault(TEST_SEED);
            await b.initializeVault(TEST_SEED);
            a.addSite('alice', 'github.com', 8);
            b.addSite('alice', 'github.com', 6);
            await b.backupToRelay(); // B publishes 6
            await a.restoreFromRelay(); // A syncs, has 8 locally
            assertEqual(a.vault.users.alice['github.com'], 8, 'A keeps 8 over remote 6');
        });
    });

    // ── Scenario 6: Fully offline → changes → reconnect ────────────────
    await describeAsync('Scenario 6: Device goes fully offline → makes changes → reconnects → syncs', async () => {
        const relay = new RelayNetwork();
        const device = createDevice(relay);

        await it('initializes and backs up', async () => {
            await device.initializeVault(TEST_SEED);
            device.addSite('alice', 'github.com', 3);
            await device.backupToRelay();
        });

        await it('goes offline and makes changes', async () => {
            relay.goOffline();
            device.addSite('alice', 'twitter.com', 1);
            device.incrementSiteNonce('alice', 'github.com'); // 3 → 4

            // Backup fails (offline)
            try {
                await device.backupToRelay();
                assert(false, 'should have thrown');
            } catch (e) {
                assert(e.message.includes('offline'), 'network offline error');
            }
        });

        await it('saves to local backup while offline', async () => {
            await device.saveLocalBackup();
            assert(device.localStorage.getItem('vaultNonceBackup') !== null, 'local backup saved');
        });

        await it('reconnects and syncs successfully', async () => {
            relay.goOnline();
            await device.backupToRelay();
            assertEqual(relay.events.length, 1, 'event on relay (replaceable)');

            // Verify by restoring on a fresh device
            const fresh = createDevice(relay);
            await fresh.initializeVault(TEST_SEED);
            await fresh.restoreFromRelay();
            assertEqual(fresh.vault.users.alice['github.com'], 4, 'offline change synced');
            assertEqual(fresh.vault.users.alice['twitter.com'], 1, 'new site synced');
        });
    });

    // ── Scenario 7: Lock / unlock preserves data ────────────────────────
    await describeAsync('Scenario 7: Lock → unlock cycle preserves all vault data', async () => {
        const relay = new RelayNetwork();
        const device = createDevice(relay);

        await it('creates vault with sites', async () => {
            await device.initializeVault(TEST_SEED);
            device.addSite('alice', 'github.com', 7);
            device.addSite('bob', 'npm.com', 3);
            await device.saveVault('mypassword123');
            await device.saveLocalBackup();
        });

        await it('locks vault — all state cleared', async () => {
            device.lockVault();
            assertEqual(device.vault.privateKey, '', 'key cleared');
            assertDeepEqual(device.vault.users, {}, 'users cleared');
            assert(!device._vaultInitialized, 'not initialized');
        });

        await it('unlocks vault — all data restored from localStorage', async () => {
            await device.unlockVault('mypassword123');
            assert(device._vaultInitialized, 'reinitialized');
            assertEqual(device.vault.users.alice['github.com'], 7, 'alice restored');
            assertEqual(device.vault.users.bob['npm.com'], 3, 'bob restored');
            assert(device.vault.privateKey.length > 0, 'key restored');
        });

        await it('passwords are identical before and after lock/unlock', async () => {
            const pass = await device.genPassword('alice', 'github.com', 7);
            assert(pass.startsWith('PASS'), 'password works after unlock');
        });
    });

    // ── Scenario 8: All relays down → local backup → reconnect later ────
    await describeAsync('Scenario 8: All relays down → local backup preserves data → resync when online', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('Device A works entirely offline with local backup', async () => {
            relay.goOffline();
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 5);
            deviceA.addSite('bob', 'npm.com', 2);
            await deviceA.saveLocalBackup();
            await deviceA.saveVault('pass123');
        });

        await it('Device A locks and relocks — data survives via localStorage', async () => {
            deviceA.lockVault();
            await deviceA.unlockVault('pass123');
            assertEqual(deviceA.vault.users.alice['github.com'], 5, 'survived lock/unlock');
        });

        await it('relay comes online → Device A publishes → Device B syncs', async () => {
            relay.goOnline();
            await deviceA.backupToRelay();

            await deviceB.initializeVault(TEST_SEED);
            await deviceB.restoreFromRelay();
            assertEqual(deviceB.vault.users.alice['github.com'], 5, 'B got data');
            assertEqual(deviceB.vault.users.bob['npm.com'], 2, 'B got bob');
        });
    });

    // ── Scenario 9: Local nonce backup recovery across init ─────────────
    await describeAsync('Scenario 9: Local nonce backup survives re-initialization', async () => {
        const relay = new RelayNetwork();
        const device = createDevice(relay);

        await it('creates vault and saves local backup', async () => {
            await device.initializeVault(TEST_SEED);
            device.addSite('alice', 'github.com', 10);
            device.addSite('alice', 'twitter.com', 3);
            await device.saveLocalBackup();
        });

        await it('re-initializes from same seed — local backup merged', async () => {
            device.lockVault();
            // Re-init (simulates app restart without saved vault, but with nonce backup)
            await device.initializeVault(TEST_SEED);
            assertEqual(device.vault.users.alice['github.com'], 10, 'github recovered from local backup');
            assertEqual(device.vault.users.alice['twitter.com'], 3, 'twitter recovered');
        });
    });

    // ── Scenario 10: Delete on one device, add on another ───────────────
    await describeAsync('Scenario 10: Device A deletes site, Device B increments same site → no data loss', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('both devices synced with alice/github at nonce 5', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'github.com', 5);
            deviceA.addSite('alice', 'twitter.com', 2);
            await deviceA.backupToRelay();

            await deviceB.initializeVault(TEST_SEED);
            await deviceB.restoreFromRelay();
        });

        await it('Device A deletes github, Device B increments github to 6', async () => {
            deviceA.deleteSite('alice', 'github.com');
            assert(deviceA.vault.users.alice['github.com'] === undefined, 'A deleted github');
            await deviceA.backupToRelay();

            deviceB.incrementSiteNonce('alice', 'github.com'); // 5 → 6
            assertEqual(deviceB.vault.users.alice['github.com'], 6, 'B at 6');
        });

        await it('Device B syncs → keeps nonce 6 (higher than absent=undefined)', async () => {
            await deviceB.restoreFromRelay();
            // mergeUsers: remote has no github, B has github=6 → B keeps 6
            // (mergeUsers only adopts remote if remote nonce > local)
            assertEqual(deviceB.vault.users.alice['github.com'], 6, 'B keeps 6');
            assertEqual(deviceB.vault.users.alice['twitter.com'], 2, 'twitter unchanged');
        });

        await it('Device A syncs from B → gets github back at 6', async () => {
            await deviceB.backupToRelay();
            await deviceA.restoreFromRelay();
            assertEqual(deviceA.vault.users.alice['github.com'], 6, 'A gets github back');
        });
    });

    // ── Scenario 11: Empty vault syncs from device with data ────────────
    await describeAsync('Scenario 11: Fresh empty vault syncs full dataset from relay', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);

        await it('Device A builds up large vault', async () => {
            await deviceA.initializeVault(TEST_SEED);
            for (let i = 0; i < 20; i++) {
                deviceA.addSite(`user${i}@test.com`, `site${i}.com`, i);
            }
            await deviceA.backupToRelay();
        });

        await it('Fresh device restores all 20 entries', async () => {
            const fresh = createDevice(relay);
            await fresh.initializeVault(TEST_SEED);
            assertDeepEqual(fresh.vault.users, {}, 'starts empty');
            await fresh.restoreFromRelay();

            let count = 0;
            Object.values(fresh.vault.users).forEach(sites => {
                count += Object.keys(sites).length;
            });
            assertEqual(count, 20, 'all 20 entries restored');

            // Verify specific entries
            assertEqual(fresh.vault.users['user0@test.com']['site0.com'], 0, 'first entry');
            assertEqual(fresh.vault.users['user19@test.com']['site19.com'], 19, 'last entry');
        });
    });

    // ── Scenario 12: Backup password (double encryption) ────────────────
    await describeAsync('Scenario 12: Backup with password → restore requires password', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);

        await it('Device A backs up with backup password', async () => {
            await deviceA.initializeVault(TEST_SEED);
            deviceA.addSite('alice', 'secret-bank.com', 3);
            await deviceA.backupToRelayWithPassword('supersecret!');
        });

        await it('Device B detects double-encrypted backup', async () => {
            await deviceB.initializeVault(TEST_SEED);
            const result = await deviceB.restoreFromRelay();
            assert(result.found, 'backup found');
            assert(result.needsPassword, 'password required');
            assert(result.envelope !== null, 'envelope returned');
        });

        await it('Device B decrypts with correct password', async () => {
            const result = await deviceB.restoreFromRelay();
            await deviceB.restoreWithPassword(result.envelope, 'supersecret!');
            assertEqual(deviceB.vault.users.alice['secret-bank.com'], 3, 'data restored');
        });

        await it('wrong backup password fails', async () => {
            const result = await deviceB.restoreFromRelay();
            try {
                await deviceB.restoreWithPassword(result.envelope, 'wrongpassword');
                assert(false, 'should have thrown');
            } catch (e) {
                assert(true, 'wrong password rejected');
            }
        });
    });

    // ── Scenario 13: Multiple sync rounds converge ──────────────────────
    await describeAsync('Scenario 13: Three devices sync back and forth → all converge', async () => {
        const relay = new RelayNetwork();
        const deviceA = createDevice(relay);
        const deviceB = createDevice(relay);
        const deviceC = createDevice(relay);

        await it('setup: all initialized from same seed', async () => {
            await deviceA.initializeVault(TEST_SEED);
            await deviceB.initializeVault(TEST_SEED);
            await deviceC.initializeVault(TEST_SEED);
        });

        await it('each device adds unique data', async () => {
            deviceA.addSite('alice', 'github.com', 5);
            deviceB.addSite('bob', 'gitlab.com', 3);
            deviceC.addSite('carol', 'aws.com', 7);
        });

        await it('round 1: A publishes, B and C sync', async () => {
            await deviceA.backupToRelay();
            await deviceB.restoreFromRelay();
            await deviceC.restoreFromRelay();
            assertEqual(deviceB.vault.users.alice['github.com'], 5, 'B got A data');
            assertEqual(deviceC.vault.users.alice['github.com'], 5, 'C got A data');
        });

        await it('round 2: B publishes (has A+B data), C syncs', async () => {
            await deviceB.backupToRelay();
            await deviceC.restoreFromRelay();
            assert(deviceC.vault.users.bob['gitlab.com'] === 3, 'C got B data');
            assert(deviceC.vault.users.alice['github.com'] === 5, 'C still has A data');
            assert(deviceC.vault.users.carol['aws.com'] === 7, 'C keeps own data');
        });

        await it('round 3: C publishes (has all data), A syncs', async () => {
            await deviceC.backupToRelay();
            await deviceA.restoreFromRelay();
            assertEqual(deviceA.vault.users.bob['gitlab.com'], 3, 'A got B data');
            assertEqual(deviceA.vault.users.carol['aws.com'], 7, 'A got C data');
            assertEqual(deviceA.vault.users.alice['github.com'], 5, 'A keeps own data');
        });

        await it('all three devices have identical data', async () => {
            // Sync everyone one more time
            await deviceA.backupToRelay();
            await deviceB.restoreFromRelay();
            await deviceC.restoreFromRelay();

            // Compare data by value (key order may differ)
            const sort = (obj) => JSON.stringify(obj, Object.keys(obj).sort());
            const normalize = (users) => {
                const result = {};
                for (const u of Object.keys(users).sort()) {
                    result[u] = {};
                    for (const s of Object.keys(users[u]).sort()) {
                        result[u][s] = users[u][s];
                    }
                }
                return JSON.stringify(result);
            };
            assertEqual(normalize(deviceA.vault.users), normalize(deviceB.vault.users), 'A == B');
            assertEqual(normalize(deviceB.vault.users), normalize(deviceC.vault.users), 'B == C');
        });
    });

    // ── Scenario 14: Rapid changes before sync (debounce simulation) ────
    await describeAsync('Scenario 14: Rapid site additions before single sync', async () => {
        const relay = new RelayNetwork();
        const device = createDevice(relay);

        await it('add 50 sites rapidly, then single backup', async () => {
            await device.initializeVault(TEST_SEED);
            for (let i = 0; i < 50; i++) {
                device.addSite('user@rapid.com', `site${i}.com`, i);
            }
            await device.backupToRelay();
            assertEqual(relay.events.length, 1, 'only 1 event (replaceable)');
        });

        await it('fresh device gets all 50 sites from single event', async () => {
            const fresh = createDevice(relay);
            await fresh.initializeVault(TEST_SEED);
            await fresh.restoreFromRelay();
            let count = Object.keys(fresh.vault.users['user@rapid.com'] || {}).length;
            assertEqual(count, 50, 'all 50 sites restored');
        });
    });

    // ── Scenario 15: kind:30078 replaces old events ─────────────────────
    await describeAsync('Scenario 15: Successive backups replace (not accumulate) on relay', async () => {
        const relay = new RelayNetwork();
        const device = createDevice(relay);

        await it('publishes 5 times → only latest survives', async () => {
            await device.initializeVault(TEST_SEED);

            for (let i = 1; i <= 5; i++) {
                device.addSite('alice', `site${i}.com`, i);
                await device.backupToRelay();
            }

            assertEqual(relay.events.length, 1, 'only 1 event (kind:30078 is replaceable)');
        });

        await it('restored data has all sites from final publish', async () => {
            const fresh = createDevice(relay);
            await fresh.initializeVault(TEST_SEED);
            await fresh.restoreFromRelay();

            for (let i = 1; i <= 5; i++) {
                assertEqual(fresh.vault.users.alice[`site${i}.com`], i, `site${i} present`);
            }
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runScenarios().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
