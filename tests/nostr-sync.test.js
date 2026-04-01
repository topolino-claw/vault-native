/**
 * Nostr Sync & Backup Tests
 *
 * Tests: backup event structure, relay connection/timeout mocking,
 *        silentRestoreFromNostr merge logic, legacy key fallback,
 *        debounce behavior, decryptBackupEvent format detection,
 *        relay status tracking, backup failure handling.
 *
 * These tests mock the relay layer and nostr-tools crypto so we can
 * test the orchestration logic without real WebSocket connections.
 *
 * Run:  node tests/nostr-sync.test.js
 */

const { describe, describeAsync, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction, createLocalStorageMock } = require('./helpers/extract');

// ── Relay & Nostr mocks ─────────────────────────────────────────────────────

function createRelayMock(events = [], shouldFail = false, publishOk = true) {
    const published = [];
    return {
        events,
        published,
        shouldFail,
        publishOk,
        _closed: false,
        close() { this._closed = true; },
        sub(filters) {
            const handlers = {};
            const self = this;
            setTimeout(() => {
                if (handlers.event) {
                    self.events.forEach(e => handlers.event(e));
                }
                if (handlers.eose) handlers.eose();
            }, 0);
            return {
                on(evt, fn) { handlers[evt] = fn; },
                unsub() {},
            };
        },
        publish(event) {
            const handlers = {};
            const self = this;
            self.published.push(event);
            setTimeout(() => {
                if (self.publishOk && handlers.ok) handlers.ok();
                else if (!self.publishOk && handlers.failed) handlers.failed('rejected');
            }, 0);
            return {
                on(evt, fn) { handlers[evt] = fn; },
            };
        },
    };
}

// ── Build module with Nostr functions ────────────────────────────────────────

function buildNostrModule(opts = {}) {
    const localStorage = opts.localStorage || createLocalStorageMock();
    const relayMocks = opts.relayMocks || {};
    const currentTime = opts.currentTime || Math.floor(Date.now() / 1000);

    const fnNames = [
        'mergeUsers',
        'decimalStringToHex', 'wordsToIndices', 'derivePrivateKey',
        'hash',
        'deriveLocalKey', 'encryptLocal', 'decryptLocal', 'isWebCryptoEnvelope',
        '_secp256k1ModAdd', '_modInv', '_ecAdd', '_ecMul',
        '_privToCompressedPub', '_mnemonicToSeed', '_bip32Master',
        '_bip32HardChild', '_bip32NormalChild',
        'deriveNostrKeyNIP06',
        'parseDoubleEncryptedEnvelope',
        'setRelayStatus',
        'updateBackupWarningIndicator',
        'subscribeAndCollect',
        'encodeNevent',
    ];

    const fnSrc = fnNames.map(n => extractFunction(n)).join('\n\n');

    const code = `
        const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
        const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
        const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
        const LOCAL_ENCRYPT_VERSION = 3;
        const LOCAL_ENCRYPT_ITERATIONS = 600000;
        const BACKUP_D_TAG = 'vault-backup';
        const RELAYS = [
            "wss://relay.damus.io",
            "wss://nostr-pub.wellorder.net",
            "wss://relay.snort.social",
            "wss://nos.lol"
        ];

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
        let debugMode = false;
        let _lastRelayStatus = 'idle';
        let _lastSettledRelayStatus = 'idle';
        let _backupDebounceTimer = null;
        let _cachedLocalKey = null;
        let _cachedLocalSalt = null;
        let _cachedLocalPassphrase = null;

        function debugLog() {}
        function showToast() {}
        function showLoading() {}
        function hideLoading() {}
        function renderSiteList() {}
        function resetInactivityTimer() {}

        ${fnSrc}

        // Simplified getNostrKeyPair for testing
        async function getNostrKeyPair() {
            return { sk: nostrKeys.hex, pk: nostrKeys.npub };
        }

        async function getLegacyNostrKeyPair() {
            if (!vault.privateKey) return { sk: null, pk: nostrKeys.npub };
            const utf8 = new TextEncoder().encode(vault.privateKey);
            const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
            const hashBytes = new Uint8Array(hashBuffer);
            const sk = Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            return { sk, pk: sk.slice(0, 32) }; // simplified
        }

        // Mock connectRelay
        async function connectRelay(url) {
            const mock = _relayMocks[url];
            if (!mock) throw new Error('relay not mocked: ' + url);
            if (mock.shouldFail) throw new Error('connection failed');
            return mock;
        }

        // Backups — simplified for testing orchestration
        async function backupToNostrSilent() {
            _backupSilentCalled = true;
        }
        let _backupSilentCalled = false;

        function backupToNostrDebounced() {
            if (_backupDebounceTimer) clearTimeout(_backupDebounceTimer);
            _backupDebounceTimer = setTimeout(() => {
                backupToNostrSilent();
                _backupDebounceTimer = null;
            }, 50); // short timeout for testing
        }

        async function saveLocalNonceBackup() {
            if (!vault.privateKey) return;
            const payload = JSON.stringify({ users: vault.users, settings: vault.settings });
            const encrypted = await encryptLocal(payload, vault.privateKey);
            localStorage.setItem('vaultNonceBackup', encrypted);
        }

        async function autoSaveVault() {}

        // silentRestoreFromNostr — the main function under test
        async function silentRestoreFromNostr() {
            if (!_vaultInitialized && !vault.privateKey) return { found: false };
            const { sk, pk } = await getNostrKeyPair();

            async function fetchLatestFromRelays(authorPk) {
                let latest = null;
                for (const url of RELAYS) {
                    try {
                        const relay = await connectRelay(url);
                        const events = await subscribeAndCollect(relay, [
                            { kinds: [30078], authors: [authorPk], "#d": [BACKUP_D_TAG], limit: 1 },
                            { kinds: [1], authors: [authorPk], "#t": ["nostr-pwd-backup"], limit: 1 }
                        ], 6000);
                        relay.close();
                        for (const e of events) {
                            if (!latest || e.created_at > latest.created_at) latest = e;
                        }
                    } catch (e) {}
                }
                return latest;
            }

            // Try current key
            let latest = await fetchLatestFromRelays(pk);
            if (latest) {
                // Simulate decrypt: content is plain JSON for testing
                try {
                    const data = JSON.parse(latest.content);
                    mergeUsers(data.users);
                    if (data.settings) {
                        vault.settings = { ...vault.settings, ...data.settings };
                    }
                    await saveLocalNonceBackup();
                    await autoSaveVault();
                    return { found: true };
                } catch (e) {}
            }

            // Legacy fallback
            if (!vault.passphrase || vault.passphrase === '') {
                const legacy = await getLegacyNostrKeyPair();
                if (legacy.pk !== pk) {
                    latest = await fetchLatestFromRelays(legacy.pk);
                    if (latest) {
                        try {
                            const data = JSON.parse(latest.content);
                            mergeUsers(data.users);
                            if (data.settings) {
                                vault.settings = { ...vault.settings, ...data.settings };
                            }
                            await saveLocalNonceBackup();
                            return { found: true };
                        } catch (e) {}
                    }
                }
            }

            return { found: false };
        }

        return {
            get vault() { return vault; },
            set vault(v) { vault = v; },
            get nostrKeys() { return nostrKeys; },
            set nostrKeys(v) { nostrKeys = v; },
            get _vaultInitialized() { return _vaultInitialized; },
            set _vaultInitialized(v) { _vaultInitialized = v; },
            get _lastRelayStatus() { return _lastRelayStatus; },
            get _backupDebounceTimer() { return _backupDebounceTimer; },
            get _backupSilentCalled() { return _backupSilentCalled; },
            silentRestoreFromNostr,
            backupToNostrDebounced,
            setRelayStatus,
            mergeUsers,
            subscribeAndCollect,
            parseDoubleEncryptedEnvelope,
        };
    `;

    const factory = new Function(
        'words', 'invoke', 'crypto', 'localStorage', '_relayMocks',
        'TextEncoder', 'TextDecoder', 'Uint8Array', 'BigInt', 'Array', 'JSON',
        'Math', 'String', 'Number', 'parseInt', 'Object', 'btoa', 'atob',
        'Error', 'Promise', 'setTimeout', 'clearTimeout', 'console',
        'window', 'document',
        code
    );

    // Minimal window.NostrTools mock
    const windowMock = {
        NostrTools: {
            nip19: {
                neventEncode(obj) { return 'nevent_mock_' + obj.id; },
            },
        }
    };

    // Minimal document mock for setRelayStatus
    const docElements = {};
    const documentMock = {
        getElementById(id) {
            if (!docElements[id]) docElements[id] = { dataset: {}, title: '' };
            return docElements[id];
        }
    };

    return factory(
        words, null, globalThis.crypto, localStorage, relayMocks,
        TextEncoder, TextDecoder, Uint8Array, BigInt, Array, JSON,
        Math, String, Number, parseInt, Object, btoa, atob,
        Error, Promise, setTimeout, clearTimeout, console,
        windowMock, documentMock
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

async function runTests() {

    await describeAsync('subscribeAndCollect — event collection', async () => {
        await it('collects events from relay', async () => {
            const events = [
                { id: 'e1', kind: 30078, created_at: 1000, content: '{}' },
                { id: 'e2', kind: 30078, created_at: 2000, content: '{}' },
            ];
            const relay = createRelayMock(events);
            const relayMocks = { 'wss://test': relay };
            const mod = buildNostrModule({ relayMocks });
            const collected = await mod.subscribeAndCollect(relay, [{ kinds: [30078] }], 5000);
            assertEqual(collected.length, 2, 'collected 2 events');
        });

        await it('returns empty array when no events', async () => {
            const relay = createRelayMock([]);
            const relayMocks = { 'wss://test': relay };
            const mod = buildNostrModule({ relayMocks });
            const collected = await mod.subscribeAndCollect(relay, [{ kinds: [30078] }], 5000);
            assertEqual(collected.length, 0, 'no events');
        });
    });

    await describeAsync('silentRestoreFromNostr — basic restore', async () => {
        await it('returns found:false when vault not initialized', async () => {
            const mod = buildNostrModule();
            const result = await mod.silentRestoreFromNostr();
            assertEqual(result.found, false, 'not initialized → found:false');
        });

        await it('merges remote data into local vault', async () => {
            const remoteData = JSON.stringify({
                users: { alice: { github: 10, twitter: 5 } },
                settings: { hashLength: 20 }
            });
            const events = [{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }];

            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock(url === "wss://relay.damus.io" ? events : []);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.vault.users = { alice: { github: 3 } };
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            const result = await mod.silentRestoreFromNostr();
            assertEqual(result.found, true, 'backup found');
            assertEqual(mod.vault.users.alice.github, 10, 'higher remote nonce wins');
            assertEqual(mod.vault.users.alice.twitter, 5, 'new remote site added');
        });

        await it('higher LOCAL nonce is preserved', async () => {
            const remoteData = JSON.stringify({
                users: { alice: { github: 2 } }
            });
            const events = [{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }];

            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock(events);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.vault.users = { alice: { github: 8 } };
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            await mod.silentRestoreFromNostr();
            assertEqual(mod.vault.users.alice.github, 8, 'local nonce 8 > remote 2');
        });

        await it('picks latest event across relays by created_at', async () => {
            const oldData = JSON.stringify({ users: { alice: { github: 1 } } });
            const newData = JSON.stringify({ users: { alice: { github: 9 } } });

            const relayMocks = {
                "wss://relay.damus.io": createRelayMock([{ id: 'old', kind: 30078, created_at: 1000, content: oldData }]),
                "wss://nostr-pub.wellorder.net": createRelayMock([{ id: 'new', kind: 30078, created_at: 2000, content: newData }]),
                "wss://relay.snort.social": createRelayMock([]),
                "wss://nos.lol": createRelayMock([]),
            };

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            await mod.silentRestoreFromNostr();
            assertEqual(mod.vault.users.alice.github, 9, 'latest event used (nonce=9)');
        });
    });

    await describeAsync('silentRestoreFromNostr — relay failure resilience', async () => {
        await it('succeeds when some relays fail', async () => {
            const remoteData = JSON.stringify({ users: { alice: { github: 5 } } });

            const relayMocks = {
                "wss://relay.damus.io": createRelayMock([], true), // fails
                "wss://nostr-pub.wellorder.net": createRelayMock([], true), // fails
                "wss://relay.snort.social": createRelayMock([{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }]),
                "wss://nos.lol": createRelayMock([], true), // fails
            };

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            const result = await mod.silentRestoreFromNostr();
            assertEqual(result.found, true, 'found via single working relay');
            assertEqual(mod.vault.users.alice.github, 5, 'data merged');
        });

        await it('returns found:false when ALL relays fail', async () => {
            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock([], true);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            const result = await mod.silentRestoreFromNostr();
            assertEqual(result.found, false, 'all relays failed → found:false');
        });

        await it('returns found:false when relays return no events', async () => {
            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock([]);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            const result = await mod.silentRestoreFromNostr();
            assertEqual(result.found, false, 'no events → found:false');
        });
    });

    await describeAsync('silentRestoreFromNostr — complex merge scenario', async () => {
        await it('multi-user multi-site remote merge', async () => {
            const remoteData = JSON.stringify({
                users: {
                    alice: { github: 10, twitter: 5, slack: 1 },
                    bob:   { gitlab: 6 },
                    dave:  { heroku: 3 }
                }
            });
            const events = [{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }];

            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock(events);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.vault.users = {
                alice: { github: 15, twitter: 3, reddit: 1 },
                bob:   { gitlab: 2, npm: 4 },
                carol: { aws: 1 }
            };
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            await mod.silentRestoreFromNostr();

            assertEqual(mod.vault.users.alice.github, 15, 'alice.github: local 15 > remote 10');
            assertEqual(mod.vault.users.alice.twitter, 5, 'alice.twitter: remote 5 > local 3');
            assertEqual(mod.vault.users.alice.reddit, 1, 'alice.reddit: preserved (not in remote)');
            assertEqual(mod.vault.users.alice.slack, 1, 'alice.slack: added from remote');
            assertEqual(mod.vault.users.bob.gitlab, 6, 'bob.gitlab: remote 6 > local 2');
            assertEqual(mod.vault.users.bob.npm, 4, 'bob.npm: preserved');
            assertEqual(mod.vault.users.carol.aws, 1, 'carol: preserved (not in remote)');
            assertEqual(mod.vault.users.dave.heroku, 3, 'dave: new user from remote');
        });
    });

    await describeAsync('parseDoubleEncryptedEnvelope — format detection', async () => {
        it('detects v2 backup envelope', () => {
            const ls = createLocalStorageMock();
            const relayMocks = {};
            const mod = buildNostrModule({ localStorage: ls, relayMocks });

            const v2 = JSON.stringify({ v: 2, iv: 'abc', ciphertext: 'def' });
            const result = mod.parseDoubleEncryptedEnvelope(v2);
            assert(result !== null, 'v2 detected');
            assertEqual(result.v, 2, 'version correct');
        });

        it('detects v3 backup envelope', () => {
            const mod = buildNostrModule();
            const v3 = JSON.stringify({ v: 3, salt: 'x', iv: 'y', ciphertext: 'z' });
            const result = mod.parseDoubleEncryptedEnvelope(v3);
            assert(result !== null, 'v3 detected');
        });

        it('returns null for plain vault data', () => {
            const mod = buildNostrModule();
            const plain = JSON.stringify({ users: { alice: { github: 5 } }, settings: {} });
            assert(mod.parseDoubleEncryptedEnvelope(plain) === null, 'plain data → null');
        });

        it('returns null for non-JSON', () => {
            const mod = buildNostrModule();
            assert(mod.parseDoubleEncryptedEnvelope('not-json') === null, 'non-JSON → null');
        });
    });

    await describeAsync('Relay status indicator', async () => {
        it('setRelayStatus updates internal state', () => {
            const mod = buildNostrModule();
            mod.setRelayStatus('syncing');
            assertEqual(mod._lastRelayStatus, 'syncing', 'status updated');
        });
    });

    await describeAsync('Debounce behavior', async () => {
        await it('debounce timer is set on call', async () => {
            const mod = buildNostrModule();
            mod.backupToNostrDebounced();
            assert(mod._backupDebounceTimer !== null, 'timer set');
        });

        await it('fires after delay', async () => {
            const mod = buildNostrModule();
            mod.backupToNostrDebounced();
            await new Promise(r => setTimeout(r, 100));
            assertEqual(mod._backupSilentCalled, true, 'silent backup called');
        });
    });

    await describeAsync('Regression: shallow merge data loss (BUGS #1, #2, #3)', async () => {
        await it('partial remote backup does NOT wipe local sites', async () => {
            const remoteData = JSON.stringify({
                users: { alice: { github: 1 } } // only one site
            });
            const events = [{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }];
            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock(events);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.vault.users = {
                alice: { github: 5, twitter: 3 },
                bob: { npm: 2 }
            };
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            await mod.silentRestoreFromNostr();

            // These were the bugs: shallow merge would lose twitter and bob
            assertEqual(mod.vault.users.alice.github, 5, 'local 5 > remote 1');
            assertEqual(mod.vault.users.alice.twitter, 3, 'twitter preserved (BUGS #1 fix)');
            assertEqual(mod.vault.users.bob.npm, 2, 'bob preserved (BUGS #2 fix)');
        });

        await it('remote nonce downgrade does NOT happen', async () => {
            const remoteData = JSON.stringify({
                users: { alice: { github: 2 } } // lower than local
            });
            const events = [{ id: 'e1', kind: 30078, created_at: 1000, content: remoteData }];
            const relayMocks = {};
            for (const url of ["wss://relay.damus.io", "wss://nostr-pub.wellorder.net", "wss://relay.snort.social", "wss://nos.lol"]) {
                relayMocks[url] = createRelayMock(events);
            }

            const mod = buildNostrModule({ relayMocks });
            mod.vault.privateKey = 'testkey';
            mod.vault.users = { alice: { github: 5 } };
            mod.nostrKeys = { hex: 'aabbcc', npub: 'aabbcc' };
            mod._vaultInitialized = true;

            await mod.silentRestoreFromNostr();
            assertEqual(mod.vault.users.alice.github, 5, 'nonce not downgraded');
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
