/**
 * Local Storage Encryption Tests
 *
 * Tests: encryptLocal/decryptLocal roundtrip, wrong password rejection,
 *        isWebCryptoEnvelope detection, backup password encrypt/decrypt,
 *        parseDoubleEncryptedEnvelope, key derivation caching.
 *
 * Run:  node tests/local-crypto.test.js
 */

const { describe, describeAsync, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { extractFunction } = require('./helpers/extract');

// ── Build execution context ─────────────────────────────────────────────────

const fnSrc = [
    extractFunction('deriveLocalKey'),
    extractFunction('encryptLocal'),
    extractFunction('decryptLocal'),
    extractFunction('isWebCryptoEnvelope'),
    extractFunction('deriveBackupKey'),
    extractFunction('encryptWithBackupPassword'),
    extractFunction('decryptWithBackupPassword'),
    extractFunction('parseDoubleEncryptedEnvelope'),
].join('\n\n');

const code = `
    const LOCAL_ENCRYPT_VERSION = 3;
    const LOCAL_ENCRYPT_ITERATIONS = 600000;
    const BACKUP_PASSWORD_ITERATIONS = 600000;

    let _cachedLocalKey = null;
    let _cachedLocalSalt = null;
    let _cachedLocalPassphrase = null;

    ${fnSrc}

    return {
        deriveLocalKey, encryptLocal, decryptLocal, isWebCryptoEnvelope,
        deriveBackupKey, encryptWithBackupPassword, decryptWithBackupPassword,
        parseDoubleEncryptedEnvelope,
        get _cachedLocalKey() { return _cachedLocalKey; },
        get _cachedLocalPassphrase() { return _cachedLocalPassphrase; },
        resetCache() { _cachedLocalKey = null; _cachedLocalSalt = null; _cachedLocalPassphrase = null; },
    };
`;

const factory = new Function('crypto', 'TextEncoder', 'TextDecoder', 'Uint8Array', 'Array', 'JSON', 'String', 'btoa', 'atob', 'Error', code);
const mod = factory(globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, Array, JSON, String, btoa, atob, Error);

// ── Tests ───────────────────────────────────────────────────────────────────

async function runTests() {

    await describeAsync('encryptLocal / decryptLocal — roundtrip', async () => {
        await it('encrypts and decrypts back to original', async () => {
            mod.resetCache();
            const plaintext = '{"users":{"alice":{"github":5}},"settings":{"hashLength":16}}';
            const passphrase = 'strong-password-123';
            const encrypted = await mod.encryptLocal(plaintext, passphrase);
            const decrypted = await mod.decryptLocal(encrypted, passphrase);
            assertEqual(decrypted, plaintext, 'roundtrip preserves data');
        });

        await it('works with empty string', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('', 'password');
            const decrypted = await mod.decryptLocal(encrypted, 'password');
            assertEqual(decrypted, '', 'empty string roundtrip');
        });

        await it('works with unicode content', async () => {
            mod.resetCache();
            const plaintext = '{"emoji":"🔐","japanese":"日本語"}';
            const encrypted = await mod.encryptLocal(plaintext, 'pass');
            const decrypted = await mod.decryptLocal(encrypted, 'pass');
            assertEqual(decrypted, plaintext, 'unicode roundtrip');
        });

        await it('works with large payload', async () => {
            mod.resetCache();
            const obj = {};
            for (let i = 0; i < 100; i++) {
                obj[`user${i}`] = {};
                for (let j = 0; j < 50; j++) {
                    obj[`user${i}`][`site${j}`] = i * 50 + j;
                }
            }
            const plaintext = JSON.stringify(obj);
            const encrypted = await mod.encryptLocal(plaintext, 'password');
            const decrypted = await mod.decryptLocal(encrypted, 'password');
            assertEqual(decrypted, plaintext, 'large payload roundtrip');
        });
    });

    await describeAsync('encryptLocal — envelope format', async () => {
        await it('produces valid v3 JSON envelope', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('test', 'pass');
            const envelope = JSON.parse(encrypted);
            assertEqual(envelope.v, 3, 'version is 3');
            assert(typeof envelope.salt === 'string', 'has salt');
            assert(typeof envelope.iv === 'string', 'has iv');
            assert(typeof envelope.ciphertext === 'string', 'has ciphertext');
        });

        await it('salt is base64-encoded 16 bytes', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('test', 'pass');
            const envelope = JSON.parse(encrypted);
            const saltBytes = Uint8Array.from(atob(envelope.salt), c => c.charCodeAt(0));
            assertEqual(saltBytes.length, 16, 'salt is 16 bytes');
        });

        await it('iv is base64-encoded 12 bytes', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('test', 'pass');
            const envelope = JSON.parse(encrypted);
            const ivBytes = Uint8Array.from(atob(envelope.iv), c => c.charCodeAt(0));
            assertEqual(ivBytes.length, 12, 'iv is 12 bytes');
        });

        await it('each encryption produces different iv (random)', async () => {
            mod.resetCache();
            const e1 = await mod.encryptLocal('test', 'pass');
            const e2 = await mod.encryptLocal('test', 'pass');
            const iv1 = JSON.parse(e1).iv;
            const iv2 = JSON.parse(e2).iv;
            assert(iv1 !== iv2, 'different IVs');
        });
    });

    await describeAsync('decryptLocal — wrong password', async () => {
        await it('rejects wrong password with error', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('secret', 'correct-password');
            mod.resetCache();
            try {
                await mod.decryptLocal(encrypted, 'wrong-password');
                assert(false, 'should have thrown');
            } catch (err) {
                assert(true, 'threw on wrong password');
            }
        });

        await it('rejects empty password when encrypted with non-empty', async () => {
            mod.resetCache();
            const encrypted = await mod.encryptLocal('data', 'mypass');
            mod.resetCache();
            try {
                await mod.decryptLocal(encrypted, '');
                assert(false, 'should have thrown');
            } catch (err) {
                assert(true, 'threw on empty password');
            }
        });
    });

    describe('isWebCryptoEnvelope', () => {
        it('detects valid v3 envelope', () => {
            const envelope = JSON.stringify({ v: 3, salt: 'abc', iv: 'def', ciphertext: 'ghi' });
            assert(!!mod.isWebCryptoEnvelope(envelope), 'valid v3 detected');
        });

        it('rejects v2 envelope', () => {
            const envelope = JSON.stringify({ v: 2, iv: 'def', ciphertext: 'ghi' });
            assert(!mod.isWebCryptoEnvelope(envelope), 'v2 rejected');
        });

        it('rejects missing salt', () => {
            const envelope = JSON.stringify({ v: 3, iv: 'def', ciphertext: 'ghi' });
            assert(!mod.isWebCryptoEnvelope(envelope), 'no salt rejected');
        });

        it('rejects missing iv', () => {
            const envelope = JSON.stringify({ v: 3, salt: 'abc', ciphertext: 'ghi' });
            assert(!mod.isWebCryptoEnvelope(envelope), 'no iv rejected');
        });

        it('rejects missing ciphertext', () => {
            const envelope = JSON.stringify({ v: 3, salt: 'abc', iv: 'def' });
            assert(!mod.isWebCryptoEnvelope(envelope), 'no ciphertext rejected');
        });

        it('rejects non-JSON string (CryptoJS legacy)', () => {
            assert(!mod.isWebCryptoEnvelope('U2FsdGVkX1+abc123...'), 'CryptoJS rejected');
        });

        it('rejects empty string', () => {
            assert(!mod.isWebCryptoEnvelope(''), 'empty string rejected');
        });

        it('rejects null', () => {
            assert(!mod.isWebCryptoEnvelope(null), 'null rejected');
        });

        it('rejects plain JSON object (legacy multi-password format)', () => {
            const legacy = JSON.stringify({ 'abc123hash': 'encrypted-data-here' });
            assert(!mod.isWebCryptoEnvelope(legacy), 'legacy format rejected');
        });
    });

    describe('parseDoubleEncryptedEnvelope', () => {
        it('detects v2 double-encrypted envelope', () => {
            const envelope = JSON.stringify({ v: 2, iv: 'abc', ciphertext: 'def' });
            const result = mod.parseDoubleEncryptedEnvelope(envelope);
            assert(result !== null, 'v2 detected');
            assertEqual(result.v, 2, 'version preserved');
        });

        it('detects v3 double-encrypted envelope', () => {
            const envelope = JSON.stringify({ v: 3, salt: 'abc', iv: 'def', ciphertext: 'ghi' });
            const result = mod.parseDoubleEncryptedEnvelope(envelope);
            assert(result !== null, 'v3 detected');
            assertEqual(result.v, 3, 'version preserved');
        });

        it('returns null for plain JSON (no envelope)', () => {
            const plain = JSON.stringify({ users: { alice: { github: 5 } } });
            const result = mod.parseDoubleEncryptedEnvelope(plain);
            assert(result === null, 'plain JSON → null');
        });

        it('returns null for non-JSON string', () => {
            const result = mod.parseDoubleEncryptedEnvelope('not json');
            assert(result === null, 'non-JSON → null');
        });

        it('returns null for missing iv', () => {
            const result = mod.parseDoubleEncryptedEnvelope(JSON.stringify({ v: 2, ciphertext: 'x' }));
            assert(result === null, 'no iv → null');
        });

        it('returns null for missing ciphertext', () => {
            const result = mod.parseDoubleEncryptedEnvelope(JSON.stringify({ v: 2, iv: 'x' }));
            assert(result === null, 'no ciphertext → null');
        });
    });

    await describeAsync('encryptWithBackupPassword / decryptWithBackupPassword', async () => {
        const NPUB_HEX = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

        await it('roundtrip with v3 (random salt)', async () => {
            const plaintext = '{"users":{"alice":{"github":5}}}';
            const password = 'backup-pass-123!';
            const envelope = await mod.encryptWithBackupPassword(plaintext, password, NPUB_HEX);
            assertEqual(envelope.v, 3, 'produces v3');
            const decrypted = await mod.decryptWithBackupPassword(envelope, password, NPUB_HEX);
            assertEqual(decrypted, plaintext, 'roundtrip works');
        });

        await it('wrong backup password fails', async () => {
            const envelope = await mod.encryptWithBackupPassword('secret', 'correct', NPUB_HEX);
            try {
                await mod.decryptWithBackupPassword(envelope, 'wrong', NPUB_HEX);
                assert(false, 'should have thrown');
            } catch (err) {
                assert(true, 'wrong password rejected');
            }
        });

        await it('v3 envelope has random salt', async () => {
            const e1 = await mod.encryptWithBackupPassword('data', 'pass', NPUB_HEX);
            const e2 = await mod.encryptWithBackupPassword('data', 'pass', NPUB_HEX);
            assert(e1.salt !== e2.salt, 'different salts');
        });

        await it('v2 decryption uses npubHex as salt', async () => {
            // Simulate a v2 envelope by encrypting with npubHex as the salt
            // then setting v: 2 (removing salt field)
            const plaintext = 'test-data';
            const password = 'pass123';

            // v3 envelope first
            const v3 = await mod.encryptWithBackupPassword(plaintext, password, NPUB_HEX);

            // Create a v2-style envelope: salt is npubHex (deterministic)
            const enc = new TextEncoder();
            const salt = enc.encode(NPUB_HEX);
            const key = await mod.deriveBackupKey(password, salt);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertextBuf = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
            );
            const v2Envelope = {
                v: 2,
                iv: btoa(String.fromCharCode(...iv)),
                ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf)))
            };

            const decrypted = await mod.decryptWithBackupPassword(v2Envelope, password, NPUB_HEX);
            assertEqual(decrypted, plaintext, 'v2 decryption works with npubHex salt');
        });
    });

    await describeAsync('Key caching behavior', async () => {
        await it('caches key after first encryption', async () => {
            mod.resetCache();
            assert(mod._cachedLocalKey === null, 'cache starts empty');
            await mod.encryptLocal('data', 'mypass');
            assert(mod._cachedLocalKey !== null, 'cache populated');
            assertEqual(mod._cachedLocalPassphrase, 'mypass', 'passphrase cached');
        });

        await it('uses cached key for same passphrase', async () => {
            mod.resetCache();
            const e1 = await mod.encryptLocal('data1', 'pass');
            const key1 = mod._cachedLocalKey;
            const e2 = await mod.encryptLocal('data2', 'pass');
            const key2 = mod._cachedLocalKey;
            assert(key1 === key2, 'same CryptoKey object reused');
        });

        await it('invalidates cache on passphrase change', async () => {
            mod.resetCache();
            await mod.encryptLocal('data', 'pass1');
            const key1 = mod._cachedLocalKey;
            await mod.encryptLocal('data', 'pass2');
            const key2 = mod._cachedLocalKey;
            assert(key1 !== key2, 'different key for different passphrase');
            assertEqual(mod._cachedLocalPassphrase, 'pass2', 'new passphrase cached');
        });
    });

    await describeAsync('Cross-encryption isolation', async () => {
        await it('local and backup passwords are independent', async () => {
            mod.resetCache();
            const localEncrypted = await mod.encryptLocal('local-data', 'local-pass');
            const backupEnvelope = await mod.encryptWithBackupPassword('backup-data', 'backup-pass', 'npub');

            // Verify they decrypt independently
            const localDecrypted = await mod.decryptLocal(localEncrypted, 'local-pass');
            assertEqual(localDecrypted, 'local-data', 'local decrypts correctly');

            const backupDecrypted = await mod.decryptWithBackupPassword(backupEnvelope, 'backup-pass', 'npub');
            assertEqual(backupDecrypted, 'backup-data', 'backup decrypts correctly');
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
