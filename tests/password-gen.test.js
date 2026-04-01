/**
 * Password Generation & Hashing Tests
 *
 * Tests: hash(), generatePassword() determinism & format, getPasswordStrength()
 *
 * Run:  node tests/password-gen.test.js
 */

const { describeAsync, it, assert, assertEqual, summary } = require('./helpers/test-harness');
const { extractFunction, words } = require('./helpers/extract');

// ── Build execution context ─────────────────────────────────────────────────

const fnSrc = [
    extractFunction('hash'),
    extractFunction('generatePassword'),
    extractFunction('getPasswordStrength'),
].join('\n\n');

const code = `
    ${fnSrc}
    return { hash, generatePassword, getPasswordStrength };
`;

const factory = new Function('crypto', 'TextEncoder', 'Uint8Array', 'Array', 'invoke', code);
const mod = factory(globalThis.crypto, TextEncoder, Uint8Array, Array, null);
const { hash, generatePassword, getPasswordStrength } = mod;

// ── Tests ───────────────────────────────────────────────────────────────────

async function runTests() {

    await describeAsync('hash() — SHA-256', async () => {
        await it('hashes empty string correctly', async () => {
            const result = await hash('');
            // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            assertEqual(result, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'empty string hash');
        });

        await it('hashes "hello" correctly', async () => {
            const result = await hash('hello');
            // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            assertEqual(result, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'hello hash');
        });

        await it('returns 64-char hex string', async () => {
            const result = await hash('test');
            assertEqual(result.length, 64, '64 chars');
            assert(/^[0-9a-f]+$/.test(result), 'valid hex');
        });

        await it('is deterministic', async () => {
            const h1 = await hash('deterministic');
            const h2 = await hash('deterministic');
            assertEqual(h1, h2, 'same input → same output');
        });

        await it('different inputs produce different hashes', async () => {
            const h1 = await hash('input1');
            const h2 = await hash('input2');
            assert(h1 !== h2, 'different inputs → different hashes');
        });
    });

    await describeAsync('generatePassword() — deterministic password generation', async () => {
        const PK = 'abc123';
        const USER = 'alice@example.com';
        const SITE = 'github.com';

        await it('produces correct format: PASS + hex + 249+', async () => {
            const pass = await generatePassword(PK, USER, SITE, 0, 16);
            assert(pass.startsWith('PASS'), 'starts with PASS');
            assert(pass.endsWith('249+'), 'ends with 249+');
            assertEqual(pass.length, 24, 'total length = 4 + 16 + 4');
        });

        await it('hex portion is valid lowercase hex', async () => {
            const pass = await generatePassword(PK, USER, SITE, 0, 16);
            const hex = pass.slice(4, -4);
            assertEqual(hex.length, 16, 'hex portion is 16 chars');
            assert(/^[0-9a-f]+$/.test(hex), 'valid hex');
        });

        await it('is deterministic — same inputs → same password', async () => {
            const p1 = await generatePassword(PK, USER, SITE, 0, 16);
            const p2 = await generatePassword(PK, USER, SITE, 0, 16);
            assertEqual(p1, p2, 'deterministic');
        });

        await it('different nonces produce different passwords', async () => {
            const p0 = await generatePassword(PK, USER, SITE, 0, 16);
            const p1 = await generatePassword(PK, USER, SITE, 1, 16);
            assert(p0 !== p1, 'nonce 0 ≠ nonce 1');
        });

        await it('different users produce different passwords', async () => {
            const p1 = await generatePassword(PK, 'alice', SITE, 0, 16);
            const p2 = await generatePassword(PK, 'bob', SITE, 0, 16);
            assert(p1 !== p2, 'different user → different password');
        });

        await it('different sites produce different passwords', async () => {
            const p1 = await generatePassword(PK, USER, 'github.com', 0, 16);
            const p2 = await generatePassword(PK, USER, 'gitlab.com', 0, 16);
            assert(p1 !== p2, 'different site → different password');
        });

        await it('different private keys produce different passwords', async () => {
            const p1 = await generatePassword('key1', USER, SITE, 0, 16);
            const p2 = await generatePassword('key2', USER, SITE, 0, 16);
            assert(p1 !== p2, 'different key → different password');
        });

        await it('respects hashLength parameter', async () => {
            const p8 = await generatePassword(PK, USER, SITE, 0, 8);
            const p32 = await generatePassword(PK, USER, SITE, 0, 32);
            assertEqual(p8.length, 16, 'hashLength 8 → 16 chars');
            assertEqual(p32.length, 40, 'hashLength 32 → 40 chars');
        });

        await it('nonce 0 through 10 all produce unique passwords', async () => {
            const passwords = new Set();
            for (let n = 0; n <= 10; n++) {
                passwords.add(await generatePassword(PK, USER, SITE, n, 16));
            }
            assertEqual(passwords.size, 11, '11 unique passwords for nonces 0-10');
        });

        await it('high nonce values work correctly', async () => {
            const p = await generatePassword(PK, USER, SITE, 999999, 16);
            assert(p.startsWith('PASS'), 'format preserved at high nonce');
            assertEqual(p.length, 24, 'length preserved');
        });
    });

    await describeAsync('generatePassword() — algorithm verification', async () => {
        await it('matches manual SHA-256 computation', async () => {
            const pk = 'testkey';
            const user = 'user';
            const site = 'site';
            const nonce = 0;
            const hl = 16;

            // Manual: SHA-256("testkey/user/site/0").substring(0, 16)
            const concat = `${pk}/${user}/${site}/${nonce}`;
            const expected = (await hash(concat)).substring(0, hl);
            const pass = await generatePassword(pk, user, site, nonce, hl);
            assertEqual(pass, 'PASS' + expected + '249+', 'matches manual computation');
        });
    });

    await describeAsync('Password strength — complexity requirements', async () => {
        await it('generated password satisfies common complexity rules', async () => {
            const pass = await generatePassword('key', 'user', 'site', 0, 16);
            assert(/[A-Z]/.test(pass), 'has uppercase (from PASS)');
            assert(/[a-z]/.test(pass), 'has lowercase (from hex)');
            assert(/[0-9]/.test(pass), 'has digits (from 249+ and hex)');
            assert(/[^a-zA-Z0-9]/.test(pass), 'has special char (from +)');
        });

        await it('minimum length password (hashLength=8) still satisfies complexity', async () => {
            const pass = await generatePassword('key', 'user', 'site', 0, 8);
            assertEqual(pass.length, 16, '16 chars minimum');
            assert(/[A-Z]/.test(pass), 'has uppercase');
            assert(/[a-z]/.test(pass), 'has lowercase');
            assert(/[0-9]/.test(pass), 'has digits');
            assert(/[^a-zA-Z0-9]/.test(pass), 'has special');
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
