/**
 * BIP39 & Key Derivation Tests
 *
 * Tests: wordsToIndices, decimalStringToHex, generateMnemonic,
 *        verifyBip39SeedPhrase, derivePrivateKey, NIP-06 derivation,
 *        BIP32 primitives, secp256k1 EC math.
 *
 * Run:  node tests/bip39.test.js
 */

const { describe, describeAsync, it, assert, assertEqual, assertDeepEqual, assertThrows, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction, createModule } = require('./helpers/extract');

// ── Extract pure functions ──────────────────────────────────────────────────

const pureFns = createModule([
    'decimalStringToHex',
    'wordsToIndices',
    'getPasswordStrength',
], [], { words, invoke: null });

const { decimalStringToHex, wordsToIndices, getPasswordStrength } = pureFns;

// ── Async crypto functions (need Web Crypto) ────────────────────────────────

// Build a context with all the BIP39/BIP32/NIP-06 functions
const cryptoFnNames = [
    'decimalStringToHex', 'wordsToIndices',
    'verifyBip39SeedPhrase', 'generateMnemonic', 'derivePrivateKey',
    '_secp256k1ModAdd', '_modInv', '_ecAdd', '_ecMul',
    '_privToCompressedPub', '_mnemonicToSeed', '_bip32Master',
    '_bip32HardChild', '_bip32NormalChild',
    'deriveNostrKeyNIP06',
];

const cryptoConstNames = [
    'SECP256K1_N', 'SECP256K1_P', 'SECP256K1_Gx', 'SECP256K1_Gy',
];

// Extract consts manually since they're BigInt
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

// Build async crypto module
let cryptoMod;
const asyncTests = [];

function queueAsync(describeName, tests) {
    asyncTests.push({ describeName, tests });
}

// ── Sync tests ──────────────────────────────────────────────────────────────

describe('decimalStringToHex', () => {
    it('converts 0 to "0"', () => {
        assertEqual(decimalStringToHex('0'), '0', '0 → "0"');
    });

    it('converts 255 to "ff"', () => {
        assertEqual(decimalStringToHex('255'), 'ff', '255 → "ff"');
    });

    it('converts 256 to "100"', () => {
        assertEqual(decimalStringToHex('256'), '100', '256 → "100"');
    });

    it('converts large number correctly', () => {
        assertEqual(decimalStringToHex('1000000'), 'f4240', '1000000 → "f4240"');
    });

    it('throws on non-digit input', () => {
        assertThrows(() => decimalStringToHex('abc'), 'Invalid', 'non-digit throws');
    });

    it('throws on empty string', () => {
        assertThrows(() => decimalStringToHex(''), 'Invalid', 'empty throws');
    });

    it('handles very large numbers (BIP39-scale)', () => {
        // 48 digits (12 words × 4 digits each)
        const big = '000000000000000000000000000000000000000000000002';
        const result = decimalStringToHex(big);
        assertEqual(result, '2', 'leading zeros collapse');
    });
});

describe('wordsToIndices', () => {
    it('converts single word "abandon" to "0000"', () => {
        assertEqual(wordsToIndices('abandon'), '0000', 'abandon → 0000');
    });

    it('converts "about" (index 3) to "0003"', () => {
        assertEqual(wordsToIndices('about'), '0003', 'about → 0003');
    });

    it('converts "zoo" (index 2047) to "2047"', () => {
        assertEqual(wordsToIndices('zoo'), '2047', 'zoo → 2047');
    });

    it('handles multi-word input', () => {
        const result = wordsToIndices('abandon abandon about');
        assertEqual(result, '000000000003', '3 words concatenated');
    });

    it('is case-insensitive', () => {
        assertEqual(wordsToIndices('ABANDON'), '0000', 'uppercase works');
    });

    it('handles extra whitespace', () => {
        assertEqual(wordsToIndices('  abandon   about  '), '00000003', 'trims & splits');
    });

    it('throws on invalid word', () => {
        assertThrows(() => wordsToIndices('notaword'), 'not found', 'invalid word throws');
    });
});

describe('getPasswordStrength', () => {
    it('8 hex chars = 32 bits = Weak', () => {
        const s = getPasswordStrength(8);
        assertEqual(s.bits, 32, '8 hex = 32 bits');
        assertEqual(s.label, 'Weak', 'label is Weak');
        assertEqual(s.len, 16, 'total len = 4+8+4');
    });

    it('12 hex chars = 48 bits = Good', () => {
        const s = getPasswordStrength(12);
        assertEqual(s.bits, 48, '12 hex = 48 bits');
        assertEqual(s.label, 'Good', 'label is Good');
    });

    it('16 hex chars = 64 bits = Strong (default)', () => {
        const s = getPasswordStrength(16);
        assertEqual(s.bits, 64, '16 hex = 64 bits');
        assertEqual(s.label, 'Strong', 'label is Strong');
        assertEqual(s.len, 24, 'total len = 4+16+4');
    });

    it('20 hex chars = 80 bits = Excellent', () => {
        const s = getPasswordStrength(20);
        assertEqual(s.bits, 80, '20 hex = 80 bits');
        assertEqual(s.label, 'Excellent', 'label is Excellent');
    });

    it('32 hex chars = 128 bits = Excellent', () => {
        const s = getPasswordStrength(32);
        assertEqual(s.bits, 128, '32 hex = 128 bits');
        assertEqual(s.label, 'Excellent', 'label is Excellent');
        assertEqual(s.len, 40, 'total len = 4+32+4');
    });

    it('64 hex chars = 256 bits = Excellent (max)', () => {
        const s = getPasswordStrength(64);
        assertEqual(s.bits, 256, '64 hex = 256 bits');
        assertEqual(s.label, 'Excellent', 'label is Excellent');
    });
});

describe('BIP39 word list integrity', () => {
    it('has exactly 2048 words', () => {
        assertEqual(words.length, 2048, 'wordlist length');
    });

    it('first word is "abandon"', () => {
        assertEqual(words[0], 'abandon', 'first word');
    });

    it('last word is "zoo"', () => {
        assertEqual(words[2047], 'zoo', 'last word');
    });

    it('all words are lowercase a-z only', () => {
        const invalid = words.filter(w => !/^[a-z]+$/.test(w));
        assertEqual(invalid.length, 0, 'all words are lowercase alpha');
    });

    it('no duplicate words', () => {
        const unique = new Set(words);
        assertEqual(unique.size, 2048, 'no duplicates');
    });
});

// ── Async tests (BIP39 validation, key derivation) ─────────────────────────

async function runAsyncTests() {
    // Build the crypto module inside async context
    const fnSrc = cryptoFnNames.map(n => extractFunction(n)).join('\n\n');
    const code = `
        const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        const SECP256K1_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
        const SECP256K1_Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
        const SECP256K1_Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
        ${fnSrc}
        return { ${cryptoFnNames.join(', ')} };
    `;

    const factory = new Function('words', 'invoke', 'crypto', 'TextEncoder', 'Uint8Array', 'BigInt', 'Array', 'Math', 'String', 'Number', 'parseInt', code);
    cryptoMod = factory(words, null, globalThis.crypto, TextEncoder, Uint8Array, BigInt, Array, Math, String, Number, parseInt);

    // ── Test: verifyBip39SeedPhrase ─────────────────────────────────────────
    const VALID_12 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    await describeAsync('verifyBip39SeedPhrase', async () => {
        await it('accepts valid 12-word test vector', async () => {
            const result = await cryptoMod.verifyBip39SeedPhrase(VALID_12);
            assert(result === true, 'valid phrase accepted');
        });

        await it('rejects wrong checksum word', async () => {
            const bad = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
            const result = await cryptoMod.verifyBip39SeedPhrase(bad);
            assert(result === false, 'bad checksum rejected');
        });

        await it('rejects 11-word phrase', async () => {
            const short = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
            const result = await cryptoMod.verifyBip39SeedPhrase(short);
            assert(result === false, '11 words rejected');
        });

        await it('rejects phrase with non-BIP39 word', async () => {
            const bad = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword';
            const result = await cryptoMod.verifyBip39SeedPhrase(bad);
            assert(result === false, 'invalid word rejected');
        });

        await it('handles mixed case and extra spaces', async () => {
            const messy = '  ABANDON  abandon  ABANDON abandon  abandon abandon abandon abandon abandon abandon abandon  ABOUT  ';
            const result = await cryptoMod.verifyBip39SeedPhrase(messy);
            assert(result === true, 'normalization works');
        });
    });

    await describeAsync('generateMnemonic', async () => {
        await it('produces 12 words', async () => {
            const mnemonic = await cryptoMod.generateMnemonic();
            const wordCount = mnemonic.split(' ').length;
            assertEqual(wordCount, 12, '12 words generated');
        });

        await it('all words are in BIP39 list', async () => {
            const mnemonic = await cryptoMod.generateMnemonic();
            const invalid = mnemonic.split(' ').filter(w => !words.includes(w));
            assertEqual(invalid.length, 0, 'all words valid');
        });

        await it('generated mnemonic passes checksum validation', async () => {
            const mnemonic = await cryptoMod.generateMnemonic();
            const valid = await cryptoMod.verifyBip39SeedPhrase(mnemonic);
            assert(valid === true, 'generated mnemonic is valid BIP39');
        });

        await it('produces different mnemonics on each call', async () => {
            const m1 = await cryptoMod.generateMnemonic();
            const m2 = await cryptoMod.generateMnemonic();
            assert(m1 !== m2, 'two calls produce different results');
        });
    });

    await describeAsync('derivePrivateKey', async () => {
        await it('derives correct key from test vector', async () => {
            // "abandon" × 11 + "about" → indices all 0000 except last is 0003
            // → decimal "000000000000000000000000000000000000000000000003"
            // → hex "3"
            const pk = await cryptoMod.derivePrivateKey(VALID_12);
            assertEqual(pk, '3', 'test vector private key');
        });

        await it('is case-insensitive', async () => {
            const upper = 'ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT';
            const pk1 = await cryptoMod.derivePrivateKey(VALID_12);
            const pk2 = await cryptoMod.derivePrivateKey(upper);
            assertEqual(pk1, pk2, 'case insensitive');
        });

        await it('is deterministic', async () => {
            const pk1 = await cryptoMod.derivePrivateKey(VALID_12);
            const pk2 = await cryptoMod.derivePrivateKey(VALID_12);
            assertEqual(pk1, pk2, 'deterministic');
        });

        await it('different phrases produce different keys', async () => {
            const p2 = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
            const pk1 = await cryptoMod.derivePrivateKey(VALID_12);
            const pk2 = await cryptoMod.derivePrivateKey(p2);
            assert(pk1 !== pk2, 'different phrases → different keys');
        });
    });

    await describeAsync('NIP-06 key derivation (deriveNostrKeyNIP06)', async () => {
        const TEST_MNEMONIC = VALID_12;
        const EXPECTED_HEX = '5f29af3b9676180290e77a4efad265c4c2ff28a5302461f73597fda26bb25731';

        await it('derives correct NIP-06 key for test vector (no passphrase)', async () => {
            const hex = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            assertEqual(hex, EXPECTED_HEX, 'NIP-06 test vector match');
        });

        await it('is deterministic', async () => {
            const h1 = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            const h2 = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            assertEqual(h1, h2, 'deterministic');
        });

        await it('produces 64-char hex string', async () => {
            const hex = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            assertEqual(hex.length, 64, '64 hex chars');
            assert(/^[0-9a-f]+$/.test(hex), 'valid hex');
        });

        await it('passphrase changes the derived key', async () => {
            const h1 = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            const h2 = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, 'my-passphrase');
            assert(h1 !== h2, 'passphrase changes key');
        });

        await it('different mnemonics produce different keys', async () => {
            const m2 = await cryptoMod.generateMnemonic();
            const h1 = await cryptoMod.deriveNostrKeyNIP06(TEST_MNEMONIC, '');
            const h2 = await cryptoMod.deriveNostrKeyNIP06(m2, '');
            assert(h1 !== h2, 'different mnemonics → different keys');
        });
    });

    await describeAsync('BIP32 primitive: _mnemonicToSeed', async () => {
        await it('produces 64-byte seed', async () => {
            const seed = await cryptoMod._mnemonicToSeed(VALID_12);
            assertEqual(seed.length, 64, '64 bytes');
        });

        await it('passphrase changes the seed', async () => {
            const s1 = await cryptoMod._mnemonicToSeed(VALID_12, '');
            const s2 = await cryptoMod._mnemonicToSeed(VALID_12, 'test');
            const h1 = Array.from(s1).map(b => b.toString(16).padStart(2, '0')).join('');
            const h2 = Array.from(s2).map(b => b.toString(16).padStart(2, '0')).join('');
            assert(h1 !== h2, 'different passphrase → different seed');
        });
    });

    await describeAsync('BIP32 primitive: _bip32Master', async () => {
        await it('produces privateKey and chainCode of 32 bytes each', async () => {
            const seed = await cryptoMod._mnemonicToSeed(VALID_12);
            const { privateKey, chainCode } = await cryptoMod._bip32Master(seed);
            assertEqual(privateKey.length, 32, 'privateKey is 32 bytes');
            assertEqual(chainCode.length, 32, 'chainCode is 32 bytes');
        });
    });

    describe('EC math: _privToCompressedPub', () => {
        it('produces 33-byte compressed public key', () => {
            // Use a known private key (1)
            const pk = new Uint8Array(32);
            pk[31] = 1; // private key = 1 → generator point G
            const pub = cryptoMod._privToCompressedPub(pk);
            assertEqual(pub.length, 33, '33 bytes');
            assert(pub[0] === 0x02 || pub[0] === 0x03, 'valid prefix');
        });

        it('private key 1 → generator point G', () => {
            const pk = new Uint8Array(32);
            pk[31] = 1;
            const pub = cryptoMod._privToCompressedPub(pk);
            // G.x = 79BE667E...
            const xHex = Array.from(pub.slice(1)).map(b => b.toString(16).padStart(2, '0')).join('');
            assert(xHex.startsWith('79be667ef9dcbbac'), 'x-coord matches G.x');
            // G.y is even, so prefix should be 02
            assertEqual(pub[0], 0x02, 'even y → 02 prefix');
        });
    });

    describe('EC math: _modInv', () => {
        it('modular inverse of 3 mod 7 = 5 (since 3*5=15≡1 mod 7)', () => {
            const result = cryptoMod._modInv(3n, 7n);
            assertEqual(result, 5n, '3^(-1) mod 7 = 5');
        });

        it('modular inverse of 2 mod 5 = 3 (since 2*3=6≡1 mod 5)', () => {
            const result = cryptoMod._modInv(2n, 5n);
            assertEqual(result, 3n, '2^(-1) mod 5 = 3');
        });
    });
}

// ── Run all ─────────────────────────────────────────────────────────────────

runAsyncTests().then(() => {
    const ok = summary();
    process.exit(ok ? 0 : 1);
}).catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
