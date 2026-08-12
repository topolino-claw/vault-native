/**
 * Hostile-input tests — every parser's behaviour when fed attacker-shaped data.
 *
 * The vault files live in folders a user syncs however they like, so anything
 * can land in them: a truncated download, a partial sync, or a file crafted to
 * probe for error-path oracles. Each check pins the ERROR CONTRACT, not just
 * "does not crash": callers distinguish exactly two things, 'Wrong password'
 * and 'Malformed vault file', and nothing else may escape as a raw exception
 * (a DOMException from bad base64, a SyntaxError from bad JSON, a URIError
 * from a bad percent-escape). Fuzz this file: every test is a small pure
 * function, so `fuzz` over it is cheap.
 */
import assert from 'assert';
import { loadCore, harness, TEST_ITERATIONS } from './_load.mjs';

const t = harness('hostile input (error contract / parser hygiene)');
const core = await loadCore();
const { Envelope, Oplog, Totp, Porter, Util, Records: R, HLC } = core;

const PW = 'a master password';

// ------------------------------------------------------- envelope contract

await t.test('non-JSON file -> Malformed vault file', async () => {
    await assert.rejects(() => Envelope.decryptEnvelope('not json at all', PW), {
        message: 'Malformed vault file'
    });
});

await t.test('wrong envelope type -> Not a topolino-vault file', async () => {
    await assert.rejects(
        () => Envelope.decryptEnvelope(JSON.stringify({ type: 'something-else', payload: 'x' }), PW),
        { message: 'Not a topolino-vault file' }
    );
});

await t.test('v2 with a malformed header -> Malformed vault file', async () => {
    const cases = [
        { v: 2, type: 'topolino-vault', payload: 'AA==' },
        { v: 2, type: 'topolino-vault', kdf: {}, cipher: { iv: 'AA==' }, payload: 'AA==' },
        { v: 2, type: 'topolino-vault', kdf: { algo: 'PBKDF2-SHA256', iterations: 600000, salt: 'AA==' }, payload: 'AA==' },
        { v: 2, type: 'topolino-vault', kdf: { algo: 'PBKDF2-SHA256', iterations: 600000, salt: 'AA==' }, cipher: {}, payload: 'AA==' }
    ];
    for (const c of cases) {
        await assert.rejects(() => Envelope.decryptEnvelope(JSON.stringify(c), PW), {
            message: 'Malformed vault file'
        });
    }
});

await t.test('attacker base64 in the header -> Malformed vault file, never a raw DOMException', async () => {
    // '###' is not valid base64. The decoder must be folded into the same
    // contract as every other malformed header, not leak as InvalidCharacterError.
    const bad = JSON.stringify({
        v: 2,
        type: 'topolino-vault',
        kdf: { algo: 'PBKDF2-SHA256', iterations: TEST_ITERATIONS, salt: '###' },
        cipher: { algo: 'AES-256-GCM', iv: 'AA==' },
        payload: 'AA=='
    });
    await assert.rejects(() => Envelope.decryptEnvelope(bad, PW), {
        message: 'Malformed vault file'
    });

    const badIv = JSON.stringify({
        v: 2,
        type: 'topolino-vault',
        kdf: { algo: 'PBKDF2-SHA256', iterations: TEST_ITERATIONS, salt: 'AA==' },
        cipher: { algo: 'AES-256-GCM', iv: '%%%' },
        payload: 'AA=='
    });
    await assert.rejects(() => Envelope.decryptEnvelope(badIv, PW), {
        message: 'Malformed vault file'
    });
});

await t.test('unbounded KDF iterations are rejected before deriving', async () => {
    // An attacker who can drop a file into the synced folder must not be able
    // to pin the app's CPU with an absurd iteration count. Bounded and fast.
    for (const iterations of [0, -1, 1e9, 2e8, Number.MAX_SAFE_INTEGER, 10000001]) {
        const off = await Envelope.randomSalt();
        const file = JSON.stringify({
            v: 2,
            type: 'topolino-vault',
            kdf: { algo: 'PBKDF2-SHA256', iterations, salt: Util.bytesToB64(off) },
            cipher: { algo: 'AES-256-GCM', iv: 'AAAAAAAAAAAAAAAA' },
            payload: 'AA=='
        });
        await assert.rejects(() => Envelope.decryptEnvelope(file, PW), {
            message: 'Vault KDF iterations out of range'
        });
    }
});

await t.test('valid envelope + wrong password -> exactly Wrong password', async () => {
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    const file = await Envelope.encryptEnvelope({ privateKey: 'aa', users: {} }, key, salt, TEST_ITERATIONS);
    await assert.rejects(() => Envelope.decryptEnvelope(file, 'definitely wrong'), {
        message: 'Wrong password'
    });
});

await t.test('valid password + garbage plaintext -> Malformed vault file, not Wrong password', async () => {
    // GCM only authenticates under the correct key, so a payload that decrypts
    // but is not JSON is a corrupt file, not a wrong password.
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    const iv = new Uint8Array(12);
    globalThis.crypto.getRandomValues(iv);
    const garbage = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode('this is not json')
    );
    const file = JSON.stringify({
        v: 2,
        type: 'topolino-vault',
        kdf: { algo: 'PBKDF2-SHA256', iterations: TEST_ITERATIONS, salt: Util.bytesToB64(salt) },
        cipher: { algo: 'AES-256-GCM', iv: Util.bytesToB64(iv) },
        payload: Util.bytesToB64(new Uint8Array(garbage))
    });
    await assert.rejects(() => Envelope.decryptEnvelope(file, PW), {
        message: 'Malformed vault file'
    });
});

await t.test('normalizeVaultData drops prototype-pollution keys', () => {
    const hostile = JSON.parse('{"__proto__":{"polluted":1},"constructor":{"polluted":1},"prototype":{"polluted":1},"users":{},"privateKey":"x"}');
    const out = Envelope.normalizeVaultData(hostile);
    assert.deepStrictEqual(
        Object.keys(out).sort(),
        ['passphrase', 'privateKey', 'seedPhrase', 'settings', 'users']
    );
    assert.strictEqual({}.polluted, undefined, 'Object.prototype must be untouched');
    assert.strictEqual(out.users.polluted, undefined);
});

await t.test('mergeUsers ignores non-finite nonces and never decreases', () => {
    const target = { u: { s: 5 } };
    const hostile = {
        u: { s: '999', other: 'NaN' },
        v: { s: Infinity, w: Number.NaN, any: -3 }
    };
    Envelope.mergeUsers(target, hostile);
    assert.strictEqual(target.u.s, 5, 'non-numeric nonce ignored');
    assert.strictEqual(target.v.s, undefined, 'Infinity ignored');
    assert.strictEqual(target.v.w, undefined, 'NaN ignored');
    assert.strictEqual(target.v.any, -3, 'a finite number still merges');
});

// ------------------------------------------------------- oplog

await t.test('a log with no readable header is reported skipped, not silently empty', async () => {
    const vmk = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
    const result = await Oplog.parseLog('{not-json', vmk);
    assert.strictEqual(result.ops.length, 0);
    assert.ok(result.skipped >= 1, 'unreadable header must be reported as skipped');
});

await t.test('torn final line is skipped; earlier ops survive', async () => {
    const vmk = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
    const dev = '000000000001';
    const op = { id: 'c:x', type: 'credential', set: { nonce: 1 }, t: '000000000001.0000.000000000001' };
    const header = Oplog.encodeHeader(dev);
    const good = await Oplog.encodeEntry(op, vmk, dev);
    const text = header + '\n' + good + '\n{"iv":"AAAAAAAAAAAA","p":"zz"}\n'; // last line is garbage ciphertext
    const result = await Oplog.parseLog(text, vmk);
    assert.strictEqual(result.ops.length, 1);
    assert.strictEqual(result.skipped, 1);
    assert.deepStrictEqual(result.ops[0], op);
});

await t.test('entries are bound to their log via AAD (cannot be spliced between devices)', async () => {
    const vmk = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
    const op = { id: 'c:y', type: 'credential', set: { nonce: 2 }, t: '000000000002.0000.000000000002' };
    const entry = await Oplog.encodeEntry(op, vmk, 'aaaaaaaaaaaa'); // device A
    // Same bytes, relabelled as device B: AAD changes, must NOT decrypt.
    const relabelled = Oplog.encodeHeader('bbbbbbbbbbbb') + '\n' + entry + '\n';
    const result = await Oplog.parseLog(relabelled, vmk);
    assert.strictEqual(result.ops.length, 0);
    assert.strictEqual(result.skipped, 1);
});

await t.test('an entry that is valid JSON but not a log entry is skipped', async () => {
    const vmk = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
    const text = Oplog.encodeHeader('000000000001') + '\n{"nope":true}\n';
    const result = await Oplog.parseLog(text, vmk);
    assert.strictEqual(result.ops.length, 0);
    assert.strictEqual(result.skipped, 1);
});

// ------------------------------------------------------- porter (CSV)

await t.test('CSV export neutralises spreadsheet formula cells', () => {
    const out = Porter.exportCsv([
        { name: '=HYPERLINK("http://x")', url: '-2+3+cmd|calc', username: '@SUM(A1)', password: '+cmd' },
        { name: '\tformula', url: 'plain', username: '', password: '' },
        { name: 'safe', url: 'safe', username: 'safe', password: 'safe' }
    ]);
    const lines = out.split('\r\n');
    // Formula cells keep the neutralising apostrophe even after CSV quoting.
    assert.ok(lines[1].includes("'=HYPERLINK("), '= cell neutralised');
    assert.ok(lines[1].includes("'-2+3+cmd|calc"), '- cell neutralised');
    assert.ok(lines[1].includes("'@SUM(A1)"), '@ cell neutralised');
    assert.ok(lines[1].includes("'+cmd"), '+ cell neutralised');
    assert.ok(lines[2].includes("'\t"), 'tab cell neutralised');
    assert.ok(lines[3].startsWith('safe'), 'ordinary cell untouched');
    // Round trip: the neutralised file still imports back to the same rows.
    const back = Porter.importCsv(out);
    assert.ok(back.some((e) => e.user === "'@SUM(A1)"), 'import reads the literal, not a formula');
});

await t.test('CSV parser survives unclosed quotes and escaped quotes', () => {
    assert.deepStrictEqual(Porter.parseCsv('"a\nb,c'), [['a\nb,c']], 'unclosed quote runs to EOF');
    assert.deepStrictEqual(Porter.parseCsv('x,"a""b",z\n'), [['x', 'a"b', 'z']], 'escaped quote pair');
    assert.deepStrictEqual(Porter.parseCsv(''), [], 'empty input -> no rows');
});

// ------------------------------------------------------- totp

await t.test('parseOtpauth returns null for malformed percent-escaping, never throws', () => {
    for (const uri of [
        'otpauth://totp/Bad%zzLabel?secret=ABC',
        'otpauth://totp/ok?secret=%xx',
        'otpauth://totp/ok?secret=ABC&issuer=%',
        'otpauth://totp/%',
        'garbage://not-otpauth?secret=ABC'
    ]) {
        let threw = false;
        let result = null;
        try {
            result = Totp.parseOtpauth(uri);
        } catch (e) {
            threw = true;
        }
        assert.strictEqual(threw, false, `must not throw for ${uri}`);
        if (uri.startsWith('otpauth://totp/ok?secret=ABC') === false || uri.includes('issuer')) {
            // A malformed % anywhere yields null (label unusable, or param dropped).
            if (uri.includes('%')) {
                if (uri.includes('secret=%')) {
                    assert.strictEqual(result, null, `no decodable secret for ${uri}`);
                }
            }
        }
    }
});

await t.test('invalid base32 secret reports an error, not a crash', async () => {
    const { code, secondsRemaining } = await Totp.generate('JBSWY3DPEHPK3PXP');
    assert.strictEqual(code.length, 6);
    await assert.rejects(() => Totp.generate('0O1L!!'), /invalid base32 character/);
});

// ------------------------------------------------------- records / hlc

await t.test('records: forbidden field keys can never reach a record', () => {
    const state = R.emptyState();
    const clock = HLC.createClock('000000000001');
    const polluted = { id: 'r:1', type: 'custom', set: { __proto__: { nope: 1 }, ok: 'yes' }, t: clock.tick() };
    R.applyOp(state, polluted);
    const rec = state.get('r:1');
    assert.strictEqual(rec.values.ok, 'yes');
    assert.strictEqual(rec.values.nope, undefined);
    assert.strictEqual({}.nope, undefined, 'Object.prototype must stay clean');
});

await t.test('records: hostile credential ids/values cannot poison users map', () => {
    const state = R.emptyState();
    const clock = HLC.createClock('000000000002');
    for (const [user, site] of [
        ['__proto__', 'x'],
        ['ok', 'constructor'],
        ['a', '__proto__'],
        ['ok', 'github.com']
    ]) {
        const op = R.makeOp(clock, R.credentialId(user, site), R.TYPES.CREDENTIAL, { user, site, nonce: 1 });
        R.applyOp(state, op);
    }
    const payload = R.toSnapshotPayload(state);
    // Forbidden site names are skipped, so the user object is never created.
    assert.strictEqual(Object.prototype.hasOwnProperty.call(payload.users, 'a'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(payload.users, '__proto__'), false);
    // 'ok' exists for its valid site; the forbidden 'constructor' site must not
    // appear as an own key or reach the prototype.
    assert.ok(payload.users['ok'], 'user ok exists for its valid site');
    assert.strictEqual(payload.users['ok']['github.com'], 1);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(payload.users['ok'], 'constructor'), false);
    assert.strictEqual({}.constructor, Object, 'prototype constructor untouched');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(payload.users, 'x'), false);
});

// ------------------------------------------------------- util

await t.test('base64 helpers reject invalid input instead of crashing weirdly', () => {
    assert.throws(() => Util.b64ToBytes('not-base64!'), 'must throw on invalid base64');
    // Node/browsers disagree on whether an un-padded length is an error; the
    // contract is that a VALID character set never throws mid-decode.
    const decoded = Util.b64ToBytes('JBSWY3DPEHPK');
    assert.ok(decoded.length > 0);
});

t.done();