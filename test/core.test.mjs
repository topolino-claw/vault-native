/**
 * Unit tests for the vault core: clock ordering, CRDT merge laws, log
 * durability, keyslots, and the store's sync behaviour.
 *
 * Run: node test/core.test.mjs
 */
import assert from 'assert';
import { loadCore, harness, TEST_ITERATIONS } from './_load.mjs';
import { MemDisk, memTransport, replicate } from './memfs.mjs';

const { HLC, Records: R, Oplog, Keyslots, Store, Envelope, Totp, Porter } = await loadCore();
const t = harness('core');

const PW = 'correct horse battery staple';
const opts = { iterations: TEST_ITERATIONS };

// ---------------------------------------------------------------- HLC

await t.test('stamps sort lexicographically in causal order', () => {
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const a = clock.tick();
    const b = clock.tick();
    const c = clock.tick();
    assert.ok(a < b && b < c, 'counter must advance while the wall clock is stalled');
    assert.ok(HLC.isStamp(a));
});

await t.test('a stalled or backwards wall clock cannot reorder stamps', () => {
    let now = 5000;
    const clock = HLC.createClock('aaaaaaaaaaaa', () => now);
    const first = clock.tick();
    now = 1; // clock jumps backwards, e.g. NTP correction or a dead RTC
    const second = clock.tick();
    assert.ok(second > first, 'causality must survive a backwards wall clock');
});

await t.test('observing a remote stamp makes later local stamps sort after it', () => {
    const local = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const remote = HLC.createClock('bbbbbbbbbbbb', () => 9_000_000);
    const remoteStamp = remote.tick();
    local.observe(remoteStamp);
    assert.ok(local.tick() > remoteStamp);
});

await t.test('malformed stamps are rejected rather than sorted', () => {
    assert.strictEqual(HLC.isStamp('nonsense'), false);
    assert.strictEqual(HLC.isStamp(''), false);
    assert.strictEqual(HLC.isStamp(null), false);
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    clock.observe('garbage'); // must not corrupt the clock
    assert.ok(HLC.isStamp(clock.tick()));
});

// ---------------------------------------------------------------- CRDT laws

function replay(ops) {
    const state = R.emptyState();
    R.applyOps(state, ops);
    return JSON.stringify(R.toSnapshotPayload(state));
}

await t.test('merge is commutative, associative and idempotent', () => {
    const a = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const b = HLC.createClock('bbbbbbbbbbbb', () => 1000);
    const ops = [
        R.makeOp(a, R.credentialId('me', 'github'), R.TYPES.CREDENTIAL, { user: 'me', site: 'github', nonce: 1 }),
        R.makeOp(b, R.credentialId('me', 'github'), R.TYPES.CREDENTIAL, { user: 'me', site: 'github', nonce: 3 }),
        R.makeOp(a, 'n:1', R.TYPES.NOTE, { title: 'recovery', body: 'in the safe' }),
        R.makeOp(b, 'n:1', R.TYPES.NOTE, { title: 'recovery codes' })
    ];

    const forward = replay(ops);
    const reversed = replay([...ops].reverse());
    const doubled = replay([...ops, ...ops]);
    const shuffled = replay([ops[2], ops[0], ops[3], ops[1]]);

    assert.strictEqual(forward, reversed, 'order must not matter');
    assert.strictEqual(forward, doubled, 'replaying twice must not change state');
    assert.strictEqual(forward, shuffled, 'any interleaving must converge');
});

await t.test('nonce never decreases, whatever the stamps say', () => {
    const early = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const late = HLC.createClock('bbbbbbbbbbbb', () => 9_000_000);
    const id = R.credentialId('me', 'bank');

    const state = R.emptyState();
    // The LATER stamp carries the LOWER nonce — a rollback attempt, or a
    // restored backup. Last-write-wins would accept it; grow-only must not.
    R.applyOp(state, R.makeOp(early, id, R.TYPES.CREDENTIAL, { user: 'me', site: 'bank', nonce: 7 }));
    R.applyOp(state, R.makeOp(late, id, R.TYPES.CREDENTIAL, { user: 'me', site: 'bank', nonce: 2 }));

    assert.strictEqual(R.getRecord(state, id).nonce, 7);
});

await t.test('concurrent creates of the same site converge to one record', () => {
    const a = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const b = HLC.createClock('bbbbbbbbbbbb', () => 1000);
    const state = R.emptyState();
    R.applyOp(state, R.makeOp(a, R.credentialId('me', 'proton'), R.TYPES.CREDENTIAL, { user: 'me', site: 'proton', nonce: 0 }));
    R.applyOp(state, R.makeOp(b, R.credentialId('me', 'proton'), R.TYPES.CREDENTIAL, { user: 'me', site: 'proton', nonce: 1 }));
    assert.strictEqual(R.listRecords(state, R.TYPES.CREDENTIAL).length, 1);
});

await t.test('delete is last-write-wins and revivable', () => {
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const state = R.emptyState();
    R.applyOp(state, R.makeOp(clock, 'n:2', R.TYPES.NOTE, { body: 'hi' }));
    R.applyOp(state, R.makeOp(clock, 'n:2', R.TYPES.NOTE, { deleted: true }));
    assert.strictEqual(R.getRecord(state, 'n:2'), null);
    R.applyOp(state, R.makeOp(clock, 'n:2', R.TYPES.NOTE, { deleted: false }));
    assert.strictEqual(R.getRecord(state, 'n:2').body, 'hi', 'revive must not lose field values');
});

await t.test('hostile keys cannot reach Object.prototype', () => {
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const state = R.emptyState();
    R.applyOp(state, R.makeOp(clock, 'n:3', R.TYPES.NOTE, { __proto__: { polluted: true }, ok: 1 }));
    R.applyOp(state, { id: '__proto__', type: 'note', set: { polluted: true }, t: clock.tick() });
    assert.strictEqual({}.polluted, undefined);
    assert.strictEqual(R.getRecord(state, 'n:3').ok, 1);
});

await t.test('non-numeric and infinite nonces are ignored', () => {
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const id = R.credentialId('me', 'x');
    const state = R.emptyState();
    R.applyOp(state, R.makeOp(clock, id, R.TYPES.CREDENTIAL, { user: 'me', site: 'x', nonce: 4 }));
    R.applyOp(state, R.makeOp(clock, id, R.TYPES.CREDENTIAL, { nonce: Infinity }));
    R.applyOp(state, R.makeOp(clock, id, R.TYPES.CREDENTIAL, { nonce: 'nine' }));
    assert.strictEqual(R.getRecord(state, id).nonce, 4);
});

// ---------------------------------------------------------------- oplog

await t.test('a torn final line costs only that line', async () => {
    const vmk = await Keyslots.generateVaultKey();
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const ops = [
        R.makeOp(clock, 'n:a', R.TYPES.NOTE, { body: 'one' }),
        R.makeOp(clock, 'n:b', R.TYPES.NOTE, { body: 'two' }),
        R.makeOp(clock, 'n:c', R.TYPES.NOTE, { body: 'three' })
    ];
    const log = await Oplog.encodeLog(ops, vmk, 'aaaaaaaaaaaa');

    const torn = log.slice(0, log.length - 40); // power loss mid-append
    const parsed = await Oplog.parseLog(torn, vmk);
    assert.strictEqual(parsed.ops.length, 2, 'the two intact entries must survive');
    assert.ok(parsed.skipped >= 1);
});

await t.test('entries cannot be spliced between device logs', async () => {
    const vmk = await Keyslots.generateVaultKey();
    const clock = HLC.createClock('aaaaaaaaaaaa', () => 1000);
    const entry = await Oplog.encodeEntry(R.makeOp(clock, 'n:a', R.TYPES.NOTE, { body: 'x' }), vmk, 'aaaaaaaaaaaa');
    const foreign = Oplog.encodeHeader('bbbbbbbbbbbb') + '\n' + entry + '\n';
    const parsed = await Oplog.parseLog(foreign, vmk);
    assert.strictEqual(parsed.ops.length, 0, 'AAD must bind an entry to its own log');
    assert.strictEqual(parsed.skipped, 1);
});

await t.test('a log with no readable header yields nothing rather than garbage', async () => {
    const vmk = await Keyslots.generateVaultKey();
    const parsed = await Oplog.parseLog('this is not a log\nnor is this\n', vmk);
    assert.strictEqual(parsed.ops.length, 0);
    assert.strictEqual(parsed.deviceId, null);
});

// ---------------------------------------------------------------- keyslots

await t.test('keyslot document leaks nothing derived from the password', async () => {
    const { doc } = await Keyslots.createDoc(PW, opts);
    const serialized = JSON.stringify(doc);
    const sha = globalThis.CryptoJS.SHA256(PW).toString();
    assert.ok(!serialized.includes(sha), 'the old SHA-256(password) oracle must be gone');
    assert.ok(!serialized.includes(PW));
    // Two vaults with the SAME password must share no slot material at all.
    const second = await Keyslots.createDoc(PW, opts);
    assert.notStrictEqual(doc.slots[0].id, second.doc.slots[0].id);
    assert.notStrictEqual(doc.slots[0].kdf.salt, second.doc.slots[0].kdf.salt);
    assert.notStrictEqual(doc.slots[0].wrapped, second.doc.slots[0].wrapped);
});

await t.test('unlock accepts the right password and rejects others', async () => {
    const { doc } = await Keyslots.createDoc(PW, opts);
    const { vmk } = await Keyslots.unlockDoc(doc, PW);
    assert.ok(vmk);
    await assert.rejects(Keyslots.unlockDoc(doc, PW + '!'), /Wrong password/);
});

await t.test('multiple credentials unlock the same vault key', async () => {
    const { doc, vmk } = await Keyslots.createDoc(PW, opts);
    await Keyslots.addSlot(doc, vmk, 'second-factor-phrase', { ...opts, label: 'recovery' });
    const viaFirst = await Keyslots.unlockDoc(doc, PW);
    const viaSecond = await Keyslots.unlockDoc(doc, 'second-factor-phrase');
    const raw = async (k) => Buffer.from(await crypto.subtle.exportKey('raw', k)).toString('hex');
    assert.strictEqual(await raw(viaFirst.vmk), await raw(viaSecond.vmk));
});

await t.test('password change rewraps without touching data, and revokes the old', async () => {
    const { doc, vmk } = await Keyslots.createDoc(PW, opts);
    const before = Buffer.from(await crypto.subtle.exportKey('raw', vmk)).toString('hex');
    await Keyslots.changePassword(doc, PW, 'a whole new password', opts);
    const after = await Keyslots.unlockDoc(doc, 'a whole new password');
    assert.strictEqual(Buffer.from(await crypto.subtle.exportKey('raw', after.vmk)).toString('hex'), before);
    await assert.rejects(Keyslots.unlockDoc(doc, PW), /Wrong password/);
});

await t.test('the last keyslot cannot be removed', async () => {
    const { doc } = await Keyslots.createDoc(PW, opts);
    assert.throws(() => Keyslots.removeSlot(doc, doc.slots[0].id), /only keyslot/);
});

await t.test('a slot cannot be replayed into another vault', async () => {
    const first = await Keyslots.createDoc(PW, opts);
    const second = await Keyslots.createDoc(PW, opts);
    // Splice a slot from vault A into vault B's document.
    second.doc.slots[0].wrapped = first.doc.slots[0].wrapped;
    await assert.rejects(Keyslots.unlockDoc(second.doc, PW), /Wrong password/);
});

// ---------------------------------------------------------------- envelope

await t.test('unknown payload keys survive a normalize round-trip', () => {
    const normalized = Envelope.normalizeVaultData({
        privateKey: 'abc',
        users: { me: { site: 1 } },
        records: [{ id: 'n:1', type: 'note', body: 'keep me' }]
    });
    assert.strictEqual(normalized.records.length, 1, 'a lossy normalize deletes user data');
    assert.strictEqual(normalized.settings.hashLength, 16);
});

// ---------------------------------------------------------------- store

async function openStore(disk, deviceId, extra = {}) {
    return Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId,
        create: true,
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_000_000,
        ...extra
    });
}

await t.test('store round-trips credentials and richer record types', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.setIdentity({ privateKey: 'deadbeef', seedPhrase: 'abandon ability able' });
    await store.setNonce('me', 'github.com', 3);
    await store.putRecord(R.TYPES.NOTE, 'n:passport', { title: 'passport', body: 'expires 2031' });
    await store.putRecord(R.TYPES.TOTP, 'totp:bank', { issuer: 'bank', secret: 'JBSWY3DPEHPK3PXP' });

    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS
    });
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(reopened.getRecord('n:passport').body, 'expires 2031');
    assert.strictEqual(reopened.getRecord('totp:bank').secret, 'JBSWY3DPEHPK3PXP');
    assert.strictEqual(reopened.snapshotPayload().privateKey, 'deadbeef');
});

await t.test('the snapshot stays readable by the plugin-compatible envelope', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.setNonce('me', 'github.com', 2);
    await store.putRecord(R.TYPES.NOTE, 'n:1', { body: 'secret' });

    const raw = disk.files.get(Store.SNAPSHOT_FILE);
    assert.ok(Envelope.looksLikeVaultFile(raw));
    const decrypted = await Envelope.decryptEnvelope(raw, PW);
    assert.strictEqual(decrypted.data.users.me['github.com'], 2);
    assert.strictEqual(decrypted.data.records.length, 1);
});

await t.test('two devices converge without a conflict file existing', async () => {
    const shared = new MemDisk();
    const a = await openStore(shared, 'aaaaaaaaaaaa');
    await a.setNonce('me', 'github.com', 1);

    const b = await openStore(shared, 'bbbbbbbbbbbb');
    await b.setNonce('me', 'proton.me', 5);
    await b.putRecord(R.TYPES.NOTE, 'n:9', { body: 'from b' });

    await a.sync();
    await b.sync();

    assert.strictEqual(a.getCredential('me', 'proton.me').nonce, 5);
    assert.strictEqual(a.getRecord('n:9').body, 'from b');
    assert.strictEqual(b.getCredential('me', 'github.com').nonce, 1);
    assert.deepStrictEqual(a.snapshotPayload(), b.snapshotPayload());

    const conflicts = Array.from(shared.files.keys()).filter(Store.isConflictName);
    assert.strictEqual(conflicts.length, 0, 'per-device logs must not produce conflicts');
});

await t.test('a Syncthing conflict file is absorbed losslessly and removed', async () => {
    // Two disks that diverge, then replicate — the classic Syncthing case.
    const diskA = new MemDisk();
    const a = await openStore(diskA, 'aaaaaaaaaaaa');
    await a.setNonce('me', 'github.com', 4);

    const diskB = diskA.clone();
    const b = await Store.open({
        transport: memTransport(diskB),
        password: PW,
        deviceId: 'bbbbbbbbbbbb',
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_100_000
    });
    await b.setNonce('me', 'github.com', 9);
    await b.setNonce('me', 'other.com', 2);

    const { conflicted } = replicate(diskB, diskA);
    assert.ok(conflicted > 0, 'the shared snapshot should conflict');

    const a2 = await Store.open({
        transport: memTransport(diskA),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_200_000
    });
    assert.strictEqual(a2.getCredential('me', 'github.com').nonce, 9, 'higher nonce must win');
    assert.strictEqual(a2.getCredential('me', 'other.com').nonce, 2, 'the other device\'s work must survive');
    assert.strictEqual(
        Array.from(diskA.files.keys()).filter(Store.isConflictName).length,
        0,
        'absorbed conflict files must be cleaned up'
    );
});

await t.test('a plugin-style snapshot edit is absorbed and cannot roll a nonce back', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.setNonce('me', 'github.com', 5);
    await store.setNonce('me', 'mail.com', 1);

    // The plugin decrypts, bumps one nonce, drops what it cannot model, saves.
    const current = await Envelope.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    const edited = {
        privateKey: current.data.privateKey,
        seedPhrase: current.data.seedPhrase,
        passphrase: '',
        users: { me: { 'github.com': 2, 'mail.com': 8 } }, // one rolled back, one advanced
        settings: current.data.settings
    };
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    disk.files.set(Store.SNAPSHOT_FILE, await Envelope.encryptEnvelope(edited, key, salt, TEST_ITERATIONS));

    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_300_000
    });
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 5, 'rollback must be refused');
    assert.strictEqual(reopened.getCredential('me', 'mail.com').nonce, 8, 'a real advance must be taken');
});

await t.test('records the plugin drops are restored from the log', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.putRecord(R.TYPES.NOTE, 'n:keep', { body: 'must survive' });

    // Plugin rewrites the snapshot without `records`.
    const current = await Envelope.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    delete current.data.records;
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    disk.files.set(Store.SNAPSHOT_FILE, await Envelope.encryptEnvelope(current.data, key, salt, TEST_ITERATIONS));

    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS
    });
    assert.strictEqual(reopened.getRecord('n:keep').body, 'must survive');
    const rebuilt = await Envelope.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    assert.strictEqual(rebuilt.data.records.length, 1, 'the snapshot must be republished intact');
});

await t.test('changing the master password does not touch the data', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.setNonce('me', 'github.com', 7);
    const logBefore = disk.files.get(Store.logNameFor('aaaaaaaaaaaa'));

    await store.changePassword(PW, 'a brand new master password');

    assert.strictEqual(disk.files.get(Store.logNameFor('aaaaaaaaaaaa')), logBefore, 'logs must not be rewritten');
    const reopened = await Store.open({
        transport: memTransport(disk),
        password: 'a brand new master password',
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS
    });
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 7);
    await assert.rejects(
        Store.open({ transport: memTransport(disk), password: PW, deviceId: 'aaaaaaaaaaaa', iterations: TEST_ITERATIONS }),
        /Wrong password/
    );
});

await t.test('compaction shrinks the log without changing the state', async () => {
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    for (let i = 0; i <= 80; i++) await store.setNonce('me', 'github.com', i);
    const payload = store.snapshotPayload();

    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS
    });
    assert.deepStrictEqual(reopened.snapshotPayload(), payload);
    assert.ok(reopened.logLines < 81, `log should have compacted, was ${reopened.logLines}`);
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 80);
});

await t.test('an append after a torn line does not corrupt the new entry', async () => {
    // A crash leaves a partial line with no terminator. If the next append
    // continues that line, the NEXT operation is destroyed too — so one
    // interrupted write costs two. Found by the Monte Carlo suite: a record
    // written and acknowledged after a crash vanished on the next restart.
    const disk = new MemDisk();
    const store = await openStore(disk, 'aaaaaaaaaaaa');
    await store.putRecord(R.TYPES.NOTE, 'n:before', { body: 'written before the crash' });

    // Tear the tail of the log, exactly as a power loss mid-append would.
    const logName = Store.logNameFor('aaaaaaaaaaaa');
    const torn = disk.files.get(logName).replace(/\n$/, '') + '{"iv":"trunca';
    disk.set(logName, torn);

    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_500_000
    });
    await reopened.putRecord(R.TYPES.NOTE, 'n:after', { body: 'written after the crash' });

    const final = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: 'aaaaaaaaaaaa',
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_600_000
    });
    assert.ok(final.getRecord('n:before'), 'entries before the tear must survive');
    assert.ok(final.getRecord('n:after'), 'the entry written after the tear must survive');
});

// ---------------------------------------------------------------- KDF-cost DoS guard

await t.test('isValidIterations bounds the KDF cost read from a file', () => {
    assert.strictEqual(Envelope.isValidIterations(600000), true);
    assert.strictEqual(Envelope.isValidIterations(Envelope.MAX_ITERATIONS), true);
    assert.strictEqual(Envelope.isValidIterations(Envelope.MAX_ITERATIONS + 1), false);
    assert.strictEqual(Envelope.isValidIterations(0), false);
    assert.strictEqual(Envelope.isValidIterations(-1), false);
    assert.strictEqual(Envelope.isValidIterations(1.5), false);
    assert.strictEqual(Envelope.isValidIterations('600000'), false);
});

await t.test('decryptEnvelope refuses an out-of-range KDF cost instead of running it', async () => {
    // A file merely dropped into the synced folder can claim any iteration
    // count; an unbounded one would make deriveVaultKey run for minutes with
    // no password required (ROADMAP 2.5). It must be rejected before deriving.
    const evil = JSON.stringify({
        v: 2,
        type: 'topolino-vault',
        kdf: { algo: 'PBKDF2-SHA256', iterations: 20_000_000, salt: Envelope.toBase64(Envelope.randomSalt()) },
        cipher: { algo: 'AES-256-GCM', iv: Envelope.toBase64(new Uint8Array(12)) },
        payload: Envelope.toBase64(new Uint8Array(16))
    });
    const start = Date.now();
    await assert.rejects(() => Envelope.decryptEnvelope(evil, PW), /out of range/);
    assert.ok(Date.now() - start < 2000, 'must fail fast, not run the KDF');
});

await t.test('decryptEnvelope refuses a v2 file with a malformed KDF/cipher header', async () => {
    const noKdf = JSON.stringify({ v: 2, type: 'topolino-vault', payload: 'AAAA' });
    await assert.rejects(() => Envelope.decryptEnvelope(noKdf, PW), /Malformed vault file/);
});

await t.test('a keyslot claiming an out-of-range KDF cost is treated as invalid', async () => {
    const { doc } = await Keyslots.createDoc(PW, { iterations: TEST_ITERATIONS });
    doc.slots[0].kdf.iterations = 20_000_000; // tampered: over the ceiling
    // isSlot rejects it, so unlockDoc skips the slot and reports the same
    // "Wrong password" an empty vault would — and never derives at that cost.
    const start = Date.now();
    await assert.rejects(() => Keyslots.unlockDoc(doc, PW), /Wrong password/);
    assert.ok(Date.now() - start < 2000, 'must not run the tampered KDF cost');
});

// ---------------------------------------------------------------- TOTP (RFC 6238)

await t.test('TOTP matches the RFC 6238 test vectors', async () => {
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // base32 of "12345678901234567890"
    const vectors = [
        [59, '94287082'],
        [1111111109, '07081804'],
        [1111111111, '14050471'],
        [1234567890, '89005924'],
        [2000000000, '69279037']
    ];
    for (const [ts, expected] of vectors) {
        const { code } = await Totp.generate(secret, { timestamp: ts, digits: 8 });
        assert.strictEqual(code, expected, `t=${ts}`);
    }
});

await t.test('TOTP reports a 6-digit code and the seconds left in the window', async () => {
    const r = await Totp.generate('GEZDGNBVGY3TQOJQ', { timestamp: 1000, period: 30 });
    assert.strictEqual(r.code.length, 6);
    assert.strictEqual(r.secondsRemaining, 30 - (1000 % 30));
});

await t.test('parseOtpauth extracts issuer, account and secret', () => {
    const p = Totp.parseOtpauth(
        'otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30'
    );
    assert.strictEqual(p.issuer, 'GitHub');
    assert.strictEqual(p.account, 'me@example.com');
    assert.strictEqual(p.secret, 'JBSWY3DPEHPK3PXP');
    assert.strictEqual(p.digits, 6);
    assert.strictEqual(Totp.parseOtpauth('https://example.com'), null);
});

// ---------------------------------------------------------------- CSV import/export

await t.test('importCsv reads a mainstream export and normalizes it', () => {
    const csv = [
        'name,login_uri,login_username,login_password,notes',
        'GitHub,https://www.github.com/login,me@example.com,hunter2,work account',
        '"Bank, National",https://bank.example,acct1,"p,w""d",'
    ].join('\n');
    const rows = Porter.importCsv(csv);
    assert.strictEqual(rows.length, 2);
    assert.strictEqual(rows[0].site, 'github.com');
    assert.strictEqual(rows[0].user, 'me@example.com');
    assert.strictEqual(rows[0].password, 'hunter2');
    assert.strictEqual(rows[0].note, 'work account');
    assert.strictEqual(rows[1].site, 'bank.example'); // quoted comma survived the parse
    assert.strictEqual(rows[1].password, 'p,w"d'); // escaped quote survived
});

await t.test('importCsv returns nothing for an unrecognizable file', () => {
    assert.deepStrictEqual(Porter.importCsv('a,b,c\n1,2,3'), []);
    assert.deepStrictEqual(Porter.importCsv(''), []);
});

await t.test('exportCsv round-trips through the parser', () => {
    const csv = Porter.exportCsv([
        { name: 'github.com', url: 'github.com', username: 'me', password: 'PASSabcd1234efgh249+' },
        { name: 'weird, name', url: '', username: 'x"y', password: 'p' }
    ]);
    const back = Porter.importCsv(csv);
    assert.strictEqual(back.length, 2);
    assert.strictEqual(back[0].user, 'me');
    assert.strictEqual(back[1].user, 'x"y');
});

t.done();
