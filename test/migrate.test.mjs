/**
 * The one-shot legacy migration.
 *
 * DELETE THIS FILE together with vault/core/migrate-legacy.js.
 *
 * This is the highest-consequence code path in the change: it runs once, on
 * every existing install, against the only copy of a vault whose seed phrase
 * may exist nowhere else. The tests are written from that premise — most of
 * them assert what must survive a FAILED migration, not a successful one.
 *
 * Run: node test/migrate.test.mjs
 */
import assert from 'assert';
import { loadCore, harness, TEST_ITERATIONS } from './_load.mjs';
import { MemDisk, memTransport } from './memfs.mjs';

const { Envelope, Records: R, Store, Migrate, CryptoJS } = await loadCore();
await import(new URL('../vault/core/transports.js', import.meta.url).pathname);
await import(new URL('../vault/core/bootstrap.js', import.meta.url).pathname);
const Bootstrap = globalThis.VaultBootstrap;

const t = harness('migrate');

const PW = 'the old master password';
const LEGACY_DATA = {
    privateKey: 'deadbeefcafe1234',
    seedPhrase: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
    passphrase: '',
    users: { me: { 'github.com': 3, 'proton.me': 0 }, work: { 'jira.example': 7 } },
    settings: { hashLength: 16 }
};

/** localStorage stand-in. */
function fakeStorage(initial = {}) {
    const map = new Map(Object.entries(initial));
    return {
        get length() {
            return map.size;
        },
        key: (i) => Array.from(map.keys())[i] ?? null,
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => map.set(k, String(v)),
        removeItem: (k) => map.delete(k),
        _map: map
    };
}

/** The exact shape the old app wrote: keyed by SHA-256(masterPassword). */
async function legacyV2Slot(data, password) {
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(password, salt, TEST_ITERATIONS);
    const blob = await Envelope.encryptEnvelope(data, key, salt, TEST_ITERATIONS);
    return { [CryptoJS.SHA256(password).toString()]: blob };
}

function legacyV1Slot(data, password) {
    return {
        [CryptoJS.SHA256(password).toString()]: CryptoJS.AES.encrypt(
            JSON.stringify(data),
            password
        ).toString()
    };
}

function openArgs(disk, storage, extra = {}) {
    return Object.assign(
        {
            transport: memTransport(disk),
            password: PW,
            storage,
            iterations: TEST_ITERATIONS,
            now: () => 1_700_000_000_000
        },
        extra
    );
}

await t.test('a v2 localStorage slot migrates, and the oracle key is deleted', async () => {
    const storage = fakeStorage({
        vaultEncrypted: JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW))
    });
    const disk = new MemDisk();

    const { store, migration } = await Bootstrap.open(openArgs(disk, storage));

    assert.strictEqual(migration.migrated, true);
    assert.strictEqual(migration.credentials, 3);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(store.getCredential('work', 'jira.example').nonce, 7);
    assert.strictEqual(store.getRecord(R.IDENTITY_ID).seedPhrase, LEGACY_DATA.seedPhrase);

    // The whole point: no artifact keyed by a hash of the master password.
    assert.strictEqual(storage.getItem('vaultEncrypted'), null);
    assert.strictEqual(storage.getItem(Migrate.SCHEMA_KEY), String(Migrate.CURRENT_SCHEMA));
    const sha = CryptoJS.SHA256(PW).toString();
    for (const value of storage._map.keys()) assert.ok(!value.includes(sha));
});

await t.test('a v1 CryptoJS slot migrates too', async () => {
    const storage = fakeStorage({ vaultEncrypted: JSON.stringify(legacyV1Slot(LEGACY_DATA, PW)) });
    const disk = new MemDisk();

    const { store, migration } = await Bootstrap.open(openArgs(disk, storage));

    assert.strictEqual(migration.migrated, true);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(storage.getItem('vaultEncrypted'), null);
});

await t.test('several legacy slots merge by highest nonce, never lowest', async () => {
    const ahead = JSON.parse(JSON.stringify(LEGACY_DATA));
    ahead.users.me['github.com'] = 9;
    ahead.users.me['newsite.com'] = 1;

    const slots = Object.assign(
        await legacyV2Slot(LEGACY_DATA, PW),
        legacyV1Slot(ahead, PW)
    );
    const storage = fakeStorage({ vaultEncrypted: JSON.stringify(slots) });

    const { store, migration } = await Bootstrap.open(openArgs(new MemDisk(), storage));

    assert.strictEqual(migration.migrated, true);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 9, 'must take the max');
    assert.strictEqual(store.getCredential('me', 'newsite.com').nonce, 1);
    assert.strictEqual(store.getCredential('work', 'jira.example').nonce, 7);
});

await t.test('an existing legacy vault FILE upgrades without touching localStorage', async () => {
    // The v1 file the old app wrote into the Syncthing folder.
    const disk = new MemDisk();
    disk.set(
        Store.SNAPSHOT_FILE,
        JSON.stringify({
            v: 1,
            type: 'topolino-vault',
            payload: CryptoJS.AES.encrypt(JSON.stringify(LEGACY_DATA), PW).toString()
        })
    );
    const storage = fakeStorage();

    const { store } = await Bootstrap.open(openArgs(disk, storage));

    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(store.getRecord(R.IDENTITY_ID).privateKey, LEGACY_DATA.privateKey);
    // Keyslots now exist, and the snapshot was rewritten as v2.
    assert.ok(disk.files.get(Store.KEYS_FILE));
    const upgraded = await Envelope.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    assert.strictEqual(upgraded.legacy, false, 'the v1 file must be rewritten as v2');
});

await t.test('a wrong password is refused and leaves every legacy artifact untouched', async () => {
    const original = JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW));
    const storage = fakeStorage({ vaultEncrypted: original });

    // This originally asserted that a wrong password opened successfully with
    // migrated:false. That WAS the bug: opening at all minted keyslots under
    // the wrong password. It must now be refused outright.
    await assert.rejects(
        Bootstrap.open(openArgs(new MemDisk(), storage, { password: 'not the password' })),
        /Wrong password/
    );

    // Nothing may be discarded on a password we could not verify — those
    // slots may belong to a vault whose password the user still remembers.
    assert.strictEqual(storage.getItem('vaultEncrypted'), original);
    assert.strictEqual(storage.getItem(Migrate.SCHEMA_KEY), null);
});

await t.test('migration is idempotent and does not run twice', async () => {
    const storage = fakeStorage({
        vaultEncrypted: JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW))
    });
    const disk = new MemDisk();

    const first = await Bootstrap.open(openArgs(disk, storage));
    assert.strictEqual(first.migration.migrated, true);

    const second = await Bootstrap.open(openArgs(disk, storage));
    assert.strictEqual(second.migration, null, 'the second open must not migrate again');
    assert.strictEqual(second.store.getCredential('me', 'github.com').nonce, 3);

    const third = await Bootstrap.open(openArgs(disk, storage));
    assert.deepStrictEqual(third.store.snapshotPayload(), second.store.snapshotPayload());
});

await t.test('a migrated vault still unlocks after a restart with no legacy data', async () => {
    const storage = fakeStorage({
        vaultEncrypted: JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW))
    });
    const disk = new MemDisk();
    await Bootstrap.open(openArgs(disk, storage));

    // Simulate the next app version: legacy module gone, only the store left.
    const reopened = await Store.open({
        transport: memTransport(disk),
        password: PW,
        deviceId: Bootstrap.deviceIdFor(storage),
        iterations: TEST_ITERATIONS
    });
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(reopened.getRecord(R.IDENTITY_ID).seedPhrase, LEGACY_DATA.seedPhrase);
});

await t.test('the migrated vault stays readable by the Obsidian plugin', async () => {
    const storage = fakeStorage({
        vaultEncrypted: JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW))
    });
    const disk = new MemDisk();
    await Bootstrap.open(openArgs(disk, storage));

    const snapshot = await Envelope.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    assert.deepStrictEqual(snapshot.data.users, LEGACY_DATA.users);
    assert.strictEqual(snapshot.data.privateKey, LEGACY_DATA.privateKey);
    assert.strictEqual(snapshot.data.settings.hashLength, 16);
});

await t.test('a corrupt legacy slot does not block migrating the readable ones', async () => {
    const slots = await legacyV2Slot(LEGACY_DATA, PW);
    slots['0'.repeat(64)] = 'not decryptable at all';
    const storage = fakeStorage({ vaultEncrypted: JSON.stringify(slots) });

    const { store, migration } = await Bootstrap.open(openArgs(new MemDisk(), storage));
    assert.strictEqual(migration.migrated, true);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
});

await t.test('a fresh install creates a vault and reports no migration', async () => {
    const storage = fakeStorage();
    const { store, migration, created } = await Bootstrap.open(
        openArgs(new MemDisk(), storage, { create: true })
    );
    assert.strictEqual(migration, null);
    assert.strictEqual(created, true);
    assert.strictEqual(store.listRecords().length, 0);
});

await t.test('device id is stable across opens', async () => {
    const storage = fakeStorage();
    const disk = new MemDisk();
    const first = await Bootstrap.open(openArgs(disk, storage, { create: true }));
    const second = await Bootstrap.open(openArgs(disk, storage));
    assert.strictEqual(first.store.deviceId, second.store.deviceId);
    assert.ok(/^[0-9a-f]{12}$/.test(first.store.deviceId));
});

// ---------------------------------------------------------------- data-loss regressions

await t.test('a wrong password NEVER creates a new vault over an existing one', async () => {
    // Shipped in the first Android build and reported from a real device: a
    // mistyped password minted fresh keyslots, "unlocked" into an empty vault,
    // and then wrote that empty state over the user's file — destroying it and
    // locking the real password out.
    const disk = new MemDisk();
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    const original = await Envelope.encryptEnvelope(LEGACY_DATA, key, salt, TEST_ITERATIONS);
    disk.set(Store.SNAPSHOT_FILE, original);

    await assert.rejects(
        Bootstrap.open(openArgs(disk, fakeStorage(), { password: 'not the password' })),
        /Wrong password/
    );

    // The file must be untouched, and the real password must still work.
    assert.strictEqual(disk.files.get(Store.SNAPSHOT_FILE), original, 'the vault file was modified');
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage()));
    assert.strictEqual(store.getRecord(R.IDENTITY_ID).seedPhrase, LEGACY_DATA.seedPhrase);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
});

await t.test('a vault file that cannot be decrypted is never overwritten', async () => {
    // Someone else's vault, or ours under a password we do not have. Either
    // way it is the only copy of somebody's seed phrase.
    const disk = new MemDisk();
    const salt = Envelope.randomSalt();
    const foreignKey = await Envelope.deriveVaultKey('someone elses password', salt, TEST_ITERATIONS);
    const foreign = await Envelope.encryptEnvelope(LEGACY_DATA, foreignKey, salt, TEST_ITERATIONS);

    // Build a legitimate vault first, then drop a foreign snapshot beside it.
    const storage = fakeStorage();
    const { store } = await Bootstrap.open(openArgs(disk, storage, { create: true }));
    await store.setNonce('me', 'github.com', 1);
    disk.set(Store.SNAPSHOT_FILE, foreign);

    await store.sync();
    assert.strictEqual(
        disk.files.get(Store.SNAPSHOT_FILE),
        foreign,
        'an unreadable vault file must survive our writes'
    );
});

await t.test('a wrong password does not consume legacy localStorage slots', async () => {
    const original = JSON.stringify(await legacyV2Slot(LEGACY_DATA, PW));
    const storage = fakeStorage({ vaultEncrypted: original });

    await assert.rejects(
        Bootstrap.open(openArgs(new MemDisk(), storage, { password: 'wrong' })),
        /Wrong password/
    );
    assert.strictEqual(storage.getItem('vaultEncrypted'), original);

    // ...and the right password still migrates cleanly afterwards.
    const { store, migration } = await Bootstrap.open(openArgs(new MemDisk(), storage));
    assert.strictEqual(migration.migrated, true);
    assert.strictEqual(store.getRecord(R.IDENTITY_ID).seedPhrase, LEGACY_DATA.seedPhrase);
});

t.done();
