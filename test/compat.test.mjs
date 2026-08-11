/**
 * Backward compatibility with the previously shipped app.
 *
 * The reference implementation here is not a reimplementation of the old
 * behaviour — it is the old code, loaded straight out of git (`HEAD`, i.e. the
 * last released commit) and run side by side with the current one. If the two
 * ever disagree, this fails.
 *
 * What "compatible" has to mean for a deterministic password manager:
 *
 *   1. The same seed, user, site and nonce must produce the SAME password,
 *      byte for byte, forever. Anything else silently locks users out of every
 *      account they own. This is the invariant with no escape hatch.
 *   2. Vault files written by the old app must open in the new one — v1
 *      (CryptoJS/MD5) and v2 (PBKDF2/GCM) alike.
 *   3. Vault files written by the new app must open in the OLD one, so a user
 *      who downgrades, or who syncs with a device still on the old build, is
 *      not stranded.
 *   4. Round-tripping between them must not lose or regress anything.
 *
 * Run: node test/compat.test.mjs
 */
import assert from 'assert';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';
import { loadCore, harness, TEST_ITERATIONS } from './_load.mjs';
import { MemDisk, memTransport } from './memfs.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..');

const { Envelope, Store, Records: R, CryptoJS } = await loadCore();
await import(new URL('../vault/core/transports.js', import.meta.url).pathname);
await import(new URL('../vault/core/bootstrap.js', import.meta.url).pathname);
const Bootstrap = globalThis.VaultBootstrap;

const t = harness('compat (current vs git HEAD)');

/** Load a file as it existed at a git revision, in its own global. */
function loadFromGit(revision, file, extraGlobals = {}) {
    const source = execSync(`git show ${revision}:${file}`, { cwd: repo, encoding: 'utf8' });
    const sandbox = Object.assign(
        {
            crypto: globalThis.crypto,
            TextEncoder,
            TextDecoder,
            btoa: globalThis.btoa,
            atob: globalThis.atob,
            CryptoJS,
            console,
            JSON,
            Math,
            Object,
            Array,
            String,
            Number,
            Boolean,
            Promise,
            Error,
            Uint8Array
        },
        extraGlobals
    );
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox, { filename: `${revision}:${file}` });
    return sandbox;
}

// The previously shipped envelope, verbatim.
const old = loadFromGit('HEAD', 'vault/envelope.js').VaultEnvelope;

/** The old app's password derivation, lifted out of the shipped app.js. */
function oldGeneratePassword() {
    const source = execSync('git show HEAD:vault/app.js', { cwd: repo, encoding: 'utf8' });
    const hashFn = source.match(/function (?:hash|sha256Hex)\(text\) \{[\s\S]*?\n\}/)[0];
    const genFn = source.match(/function generatePassword\([\s\S]*?\n\}/)[0];
    const sandbox = { CryptoJS };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(`${hashFn}\n${genFn}\nglobalThis.__gen = generatePassword;`, sandbox);
    return sandbox.__gen;
}

const PW = 'the shared master password';
const DATA = {
    privateKey: 'deadbeefcafe1234',
    seedPhrase: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
    passphrase: '',
    users: { me: { 'github.com': 3, 'proton.me': 0 }, work: { 'jira.example': 7 } },
    settings: { hashLength: 16 }
};

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

function fakeStorage(initial = {}) {
    const map = new Map(Object.entries(initial));
    return {
        get length() {
            return map.size;
        },
        key: (i) => Array.from(map.keys())[i] ?? null,
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => map.set(k, String(v)),
        removeItem: (k) => map.delete(k)
    };
}

// ------------------------------------------------------- 1. passwords

await t.test('generated passwords are byte-identical to the shipped version', async () => {
    const oldGen = oldGeneratePassword();
    const core = await loadCore();
    // The current derivation is its own module now, so load it as one instead
    // of scraping source: what gets compared is exactly what ships.
    const newGen = core.Derive.generatePassword;
    assert.strictEqual(typeof newGen, 'function', 'derive.js must export generatePassword');

    // Exhaustive over a realistic matrix rather than one lucky vector.
    let checked = 0;
    for (const key of ['deadbeefcafe1234', '0', 'ffffffffffffffffffffffffffffffff']) {
        for (const user of ['me', 'work@example.com', 'ünïcodé user']) {
            for (const site of ['github.com', 'proton.me', 'a/b:c']) {
                for (const nonce of [0, 1, 42, 9999]) {
                    for (const len of [8, 16, 24, 32]) {
                        assert.strictEqual(
                            newGen(key, user, site, nonce, len),
                            oldGen(key, user, site, nonce, len),
                            `mismatch for ${user}/${site}#${nonce} len=${len}`
                        );
                        checked++;
                    }
                }
            }
        }
    }
    assert.ok(checked >= 400, `expected a broad matrix, checked ${checked}`);
});

// ------------------------------------------------------- 2. old file -> new app

await t.test('a v2 file written by the old app opens in the new one', async () => {
    const salt = old.randomSalt();
    const key = await old.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    const file = await old.encryptEnvelope(DATA, key, salt, TEST_ITERATIONS);

    const disk = new MemDisk();
    disk.set(Store.SNAPSHOT_FILE, file);
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage()));

    assert.strictEqual(store.getRecord(R.IDENTITY_ID).seedPhrase, DATA.seedPhrase);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(store.getCredential('work', 'jira.example').nonce, 7);
});

await t.test('a v1 (CryptoJS) file written by the old app opens in the new one', async () => {
    const file = JSON.stringify({
        v: 1,
        type: 'topolino-vault',
        payload: CryptoJS.AES.encrypt(JSON.stringify(DATA), PW).toString()
    });
    const disk = new MemDisk();
    disk.set(Store.SNAPSHOT_FILE, file);
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage()));
    assert.strictEqual(store.getRecord(R.IDENTITY_ID).privateKey, DATA.privateKey);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
});

// ------------------------------------------------------- 3. new file -> old app

await t.test('a file written by the new app opens in the OLD app', async () => {
    const disk = new MemDisk();
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage(), { create: true }));
    await store.setIdentity({ privateKey: DATA.privateKey, seedPhrase: DATA.seedPhrase });
    await store.setNonce('me', 'github.com', 3);
    await store.setNonce('work', 'jira.example', 7);
    await store.putRecord(R.TYPES.NOTE, 'n:1', { body: 'a record the old app cannot model' });

    // The old app's decryptEnvelope, unmodified.
    const decrypted = await old.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);

    assert.strictEqual(decrypted.legacy, false);
    assert.strictEqual(decrypted.data.privateKey, DATA.privateKey);
    assert.strictEqual(decrypted.data.seedPhrase, DATA.seedPhrase);
    assert.strictEqual(decrypted.data.users.me['github.com'], 3);
    assert.strictEqual(decrypted.data.users.work['jira.example'], 7);
    assert.strictEqual(decrypted.data.settings.hashLength, 16);
});

await t.test('the old app can still change the password on a new-format file', async () => {
    const disk = new MemDisk();
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage(), { create: true }));
    await store.setIdentity({ privateKey: DATA.privateKey, seedPhrase: DATA.seedPhrase });
    await store.setNonce('me', 'github.com', 1);

    // Old app: read, re-encrypt under a new password, write back.
    const read = await old.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    const salt = old.randomSalt();
    const key = await old.deriveVaultKey('a different password', salt, TEST_ITERATIONS);
    const rewritten = await old.encryptEnvelope(read.data, key, salt, TEST_ITERATIONS);

    // The new app must still be able to read what the old app produced.
    const back = await Envelope.decryptEnvelope(rewritten, 'a different password');
    assert.strictEqual(back.data.seedPhrase, DATA.seedPhrase);
    assert.strictEqual(back.data.users.me['github.com'], 1);
});

// ------------------------------------------------------- 4. round trips

await t.test('old-app edits round-trip without losing or regressing anything', async () => {
    const disk = new MemDisk();
    const storage = fakeStorage();
    const { store } = await Bootstrap.open(openArgs(disk, storage, { create: true }));
    await store.setIdentity({ privateKey: DATA.privateKey, seedPhrase: DATA.seedPhrase });
    await store.setNonce('me', 'github.com', 3);
    await store.putRecord(R.TYPES.NOTE, 'n:keep', { body: 'only the new app models this' });

    // The old app opens it, bumps a nonce, adds a site, and saves. Its
    // normalizeVaultData drops `records` — it cannot know about them.
    const read = await old.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    const edited = old.normalizeVaultData(read.data);
    assert.strictEqual(edited.records, undefined, 'the old app is expected to drop unknown keys');
    edited.users.me['github.com'] = 4;
    edited.users.me['newsite.com'] = 0;
    const salt = old.randomSalt();
    const key = await old.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    disk.set(Store.SNAPSHOT_FILE, await old.encryptEnvelope(edited, key, salt, TEST_ITERATIONS));

    // New app reopens: it must take the old app's edits AND restore what the
    // old app could not represent, because the log still has it.
    const { store: reopened } = await Bootstrap.open(openArgs(disk, storage));
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 4, "old app's bump must be taken");
    assert.strictEqual(reopened.getCredential('me', 'newsite.com').nonce, 0, "old app's new site must survive");
    assert.strictEqual(
        reopened.getRecord('n:keep').body,
        'only the new app models this',
        'records the old app dropped must be restored from the log'
    );
    assert.strictEqual(reopened.getRecord(R.IDENTITY_ID).seedPhrase, DATA.seedPhrase);
});

await t.test('an old app rolling a nonce backwards is refused', async () => {
    const disk = new MemDisk();
    const storage = fakeStorage();
    const { store } = await Bootstrap.open(openArgs(disk, storage, { create: true }));
    await store.setIdentity({ privateKey: DATA.privateKey, seedPhrase: DATA.seedPhrase });
    await store.setNonce('me', 'github.com', 9);

    const read = await old.decryptEnvelope(disk.files.get(Store.SNAPSHOT_FILE), PW);
    const edited = old.normalizeVaultData(read.data);
    edited.users.me['github.com'] = 2; // a restored backup, or a stale device
    const salt = old.randomSalt();
    const key = await old.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    disk.set(Store.SNAPSHOT_FILE, await old.encryptEnvelope(edited, key, salt, TEST_ITERATIONS));

    const { store: reopened } = await Bootstrap.open(openArgs(disk, storage));
    assert.strictEqual(reopened.getCredential('me', 'github.com').nonce, 9, 'must not go backwards');
});

// ------------------------------------------------------- 5. envelope format

await t.test('the envelope on disk is structurally what the old app expects', async () => {
    const disk = new MemDisk();
    const { store } = await Bootstrap.open(openArgs(disk, fakeStorage(), { create: true }));
    await store.setNonce('me', 'github.com', 1);

    const parsed = JSON.parse(disk.files.get(Store.SNAPSHOT_FILE));
    assert.strictEqual(parsed.v, 2);
    assert.strictEqual(parsed.type, 'topolino-vault');
    assert.strictEqual(parsed.kdf.algo, 'PBKDF2-SHA256');
    assert.strictEqual(parsed.cipher.algo, 'AES-256-GCM');
    assert.strictEqual(typeof parsed.payload, 'string');
    assert.strictEqual(old.looksLikeVaultFile(disk.files.get(Store.SNAPSHOT_FILE)), true);
});

await t.test('production KDF cost is unchanged at 600k iterations', () => {
    // A silent change here would make files unreadable by any build that
    // hardcodes expectations, and would quietly weaken or slow every unlock.
    assert.strictEqual(Envelope.V2_ITERATIONS, 600000);
    assert.strictEqual(old.V2_ITERATIONS, Envelope.V2_ITERATIONS);
});

await t.test('the new sidecar files are ignored by the old app', () => {
    // The old app only ever reads the one file it was pointed at, so the
    // keyslot file and per-device logs are invisible to it. They must at least
    // not masquerade as vault files if it is ever pointed at one.
    assert.strictEqual(old.looksLikeVaultFile('{"v":1,"type":"topolino-vault-keys","slots":[]}'), false);
    assert.strictEqual(old.looksLikeVaultFile('{"tvlog":1,"dev":"000000000001"}'), false);
});

// ------------------------------------------------------- 6. cross-platform interop

/**
 * Desktop uses the folder layout; Android gets a single-document URI and
 * cannot create siblings. Both may point at the SAME synced folder, so the
 * shared file has to stay a plain vault envelope on both.
 */
await t.test('a desktop folder and an Android single file share one vault', async () => {
    const disk = new MemDisk();

    // Desktop: folder layout.
    const desktop = await Bootstrap.open(openArgs(disk, fakeStorage(), { create: true }));
    await desktop.store.setIdentity({ privateKey: DATA.privateKey, seedPhrase: DATA.seedPhrase });
    await desktop.store.setNonce('me', 'github.com', 3);

    // Phone: SAF URI pointed at topolino-vault.json inside that same folder.
    const invoke = async (cmd, args) => {
        if (cmd === 'read_vault_file') {
            const v = disk.files.get(Store.SNAPSHOT_FILE);
            if (v === undefined) throw new Error('not found');
            return v;
        }
        if (cmd === 'write_vault_file') {
            disk.set(Store.SNAPSHOT_FILE, args.contents);
            return;
        }
        throw new Error('unsupported: ' + cmd);
    };
    const phoneStorage = fakeStorage();
    const phone = await Bootstrap.open({
        transport: globalThis.VaultTransports.tauriSingleFile(invoke, 'content://doc/vault', phoneStorage),
        password: PW,
        storage: fakeStorage(),
        iterations: TEST_ITERATIONS,
        now: () => 1_700_000_100_000
    });

    assert.strictEqual(phone.store.getCredential('me', 'github.com').nonce, 3, 'phone must read the folder vault');
    await phone.store.setNonce('me', 'proton.me', 1);

    // The shared file must still be a plain envelope — NOT a private container.
    // Wrapping it made the desktop unable to read what the phone had written,
    // so the phone's edits silently stopped reaching it.
    const shared = disk.files.get(Store.SNAPSHOT_FILE);
    assert.strictEqual(old.looksLikeVaultFile(shared), true, 'the shared file must stay a vault envelope');
    assert.strictEqual(JSON.parse(shared).type, 'topolino-vault');

    // Desktop reopens and sees the phone's change.
    const back = await Bootstrap.open(openArgs(disk, fakeStorage(), { now: () => 1_700_000_200_000 }));
    assert.strictEqual(back.store.getCredential('me', 'github.com').nonce, 3);
    assert.strictEqual(back.store.getCredential('me', 'proton.me').nonce, 1, "the phone's edit must reach the desktop");
});

await t.test('a vault file left by the container build is still readable', async () => {
    // One build wrapped the shared file in a private container. Those installs
    // must not be stranded.
    const disk = new MemDisk();
    const salt = Envelope.randomSalt();
    const key = await Envelope.deriveVaultKey(PW, salt, TEST_ITERATIONS);
    const envelope = await Envelope.encryptEnvelope(DATA, key, salt, TEST_ITERATIONS);
    let stored = JSON.stringify({ __tv_container__: 1, files: { 'topolino-vault.json': envelope } });

    const invoke = async (cmd, args) => {
        if (cmd === 'read_vault_file') return stored;
        if (cmd === 'write_vault_file') {
            stored = args.contents;
            return;
        }
        throw new Error('unsupported: ' + cmd);
    };
    const { store } = await Bootstrap.open({
        transport: globalThis.VaultTransports.tauriSingleFile(invoke, 'content://doc/vault', fakeStorage()),
        password: PW,
        storage: fakeStorage(),
        iterations: TEST_ITERATIONS
    });

    assert.strictEqual(store.getRecord(R.IDENTITY_ID).seedPhrase, DATA.seedPhrase);
    assert.strictEqual(store.getCredential('me', 'github.com').nonce, 3);
    // And it is rewritten as a bare envelope, healing the format.
    assert.strictEqual(old.looksLikeVaultFile(stored), true);
});

t.done();
