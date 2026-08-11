/**
 * Loads the real vault/app.js against a minimal DOM and drives the vault
 * lifecycle end to end.
 *
 * The core suites test the vault logic; this tests the wiring around it, which
 * is where integration mistakes live and where nothing else would catch them.
 * A function that app.js calls but no longer defines is a ReferenceError the
 * user meets at runtime — this file turns that into a failing test. (It found
 * one that predates this work: updateBackupWarningIndicator was called by the
 * settings screen and never defined anywhere.)
 *
 * Run: node test/app-wiring.test.mjs
 */
import assert from 'assert';
import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import vm from 'vm';
import { harness } from './_load.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const t = harness('app-wiring');

/** Enough DOM for app.js to load and run without a browser. */
function makeDom() {
    const elements = new Map();
    const make = (id) => ({
        id,
        value: '',
        textContent: '',
        innerHTML: '',
        dataset: {},
        classList: { add() {}, remove() {}, contains: () => false },
        addEventListener() {},
        querySelectorAll: () => [],
        appendChild() {},
        focus() {}
    });
    return {
        elements,
        document: {
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, make(id));
                return elements.get(id);
            },
            // Returns an element rather than null: every selector app.js uses
            // (e.g. `.nonce-control`) does exist in index.html, so null here
            // would be the shim inventing a failure the app never sees.
            querySelector(sel) {
                if (!elements.has(sel)) elements.set(sel, make(sel));
                return elements.get(sel);
            },
            querySelectorAll: () => [],
            createElement: (tag) => {
                const el = make(tag);
                // Model textContent -> innerHTML the way a real browser does:
                // text-node serialization escapes & < > but NOT quotes. The
                // app's escapeHtml no longer leans on this path (it escapes
                // quotes itself), and the shim must not pretend the DOM does —
                // that is exactly what previously hid the attribute-injection
                // bug the escapeHtml/renderSiteList tests now cover.
                Object.defineProperty(el, 'textContent', {
                    get() {
                        return el._text || '';
                    },
                    set(v) {
                        el._text = String(v);
                        el.innerHTML = String(v)
                            .replace(/&/g, '&amp;')
                            .replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;');
                    }
                });
                return el;
            },
            addEventListener() {},
            hidden: false
        }
    };
}

function makeStorage() {
    const map = new Map();
    return {
        get length() {
            return map.size;
        },
        key: (i) => Array.from(map.keys())[i] ?? null,
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => map.set(k, String(v)),
        removeItem: (k) => map.delete(k),
        clear: () => map.clear(),
        _map: map
    };
}

/**
 * A mock of window.__TAURI__ backed by an in-memory disk keyed by absolute
 * path, implementing exactly the commands vault/core/transports.js invokes.
 * Lets the native storage flows (setup, move) run without a device. Set the
 * picker results with setNextDir/setNextFile; '__ERR__' makes the folder
 * picker throw, which is how Android behaves.
 */
function makeTauri() {
    const disk = new Map();
    let nextDir = null;
    let nextFile = null;
    const sep = '/';
    return {
        disk,
        setNextDir: (d) => { nextDir = d; },
        setNextFile: (f) => { nextFile = f; },
        core: {
            async invoke(cmd, args = {}) {
                switch (cmd) {
                    case 'choose_vault_dir':
                        if (nextDir === '__ERR__') throw new Error('no folder picker on this platform');
                        return nextDir;
                    case 'choose_vault_file':
                        return nextFile;
                    case 'read_vault_file':
                        if (!disk.has(args.path)) throw new Error('ENOENT: ' + args.path);
                        return disk.get(args.path);
                    case 'write_vault_file':
                        disk.set(args.path, args.contents);
                        return null;
                    case 'append_vault_line': {
                        const prev = disk.get(args.path) || '';
                        const s = prev && !prev.endsWith('\n') ? '\n' : '';
                        disk.set(args.path, prev + s + args.line + '\n');
                        return null;
                    }
                    case 'list_vault_dir': {
                        const d = args.dir.replace(/[/\\]+$/, '') + sep;
                        const out = [];
                        for (const k of disk.keys()) {
                            if (k.startsWith(d) && !k.slice(d.length).includes(sep)) out.push(k.slice(d.length));
                        }
                        return out;
                    }
                    case 'remove_vault_file':
                        disk.delete(args.path);
                        return null;
                    default:
                        throw new Error('unhandled command: ' + cmd);
                }
            }
        }
    };
}

/** Load the real app.js exactly as index.html does, in load order. */
function loadApp(tauri) {
    const dom = makeDom();
    const storage = makeStorage();
    const clipboard = { text: '', writeText(v) { clipboard.text = v; return Promise.resolve(); } };

    const sandbox = {
        console: { log() {}, error() {}, warn() {} },
        crypto: globalThis.crypto,
        TextEncoder,
        TextDecoder,
        btoa: globalThis.btoa,
        atob: globalThis.atob,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        JSON,
        Math,
        Date,
        Object,
        Array,
        String,
        Number,
        Boolean,
        Promise,
        Set,
        Map,
        Error,
        parseInt,
        parseFloat,
        isNaN,
        Uint8Array,
        alert: () => {},
        confirm: () => true,
        prompt: () => null,
        document: dom.document,
        localStorage: storage,
        navigator: { clipboard },
        // A test-supplied Tauri mock, or undefined — which exercises the
        // browser-storage transport, the offline fallback path on a real device.
        __TAURI__: tauri
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);

    const files = [
        '../vault/bip39WordList.js',
        '../vault/crypto-js.min.js',
        '../vault/envelope.js',
        '../vault/core/derive.js',
        '../vault/core/util.js',
        '../vault/core/hlc.js',
        '../vault/core/records.js',
        '../vault/core/oplog.js',
        '../vault/core/keyslots.js',
        '../vault/core/store.js',
        '../vault/core/transports.js',
        '../vault/core/migrate-legacy.js',
        '../vault/core/bootstrap.js',
        '../vault/core/totp.js',
        '../vault/core/porter.js',
        '../vault/app.js'
    ];
    for (const rel of files) {
        const file = path.resolve(here, rel);
        vm.runInContext(readFileSync(file, 'utf8'), sandbox, { filename: file });
    }

    /**
     * Evaluate an expression inside the app.
     *
     * Needed because `let`/`const` at the top level of a script live in the
     * context's lexical scope, not as properties of the global object — so
     * `sandbox.vault` is undefined while `vault` is perfectly visible to the
     * app's own code. Function declarations do land on the global, which is
     * why those can be called directly.
     */
    const evalIn = (code) => vm.runInContext(code, sandbox);

    return { sandbox, dom, storage, clipboard, evalIn };
}

await t.test('every script in index.html loads without a reference error', async () => {
    const { sandbox } = loadApp();
    for (const name of [
        'unlockVault',
        'lockVault',
        'copyPassword',
        'deleteSite',
        'changeMasterPassword',
        'setupVaultStorage',
        'exportVaultFile',
        'importVaultFile',
        'mergeSyncConflictFiles',
        'checkVaultFileHealth',
        'updateBackupWarningIndicator',
        'syncVaultFromStore',
        'openVaultStore'
    ]) {
        assert.strictEqual(typeof sandbox[name], 'function', `${name} must be defined`);
    }
});

await t.test('index.html loads exactly the scripts this test loads', () => {
    const html = readFileSync(path.resolve(here, '../vault/index.html'), 'utf8');
    const srcs = Array.from(html.matchAll(/<script src="([^"]+)"><\/script>/g)).map((m) => m[1]);
    // Guards against a module being added to the page but not to the tests,
    // or vice versa — either way the tested code stops being the shipped code.
    assert.deepStrictEqual(srcs, [
        'bip39WordList.js',
        'crypto-js.min.js',
        'envelope.js',
        'core/derive.js',
        'core/util.js',
        'core/hlc.js',
        'core/records.js',
        'core/oplog.js',
        'core/keyslots.js',
        'core/store.js',
        'core/transports.js',
        'core/migrate-legacy.js',
        'core/bootstrap.js',
        'core/totp.js',
        'core/porter.js',
        'app.js'
    ]);
});

await t.test('a fresh install starts at the welcome screen', () => {
    const { sandbox } = loadApp();
    assert.strictEqual(sandbox.hasSavedEncryptedVault(), false);
});

await t.test('create, save a nonce, lock, and unlock again', async () => {
    const { sandbox, dom, storage, evalIn } = loadApp();
    const PW = 'a decent master password';

    await sandbox.initializeVault(
        'abandon ability able about above absent absorb abstract absurd abuse access accident'
    );
    const privateKey = evalIn('vault.privateKey');
    assert.ok(privateKey, 'derivation must produce a key');

    dom.document.getElementById('storagePass1').value = PW;
    dom.document.getElementById('storagePass2').value = PW;
    await sandbox.setupVaultStorage();

    assert.ok(evalIn('vaultStore'), 'a store must be open after setup');
    assert.strictEqual(sandbox.hasSavedEncryptedVault(), true);

    // Save a password the way the UI does.
    dom.document.getElementById('genSite').value = 'github.com';
    dom.document.getElementById('genUser').value = 'me';
    evalIn('currentNonce = 2');
    assert.strictEqual(sandbox.copyPassword(), true);
    await new Promise((r) => setTimeout(r, 50)); // the nonce write is async

    assert.strictEqual(evalIn("vaultStore.getCredential('me', 'github.com').nonce"), 2);

    sandbox.lockVault(true);
    assert.strictEqual(evalIn('vaultStore'), null, 'locking must drop the store handle');
    assert.strictEqual(evalIn('vault.privateKey'), '', 'locking must clear the seed');

    dom.document.getElementById('unlockPassword').value = PW;
    await sandbox.unlockVault();

    assert.strictEqual(evalIn('vault.privateKey'), privateKey, 'unlock must restore the identity');
    assert.strictEqual(evalIn("vault.users.me['github.com']"), 2, 'the nonce must survive');

    // Nothing keyed by a hash of the master password may exist anywhere.
    const sha = sandbox.VaultDerive.sha256Hex(PW);
    for (const [k, v] of storage._map) {
        assert.ok(!k.includes(sha), `storage key leaks SHA-256(password): ${k}`);
        assert.ok(!v.includes(sha), `storage value leaks SHA-256(password): ${k}`);
    }
});

await t.test('the generated password is unchanged by all of this', async () => {
    const { sandbox } = loadApp();
    // Pinned value: the derivation is deterministic, so any change here would
    // silently invalidate every password every user has ever generated.
    const pass = sandbox.VaultDerive.generatePassword('abcdef0123456789', 'me', 'github.com', 0, 16);
    assert.strictEqual(
        pass,
        'PASS' + sandbox.VaultDerive.sha256Hex('abcdef0123456789/me/github.com/0').slice(0, 16) + '249+'
    );
    assert.match(pass, /^PASS[0-9a-f]{16}249\+$/);
});

await t.test('a wrong password is refused and rate limited', async () => {
    const { sandbox, dom, evalIn } = loadApp();
    const PW = 'a decent master password';
    await sandbox.initializeVault(
        'abandon ability able about above absent absorb abstract absurd abuse access accident'
    );
    dom.document.getElementById('storagePass1').value = PW;
    dom.document.getElementById('storagePass2').value = PW;
    await sandbox.setupVaultStorage();
    sandbox.lockVault(true);

    dom.document.getElementById('unlockPassword').value = 'wrong';
    for (let i = 0; i < 5; i++) await sandbox.unlockVault();
    assert.strictEqual(evalIn('vault.privateKey'), '', 'a wrong password must never unlock');
    assert.ok(evalIn('unlockLockoutUntil') > Date.now(), 'repeated failures must lock out');
});

await t.test('changing the master password keeps the vault openable', async () => {
    const { sandbox, dom, evalIn } = loadApp();
    const PW = 'the first master password';
    await sandbox.initializeVault(
        'abandon ability able about above absent absorb abstract absurd abuse access accident'
    );
    dom.document.getElementById('storagePass1').value = PW;
    dom.document.getElementById('storagePass2').value = PW;
    await sandbox.setupVaultStorage();

    dom.document.getElementById('genSite').value = 'bank.example';
    dom.document.getElementById('genUser').value = 'me';
    evalIn('currentNonce = 4');
    sandbox.copyPassword();
    await new Promise((r) => setTimeout(r, 50));

    dom.document.getElementById('currentMasterPassword').value = PW;
    dom.document.getElementById('newMasterPassword').value = 'the second master password';
    dom.document.getElementById('confirmMasterPassword').value = 'the second master password';
    await sandbox.changeMasterPassword();

    sandbox.lockVault(true);
    dom.document.getElementById('unlockPassword').value = 'the second master password';
    await sandbox.unlockVault();
    assert.strictEqual(evalIn("vault.users.me['bank.example']"), 4);

    sandbox.lockVault(true);
    dom.document.getElementById('unlockPassword').value = PW;
    await sandbox.unlockVault();
    assert.strictEqual(evalIn('vault.privateKey'), '', 'the old password must stop working');
});

await t.test('the seed shown is not silently replaced on revisiting the screen', async () => {
    // Reported from a device: revisiting the seed screen regenerated the
    // phrase with the confirmation suppressed, so the verification step asked
    // for words from a seed the user had never been shown.
    const { sandbox, evalIn } = loadApp();

    sandbox.showScreen('newWalletScreen');
    await new Promise((r) => setTimeout(r, 20));
    const first = evalIn('vault.seedPhrase');
    assert.ok(first && first.split(' ').length === 12, 'a seed must be generated');

    sandbox.showScreen('welcomeScreen');
    sandbox.showScreen('newWalletScreen');
    await new Promise((r) => setTimeout(r, 20));
    assert.strictEqual(evalIn('vault.seedPhrase'), first, 'the seed must not change underfoot');
});

await t.test('verification checks the words that were actually shown', async () => {
    const { sandbox, dom, evalIn } = loadApp();
    sandbox.showScreen('newWalletScreen');
    await new Promise((r) => setTimeout(r, 20));

    const shown = evalIn('vault.seedPhrase').split(' ');
    sandbox.confirmSeedBackup();

    // Something replaces the seed after the questions were generated.
    evalIn("vault.seedPhrase = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo'");

    // Answering with the words the user was SHOWN must still be accepted, and
    // the vault must be initialised from that phrase.
    const inputs = [0, 1, 2].map((i) => ({ value: shown[i], dataset: { index: String(i) }, style: {} }));
    dom.document.querySelectorAll = (sel) => (sel === '.verify-word' ? inputs : []);

    await sandbox.verifySeedBackup();
    assert.strictEqual(evalIn('vault.seedPhrase'), shown.join(' '), 'must keep the shown phrase');
    assert.ok(evalIn('vault.privateKey'), 'the identity must be derived from it');
});

await t.test('resetThisDevice clears local state and returns to welcome', async () => {
    const { sandbox, dom, storage, evalIn } = loadApp();
    const PW = 'a decent master password';
    await sandbox.initializeVault(
        'abandon ability able about above absent absorb abstract absurd abuse access accident'
    );
    dom.document.getElementById('storagePass1').value = PW;
    dom.document.getElementById('storagePass2').value = PW;
    await sandbox.setupVaultStorage();
    assert.strictEqual(sandbox.hasSavedEncryptedVault(), true);

    sandbox.resetThisDevice();

    assert.strictEqual(sandbox.hasSavedEncryptedVault(), false, 'must be startable again');
    assert.strictEqual(evalIn('vaultStore'), null);
    assert.strictEqual(evalIn('vault.privateKey'), '');
    for (const key of ['vaultEncrypted', 'vaultDirPath', 'vaultFilePath', 'tvDeviceId', 'tvSchema']) {
        assert.strictEqual(storage.getItem(key), null, `${key} must be cleared`);
    }
    for (const key of storage._map.keys()) {
        assert.ok(!key.startsWith('tvfs:'), `local vault file ${key} must be cleared`);
    }
});

// ------------------------------------------------ restore-from-seed into an existing vault

/** Drive the setup screen the way a user would. */
async function runSetup(app, { password, confirm, mode }) {
    const { sandbox, dom } = app;
    if (mode) sandbox.setVaultSetupMode(mode);
    dom.document.getElementById('storagePass1').value = password;
    dom.document.getElementById('storagePass2').value = confirm === undefined ? password : confirm;
    await sandbox.setupVaultStorage();
}

/** Copy a previous run's stored vault files into a fresh app instance. */
function carryVaultFiles(from, to) {
    for (const [k, v] of from.storage._map) {
        if (k.startsWith('tvfs:')) to.storage.setItem(k, v);
    }
}

await t.test('restoring a seed into an EXISTING vault opens it instead of replacing it', async () => {
    // The flow: open the app, type the seed you already have, point at the
    // vault you already have, unlock it.
    const PW = 'the existing vault password';
    const SEED =
        'abandon ability able about above absent absorb abstract absurd abuse access accident';

    const first = loadApp();
    await first.sandbox.initializeVault(SEED);
    await runSetup(first, { password: PW });
    first.dom.document.getElementById('genSite').value = 'github.com';
    first.dom.document.getElementById('genUser').value = 'me';
    first.evalIn('currentNonce = 5');
    first.sandbox.copyPassword();
    await new Promise((r) => setTimeout(r, 50));

    // A reinstall: same stored vault, fresh app, user types their seed again.
    const second = loadApp();
    carryVaultFiles(first, second);
    await second.sandbox.initializeVault(SEED);
    await runSetup(second, { password: PW, mode: 'existing' });

    assert.ok(second.evalIn('vaultStore'), 'the existing vault must open');
    assert.strictEqual(
        second.evalIn("vault.users.me['github.com']"),
        5,
        'the existing vault contents must be there'
    );
    assert.strictEqual(second.evalIn('vault.seedPhrase'), SEED);
});

await t.test('opening an existing vault with the wrong password is refused', async () => {
    const PW = 'the existing vault password';
    const SEED =
        'abandon ability able about above absent absorb abstract absurd abuse access accident';

    const first = loadApp();
    await first.sandbox.initializeVault(SEED);
    await runSetup(first, { password: PW });

    const second = loadApp();
    carryVaultFiles(first, second);
    await second.sandbox.initializeVault(SEED);
    await runSetup(second, { password: 'not it', mode: 'existing' });
    assert.strictEqual(second.evalIn('vaultStore'), null, 'must not open');

    // The stored vault must be untouched, so the right password still works.
    const third = loadApp();
    carryVaultFiles(second, third);
    await third.sandbox.initializeVault(SEED);
    await runSetup(third, { password: PW, mode: 'existing' });
    assert.ok(third.evalIn('vaultStore'), 'the real password must still open it');
});

await t.test("an existing vault's own seed wins over a different one typed in", async () => {
    const PW = 'shared password';
    const SEED_A =
        'abandon ability able about above absent absorb abstract absurd abuse access accident';
    const SEED_B =
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

    const first = loadApp();
    await first.sandbox.initializeVault(SEED_A);
    await runSetup(first, { password: PW });
    const keyA = first.evalIn('vault.privateKey');

    const second = loadApp();
    carryVaultFiles(first, second);
    // The user types a DIFFERENT seed, then opens the existing vault. Every
    // password in that vault was derived from seed A; silently adopting seed B
    // would change all of them.
    second.evalIn(`vault.seedPhrase = ${JSON.stringify(SEED_B)}; vault.privateKey = 'ffff'`);
    await runSetup(second, { password: PW, mode: 'existing' });

    assert.strictEqual(second.evalIn('vault.privateKey'), keyA, "the vault's own seed must win");
    assert.strictEqual(second.evalIn('vault.seedPhrase'), SEED_A);
});

await t.test('setup mode drives the password fields and the submit label', () => {
    const { sandbox, dom } = loadApp();
    sandbox.setVaultSetupMode('existing');
    assert.strictEqual(dom.document.getElementById('btnSetupVaultStorage').textContent, 'Open Vault');
    assert.strictEqual(
        dom.document.getElementById('storagePass1Label').textContent,
        'Existing Vault Password'
    );
    sandbox.setVaultSetupMode('new');
    assert.strictEqual(
        dom.document.getElementById('btnSetupVaultStorage').textContent,
        'Save Encrypted Vault'
    );
    assert.strictEqual(dom.document.getElementById('storagePass1Label').textContent, 'Vault Password');
});

await t.test('escapeHtml neutralises quotes for attribute contexts, not just < >', () => {
    const { sandbox } = loadApp();
    const esc = sandbox.escapeHtml;
    assert.strictEqual(esc('a & b'), 'a &amp; b');
    assert.strictEqual(esc('<img>'), '&lt;img&gt;');
    assert.strictEqual(esc('x" onx="y'), 'x&quot; onx=&quot;y');
    assert.strictEqual(esc("it's"), 'it&#39;s');
    assert.strictEqual(esc('&lt;'), '&amp;lt;'); // & escaped first: no double-encode
});

await t.test('renderSiteList escapes a crafted site name so it cannot break out of an attribute', () => {
    const { sandbox, dom, evalIn } = loadApp();
    // The kind of name a malicious synced or imported vault could carry.
    evalIn(`vault.users = { "me": { 'x" onpointerover="alert(1)': 7 } };`);
    sandbox.renderSiteList();
    const html = dom.document.getElementById('siteList').innerHTML;
    assert.ok(html.length > 0, 'the row should render');
    assert.ok(!/"\s+onpointerover=/.test(html), 'the quote must not break out of the attribute: ' + html);
    assert.ok(html.includes('&quot;'), 'the double quote must be entity-encoded');
});

const MOVE_SEED = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

async function setupInFolder(sandbox, dom, tauri, dir, pw) {
    await sandbox.initializeVault(MOVE_SEED);
    tauri.setNextDir(dir);
    dom.document.getElementById('storagePass1').value = pw;
    dom.document.getElementById('storagePass2').value = pw;
    await sandbox.setupVaultStorage();
}

async function saveCredential(sandbox, dom, evalIn, user, site, nonce) {
    dom.document.getElementById('genSite').value = site;
    dom.document.getElementById('genUser').value = user;
    evalIn(`currentNonce = ${nonce}`);
    sandbox.copyPassword();
    await new Promise((r) => setTimeout(r, 50)); // the nonce write is async
}

await t.test('moveVaultFile relocates to a new folder without losing credentials', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    const PW = 'a decent master password';

    await setupInFolder(sandbox, dom, tauri, '/vaults/A', PW);
    assert.strictEqual(evalIn('vaultDirPath'), '/vaults/A');
    await saveCredential(sandbox, dom, evalIn, 'me', 'github.com', 3);
    assert.strictEqual(evalIn("vaultStore.getCredential('me', 'github.com').nonce"), 3);

    tauri.setNextDir('/vaults/B');
    await sandbox.moveVaultFile();

    assert.strictEqual(evalIn('vaultDirPath'), '/vaults/B', 'now points at folder B');
    assert.strictEqual(evalIn("vault.users['me']['github.com']"), 3, 'credential survived in the UI view');
    assert.strictEqual(evalIn("vaultStore.getCredential('me', 'github.com').nonce"), 3, 'and in the new store');
    assert.ok(tauri.disk.has('/vaults/B/topolino-vault.json'), 'snapshot written in the new folder');
    assert.ok(tauri.disk.has('/vaults/B/topolino-vault.keys.json'), 'keyslots written in the new folder');
});

await t.test('moveVaultFile falls back to a single file when there is no folder picker (the Android fix)', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    const PW = 'a decent master password';

    await setupInFolder(sandbox, dom, tauri, '/vaults/A', PW);
    await saveCredential(sandbox, dom, evalIn, 'you', 'example.com', 1);

    // Android: the folder picker errors; the save dialog returns a content URI.
    tauri.setNextDir('__ERR__');
    tauri.setNextFile('content://vault/topolino-vault.json');
    await sandbox.moveVaultFile();

    assert.strictEqual(evalIn('vaultFilePath'), 'content://vault/topolino-vault.json', 'moved to the single file');
    assert.strictEqual(evalIn('vaultDirPath'), '', 'the folder pointer is cleared');
    assert.strictEqual(evalIn("vault.users['you']['example.com']"), 1, 'credential survived the fallback move');
});

await t.test('notes: saveNote stores a record and renderNotesList surfaces it', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    await setupInFolder(sandbox, dom, tauri, '/vaults/N', 'a decent master password');

    sandbox.openNoteEdit(null);
    dom.document.getElementById('noteTitle').value = 'Recovery codes';
    dom.document.getElementById('noteBody').value = 'abc-123\ndef-456';
    await sandbox.saveNote();

    const notes = evalIn("vaultStore.listRecords('note')");
    assert.strictEqual(notes.length, 1);
    assert.strictEqual(notes[0].title, 'Recovery codes');
    sandbox.renderNotesList();
    assert.ok(dom.document.getElementById('notesList').innerHTML.includes('Recovery codes'));
});

await t.test('totp: addTotp stores a token and renderTotpList shows a 6-digit code', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    await setupInFolder(sandbox, dom, tauri, '/vaults/T', 'a decent master password');

    sandbox.openAddTotp();
    dom.document.getElementById('totpIssuer').value = 'GitHub';
    dom.document.getElementById('totpSecret').value = 'JBSWY3DPEHPK3PXP';
    await sandbox.addTotp();

    const toks = evalIn("vaultStore.listRecords('totp')");
    assert.strictEqual(toks.length, 1);
    assert.strictEqual(toks[0].issuer, 'GitHub');
    await sandbox.renderTotpList();
    assert.ok(/data-code="\d{6}"/.test(dom.document.getElementById('totpList').innerHTML), 'a code should render');
    // addTotp navigated to totpScreen, which started a 1s refresh interval;
    // clear it or the test process never exits.
    evalIn('if (totpTimer) { clearInterval(totpTimer); totpTimer = null; }');
});

await t.test('csv import creates credentials and keeps old logins as notes', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    await setupInFolder(sandbox, dom, tauri, '/vaults/C', 'a decent master password');

    dom.document.getElementById('csvImportText').value =
        'name,login_uri,login_username,login_password\nGitHub,https://github.com,me@example.com,hunter2\n';
    await sandbox.importCsvText();

    assert.strictEqual(evalIn("vault.users['me@example.com']['github.com']"), 0, 'credential created at nonce 0');
    const notes = evalIn("vaultStore.listRecords('note')");
    assert.strictEqual(notes.length, 1, 'the old login is preserved as a note');
    assert.ok(notes[0].body.includes('hunter2'));
});

await t.test('csv export lists entries with generated passwords', async () => {
    const tauri = makeTauri();
    const { sandbox, dom, evalIn } = loadApp(tauri);
    await setupInFolder(sandbox, dom, tauri, '/vaults/E', 'a decent master password');

    evalIn("vault.users = { 'me': { 'github.com': 0 } }");
    sandbox.renderCsvExport();
    const csv = dom.document.getElementById('csvExportText').value;
    assert.strictEqual(csv.split('\r\n')[0], 'name,url,username,password');
    assert.ok(/github\.com,github\.com,me,PASS[0-9a-f]+249\+/.test(csv), csv);
});

await t.test('the vault path is shown on the settings and sync-file screens', async () => {
    const tauri = makeTauri();
    const { sandbox, dom } = loadApp(tauri);
    await setupInFolder(sandbox, dom, tauri, '/vaults/P', 'a decent master password');

    sandbox.showScreen('settingsScreen');
    assert.strictEqual(dom.document.getElementById('vaultPathSettings').textContent, '/vaults/P');
    sandbox.showScreen('backupScreen');
    assert.strictEqual(dom.document.getElementById('vaultPathBackup').textContent, '/vaults/P');
});

t.done();
