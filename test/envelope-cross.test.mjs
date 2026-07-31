/**
 * Cross-implementation compatibility test: the native app's vault/envelope.js
 * against the Obsidian plugin's src/core/envelope.ts (the reference
 * implementation). Both must read what the other writes, forever.
 *
 * Run:  node test/envelope-cross.test.mjs
 * The plugin repo is expected at ../topolino-vault-obsidian (override with
 * PLUGIN_REPO=/path). Its envelope.ts is bundled on the fly with esbuild.
 */
import { createRequire } from 'module';
import { execSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import path from 'path';
import assert from 'assert';

const here = path.dirname(fileURLToPath(import.meta.url));
const pluginRepo = process.env.PLUGIN_REPO || path.resolve(here, '../../topolino-vault-obsidian');
const require = createRequire(import.meta.url);

const CryptoJS = require(path.resolve(here, '../vault/crypto-js.min.js'));
globalThis.CryptoJS = CryptoJS;
await import(path.resolve(here, '../vault/envelope.js'));
const native = globalThis.VaultEnvelope;

const tmp = mkdtempSync(path.join(tmpdir(), 'envelope-cross-'));
process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));
execSync(
    `npx esbuild src/core/envelope.ts --bundle --format=esm --platform=node --outfile=${tmp}/plugin-envelope.mjs`,
    { cwd: pluginRepo, stdio: 'pipe' }
);
const plugin = await import(path.join(tmp, 'plugin-envelope.mjs'));

const pw = 'correct horse battery staple';
const data = {
    privateKey: '1a2b3c4d5e6f',
    seedPhrase: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
    passphrase: '',
    users: { fabricio: { github: 2, proton: 0 }, work: { jira: 5 } },
    settings: { hashLength: 16 },
};

let passed = 0;
const ok = (name) => { passed++; console.log('ok -', name); };

// 1. plugin encrypts -> native decrypts
{
    const salt = plugin.randomSalt();
    const key = await plugin.deriveVaultKey(pw, salt);
    const file = await plugin.encryptEnvelope(data, key, salt);
    const res = await native.decryptEnvelope(file, pw);
    assert.deepStrictEqual(res.data, data);
    assert.strictEqual(res.legacy, false);
    assert.strictEqual(res.iterations, 600000);
    ok('plugin v2 file decrypts in native app');
}

// 2. native encrypts -> plugin decrypts
{
    const salt = native.randomSalt();
    const key = await native.deriveVaultKey(pw, salt);
    const file = await native.encryptEnvelope(data, key, salt);
    const res = await plugin.decryptEnvelope(file, pw);
    assert.deepStrictEqual(res.data, data);
    assert.strictEqual(res.legacy, false);
    ok('native v2 file decrypts in plugin');
}

// 3. legacy v1 file (old native app format) -> native decrypts + flags upgrade
{
    const v1 = JSON.stringify({
        v: 1,
        type: 'topolino-vault',
        payload: CryptoJS.AES.encrypt(JSON.stringify(data), pw).toString(),
    });
    const res = await native.decryptEnvelope(v1, pw);
    assert.deepStrictEqual(res.data, data);
    assert.strictEqual(res.legacy, true);
    const upgraded = await native.encryptEnvelope(res.data, res.key, res.salt, res.iterations);
    const res2 = await plugin.decryptEnvelope(upgraded, pw);
    assert.deepStrictEqual(res2.data, data);
    ok('v1 file upgrades to v2 readable by plugin');
}

// 4. wrong password rejected on v2
{
    const salt = native.randomSalt();
    const key = await native.deriveVaultKey(pw, salt);
    const file = await native.encryptEnvelope(data, key, salt);
    await assert.rejects(native.decryptEnvelope(file, 'nope'), /Wrong password/);
    ok('wrong password rejected (v2)');
}

// 5. structural guards
{
    assert.strictEqual(native.looksLikeVaultFile('{"type":"topolino-vault","payload":"x"}'), true);
    assert.strictEqual(native.looksLikeVaultFile('{"hello":1}'), false);
    assert.strictEqual(native.looksLikeVaultFile('not json'), false);
    ok('looksLikeVaultFile guards');
}

// 6. tampered ciphertext rejected (GCM auth)
{
    const salt = native.randomSalt();
    const key = await native.deriveVaultKey(pw, salt);
    const env = JSON.parse(await native.encryptEnvelope(data, key, salt));
    const bytes = native.fromBase64(env.payload);
    bytes[0] ^= 0xff;
    env.payload = native.toBase64(bytes);
    await assert.rejects(native.decryptEnvelope(JSON.stringify(env), pw), /Wrong password/);
    ok('tampered payload rejected');
}

console.log(`\n${passed} passed, 0 failed`);
