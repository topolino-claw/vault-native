/**
 * Static configuration assertions — the guarantees that live in build files
 * rather than code. These are the ones a "one small config tweak" breaks
 * silently, so they are pinned here.
 */
import assert from 'assert';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { harness } from './_load.mjs';

const t = harness('security configuration parity');
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..');

const indexHtml = readFileSync(path.join(repo, 'vault/index.html'), 'utf8');
const tauriConf = readFileSync(path.join(repo, 'src-tauri/tauri.conf.json'), 'utf8');

// The two boundaries the frontend must never negotiate with:
//  - script-src 'self'    -> inline/remote script injection is denied
//  - connect-src 'none'   -> the page cannot make a single network call
const REQUIRED_DIRECTIVES = { 'default-src': 'self', 'script-src': 'self', 'connect-src': 'none' };

await t.test('index.html CSP and tauri.conf.json CSP are the same policy', () => {
    const meta = indexHtml
        .match(/<meta[^>]+Content-Security-Policy[^>]+>/i)?.[0] || '';
    const metaCsp = decodeURIComponent(meta.match(/content="([^"]*)"/i)?.[1] || '');
    const confCsp = JSON.parse(tauriConf).app.security.csp;

    assert.ok(metaCsp, 'meta CSP present');
    assert.ok(confCsp, 'tauri.conf CSP present');

    const norm = (csp) =>
        csp
            .split(';')
            .map((d) => d.trim().toLowerCase())
            .filter(Boolean)
            .sort()
            .join(';');
    assert.strictEqual(norm(metaCsp), norm(confCsp), 'the two CSPs must agree byte-for-byte by policy');

    for (const [directive, value] of Object.entries(REQUIRED_DIRECTIVES)) {
        assert.match(
            metaCsp,
            new RegExp(directive + "\\s+'" + value + "'"),
            `${directive} ${value} in meta`
        );
        assert.match(
            confCsp,
            new RegExp(directive + "\\s+'" + value + "'"),
            `${directive} ${value} in conf`
        );
    }
});

await t.test('script-src has no unsafe-inline / eval / remote sources', () => {
    const confCsp = JSON.parse(tauriConf).app.security.csp;
    assert.ok(!/script-src[^;]*unsafe-inline/.test(confCsp), 'no inline scripts');
    assert.ok(!/script-src[^;]*unsafe-eval/.test(confCsp), 'no eval');
    assert.ok(!/script-src[^;]*https?:/.test(confCsp), 'no remote scripts');
    assert.ok(!/https?:/.test(confCsp.replace(/img-src[^;]*data:/, '')), 'no external network sources');
});

await t.test('every page script is a local file shipped with the app', () => {
    const scripts = indexHtml.match(/<script[^>]+src="([^"]+)"/g) || [];
    assert.ok(scripts.length >= 10, 'core scripts present');
    for (const tag of scripts) {
        const src = tag.match(/src="([^"]+)"/)[1];
        assert.ok(
            !/^https?:|^\/\/|^data:|^blob:/.test(src),
            `script src must be local, got: ${src}`
        );
    }
});

await t.test('connect-src is none in both documents', () => {
    const meta = indexHtml.match(/<meta[^>]+Content-Security-Policy[^>]+>/i)?.[0] || '';
    const metaCsp = decodeURIComponent(meta.match(/content="([^"]*)"/i)?.[1] || '');
    const confCsp = JSON.parse(tauriConf).app.security.csp;
    for (const csp of [metaCsp, confCsp]) {
        assert.match(csp, /connect-src\s+'none'/, 'connect-src none');
    }
});

await t.test('networking primitives are absent from the shipped frontend', () => {
    const sources = ['vault/app.js', 'vault/envelope.js', 'vault/core/store.js', 'vault/core/transports.js'];
    const forbidden = ['fetch(', 'XMLHttpRequest', 'new WebSocket', 'sendBeacon('];
    for (const file of sources) {
        const text = readFileSync(path.join(repo, file), 'utf8');
        for (const token of forbidden) {
            assert.ok(!text.includes(token), `${file} must not contain ${token}`);
        }
    }
});

t.done();