/**
 * Shared loader for the vault core in Node.
 *
 * The core modules attach themselves to the global object exactly as they do
 * in the browser, so tests exercise the same files the app ships — no bundler,
 * no shims, no second implementation to drift out of sync. Load order matters
 * because later modules read earlier ones off the global.
 */
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

let loaded = null;

export async function loadCore() {
    if (loaded) return loaded;

    globalThis.CryptoJS = require(path.resolve(here, '../vault/crypto-js.min.js'));

    await import(path.resolve(here, '../vault/envelope.js'));
    await import(path.resolve(here, '../vault/core/derive.js'));
    await import(path.resolve(here, '../vault/core/util.js'));
    await import(path.resolve(here, '../vault/core/hlc.js'));
    await import(path.resolve(here, '../vault/core/records.js'));
    await import(path.resolve(here, '../vault/core/oplog.js'));
    await import(path.resolve(here, '../vault/core/keyslots.js'));
    await import(path.resolve(here, '../vault/core/store.js'));
    await import(path.resolve(here, '../vault/core/migrate-legacy.js'));
    await import(path.resolve(here, '../vault/core/totp.js'));
    await import(path.resolve(here, '../vault/core/porter.js'));

    loaded = {
        Envelope: globalThis.VaultEnvelope,
        Totp: globalThis.VaultTotp,
        Porter: globalThis.VaultPorter,
        Derive: globalThis.VaultDerive,
        Util: globalThis.VaultUtil,
        HLC: globalThis.VaultHLC,
        Records: globalThis.VaultRecords,
        Oplog: globalThis.VaultOplog,
        Keyslots: globalThis.VaultKeyslots,
        Store: globalThis.VaultStore,
        Migrate: globalThis.VaultMigrateLegacy,
        CryptoJS: globalThis.CryptoJS
    };
    return loaded;
}

/** Keyslot iterations are dialled down in tests; production uses 600k. */
export const TEST_ITERATIONS = 1000;

/** Minimal counting test harness shared by the suites. */
export function harness(title) {
    let passed = 0;
    const failures = [];
    console.log(title);
    return {
        async test(name, fn) {
            // Written to stderr before the test runs so a hang names the test
            // that hung — stdout is block-buffered when redirected to a file.
            if (process.env.TEST_TRACE) process.stderr.write('>> ' + name + '\n');
            try {
                await fn();
                passed++;
                console.log('ok -', name);
            } catch (e) {
                failures.push({ name, e });
                console.log('FAIL -', name, '\n   ', e && e.message);
            }
        },
        done() {
            console.log(`\n${passed} passed, ${failures.length} failed`);
            if (failures.length) process.exitCode = 1;
            return failures.length === 0;
        }
    };
}
