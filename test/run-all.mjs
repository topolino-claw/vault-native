/**
 * Runs every suite. `node test/run-all.mjs`
 *
 * The Obsidian plugin is no longer a compatibility target, so
 * envelope-cross.test.mjs is not part of this run. It is left in the tree for
 * reference; delete it whenever. Compatibility that still matters — with
 * previously shipped versions of THIS app — is covered by compat.test.mjs,
 * which loads the old code straight out of git.
 */
import { spawnSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));

const suites = [
    { file: 'core.test.mjs', what: 'clock, CRDT merge, oplog, keyslots, store' },
    { file: 'migrate.test.mjs', what: 'one-shot legacy migration' },
    { file: 'compat.test.mjs', what: 'backward compatibility with the shipped version' },
    { file: 'app-wiring.test.mjs', what: 'app.js against a headless DOM' },
    { file: 'hostile.test.mjs', what: 'hostile input / error-contract fuzz' },
    { file: 'security-config.test.mjs', what: 'CSP parity and attack-surface statics' },
    { file: 'montecarlo.test.mjs', what: 'multi-device simulation' }
];

let failed = 0;
for (const suite of suites) {
    console.log(`\n=== ${suite.file} — ${suite.what}`);
    const result = spawnSync(process.execPath, [path.join(here, suite.file)], {
        stdio: 'inherit',
        env: process.env
    });
    if (result.status !== 0) failed++;
}

console.log(failed ? `\n${failed} suite(s) FAILED` : '\nall suites passed');
process.exit(failed ? 1 : 0);
