/**
 * Tests for mergeUsers() — the single deep-merge function in vault/app.js.
 *
 * This file extracts mergeUsers() from the actual source code via regex,
 * so tests always run against the real production function — not a copy.
 *
 * Run:  node tests/deep-merge.test.js
 */

const fs = require('fs');
const path = require('path');

// ─── Extract mergeUsers() from the real source ─────────────────────────────

const appSrc = fs.readFileSync(
    path.join(__dirname, '..', 'vault', 'app.js'),
    'utf-8'
);

// Match the function block: `function mergeUsers(remoteUsers) { ... }`
const fnMatch = appSrc.match(/^function mergeUsers\(remoteUsers\)\s*\{[\s\S]*?^\}/m);
if (!fnMatch) {
    console.error('\x1b[31mFATAL: could not extract mergeUsers() from vault/app.js\x1b[0m');
    process.exit(1);
}

/**
 * Wraps the extracted mergeUsers() so it operates on a test vault
 * and returns the merged result without mutating the input.
 */
function deepMergeUsers(local, remote) {
    const vault = { users: structuredClone(local) };
    // Build a closure that gives mergeUsers access to `vault`
    const run = new Function('vault', 'remoteUsers', `
        ${fnMatch[0]}
        mergeUsers(remoteUsers);
        return vault.users;
    `);
    return run(vault, remote);
}

// ─── Old buggy implementations (for regression proof) ───────────────────────

function shallowMergeUsers(local, remote) {
    return { ...structuredClone(local), ...remote };
}

function replacementMergeUsers(local, remote) {
    return remote || structuredClone(local);
}

// ─── Minimal test harness ───────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, message) {
    if (condition) {
        passed++;
        console.log(`  \x1b[32m\u2713\x1b[0m ${message}`);
    } else {
        failed++;
        failures.push(message);
        console.log(`  \x1b[31m\u2717\x1b[0m ${message}`);
    }
}

function assertDeepEqual(actual, expected, message) {
    const a = JSON.stringify(actual, null, 0);
    const e = JSON.stringify(expected, null, 0);
    if (a === e) {
        passed++;
        console.log(`  \x1b[32m\u2713\x1b[0m ${message}`);
    } else {
        failed++;
        failures.push(`${message}\n      expected: ${e}\n      actual:   ${a}`);
        console.log(`  \x1b[31m\u2717\x1b[0m ${message}`);
        console.log(`      expected: ${e}`);
        console.log(`      actual:   ${a}`);
    }
}

function describe(name, fn) {
    console.log(`\n\x1b[1m${name}\x1b[0m`);
    fn();
}

// ─── Source integrity check ─────────────────────────────────────────────────

describe('Source integrity', () => {

    assert(fnMatch !== null, 'mergeUsers() found in vault/app.js');

    const callers = (appSrc.match(/mergeUsers\(data\.users\)/g) || []).length;
    assert(callers === 5, `mergeUsers(data.users) called in 5 restore paths (found ${callers})`);

    // No leftover shallow merges on vault.users
    const shallowPattern = /vault\.users\s*=\s*\{\s*\.\.\.vault\.users/g;
    const shallowHits = (appSrc.match(shallowPattern) || []).length;
    assert(shallowHits === 0, `no shallow-spread merges on vault.users remain (found ${shallowHits})`);

    // No leftover full replacements like `vault.users = data.users || vault.users`
    // (excludes `vault.users = data.users || {}` in unlockVault which is a full load, not a merge)
    const replacePattern = /vault\.users\s*=\s*data\.users\s*\|\|\s*vault\.users/g;
    const replaceHits = (appSrc.match(replacePattern) || []).length;
    assert(replaceHits === 0, `no full-replacement merges on vault.users remain (found ${replaceHits})`);
});

// ─── Core merge logic ───────────────────────────────────────────────────────

describe('Higher nonce wins', () => {
    const local  = { alice: { github: 5, twitter: 3 } };
    const remote = { alice: { github: 2 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 5, 'keeps local nonce when local is higher (5 > 2)');
    assert(result.alice.twitter === 3, 'preserves local sites missing from remote');
});

describe('Remote nonce higher than local', () => {
    const local  = { alice: { github: 1 } };
    const remote = { alice: { github: 7 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 7, 'accepts remote nonce when remote is higher (7 > 1)');
});

describe('Equal nonces', () => {
    const local  = { alice: { github: 3 } };
    const remote = { alice: { github: 3 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 3, 'keeps value when nonces are equal');
});

describe('New user from remote', () => {
    const local  = { alice: { github: 2 } };
    const remote = { bob: { gitlab: 1 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 2, 'preserves existing user');
    assert(result.bob.gitlab === 1, 'adds new user from remote');
});

describe('New site for existing user', () => {
    const local  = { alice: { github: 2 } };
    const remote = { alice: { gitlab: 4 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 2, 'preserves existing site');
    assert(result.alice.gitlab === 4, 'adds new site from remote');
});

describe('Empty local vault', () => {
    const remote = { alice: { github: 3, twitter: 1 }, bob: { gitlab: 2 } };
    const result = deepMergeUsers({}, remote);

    assertDeepEqual(result, remote, 'populates empty vault with all remote data');
});

describe('Empty remote backup', () => {
    const local = { alice: { github: 5 } };
    const result = deepMergeUsers(local, {});

    assertDeepEqual(result, local, 'empty remote does not erase local data');
});

describe('Null / undefined remote (guard)', () => {
    const local = { alice: { github: 5 } };

    assertDeepEqual(deepMergeUsers(local, null), local, 'null remote preserves local');
    assertDeepEqual(deepMergeUsers(local, undefined), local, 'undefined remote preserves local');
});

describe('Complex multi-user multi-site merge', () => {
    const local = {
        alice: { github: 5, twitter: 3, reddit: 1 },
        bob:   { gitlab: 2, npm: 4 },
        carol: { aws: 1 }
    };
    const remote = {
        alice: { github: 2, twitter: 8, slack: 1 },
        bob:   { gitlab: 6 },
        dave:  { heroku: 3 }
    };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 5,  'alice.github: local 5 > remote 2');
    assert(result.alice.twitter === 8, 'alice.twitter: remote 8 > local 3');
    assert(result.alice.reddit === 1,  'alice.reddit: preserved (not in remote)');
    assert(result.alice.slack === 1,   'alice.slack: added from remote');
    assert(result.bob.gitlab === 6,    'bob.gitlab: remote 6 > local 2');
    assert(result.bob.npm === 4,       'bob.npm: preserved (not in remote)');
    assert(result.carol.aws === 1,     'carol.aws: preserved (user not in remote)');
    assert(result.dave.heroku === 3,   'dave.heroku: new user from remote');
});

describe('Nonce zero handling', () => {
    assert(deepMergeUsers({ alice: { github: 0 } }, { alice: { github: 1 } }).alice.github === 1,
        'remote nonce 1 overwrites local nonce 0');

    assert(deepMergeUsers({ alice: { github: 1 } }, { alice: { github: 0 } }).alice.github === 1,
        'local nonce 1 kept over remote nonce 0');
});

describe('Does not mutate inputs', () => {
    const local  = { alice: { github: 5 } };
    const remote = { alice: { github: 9 } };
    const snap = JSON.stringify(local);
    deepMergeUsers(local, remote);

    assert(JSON.stringify(local) === snap, 'local input is not mutated');
});

describe('Partial backup does NOT wipe local (restoreFromId scenario)', () => {
    const local  = { alice: { github: 5, twitter: 3 }, bob: { npm: 2 } };
    const remote = { alice: { github: 1 } };
    const result = deepMergeUsers(local, remote);

    assert(result.alice.github === 5,  'alice.github: local 5 kept over remote 1');
    assert(result.alice.twitter === 3, 'alice.twitter: preserved');
    assert(result.bob.npm === 2,       'bob.npm: user preserved entirely');
});

// ─── Regression — old buggy behavior ────────────────────────────────────────

describe('Regression: shallow merge data loss', () => {
    const local  = { alice: { github: 5, twitter: 3 } };
    const remote = { alice: { github: 2 } };

    const shallow = shallowMergeUsers(local, remote);
    assert(shallow.alice.twitter === undefined, 'SHALLOW: twitter is LOST (the bug)');
    assert(shallow.alice.github === 2, 'SHALLOW: github nonce DOWNGRADED (the bug)');

    const deep = deepMergeUsers(local, remote);
    assert(deep.alice.twitter === 3, 'DEEP: twitter is preserved (the fix)');
    assert(deep.alice.github === 5, 'DEEP: github nonce stays at 5 (the fix)');
});

describe('Regression: full replacement data loss', () => {
    const local  = { alice: { github: 5, twitter: 3 }, bob: { npm: 2 } };
    const remote = { alice: { github: 1 } };

    const replaced = replacementMergeUsers(local, remote);
    assert(replaced.bob === undefined, 'REPLACE: bob is LOST entirely (the bug)');
    assert(replaced.alice.twitter === undefined, 'REPLACE: alice.twitter is LOST (the bug)');

    const deep = deepMergeUsers(local, remote);
    assert(deep.bob.npm === 2, 'DEEP: bob.npm is preserved (the fix)');
    assert(deep.alice.twitter === 3, 'DEEP: alice.twitter is preserved (the fix)');
});

// ─── Edge cases ─────────────────────────────────────────────────────────────

describe('Edge cases', () => {
    assertDeepEqual(deepMergeUsers({}, {}), {}, 'empty + empty = empty');

    const big = deepMergeUsers({ a: { s: 999999 } }, { a: { s: 1000000 } });
    assert(big.a.s === 1000000, 'handles large nonce values');
});

describe('Stress: 100 users x 50 sites', () => {
    const local = {}, remote = {};
    for (let i = 0; i < 100; i++) {
        local[`u${i}`] = {};
        remote[`u${i}`] = {};
        for (let j = 0; j < 50; j++) {
            local[`u${i}`][`s${j}`] = i + j;
            remote[`u${i}`][`s${j}`] = i + j + (j % 2 === 0 ? 1 : -1);
        }
    }
    const result = deepMergeUsers(local, remote);

    let ok = 0;
    for (let i = 0; i < 100; i++)
        for (let j = 0; j < 50; j++)
            if (result[`u${i}`][`s${j}`] === Math.max(local[`u${i}`][`s${j}`], remote[`u${i}`][`s${j}`]))
                ok++;

    assert(ok === 5000, `all 5000 sites merged correctly (got ${ok})`);
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log('\n' + '\u2500'.repeat(60));
if (failed === 0) {
    console.log(`\x1b[32m\x1b[1mAll ${passed} tests passed.\x1b[0m\n`);
    process.exit(0);
} else {
    console.log(`\x1b[31m\x1b[1m${failed} failed\x1b[0m, \x1b[32m${passed} passed\x1b[0m\n`);
    failures.forEach(f => console.log(`  \x1b[31m\u2717\x1b[0m ${f}`));
    console.log();
    process.exit(1);
}
