/**
 * Import / Export Tests
 *
 * Tests: JSON export format (downloadData), import merge behavior,
 *        invalid import handling, merge-on-import uses mergeUsers.
 *
 * Run:  node tests/import-export.test.js
 */

const { describe, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction } = require('./helpers/extract');

// ── Build module for import/export logic ────────────────────────────────────

const mergeUsersSrc = extractFunction('mergeUsers');

function testMerge(local, remote) {
    const vault = { users: structuredClone(local) };
    const run = new Function('vault', 'remoteUsers', `
        ${mergeUsersSrc}
        mergeUsers(remoteUsers);
        return vault.users;
    `);
    return run(vault, remote);
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe('Export format (downloadData)', () => {
    it('source exports only users and settings (no secrets)', () => {
        const fn = extractFunction('downloadData');
        // Should contain { users: vault.users, settings: vault.settings }
        assert(fn.includes('vault.users'), 'includes users');
        assert(fn.includes('vault.settings'), 'includes settings');
        // Should NOT include privateKey or seedPhrase
        assert(!fn.includes('vault.privateKey'), 'no privateKey in export');
        assert(!fn.includes('vault.seedPhrase'), 'no seedPhrase in export');
    });

    it('export filename is vault-export.json', () => {
        const fn = extractFunction('downloadData');
        assert(fn.includes('vault-export.json'), 'correct filename');
    });
});

describe('Import merge — triggerImport uses mergeUsers', () => {
    it('source code calls mergeUsers(data.users) in import path', () => {
        const fn = extractFunction('triggerImport');
        assert(fn.includes('mergeUsers(data.users)'), 'uses mergeUsers for import');
    });

    it('source validates data.users is an object', () => {
        const fn = extractFunction('triggerImport');
        assert(fn.includes("typeof data.users !== 'object'") || fn.includes("!data.users"), 'validates users field');
    });
});

describe('Import merge behavior (via mergeUsers)', () => {
    it('import adds new users without touching existing', () => {
        const local = { alice: { github: 5 } };
        const imported = { bob: { gitlab: 3 } };
        const result = testMerge(local, imported);
        assertEqual(result.alice.github, 5, 'alice preserved');
        assertEqual(result.bob.gitlab, 3, 'bob added');
    });

    it('import adds new sites to existing users', () => {
        const local = { alice: { github: 5 } };
        const imported = { alice: { twitter: 3 } };
        const result = testMerge(local, imported);
        assertEqual(result.alice.github, 5, 'github preserved');
        assertEqual(result.alice.twitter, 3, 'twitter added');
    });

    it('import takes higher nonce', () => {
        const local = { alice: { github: 5 } };
        const imported = { alice: { github: 8 } };
        const result = testMerge(local, imported);
        assertEqual(result.alice.github, 8, 'higher nonce from import');
    });

    it('import does not downgrade nonces', () => {
        const local = { alice: { github: 8 } };
        const imported = { alice: { github: 3 } };
        const result = testMerge(local, imported);
        assertEqual(result.alice.github, 8, 'local nonce preserved');
    });

    it('large import (100 users) merges correctly', () => {
        const local = {};
        const imported = {};
        for (let i = 0; i < 100; i++) {
            local[`user${i}`] = { [`site${i}`]: i };
            imported[`user${i}`] = { [`site${i}`]: i + 1, newsite: 1 };
        }
        const result = testMerge(local, imported);
        for (let i = 0; i < 100; i++) {
            assertEqual(result[`user${i}`][`site${i}`], i + 1, `user${i}: import wins`);
            assertEqual(result[`user${i}`].newsite, 1, `user${i}: new site added`);
        }
    });
});

describe('Import with invalid data — robustness', () => {
    it('null import does not crash', () => {
        const local = { alice: { github: 5 } };
        const result = testMerge(local, null);
        assertEqual(result.alice.github, 5, 'local preserved on null import');
    });

    it('undefined import does not crash', () => {
        const local = { alice: { github: 5 } };
        const result = testMerge(local, undefined);
        assertEqual(result.alice.github, 5, 'local preserved on undefined import');
    });

    it('empty object import does not crash', () => {
        const local = { alice: { github: 5 } };
        const result = testMerge(local, {});
        assertEqual(result.alice.github, 5, 'local preserved on empty import');
    });

    it('import with invalid nonce types is filtered', () => {
        const local = {};
        const imported = {
            alice: {
                valid: 5,
                str: 'bad',
                float: 3.14,
                neg: -1,
                nil: null,
                arr: [1, 2, 3],
                obj: { nested: true }
            }
        };
        const result = testMerge(local, imported);
        assertEqual(result.alice.valid, 5, 'valid nonce accepted');
        assert(result.alice.str === undefined, 'string rejected');
        assert(result.alice.float === undefined, 'float rejected');
        assert(result.alice.neg === undefined, 'negative rejected');
        assert(result.alice.nil === undefined, 'null rejected');
        assert(result.alice.arr === undefined, 'array rejected');
        assert(result.alice.obj === undefined, 'object rejected');
    });

    it('import with mixed valid users and invalid nonces', () => {
        const local = { alice: { github: 3 } };
        const imported = {
            alice: { github: 'not-a-number', twitter: 5 },
            bob: { gitlab: -1, npm: 7 }
        };
        const result = testMerge(local, imported);
        assertEqual(result.alice.github, 3, 'invalid import nonce ignored, local preserved');
        assertEqual(result.alice.twitter, 5, 'valid import nonce accepted');
        assert(result.bob.gitlab === undefined, 'negative nonce rejected');
        assertEqual(result.bob.npm, 7, 'valid nonce accepted');
    });
});

describe('Import idempotency', () => {
    it('importing same data twice produces same result', () => {
        const local = { alice: { github: 5 } };
        const imported = { alice: { github: 8 }, bob: { npm: 3 } };
        const result1 = testMerge(local, imported);
        const result2 = testMerge(result1, imported);
        assertDeepEqual(result1, result2, 'idempotent merge');
    });

    it('sequential imports accumulate correctly', () => {
        let users = {};
        users = testMerge(users, { alice: { github: 1 } });
        users = testMerge(users, { alice: { github: 3 } });
        users = testMerge(users, { alice: { github: 2 } }); // lower — ignored
        users = testMerge(users, { bob: { npm: 1 } });
        assertEqual(users.alice.github, 3, 'alice.github at highest (3)');
        assertEqual(users.bob.npm, 1, 'bob.npm accumulated');
    });
});

describe('Settings merge on import', () => {
    it('source code merges settings with spread (imported settings do not overwrite all)', () => {
        const fn = extractFunction('triggerImport');
        assert(fn.includes('...vault.settings') || fn.includes('vault.settings,'), 'settings merged, not replaced');
    });
});

// ── Summary ─────────────────────────────────────────────────────────────────

const ok = summary();
process.exit(ok ? 0 : 1);
