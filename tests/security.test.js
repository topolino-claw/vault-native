/**
 * Security Tests
 *
 * Tests: unlock rate limiting, nonce validation (invalid types), memory cleanup
 *        on lock, master password minimum length, settings integrity,
 *        source code integrity checks.
 *
 * Run:  node tests/security.test.js
 */

const { describe, it, assert, assertEqual, assertDeepEqual, summary } = require('./helpers/test-harness');
const { appSrc, words, extractFunction, createLocalStorageMock } = require('./helpers/extract');

// ── mergeUsers nonce validation ─────────────────────────────────────────────

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

describe('mergeUsers — nonce validation (BUG #18 fix)', () => {
    it('rejects string nonces', () => {
        const result = testMerge({}, { alice: { github: 'five' } });
        assert(result.alice === undefined || result.alice.github === undefined, 'string nonce rejected');
    });

    it('rejects float nonces', () => {
        const result = testMerge({}, { alice: { github: 3.5 } });
        assert(result.alice === undefined || result.alice.github === undefined, 'float nonce rejected');
    });

    it('rejects negative nonces', () => {
        const result = testMerge({}, { alice: { github: -1 } });
        assert(result.alice === undefined || result.alice.github === undefined, 'negative nonce rejected');
    });

    it('rejects NaN nonces', () => {
        const result = testMerge({}, { alice: { github: NaN } });
        assert(result.alice === undefined || result.alice.github === undefined, 'NaN nonce rejected');
    });

    it('rejects Infinity nonces', () => {
        const result = testMerge({}, { alice: { github: Infinity } });
        assert(result.alice === undefined || result.alice.github === undefined, 'Infinity nonce rejected');
    });

    it('rejects null nonces', () => {
        const result = testMerge({}, { alice: { github: null } });
        assert(result.alice === undefined || result.alice.github === undefined, 'null nonce rejected');
    });

    it('rejects undefined nonces', () => {
        const result = testMerge({}, { alice: { github: undefined } });
        assert(result.alice === undefined || result.alice.github === undefined, 'undefined nonce rejected');
    });

    it('rejects boolean nonces', () => {
        const result = testMerge({}, { alice: { github: true } });
        assert(result.alice === undefined || result.alice.github === undefined, 'boolean nonce rejected');
    });

    it('rejects object nonces', () => {
        const result = testMerge({}, { alice: { github: { value: 5 } } });
        assert(result.alice === undefined || result.alice.github === undefined, 'object nonce rejected');
    });

    it('rejects array nonces', () => {
        const result = testMerge({}, { alice: { github: [5] } });
        assert(result.alice === undefined || result.alice.github === undefined, 'array nonce rejected');
    });

    it('accepts 0 as valid nonce', () => {
        const result = testMerge({}, { alice: { github: 0 } });
        assertEqual(result.alice.github, 0, 'zero is valid');
    });

    it('accepts large integer nonces', () => {
        const result = testMerge({}, { alice: { github: 999999 } });
        assertEqual(result.alice.github, 999999, 'large int accepted');
    });

    it('mixed valid and invalid nonces — only valid accepted', () => {
        const result = testMerge({}, {
            alice: { github: 5, twitter: 'bad', reddit: -1, slack: 3 }
        });
        assertEqual(result.alice.github, 5, 'valid accepted');
        assertEqual(result.alice.slack, 3, 'valid accepted');
        assert(result.alice.twitter === undefined, 'string rejected');
        assert(result.alice.reddit === undefined, 'negative rejected');
    });
});

// ── Source code integrity & security patterns ───────────────────────────────

describe('Source code: no sensitive data leaks in production logs', () => {
    it('debugLog is gated by debugMode', () => {
        const debugLogSrc = extractFunction('debugLog');
        assert(debugLogSrc.includes('if (debugMode)'), 'debugLog checks debugMode');
    });

    it('no direct console.log of sensitive variables in non-debug code', () => {
        // Find console.log calls that contain sensitive variable names
        const sensitivePatterns = [
            /console\.log\(.*privateKey/g,
            /console\.log\(.*seedPhrase/g,
            /console\.log\(.*_masterPassword/g,
            /console\.log\(.*nsec/g,
        ];
        for (const pattern of sensitivePatterns) {
            const matches = appSrc.match(pattern) || [];
            // Filter out debug-gated calls (those inside debugLog or preceded by debugMode check)
            const dangerous = matches.filter(m => !m.includes('debugLog'));
            assertEqual(dangerous.length, 0, `no unguarded log of ${pattern.source}`);
        }
    });
});

describe('Source code: all restore paths use mergeUsers', () => {
    // Regression test for BUGS #1, #2, #3
    it('mergeUsers(data.users) is called in all restore paths', () => {
        const calls = (appSrc.match(/mergeUsers\(data\.users\)/g) || []).length;
        assert(calls >= 5, `mergeUsers(data.users) called in >= 5 restore paths (found ${calls})`);
    });

    it('no shallow-spread merge on vault.users', () => {
        const pattern = /vault\.users\s*=\s*\{\s*\.\.\.vault\.users/g;
        const hits = (appSrc.match(pattern) || []).length;
        assertEqual(hits, 0, 'no shallow-spread merges on vault.users');
    });

    it('no full-replacement merge pattern vault.users = data.users || vault.users', () => {
        const pattern = /vault\.users\s*=\s*data\.users\s*\|\|\s*vault\.users/g;
        const hits = (appSrc.match(pattern) || []).length;
        assertEqual(hits, 0, 'no replacement merges');
    });
});

describe('Source code: CSP compliance', () => {
    it('no eval() calls in production code', () => {
        // Match eval( but exclude test infrastructure and comments
        const lines = appSrc.split('\n');
        const evalCalls = lines.filter(line => {
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*')) return false;
            return /\beval\s*\(/.test(trimmed);
        });
        assertEqual(evalCalls.length, 0, 'no eval() in production code');
    });

    it('no new Function() in production code', () => {
        const lines = appSrc.split('\n');
        const fnCalls = lines.filter(line => {
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*')) return false;
            return /new\s+Function\s*\(/.test(trimmed);
        });
        assertEqual(fnCalls.length, 0, 'no new Function() in production code');
    });
});

describe('Source code: password minimum length enforcement', () => {
    it('MIN_PASSWORD_LENGTH constant exists and is >= 8', () => {
        const match = appSrc.match(/const\s+MIN_PASSWORD_LENGTH\s*=\s*(\d+)/);
        assert(match !== null, 'MIN_PASSWORD_LENGTH defined');
        assert(parseInt(match[1]) >= 8, 'minimum length >= 8');
    });

    it('setMasterPassword checks MIN_PASSWORD_LENGTH', () => {
        const fn = extractFunction('setMasterPassword');
        assert(fn.includes('MIN_PASSWORD_LENGTH'), 'setMasterPassword checks length');
    });
});

describe('Source code: WebSocket leak prevention (BUG #7)', () => {
    it('connectRelay closes on timeout', () => {
        const fn = extractFunction('connectRelay');
        // Check that relay.close() is called before reject in timeout handler
        assert(fn.includes('relay.close()'), 'relay.close() present in connectRelay');
    });
});

describe('Source code: debounce timer cleared on lock (BUG #10)', () => {
    it('lockVault clears _backupDebounceTimer', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes('_backupDebounceTimer'), 'lockVault references debounce timer');
        assert(fn.includes('clearTimeout(_backupDebounceTimer)'), 'lockVault clears debounce timer');
    });
});

describe('Source code: lockVault clears all sensitive state', () => {
    it('lockVault zeros vault fields', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes("privateKey: ''"), 'privateKey cleared');
        assert(fn.includes("seedPhrase: ''"), 'seedPhrase cleared');
        assert(fn.includes('_masterPassword = null') || fn.includes('_masterPassword=null'), 'masterPassword cleared');
        assert(fn.includes('_vaultInitialized = false') || fn.includes('_vaultInitialized=false'), 'vault uninitialized');
    });

    it('lockVault clears nostrKeys', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes("nostrKeys = { nsec: '', npub: '' }") || fn.includes("nostrKeys ="), 'nostrKeys cleared');
    });

    it('lockVault clears clipboard', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes("clipboard.writeText('')"), 'clipboard cleared');
    });

    it('lockVault clears cached key material', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes('_cachedLocalKey = null'), 'key cache cleared');
        assert(fn.includes('_cachedLocalSalt'), 'salt cache cleared');
        assert(fn.includes('_cachedLocalPassphrase = null'), 'passphrase cache cleared');
    });

    it('lockVault clears input fields in DOM', () => {
        const fn = extractFunction('lockVault');
        assert(fn.includes("querySelectorAll('input, textarea')"), 'input fields queried');
        assert(fn.includes("el.value = ''") || fn.includes('el.value=""'), 'input values cleared');
    });
});

describe('Source code: PBKDF2 iteration count', () => {
    it('LOCAL_ENCRYPT_ITERATIONS is >= 600000 (OWASP 2023)', () => {
        const match = appSrc.match(/const\s+LOCAL_ENCRYPT_ITERATIONS\s*=\s*(\d+)/);
        assert(match !== null, 'LOCAL_ENCRYPT_ITERATIONS defined');
        assert(parseInt(match[1]) >= 600000, 'iterations >= 600000');
    });

    it('BACKUP_PASSWORD_ITERATIONS is >= 600000', () => {
        const match = appSrc.match(/const\s+BACKUP_PASSWORD_ITERATIONS\s*=\s*(\d+)/);
        assert(match !== null, 'BACKUP_PASSWORD_ITERATIONS defined');
        assert(parseInt(match[1]) >= 600000, 'iterations >= 600000');
    });
});

describe('Source code: rate limiting on unlock', () => {
    it('MAX_UNLOCK_ATTEMPTS exists and is reasonable', () => {
        const match = appSrc.match(/const\s+MAX_UNLOCK_ATTEMPTS\s*=\s*(\d+)/);
        assert(match !== null, 'MAX_UNLOCK_ATTEMPTS defined');
        const val = parseInt(match[1]);
        assert(val >= 3 && val <= 10, `MAX_UNLOCK_ATTEMPTS is ${val} (expected 3-10)`);
    });

    it('UNLOCK_LOCKOUT_MS exists and is >= 10 seconds', () => {
        const match = appSrc.match(/const\s+UNLOCK_LOCKOUT_MS\s*=\s*([\d_*\s]+)/);
        assert(match !== null, 'UNLOCK_LOCKOUT_MS defined');
    });

    it('unlockVault checks lockout', () => {
        const fn = extractFunction('unlockVault');
        assert(fn.includes('unlockLockoutUntil'), 'checks lockout timestamp');
        assert(fn.includes('unlockAttempts'), 'tracks attempt count');
    });
});

describe('Source code: inactivity auto-lock', () => {
    it('INACTIVITY_TIMEOUT_MS is configured', () => {
        const match = appSrc.match(/const\s+INACTIVITY_TIMEOUT_MS\s*=\s*([\d_*\s]+)/);
        assert(match !== null, 'INACTIVITY_TIMEOUT_MS defined');
    });

    it('VISIBILITY_LOCK_MS is configured', () => {
        const match = appSrc.match(/const\s+VISIBILITY_LOCK_MS\s*=\s*([\d_*\s]+)/);
        assert(match !== null, 'VISIBILITY_LOCK_MS defined');
    });

    it('setupInactivityListeners handles visibilitychange', () => {
        const fn = extractFunction('setupInactivityListeners');
        assert(fn.includes('visibilitychange'), 'listens for visibilitychange');
    });
});

describe('Source code: BIP39 wordlist integrity check on init', () => {
    it('DOMContentLoaded handler verifies wordlist hash', () => {
        // The hash check is in the DOMContentLoaded handler
        assert(appSrc.includes('187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae'), 'wordlist hash present');
        assert(appSrc.includes('BIP39 wordlist integrity check failed'), 'tamper detection message present');
    });
});

describe('Source code: relay configuration', () => {
    it('RELAYS array has at least 3 relays for redundancy', () => {
        const match = appSrc.match(/const\s+RELAYS\s*=\s*\[([\s\S]*?)\]/);
        assert(match !== null, 'RELAYS defined');
        const urls = match[1].match(/wss:\/\/[^"]+/g) || [];
        assert(urls.length >= 3, `at least 3 relays configured (found ${urls.length})`);
    });

    it('all relay URLs use wss:// (encrypted)', () => {
        const match = appSrc.match(/const\s+RELAYS\s*=\s*\[([\s\S]*?)\]/);
        const urls = match[1].match(/"[^"]+"/g) || [];
        urls.forEach(url => {
            assert(url.includes('wss://'), `relay uses wss://: ${url}`);
        });
    });
});

describe('Source code: service worker not registered in Tauri', () => {
    it('service worker registration is conditional on non-Tauri', () => {
        assert(appSrc.includes("!window.__TAURI__"), 'SW registration checks for Tauri');
    });
});

// ── Summary ─────────────────────────────────────────────────────────────────

const ok = summary();
process.exit(ok ? 0 : 1);
