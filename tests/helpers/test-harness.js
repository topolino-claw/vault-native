/**
 * Minimal test harness — zero dependencies, colored terminal output.
 * Shared across all vault-native test files.
 *
 * Usage:
 *   const { describe, it, assert, assertDeepEqual, assertThrows, assertRejects, summary } = require('./helpers/test-harness');
 *   describe('group', () => { it('case', () => assert(true, 'works')); });
 *   summary();   // prints totals and exits with correct code
 */

let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];
let currentDescribe = '';

function describe(name, fn) {
    currentDescribe = name;
    console.log(`\n\x1b[1m${name}\x1b[0m`);
    const result = fn();
    // Support async describe callbacks
    if (result && typeof result.then === 'function') {
        return result;
    }
}

// Async-aware describe that collects and awaits all it() promises
async function describeAsync(name, fn) {
    currentDescribe = name;
    console.log(`\n\x1b[1m${name}\x1b[0m`);
    await fn();
}

function it(name, fn) {
    try {
        const result = fn();
        // Support async tests
        if (result && typeof result.then === 'function') {
            return result.then(() => {
                passed++;
                console.log(`  \x1b[32m\u2713\x1b[0m ${name}`);
            }).catch(err => {
                failed++;
                const msg = `${currentDescribe} > ${name}: ${err.message || err}`;
                failures.push(msg);
                console.log(`  \x1b[31m\u2717\x1b[0m ${name}`);
                console.log(`      ${err.message || err}`);
            });
        }
        passed++;
        console.log(`  \x1b[32m\u2713\x1b[0m ${name}`);
    } catch (err) {
        failed++;
        const msg = `${currentDescribe} > ${name}: ${err.message || err}`;
        failures.push(msg);
        console.log(`  \x1b[31m\u2717\x1b[0m ${name}`);
        console.log(`      ${err.message || err}`);
    }
}

function skip(name) {
    skipped++;
    console.log(`  \x1b[33m- ${name} (skipped)\x1b[0m`);
}

function assert(condition, message) {
    if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message}\n      expected: ${JSON.stringify(expected)}\n      actual:   ${JSON.stringify(actual)}`);
    }
}

function assertDeepEqual(actual, expected, message) {
    const a = JSON.stringify(actual, null, 0);
    const e = JSON.stringify(expected, null, 0);
    if (a !== e) {
        throw new Error(`${message}\n      expected: ${e}\n      actual:   ${a}`);
    }
}

function assertThrows(fn, messageMatch, label) {
    try {
        fn();
        throw new Error(`${label}: expected to throw but did not`);
    } catch (err) {
        if (messageMatch && !err.message.includes(messageMatch)) {
            throw new Error(`${label}: threw "${err.message}" but expected match for "${messageMatch}"`);
        }
    }
}

async function assertRejects(promise, messageMatch, label) {
    try {
        await promise;
        throw new Error(`${label}: expected rejection but resolved`);
    } catch (err) {
        if (err.message && err.message.includes('expected rejection but resolved')) throw err;
        if (messageMatch && !err.message.includes(messageMatch)) {
            throw new Error(`${label}: rejected with "${err.message}" but expected match for "${messageMatch}"`);
        }
    }
}

function summary() {
    console.log('\n' + '\u2500'.repeat(60));
    const parts = [];
    if (failed > 0) parts.push(`\x1b[31m\x1b[1m${failed} failed\x1b[0m`);
    parts.push(`\x1b[32m${passed} passed\x1b[0m`);
    if (skipped > 0) parts.push(`\x1b[33m${skipped} skipped\x1b[0m`);
    console.log(parts.join(', '));

    if (failures.length > 0) {
        console.log('\nFailures:');
        failures.forEach(f => console.log(`  \x1b[31m\u2717\x1b[0m ${f}`));
    }
    console.log();
    return failed === 0;
}

module.exports = { describe, describeAsync, it, skip, assert, assertEqual, assertDeepEqual, assertThrows, assertRejects, summary };
