#!/usr/bin/env node
/**
 * Run all vault-native test suites sequentially.
 * Exits with code 1 if any suite fails.
 *
 * Usage:  node tests/run-all.js
 *         npm test
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const TESTS_DIR = __dirname;
const suites = fs.readdirSync(TESTS_DIR)
    .filter(f => f.endsWith('.test.js'))
    .sort();

console.log(`\n\x1b[1m\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m`);
console.log(`\x1b[1m\x1b[36m║       Vault-Native Complete Test Suite                ║\x1b[0m`);
console.log(`\x1b[1m\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m`);
console.log(`\n  Found ${suites.length} test suites:\n`);
suites.forEach(s => console.log(`    • ${s}`));
console.log();

let totalPassed = 0;
let totalFailed = 0;
const results = [];

for (const suite of suites) {
    const suitePath = path.join(TESTS_DIR, suite);
    const label = suite.replace('.test.js', '');

    console.log(`\x1b[1m\x1b[34m┌─────────────────────────────────────────┐\x1b[0m`);
    console.log(`\x1b[1m\x1b[34m│  ${label.padEnd(38)} │\x1b[0m`);
    console.log(`\x1b[1m\x1b[34m└─────────────────────────────────────────┘\x1b[0m`);

    try {
        const output = execSync(`node "${suitePath}"`, {
            encoding: 'utf-8',
            timeout: 120000, // 2 min per suite
            stdio: 'pipe',
        });
        process.stdout.write(output);

        // Parse pass/fail from output
        const passMatch = output.match(/(\d+)\s+passed/);
        const failMatch = output.match(/(\d+)\s+failed/);
        const p = passMatch ? parseInt(passMatch[1]) : 0;
        const f = failMatch ? parseInt(failMatch[1]) : 0;
        totalPassed += p;
        totalFailed += f;
        results.push({ suite: label, passed: p, failed: f, error: null });
    } catch (err) {
        // Suite crashed or had failures
        if (err.stdout) process.stdout.write(err.stdout);
        if (err.stderr) process.stderr.write(err.stderr);

        const passMatch = (err.stdout || '').match(/(\d+)\s+passed/);
        const failMatch = (err.stdout || '').match(/(\d+)\s+failed/);
        const p = passMatch ? parseInt(passMatch[1]) : 0;
        const f = failMatch ? parseInt(failMatch[1]) : 1;
        totalPassed += p;
        totalFailed += f;
        results.push({ suite: label, passed: p, failed: f, error: err.message ? err.message.split('\n')[0] : 'unknown' });
    }
}

// ── Final summary ───────────────────────────────────────────────────────────

console.log(`\n\x1b[1m\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m`);
console.log(`\x1b[1m\x1b[36m║              Final Summary                            ║\x1b[0m`);
console.log(`\x1b[1m\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m\n`);

const maxLen = Math.max(...results.map(r => r.suite.length));
results.forEach(r => {
    const icon = r.failed === 0 && !r.error ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
    const stats = `${r.passed} passed` + (r.failed ? `, \x1b[31m${r.failed} failed\x1b[0m` : '');
    console.log(`  ${icon} ${r.suite.padEnd(maxLen + 2)} ${stats}`);
});

console.log(`\n  ${'─'.repeat(50)}`);
console.log(`  Total: \x1b[32m${totalPassed} passed\x1b[0m` +
    (totalFailed ? `, \x1b[31m${totalFailed} failed\x1b[0m` : '') +
    ` across ${suites.length} suites\n`);

process.exit(totalFailed > 0 ? 1 : 0);
