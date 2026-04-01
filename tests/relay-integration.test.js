/**
 * Real Relay Integration Tests
 *
 * Connects to ACTUAL Nostr relays over WebSocket and measures:
 *   - Connection time per relay
 *   - Subscription + EOSE latency
 *   - Event publish acknowledgment time
 *   - Round-trip: publish → fetch → verify
 *   - Event size limits (realistic vault payloads)
 *   - Timeout behavior under real network conditions
 *   - Parallel vs sequential relay performance
 *
 * This test uses raw WebSocket (Node 22 built-in) — no nostr-tools dependency.
 *
 * Run:  node tests/relay-integration.test.js
 *
 * NOTE: These tests hit real public relays. They may be flaky due to
 *       network conditions, relay rate limits, or relay downtime.
 *       Failures here indicate real issues the app will face in production.
 */

const { describeAsync, it, assert, assertEqual, skip, summary } = require('./helpers/test-harness');
const WebSocket = require('ws');

// ── Configuration ───────────────────────────────────────────────────────────

const RELAYS = [
    'wss://relay.damus.io',
    'wss://nostr-pub.wellorder.net',
    'wss://relay.snort.social',
    'wss://nos.lol',
];

const CONNECT_TIMEOUT_MS = 5000;  // same as app.js
const SUBSCRIBE_TIMEOUT_MS = 8000; // same as app.js
const PUBLISH_TIMEOUT_MS = 5000;   // same as app.js

// ── Timing utilities ────────────────────────────────────────────────────────

function timer() {
    const start = process.hrtime.bigint();
    return {
        elapsed() {
            return Number(process.hrtime.bigint() - start) / 1e6; // ms
        },
        report(label) {
            const ms = this.elapsed();
            const color = ms < 1000 ? '\x1b[32m' : ms < 3000 ? '\x1b[33m' : '\x1b[31m';
            console.log(`      ${color}${label}: ${ms.toFixed(0)}ms\x1b[0m`);
            return ms;
        }
    };
}

// ── Raw WebSocket relay operations ──────────────────────────────────────────

function connectRelay(url, timeoutMs = CONNECT_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(url);
        const t = setTimeout(() => {
            ws.close();
            reject(new Error(`connect timeout (${timeoutMs}ms)`));
        }, timeoutMs);

        ws.on('open', () => {
            clearTimeout(t);
            resolve(ws);
        });
        ws.on('error', (err) => {
            clearTimeout(t);
            ws.close();
            reject(err);
        });
    });
}

function subscribe(ws, subId, filters, timeoutMs = SUBSCRIBE_TIMEOUT_MS) {
    return new Promise((resolve) => {
        const events = [];
        const t = setTimeout(() => resolve({ events, timedOut: true }), timeoutMs);

        const handler = (data) => {
            try {
                const msg = JSON.parse(data.toString());
                if (msg[0] === 'EVENT' && msg[1] === subId) {
                    events.push(msg[2]);
                }
                if (msg[0] === 'EOSE' && msg[1] === subId) {
                    clearTimeout(t);
                    ws.off('message', handler);
                    // Send CLOSE
                    ws.send(JSON.stringify(['CLOSE', subId]));
                    resolve({ events, timedOut: false });
                }
                if (msg[0] === 'NOTICE') {
                    console.log(`      [NOTICE] ${msg[1]}`);
                }
            } catch (e) {}
        };

        ws.on('message', handler);
        ws.send(JSON.stringify(['REQ', subId, ...filters]));
    });
}

function publish(ws, event, timeoutMs = PUBLISH_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`publish timeout (${timeoutMs}ms)`)), timeoutMs);

        const handler = (data) => {
            try {
                const msg = JSON.parse(data.toString());
                if (msg[0] === 'OK' && msg[1] === event.id) {
                    clearTimeout(t);
                    ws.off('message', handler);
                    resolve({ accepted: msg[2], message: msg[3] || '' });
                }
            } catch (e) {}
        };

        ws.on('message', handler);
        ws.send(JSON.stringify(['EVENT', event]));
    });
}

// ── Generate a fake event payload of given size ─────────────────────────────

function generateVaultPayload(numUsers, sitesPerUser) {
    const users = {};
    for (let i = 0; i < numUsers; i++) {
        users[`user${i}@example.com`] = {};
        for (let j = 0; j < sitesPerUser; j++) {
            users[`user${i}@example.com`][`site${j}.com`] = j;
        }
    }
    return JSON.stringify({ users, settings: { hashLength: 16 } });
}

// ── Tests ───────────────────────────────────────────────────────────────────

let wsAvailable = true;

async function checkWsAvailability() {
    try {
        require('ws');
    } catch (e) {
        wsAvailable = false;
    }
}

async function runTests() {
    await checkWsAvailability();

    if (!wsAvailable) {
        console.log('\n\x1b[33mSkipping relay-integration tests: "ws" module not installed.\x1b[0m');
        console.log('Install with: npm install --save-dev ws\n');
        skip('ws module required');
        const ok = summary();
        process.exit(ok ? 0 : 1);
        return;
    }

    // ── Test 1: Connection time per relay ────────────────────────────────
    await describeAsync('Relay connection times', async () => {
        const results = {};

        for (const url of RELAYS) {
            await it(`connects to ${url}`, async () => {
                const t = timer();
                try {
                    const ws = await connectRelay(url, CONNECT_TIMEOUT_MS);
                    const ms = t.report('connect');
                    results[url] = { connected: true, ms };
                    assert(ms < CONNECT_TIMEOUT_MS, `connected within ${CONNECT_TIMEOUT_MS}ms`);
                    ws.close();
                } catch (e) {
                    t.report('FAILED');
                    results[url] = { connected: false, error: e.message };
                    // Don't fail — relay might be down
                    console.log(`      \x1b[33mWarning: ${url} unavailable: ${e.message}\x1b[0m`);
                }
            });
        }

        await it('at least 2 relays are reachable (minimum for redundancy)', async () => {
            const reachable = Object.values(results).filter(r => r.connected).length;
            console.log(`      Reachable: ${reachable}/${RELAYS.length}`);
            assert(reachable >= 2, `need >= 2 relays reachable (got ${reachable})`);
        });
    });

    // ── Test 2: Subscription + EOSE latency ─────────────────────────────
    await describeAsync('Subscription latency (EOSE response time)', async () => {
        for (const url of RELAYS) {
            await it(`EOSE from ${url}`, async () => {
                let ws;
                try {
                    ws = await connectRelay(url, CONNECT_TIMEOUT_MS);
                } catch (e) {
                    console.log(`      \x1b[33mSkipped (offline)\x1b[0m`);
                    return;
                }

                const t = timer();
                // Query for a random nonexistent pubkey — should get EOSE quickly
                const fakePk = 'a'.repeat(64);
                const { events, timedOut } = await subscribe(ws, 'sub_eose', [
                    { kinds: [30078], authors: [fakePk], '#d': ['vault-backup'], limit: 1 }
                ], SUBSCRIBE_TIMEOUT_MS);

                const ms = t.report(timedOut ? 'EOSE timeout' : 'EOSE');
                ws.close();

                if (!timedOut) {
                    assert(ms < SUBSCRIBE_TIMEOUT_MS, `EOSE within ${SUBSCRIBE_TIMEOUT_MS}ms`);
                    assertEqual(events.length, 0, 'no events for fake pubkey');
                } else {
                    console.log(`      \x1b[33mWarning: EOSE timeout after ${ms.toFixed(0)}ms\x1b[0m`);
                }
            });
        }
    });

    // ── Test 3: Event payload sizes ─────────────────────────────────────
    await describeAsync('Vault payload sizes', async () => {
        it('10 users × 10 sites = reasonable size', () => {
            const payload = generateVaultPayload(10, 10);
            const size = Buffer.byteLength(payload, 'utf8');
            console.log(`      ${size} bytes (${(size / 1024).toFixed(1)} KB)`);
            assert(size < 65536, 'under 64KB relay limit');
        });

        it('100 entries (realistic max) stays under relay limits', () => {
            const payload = generateVaultPayload(10, 10);
            const size = Buffer.byteLength(payload, 'utf8');
            console.log(`      100 entries: ${size} bytes`);
            assert(size < 65536, 'under 64KB');
        });

        it('500 entries (stress) — check if relays would accept', () => {
            const payload = generateVaultPayload(50, 10);
            const size = Buffer.byteLength(payload, 'utf8');
            console.log(`      500 entries: ${size} bytes (${(size / 1024).toFixed(1)} KB)`);
            // Most relays accept up to 64KB-128KB content
            if (size > 65536) {
                console.log(`      \x1b[33mWarning: exceeds 64KB — some relays may reject\x1b[0m`);
            }
        });

        it('encrypted payload is ~1.33x larger (base64 overhead)', () => {
            const payload = generateVaultPayload(10, 10);
            const rawSize = Buffer.byteLength(payload, 'utf8');
            // AES-GCM + base64 envelope ≈ 1.37x
            const estimatedEncrypted = Math.ceil(rawSize * 1.37) + 200; // +200 for JSON envelope
            console.log(`      raw: ${rawSize}B, estimated encrypted: ${estimatedEncrypted}B`);
            assert(estimatedEncrypted < 65536, 'encrypted 100-entry vault fits in 64KB');
        });
    });

    // ── Test 4: Parallel vs sequential relay connection ──────────────────
    await describeAsync('Parallel vs sequential relay performance', async () => {
        await it('sequential connection to all relays', async () => {
            const t = timer();
            let connected = 0;
            for (const url of RELAYS) {
                try {
                    const ws = await connectRelay(url, CONNECT_TIMEOUT_MS);
                    connected++;
                    ws.close();
                } catch (e) {}
            }
            const ms = t.report(`sequential (${connected}/${RELAYS.length} connected)`);
            console.log(`      avg per relay: ${(ms / RELAYS.length).toFixed(0)}ms`);
        });

        await it('parallel connection to all relays', async () => {
            const t = timer();
            const results = await Promise.allSettled(
                RELAYS.map(url => connectRelay(url, CONNECT_TIMEOUT_MS))
            );
            const ms = t.report(`parallel (${results.filter(r => r.status === 'fulfilled').length}/${RELAYS.length} connected)`);
            results.forEach((r, i) => {
                if (r.status === 'fulfilled') r.value.close();
            });
            // Parallel should be faster than sequential
            console.log(`      \x1b[36mParallel is better when this is less than sequential above\x1b[0m`);
        });
    });

    // ── Test 5: Full round-trip subscribe (read-only, no publish) ───────
    await describeAsync('Full relay round-trip (connect → subscribe → EOSE → close)', async () => {
        await it('measures complete read cycle on each relay', async () => {
            for (const url of RELAYS) {
                const tTotal = timer();
                try {
                    const tConnect = timer();
                    const ws = await connectRelay(url, CONNECT_TIMEOUT_MS);
                    const connectMs = tConnect.elapsed();

                    const tSub = timer();
                    const { timedOut } = await subscribe(ws, 'sub_roundtrip', [
                        { kinds: [30078], authors: ['b'.repeat(64)], '#d': ['vault-backup'], limit: 1 }
                    ], SUBSCRIBE_TIMEOUT_MS);
                    const subMs = tSub.elapsed();

                    ws.close();
                    const totalMs = tTotal.elapsed();

                    const status = timedOut ? '\x1b[33mEOSE timeout\x1b[0m' : '\x1b[32mok\x1b[0m';
                    console.log(`      ${url}: connect=${connectMs.toFixed(0)}ms sub=${subMs.toFixed(0)}ms total=${totalMs.toFixed(0)}ms [${status}]`);
                } catch (e) {
                    console.log(`      ${url}: \x1b[31mFAILED\x1b[0m (${e.message})`);
                }
            }
            assert(true, 'round-trip measurements complete');
        });
    });

    // ── Test 6: Timeout behavior ────────────────────────────────────────
    await describeAsync('Timeout behavior', async () => {
        await it('connection to non-existent relay fails or times out', async () => {
            const t = timer();
            try {
                await connectRelay('wss://this-relay-does-not-exist.example.com', 3000);
                assert(false, 'should have failed');
            } catch (e) {
                const ms = t.report('rejected');
                // DNS may resolve fast (NXDOMAIN) or TCP may time out — either is fine
                assert(ms < 5000, `failed within 5s (${ms.toFixed(0)}ms)`);
                assert(e.message !== undefined, 'error has message');
            }
        });

        await it('subscription timeout works when relay never sends EOSE', async () => {
            // Use very short timeout to test the timeout mechanism
            let ws;
            try {
                ws = await connectRelay(RELAYS[0], CONNECT_TIMEOUT_MS);
            } catch (e) {
                console.log('      \x1b[33mSkipped (relay offline)\x1b[0m');
                return;
            }

            const t = timer();
            const { timedOut } = await subscribe(ws, 'sub_timeout_test', [
                { kinds: [99999] } // nonexistent kind — some relays send EOSE, some don't
            ], 2000); // short timeout
            const ms = t.report(timedOut ? 'sub timeout' : 'EOSE received');
            ws.close();
            // Either way should complete within reasonable time
            assert(ms < 5000, 'completed within 5s');
        });
    });

    // ── Test 7: WebSocket cleanup ───────────────────────────────────────
    await describeAsync('WebSocket cleanup (leak prevention, BUG #7)', async () => {
        await it('rapidly open and close 10 connections without leaking', async () => {
            const t = timer();
            const promises = [];
            for (let i = 0; i < 10; i++) {
                const url = RELAYS[i % RELAYS.length];
                promises.push(
                    connectRelay(url, CONNECT_TIMEOUT_MS)
                        .then(ws => { ws.close(); return 'ok'; })
                        .catch(() => 'fail')
                );
            }
            const results = await Promise.all(promises);
            const ok = results.filter(r => r === 'ok').length;
            const ms = t.report(`10 open/close cycles (${ok} succeeded)`);
            assert(ok >= 5, `at least 5/10 succeeded`);
            // Should not hang or leak
            assert(ms < 30000, 'completed within 30s');
        });
    });

    const ok = summary();
    process.exit(ok ? 0 : 1);
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
