/**
 * Hybrid Logical Clock — the ordering primitive for multi-device merges.
 *
 * Every mutation carries a stamp. Stamps must give a *total* order that is
 * consistent across devices even when their wall clocks disagree, because the
 * merge rule for most fields is last-write-wins and "last" has to mean
 * something both devices compute identically.
 *
 * A plain wall clock fails: two devices whose clocks differ by a minute
 * silently discard each other's edits. A plain Lamport counter fails
 * differently: it orders correctly but drifts arbitrarily far from real time,
 * so "newest" stops matching what the user did most recently. An HLC keeps the
 * physical time (so it stays human-meaningful and self-corrects) and adds a
 * counter that breaks ties and preserves causality when the physical clock is
 * stalled or running backwards.
 *
 * Stamps encode to a fixed-width string:
 *
 *     <ms:12 hex>.<counter:4 hex>.<deviceId:12 hex>
 *
 * Fixed width is the point — plain lexicographic `<` on the string is the
 * causal order, so merge code never has to parse a stamp, and the device id
 * tiebreak makes the order total (two devices can never produce equal stamps).
 * 12 hex ms covers year 10889; 4 hex allows 65536 events per millisecond.
 */
(function (root) {
    'use strict';

    const MS_DIGITS = 12;
    const CTR_DIGITS = 4;
    const DEV_DIGITS = 12;
    const MAX_CTR = 0xffff;

    function encode(ms, ctr, dev) {
        return (
            ms.toString(16).padStart(MS_DIGITS, '0') +
            '.' +
            ctr.toString(16).padStart(CTR_DIGITS, '0') +
            '.' +
            String(dev).padStart(DEV_DIGITS, '0').slice(0, DEV_DIGITS)
        );
    }

    function decode(stamp) {
        const [ms, ctr, dev] = String(stamp).split('.');
        return { ms: parseInt(ms, 16), ctr: parseInt(ctr, 16), dev };
    }

    /** Structural check — a malformed stamp from a corrupt log must not sort. */
    function isStamp(value) {
        return typeof value === 'string' && /^[0-9a-f]{12}\.[0-9a-f]{4}\.[0-9a-f]{12}$/.test(value);
    }

    /** Device ids are exactly 12 lowercase hex characters. */
    function isDeviceId(value) {
        return typeof value === 'string' && /^[0-9a-f]{12}$/.test(value);
    }

    /**
     * @param {string} deviceId - 12 hex chars identifying this device.
     * @param {() => number} [now] - Physical clock in ms. Injectable so tests
     *   can run deterministically and simulate skew.
     */
    function createClock(deviceId, now) {
        // Rejected loudly rather than padded or truncated. A device id that is
        // not 12 hex characters produces stamps that fail isStamp(), which
        // makes every operation this device creates silently invalid — the
        // vault appears to work and saves nothing. Found by the Monte Carlo
        // suite; it must stay a hard error.
        if (!isDeviceId(deviceId)) {
            throw new Error('Device id must be 12 lowercase hex characters, got: ' + deviceId);
        }
        const physical = now || (() => Date.now());
        let ms = 0;
        let ctr = 0;

        /** Stamp a local mutation. */
        function tick() {
            const pt = physical();
            if (pt > ms) {
                ms = pt;
                ctr = 0;
            } else {
                // Physical clock stalled or went backwards; keep causality via
                // the counter rather than emitting a stamp that sorts wrongly.
                ctr++;
                if (ctr > MAX_CTR) {
                    ms++;
                    ctr = 0;
                }
            }
            return encode(ms, ctr, deviceId);
        }

        /**
         * Fold a stamp observed from another device into this clock, so any
         * mutation we make afterwards sorts strictly after what we have seen.
         * Malformed stamps are ignored (isStamp guard); a well-formed remote
         * stamp advances this clock, bounded by the fixed 12-hex-digit
         * millisecond field the encoding allows.
         */
        function observe(stamp) {
            if (!isStamp(stamp)) return;
            const remote = decode(stamp);
            const pt = physical();
            const merged = Math.max(ms, remote.ms, pt);
            if (merged === ms && merged === remote.ms) ctr = Math.max(ctr, remote.ctr) + 1;
            else if (merged === ms) ctr = ctr + 1;
            else if (merged === remote.ms) ctr = remote.ctr + 1;
            else ctr = 0;
            ms = merged;
            if (ctr > MAX_CTR) {
                ms++;
                ctr = 0;
            }
        }

        return { tick, observe, deviceId, peek: () => encode(ms, ctr, deviceId) };
    }

    root.VaultHLC = {
        createClock,
        encode,
        decode,
        isStamp,
        isDeviceId,
        MS_DIGITS,
        CTR_DIGITS,
        DEV_DIGITS
    };
})(typeof window !== 'undefined' ? window : globalThis);
