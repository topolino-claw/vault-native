/**
 * The per-device append-only operation log.
 *
 * This is the piece that removes Syncthing conflicts rather than resolving
 * them. A device writes to exactly one file — its own — and never touches any
 * other device's log. Two devices therefore cannot produce a conflicting write
 * to the same file, so `.sync-conflict-*` files stop being generated for the
 * data path at all. Merging is just reading everyone's log and replaying the
 * union, which the CRDT rules in records.js make order-independent.
 *
 * Format — JSON Lines, one operation per line:
 *
 *   {"tvlog":1,"dev":"<deviceId>"}            <- plaintext header, line 1
 *   {"iv":"<b64>","p":"<b64 AES-256-GCM>"}    <- one encrypted operation
 *   ...
 *
 * Line-per-operation is a durability decision, not a stylistic one. Appending
 * never rewrites existing bytes, so a crash or a torn write can only damage
 * the final line — and because each line is independently parsed and
 * independently authenticated, a damaged line is *skipped* and everything
 * before it survives. Contrast the single-blob file this replaces, where one
 * bad byte costs the entire vault.
 *
 * Each entry is encrypted under the vault master key with the log's device id
 * as GCM additional authenticated data, which binds an entry to the log it
 * lives in: entries cannot be spliced from one device's log into another's,
 * even by someone holding the key.
 */
(function (root) {
    'use strict';

    const util = root.VaultUtil;
    const subtle = (root.crypto || crypto).subtle;

    const LOG_VERSION = 1;
    const IV_BYTES = 12;

    function encodeHeader(deviceId) {
        return JSON.stringify({ tvlog: LOG_VERSION, dev: deviceId });
    }

    function parseHeader(line) {
        try {
            const parsed = JSON.parse(line);
            if (parsed && parsed.tvlog === LOG_VERSION && typeof parsed.dev === 'string') {
                return parsed;
            }
        } catch (e) {
            /* fall through */
        }
        return null;
    }

    function aad(deviceId) {
        return new TextEncoder().encode('tvlog:' + deviceId);
    }

    /** Encrypt one operation into a single log line (no trailing newline). */
    async function encodeEntry(op, key, deviceId) {
        const iv = new Uint8Array(IV_BYTES);
        (root.crypto || crypto).getRandomValues(iv);
        const plaintext = new TextEncoder().encode(JSON.stringify(op));
        const ciphertext = await subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: aad(deviceId) },
            key,
            plaintext
        );
        return JSON.stringify({
            iv: util.bytesToB64(iv),
            p: util.bytesToB64(new Uint8Array(ciphertext))
        });
    }

    async function decodeEntry(line, key, deviceId) {
        const parsed = JSON.parse(line);
        if (!parsed || typeof parsed.iv !== 'string' || typeof parsed.p !== 'string') {
            throw new Error('not a log entry');
        }
        const plaintext = await subtle.decrypt(
            { name: 'AES-GCM', iv: util.b64ToBytes(parsed.iv), additionalData: aad(deviceId) },
            key,
            util.b64ToBytes(parsed.p)
        );
        return JSON.parse(new TextDecoder().decode(plaintext));
    }

    /**
     * Parse a whole log. Damaged or unauthenticated lines are skipped rather
     * than fatal — a partially-synced or torn log must still yield every
     * operation that landed intact.
     *
     * @returns {Promise<{deviceId: string|null, ops: object[], skipped: number, total: number}>}
     */
    async function parseLog(text, key) {
        const result = { deviceId: null, ops: [], skipped: 0, total: 0 };
        if (typeof text !== 'string' || text.length === 0) return result;

        const lines = text.split('\n');
        let start = 0;
        const header = parseHeader(lines[0]);
        if (header) {
            result.deviceId = header.dev;
            start = 1;
        } else {
            // No readable header: the log is unusable because entries are
            // authenticated against the device id. Report it as fully skipped
            // instead of silently returning nothing.
            result.skipped = lines.filter((l) => l.trim().length > 0).length;
            result.total = result.skipped;
            return result;
        }

        for (let i = start; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            result.total++;
            try {
                const op = await decodeEntry(line, key, result.deviceId);
                result.ops.push(op);
            } catch (e) {
                result.skipped++;
            }
        }
        return result;
    }

    /** Cheap structural check that does not need the key. */
    function looksLikeLog(text) {
        if (typeof text !== 'string') return false;
        return parseHeader(text.split('\n', 1)[0]) !== null;
    }

    /** Serialize a fresh log (header + entries) for a full rewrite/compaction. */
    async function encodeLog(ops, key, deviceId) {
        const lines = [encodeHeader(deviceId)];
        for (const op of ops) lines.push(await encodeEntry(op, key, deviceId));
        return lines.join('\n') + '\n';
    }

    root.VaultOplog = {
        LOG_VERSION,
        encodeHeader,
        parseHeader,
        encodeEntry,
        decodeEntry,
        parseLog,
        encodeLog,
        looksLikeLog
    };
})(typeof window !== 'undefined' ? window : globalThis);
