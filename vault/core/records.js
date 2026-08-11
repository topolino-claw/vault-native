/**
 * The vault record model and its merge rules.
 *
 * Everything the vault knows is a record, and every change is an operation
 * stamped with an HLC. Merging two devices means replaying both sets of
 * operations into the same state; the rules below are chosen so that replay is
 * commutative, associative and idempotent (a join-semilattice / state-based
 * CRDT). That is what lets two devices sync in any order, twice, or partially,
 * and still land on byte-identical state — which is the property the Monte
 * Carlo suite in test/montecarlo.test.mjs actually asserts.
 *
 * Merge rules, per field:
 *   - `nonce`  — grow-only maximum. Never decreases, whatever the stamps say.
 *                This is the one invariant that must not be expressible as
 *                last-write-wins: a nonce going backwards silently re-issues a
 *                password the user already rotated away from (ROADMAP.md §3).
 *   - everything else — last-write-wins on the HLC stamp.
 *   - `deleted` — an ordinary LWW boolean, so a later edit can revive a record
 *                and deletion cannot resurrect stale field values.
 *
 * Record types: identity (singleton), settings (singleton), credential, note,
 * totp, custom. Credentials get a *deterministic* id derived from user+site so
 * that two devices creating the same credential offline converge onto one
 * record instead of duplicating it.
 */
(function (root) {
    'use strict';

    const util = root.VaultUtil;
    const HLC = root.VaultHLC;

    const TYPES = {
        IDENTITY: 'identity',
        SETTINGS: 'settings',
        CREDENTIAL: 'credential',
        NOTE: 'note',
        TOTP: 'totp',
        CUSTOM: 'custom'
    };

    const IDENTITY_ID = 'identity';
    const SETTINGS_ID = 'settings';

    /** Fields merged by maximum rather than by stamp. */
    const GROW_ONLY_FIELDS = new Set(['nonce']);

    /**
     * Keys that must never be written into a record. Operations arrive from
     * decrypted logs, so they are authenticated — but a corrupt log, or a
     * record id crafted before this guard existed, must not be able to reach
     * Object.prototype. Records use null-prototype objects as well; this is
     * the belt to that suspenders.
     */
    const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

    function safeKey(key) {
        return typeof key === 'string' && key.length > 0 && !FORBIDDEN_KEYS.has(key);
    }

    /** Deterministic id so concurrent creates of the same site converge. */
    function credentialId(user, site) {
        return 'c:' + util.textToB64Url(String(user)) + ':' + util.textToB64Url(String(site));
    }

    function parseCredentialId(id) {
        const parts = String(id).split(':');
        if (parts.length !== 3 || parts[0] !== 'c') return null;
        try {
            return { user: util.b64UrlToText(parts[1]), site: util.b64UrlToText(parts[2]) };
        } catch (e) {
            return null;
        }
    }

    function emptyState() {
        return new Map();
    }

    function newRecord(id, type) {
        return {
            id,
            type: type || TYPES.CUSTOM,
            values: Object.create(null),
            stamps: Object.create(null)
        };
    }

    /** Build a stamped operation. `set` is a plain {field: value} patch. */
    function makeOp(clock, id, type, set) {
        return { id, type, set: util.clone(set) || {}, t: clock.tick() };
    }

    function isValidOp(op) {
        return (
            op !== null &&
            typeof op === 'object' &&
            typeof op.id === 'string' &&
            op.id.length > 0 &&
            !FORBIDDEN_KEYS.has(op.id) &&
            HLC.isStamp(op.t) &&
            op.set !== null &&
            typeof op.set === 'object'
        );
    }

    /**
     * Apply one operation. Returns true if it changed the state.
     * Safe to call with the same op any number of times, in any order.
     */
    function applyOp(state, op) {
        if (!isValidOp(op)) return false;

        let rec = state.get(op.id);
        if (!rec) {
            rec = newRecord(op.id, op.type);
            state.set(op.id, rec);
        } else if (op.type && rec.type === TYPES.CUSTOM && op.type !== TYPES.CUSTOM) {
            rec.type = op.type;
        }

        let changed = false;
        for (const key of Object.keys(op.set)) {
            if (!safeKey(key)) continue;
            const value = op.set[key];

            if (GROW_ONLY_FIELDS.has(key)) {
                // Maximum wins outright; the stamp only records provenance.
                if (typeof value !== 'number' || !Number.isFinite(value)) continue;
                const current = rec.values[key];
                if (current === undefined || value > current) {
                    rec.values[key] = value;
                    rec.stamps[key] = op.t;
                    changed = true;
                }
                continue;
            }

            const currentStamp = rec.stamps[key];
            // Fixed-width stamps make string compare the causal order, and the
            // device id inside makes it total — so this is never a coin flip.
            if (currentStamp === undefined || op.t > currentStamp) {
                rec.values[key] = util.clone(value);
                rec.stamps[key] = op.t;
                changed = true;
            }
        }
        return changed;
    }

    function applyOps(state, ops) {
        let changed = 0;
        for (const op of ops || []) if (applyOp(state, op)) changed++;
        return changed;
    }

    /** Materialize a record into a plain object, or null if absent/deleted. */
    function getRecord(state, id, includeDeleted) {
        const rec = state.get(id);
        if (!rec) return null;
        if (rec.values.deleted === true && !includeDeleted) return null;
        return Object.assign({ id: rec.id, type: rec.type }, util.clone(rec.values));
    }

    function listRecords(state, type) {
        const out = [];
        for (const id of state.keys()) {
            const rec = getRecord(state, id);
            if (!rec) continue;
            if (type && rec.type !== type) continue;
            out.push(rec);
        }
        // Sorted by id so every device serializes identically — byte-identical
        // snapshots across devices are what makes convergence checkable.
        out.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
        return out;
    }

    // ---------- bridge to the v2 snapshot payload (Obsidian plugin compat) ----------

    /**
     * Project state into the flat shape the shared vault file has always used.
     * `users` stays exactly as the plugin expects; everything the plugin does
     * not model rides along under `records`.
     */
    function toSnapshotPayload(state) {
        const identity = getRecord(state, IDENTITY_ID) || {};
        const settings = getRecord(state, SETTINGS_ID) || {};
        const users = {};

        for (const rec of listRecords(state, TYPES.CREDENTIAL)) {
            const parsed = parseCredentialId(rec.id);
            const user = rec.user !== undefined ? rec.user : parsed && parsed.user;
            const site = rec.site !== undefined ? rec.site : parsed && parsed.site;
            if (user === null || user === undefined || site === null || site === undefined) continue;
            if (!safeKey(String(user)) || !safeKey(String(site))) continue;
            if (!users[user]) users[user] = {};
            users[user][site] = typeof rec.nonce === 'number' ? rec.nonce : 0;
        }

        // `records` carries everything `users` cannot express. Identity and
        // settings have their own top-level keys; a credential holding nothing
        // but user/site/nonce is already fully described by `users`, so it is
        // omitted to keep the snapshot from storing every credential twice.
        // A credential with any extra field (a label, a note, a TOTP link) is
        // included, because dropping it would lose data.
        const PLAIN_CREDENTIAL_FIELDS = new Set(['id', 'type', 'user', 'site', 'nonce']);
        const extra = listRecords(state).filter((r) => {
            if (r.type === TYPES.IDENTITY || r.type === TYPES.SETTINGS) return false;
            if (r.type !== TYPES.CREDENTIAL) return true;
            return Object.keys(r).some((k) => !PLAIN_CREDENTIAL_FIELDS.has(k));
        });

        return {
            privateKey: identity.privateKey || '',
            seedPhrase: identity.seedPhrase || '',
            passphrase: identity.passphrase || '',
            users,
            settings: {
                hashLength: typeof settings.hashLength === 'number' ? settings.hashLength : 16
            },
            records: extra
        };
    }

    /**
     * Absorb a snapshot written by something that does not speak operations —
     * the Obsidian plugin, or an older build of this app.
     *
     * Only emits operations for information the log does not already have or
     * that is strictly newer, so a foreign snapshot cannot start a write war
     * (each device would otherwise re-stamp the other's state forever) and
     * cannot walk a nonce backwards.
     */
    function opsFromSnapshotPayload(payload, clock, state) {
        const ops = [];
        if (!payload || typeof payload !== 'object') return ops;

        const identity = getRecord(state, IDENTITY_ID);
        if (payload.privateKey && (!identity || !identity.privateKey)) {
            ops.push(
                makeOp(clock, IDENTITY_ID, TYPES.IDENTITY, {
                    privateKey: payload.privateKey,
                    seedPhrase: payload.seedPhrase || '',
                    passphrase: payload.passphrase || ''
                })
            );
        }

        const settings = getRecord(state, SETTINGS_ID);
        if (payload.settings && !settings) {
            ops.push(makeOp(clock, SETTINGS_ID, TYPES.SETTINGS, {
                hashLength: payload.settings.hashLength || 16
            }));
        }

        for (const user of Object.keys(payload.users || {})) {
            if (!safeKey(user)) continue;
            const sites = payload.users[user] || {};
            for (const site of Object.keys(sites)) {
                if (!safeKey(site)) continue;
                const nonce = sites[site];
                if (typeof nonce !== 'number' || !Number.isFinite(nonce)) continue;
                const id = credentialId(user, site);
                const existing = getRecord(state, id, true);
                const known = existing && typeof existing.nonce === 'number' ? existing.nonce : -1;
                if (nonce > known) {
                    ops.push(makeOp(clock, id, TYPES.CREDENTIAL, { user, site, nonce }));
                }
            }
        }

        // Records the plugin preserved but does not understand.
        for (const rec of payload.records || []) {
            if (!rec || typeof rec !== 'object' || typeof rec.id !== 'string') continue;
            if (state.has(rec.id)) continue;
            const set = Object.assign({}, rec);
            delete set.id;
            delete set.type;
            ops.push(makeOp(clock, rec.id, rec.type, set));
        }

        return ops;
    }

    root.VaultRecords = {
        TYPES,
        IDENTITY_ID,
        SETTINGS_ID,
        GROW_ONLY_FIELDS,
        credentialId,
        parseCredentialId,
        emptyState,
        makeOp,
        isValidOp,
        applyOp,
        applyOps,
        getRecord,
        listRecords,
        toSnapshotPayload,
        opsFromSnapshotPayload
    };
})(typeof window !== 'undefined' ? window : globalThis);
