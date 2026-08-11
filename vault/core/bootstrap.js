/**
 * Opening a vault, including the one-shot upgrade from the old layout.
 *
 * This is the seam between the UI and the store. It exists so app.js never
 * has to know whether an install is new, already migrated, or still carrying
 * the pre-keyslot layout — and so the whole path can be tested headlessly
 * (test/migrate.test.mjs) instead of only by clicking through the app.
 *
 * MIGRATION SAFETY
 * The rule throughout is: write the replacement, verify it by reading it back
 * through a fresh store, and only then drop the legacy artifacts. A migration
 * that loses a vault would be worse than any bug it fixes, so every failure
 * path leaves the old data exactly where it was. Re-running is harmless.
 */
(function (root) {
    'use strict';

    const util = root.VaultUtil;
    const envelope = root.VaultEnvelope;
    const Store = root.VaultStore;
    const R = root.VaultRecords;
    const legacy = root.VaultMigrateLegacy;

    const DEVICE_ID_KEY = 'tvDeviceId';

    /** Stable per-device id. Generated once, then never changes. */
    function deviceIdFor(storage) {
        let id = storage.getItem(DEVICE_ID_KEY);
        if (!root.VaultHLC.isDeviceId(id)) {
            id = util.randomHex(6);
            storage.setItem(DEVICE_ID_KEY, id);
        }
        return id;
    }

    async function hasExistingVault(transport) {
        if (await transport.read(Store.KEYS_FILE)) return 'keys';
        if (await transport.read(Store.SNAPSHOT_FILE)) return 'snapshot';
        const names = await transport.list();
        return names.some(Store.isLogName) ? 'logs' : null;
    }

    /**
     * Open (or create) the vault.
     *
     * @param {object} options
     * @param {object} options.transport
     * @param {string} options.password
     * @param {Storage} options.storage - localStorage or equivalent.
     * @param {boolean} [options.create] - allow creating a brand-new vault.
     * @param {number} [options.iterations] - tests only.
     * @param {() => number} [options.now] - tests only.
     * @returns {Promise<{store: object, migration: object|null, created: boolean}>}
     */
    async function open(options) {
        const { transport, password, storage } = options;
        const deviceId = options.deviceId || deviceIdFor(storage);
        const existing = await hasExistingVault(transport);
        const legacyLocal = legacy.readLegacyLocal(storage);
        const hasLegacyLocal = Object.keys(legacyLocal).length > 0;

        const storeOptions = {
            transport,
            password,
            deviceId,
            iterations: options.iterations,
            now: options.now
        };

        // A folder holding only an old-format vault file has no keyslots yet.
        // Creating them here is what upgrades it; the store absorbs the old
        // snapshot on the way (v1 and v2 both decrypt), so no data moves by
        // hand.
        //
        // But creating keyslots is only safe once the password is PROVEN
        // against the data already there. Without that check a mistyped
        // password minted a fresh empty vault, adopted the wrong password as
        // the vault's password, and locked the real one out — and the empty
        // state was then written over the user's file. Verify first; a vault
        // that exists must never be replaced by one that does not.
        const mayCreate = Boolean(options.create) || existing === 'snapshot' || hasLegacyLocal;
        if (mayCreate && (existing === 'snapshot' || hasLegacyLocal)) {
            await assertPasswordMatchesExisting(transport, password, legacyLocal, existing);
        }

        const store = await Store.open(Object.assign({}, storeOptions, { create: mayCreate }));
        const created = existing === null && !hasLegacyLocal;

        let migration = null;
        if (legacy.needsMigration(storage)) {
            migration = await migrateLegacyLocal(store, storeOptions, storage, password, legacyLocal);
        }

        return { store, migration, created };
    }

    /**
     * Refuse to adopt a password that cannot open what is already stored.
     *
     * Throws 'Wrong password' — the same message an ordinary failed unlock
     * gives, so the two are indistinguishable to an attacker and unsurprising
     * to a user who simply mistyped.
     */
    async function assertPasswordMatchesExisting(transport, password, legacyLocal, existing) {
        if (existing === 'snapshot') {
            const text = await transport.read(Store.SNAPSHOT_FILE);
            if (text && envelope.looksLikeVaultFile(text)) {
                try {
                    await envelope.decryptEnvelope(text, password);
                    return;
                } catch (e) {
                    throw new Error('Wrong password');
                }
            }
        }

        // No readable snapshot, but this device still holds legacy slots: the
        // password must open at least one of them.
        const keys = Object.keys(legacyLocal || {});
        if (keys.length) {
            for (const key of keys) {
                if (await legacy.decryptLegacyBlob(legacyLocal[key], password)) return;
            }
            throw new Error('Wrong password');
        }
    }

    /**
     * ====================================================================
     * LEGACY MIGRATION — remove with vault/core/migrate-legacy.js
     * ====================================================================
     * Folds the old `vaultEncrypted` localStorage map (keyed by
     * SHA-256(masterPassword) — ROADMAP.md 1.1) into the store, then verifies
     * and clears it. Delete this function together with the module it calls.
     */
    async function migrateLegacyLocal(store, storeOptions, storage, password, legacyLocal) {
        const collected = await legacy.collectLegacy({
            localBackups: legacyLocal,
            fileContents: null,
            password
        });

        if (!collected.data) {
            // Nothing decrypted with this password. That is not a failure —
            // the slots may belong to a different vault — so leave them alone
            // and do NOT mark the install migrated.
            return { migrated: false, reason: 'no legacy data for this password', sources: [] };
        }

        const ops = legacy.opsForLegacyData(collected.data, store.clock);
        await store.apply(ops);

        // Verify by reading back through a completely fresh store, so the
        // check cannot be satisfied by state that only exists in memory.
        const verifier = await root.VaultStore.open(
            Object.assign({}, storeOptions, { create: false })
        );
        const verified = verifyLegacyData(verifier, collected.data);

        if (!verified.ok) {
            return {
                migrated: false,
                reason: 'verification failed: ' + verified.reason,
                sources: collected.sources
            };
        }

        legacy.finishMigration(storage);
        return {
            migrated: true,
            sources: collected.sources,
            credentials: verified.credentials
        };
    }

    function verifyLegacyData(store, data) {
        if (data.privateKey) {
            const identity = store.getRecord(R.IDENTITY_ID);
            if (!identity || identity.privateKey !== data.privateKey) {
                return { ok: false, reason: 'identity missing' };
            }
        }
        let credentials = 0;
        for (const user of Object.keys(data.users || {})) {
            for (const site of Object.keys(data.users[user] || {})) {
                const expected = data.users[user][site];
                if (typeof expected !== 'number' || !Number.isFinite(expected)) continue;
                const rec = store.getCredential(user, site);
                if (!rec || typeof rec.nonce !== 'number' || rec.nonce < expected) {
                    return { ok: false, reason: `credential ${user}/${site} missing` };
                }
                credentials++;
            }
        }
        return { ok: true, credentials };
    }

    root.VaultBootstrap = { open, deviceIdFor, hasExistingVault, DEVICE_ID_KEY };
})(typeof window !== 'undefined' ? window : globalThis);
