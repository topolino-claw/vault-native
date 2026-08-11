/**
 * ============================================================================
 * ONE-SHOT LEGACY MIGRATION — DELETE THIS FILE IN THE RELEASE AFTER v1.1.0
 * ============================================================================
 *
 * This is the only code in the app that understands the pre-keyslot, pre-oplog
 * world. It is deliberately quarantined in one file with one call site so that
 * removing it is a delete, not an archaeology exercise.
 *
 * TO REMOVE (next release, once telemetry//support confirm no v1.0 installs remain):
 *   1. delete vault/core/migrate-legacy.js
 *   2. delete the <script src="core/migrate-legacy.js"> tag in vault/index.html
 *   3. delete the runLegacyMigration() call in vault/app.js (one call site,
 *      marked with the same banner)
 *   4. delete test/migrate.test.mjs
 *   5. drop `legacy` handling from VaultEnvelope.decryptEnvelope (ROADMAP 2.6)
 * Nothing else references it. `localStorage.tvSchema` tells you what a given
 * install has already been through.
 *
 * WHAT IT MIGRATES
 *   - localStorage `vaultEncrypted`: a map keyed by SHA-256(masterPassword) —
 *     the cracking oracle from ROADMAP.md 1.1. Values were either a v2
 *     envelope or raw CryptoJS ciphertext. Every value is tried against the
 *     password; the keys are ignored entirely and the map is deleted after a
 *     verified rewrite.
 *   - a v1 (CryptoJS/MD5) or v2 (PBKDF2/GCM) vault file.
 * Both are merged by the same never-decrease-a-nonce rule the vault has always
 * used, so a device that was ahead cannot be walked backwards by migrating.
 *
 * SAFETY: the migration never deletes a legacy artifact until the replacement
 * has been written AND read back successfully. Losing a vault to a botched
 * migration would be worse than any bug it fixes.
 */
(function (root) {
    'use strict';

    const envelope = root.VaultEnvelope;
    const R = root.VaultRecords;

    const SCHEMA_KEY = 'tvSchema';
    const LEGACY_LOCAL_KEY = 'vaultEncrypted';
    const CURRENT_SCHEMA = 1;

    /** Decrypt one legacy blob: v2 envelope, or raw CryptoJS from before it. */
    async function decryptLegacyBlob(blob, password) {
        if (typeof blob !== 'string' || !blob) return null;
        if (envelope.looksLikeVaultFile(blob)) {
            try {
                return (await envelope.decryptEnvelope(blob, password)).data;
            } catch (e) {
                return null;
            }
        }
        try {
            const CryptoJS = root.CryptoJS;
            const text = CryptoJS.AES.decrypt(blob, password).toString(CryptoJS.enc.Utf8);
            if (!text) return null;
            return envelope.normalizeVaultData(JSON.parse(text));
        } catch (e) {
            return null;
        }
    }

    function mergeLegacyData(target, incoming) {
        if (!target) return incoming;
        if (!incoming) return target;
        // Identity is immutable in practice; keep whichever we have.
        target.privateKey = target.privateKey || incoming.privateKey;
        target.seedPhrase = target.seedPhrase || incoming.seedPhrase;
        target.passphrase = target.passphrase || incoming.passphrase;
        target.settings = Object.assign({}, incoming.settings, target.settings);
        envelope.mergeUsers(target.users, incoming.users);
        return target;
    }

    /**
     * Collect and decrypt every legacy artifact we can find.
     * @returns {Promise<{data: object|null, sources: string[]}>}
     */
    async function collectLegacy({ localBackups, fileContents, password }) {
        const sources = [];
        let data = null;

        for (const key of Object.keys(localBackups || {})) {
            const decrypted = await decryptLegacyBlob(localBackups[key], password);
            if (decrypted) {
                data = mergeLegacyData(data, decrypted);
                sources.push('localStorage:' + key.slice(0, 8));
            }
        }

        if (fileContents) {
            const decrypted = await decryptLegacyBlob(fileContents, password);
            if (decrypted) {
                data = mergeLegacyData(data, decrypted);
                sources.push('file');
            }
        }

        return { data, sources };
    }

    /** Turn a legacy vault payload into operations for the new store. */
    function opsForLegacyData(data, clock) {
        const ops = [];
        if (!data) return ops;

        if (data.privateKey || data.seedPhrase) {
            ops.push(
                R.makeOp(clock, R.IDENTITY_ID, R.TYPES.IDENTITY, {
                    privateKey: data.privateKey || '',
                    seedPhrase: data.seedPhrase || '',
                    passphrase: data.passphrase || ''
                })
            );
        }

        ops.push(
            R.makeOp(clock, R.SETTINGS_ID, R.TYPES.SETTINGS, {
                hashLength: (data.settings && data.settings.hashLength) || 16
            })
        );

        for (const user of Object.keys(data.users || {})) {
            const sites = data.users[user] || {};
            for (const site of Object.keys(sites)) {
                const nonce = sites[site];
                if (typeof nonce !== 'number' || !Number.isFinite(nonce)) continue;
                ops.push(
                    R.makeOp(clock, R.credentialId(user, site), R.TYPES.CREDENTIAL, {
                        user,
                        site,
                        nonce
                    })
                );
            }
        }
        return ops;
    }

    function needsMigration(storage) {
        const schema = Number(storage.getItem(SCHEMA_KEY) || 0);
        if (schema >= CURRENT_SCHEMA) return false;
        return Boolean(storage.getItem(LEGACY_LOCAL_KEY));
    }

    function readLegacyLocal(storage) {
        try {
            return JSON.parse(storage.getItem(LEGACY_LOCAL_KEY) || '{}');
        } catch (e) {
            return {};
        }
    }

    /**
     * Mark the install migrated and drop the legacy artifacts.
     * Call ONLY after the replacement has been written and verified.
     */
    function finishMigration(storage) {
        storage.removeItem(LEGACY_LOCAL_KEY);
        storage.setItem(SCHEMA_KEY, String(CURRENT_SCHEMA));
    }

    root.VaultMigrateLegacy = {
        SCHEMA_KEY,
        LEGACY_LOCAL_KEY,
        CURRENT_SCHEMA,
        decryptLegacyBlob,
        collectLegacy,
        opsForLegacyData,
        needsMigration,
        readLegacyLocal,
        finishMigration
    };
})(typeof window !== 'undefined' ? window : globalThis);
