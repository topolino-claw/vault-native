/**
 * Key management: how the master password guards the vault on a device.
 *
 * WHAT THIS REPLACES (ROADMAP.md 1.1)
 * The previous scheme stored encrypted vaults in a map keyed by
 * `SHA-256(masterPassword)` — unsalted, one round, sitting in localStorage
 * right beside the ciphertext it was supposed to protect. That key is a free
 * offline verification oracle: an attacker who can read app data brute-forces
 * the master password at one SHA-256 per guess instead of one PBKDF2-600k per
 * guess, roughly a 10^6 shortcut around the KDF. Nothing else about the
 * encryption mattered while that was true.
 *
 * THE MODEL (the one LUKS, FileVault and the major password managers use)
 * A random 256-bit Vault Master Key (VMK) encrypts the data. The password
 * never encrypts data directly — it derives a key-encryption key that *wraps*
 * the VMK into a keyslot:
 *
 *     slot.wrapped = AES-GCM( PBKDF2(password, slot.salt, iters), rawVMK )
 *
 * Slot ids are random and carry no relationship to the password, so the store
 * leaks nothing to brute-force against. Unlocking tries each slot and lets
 * GCM's authentication tag say whether the password was right — the cost of a
 * guess is now one PBKDF2 per slot, which is the whole point.
 *
 * Three things fall out of this that the old scheme could not do:
 *   - Changing the master password rewraps one small blob instead of
 *     re-encrypting the vault, so it cannot half-finish and strand data.
 *   - Several credentials (password today; biometric or a device-bound secret
 *     key later, ROADMAP.md 2.4) can unlock the same vault by adding slots.
 *   - Losing a slot is not losing the vault.
 *
 * Wrapping is bound to its slot id via GCM additional authenticated data, so
 * slots cannot be swapped or replayed between documents.
 */
(function (root) {
    'use strict';

    const util = root.VaultUtil;
    const envelope = root.VaultEnvelope;
    const subtle = (root.crypto || crypto).subtle;

    const KEYS_TYPE = 'topolino-vault-keys';
    const KEYS_VERSION = 1;
    const SALT_BYTES = 16;
    const IV_BYTES = 12;
    const SLOT_ID_BYTES = 16;

    function slotAad(slotId) {
        return new TextEncoder().encode('tvslot:' + slotId);
    }

    /** A fresh random VMK. Extractable, because adding a slot must rewrap it. */
    async function generateVaultKey() {
        return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }

    async function wrapVaultKey(vmk, password, iterations) {
        const salt = new Uint8Array(SALT_BYTES);
        (root.crypto || crypto).getRandomValues(salt);
        const iv = new Uint8Array(IV_BYTES);
        (root.crypto || crypto).getRandomValues(iv);

        const id = util.randomHex(SLOT_ID_BYTES);
        const kek = await envelope.deriveVaultKey(password, salt, iterations);
        const raw = await subtle.exportKey('raw', vmk);
        const wrapped = await subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: slotAad(id) },
            kek,
            raw
        );

        return {
            id,
            kdf: {
                algo: 'PBKDF2-SHA256',
                iterations,
                salt: util.bytesToB64(salt)
            },
            iv: util.bytesToB64(iv),
            wrapped: util.bytesToB64(new Uint8Array(wrapped))
        };
    }

    async function unwrapSlot(slot, password) {
        const kek = await envelope.deriveVaultKey(
            password,
            util.b64ToBytes(slot.kdf.salt),
            slot.kdf.iterations
        );
        const raw = await subtle.decrypt(
            { name: 'AES-GCM', iv: util.b64ToBytes(slot.iv), additionalData: slotAad(slot.id) },
            kek,
            util.b64ToBytes(slot.wrapped)
        );
        return subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    }

    /**
     * @param {string} password
     * @param {{iterations?: number, label?: string}} [opts] - iterations is
     *   overridable so test suites can run thousands of unlocks; production
     *   callers must leave it at the default.
     */
    async function createDoc(password, opts) {
        const options = opts || {};
        const iterations = options.iterations || envelope.V2_ITERATIONS;
        const vmk = await generateVaultKey();
        const slot = await wrapVaultKey(vmk, password, iterations);
        if (options.label) slot.label = options.label;
        return {
            doc: { v: KEYS_VERSION, type: KEYS_TYPE, slots: [slot] },
            vmk,
            slotId: slot.id
        };
    }

    function isKeysDoc(parsed) {
        return (
            parsed !== null &&
            typeof parsed === 'object' &&
            parsed.type === KEYS_TYPE &&
            Array.isArray(parsed.slots)
        );
    }

    function isSlot(slot) {
        return (
            slot !== null &&
            typeof slot === 'object' &&
            typeof slot.id === 'string' &&
            typeof slot.iv === 'string' &&
            typeof slot.wrapped === 'string' &&
            slot.kdf !== null &&
            typeof slot.kdf === 'object' &&
            typeof slot.kdf.salt === 'string' &&
            Number.isFinite(slot.kdf.iterations) &&
            slot.kdf.iterations > 0 &&
            slot.kdf.iterations <= envelope.MAX_ITERATIONS
        );
    }

    /**
     * Try every slot. Throws 'Wrong password' if none unwraps — deliberately
     * the same message for "no such slot" and "bad password", since the two
     * must not be distinguishable.
     */
    async function unlockDoc(doc, password) {
        if (!isKeysDoc(doc)) throw new Error('Not a keyslot document');
        for (const slot of doc.slots) {
            if (!isSlot(slot)) continue;
            try {
                const vmk = await unwrapSlot(slot, password);
                return { vmk, slotId: slot.id };
            } catch (e) {
                /* wrong password for this slot — keep trying */
            }
        }
        throw new Error('Wrong password');
    }

    /** Add a credential that unlocks the same VMK. Returns the new slot id. */
    async function addSlot(doc, vmk, password, opts) {
        const options = opts || {};
        const slot = await wrapVaultKey(vmk, password, options.iterations || envelope.V2_ITERATIONS);
        if (options.label) slot.label = options.label;
        doc.slots.push(slot);
        return slot.id;
    }

    /** Remove a slot. Refuses to remove the last one — that would brick the vault. */
    function removeSlot(doc, slotId) {
        if (doc.slots.length <= 1) throw new Error('Cannot remove the only keyslot');
        const before = doc.slots.length;
        doc.slots = doc.slots.filter((s) => s.id !== slotId);
        return doc.slots.length < before;
    }

    /**
     * Change the master password: unwrap with the old, rewrap under the new,
     * swap the slot. The vault data is never touched, so this cannot leave the
     * vault half-converted the way re-encrypting everything could.
     */
    async function changePassword(doc, oldPassword, newPassword, opts) {
        const options = opts || {};
        const { vmk, slotId } = await unlockDoc(doc, oldPassword);
        const replacement = await wrapVaultKey(
            vmk,
            newPassword,
            options.iterations || envelope.V2_ITERATIONS
        );
        const old = doc.slots.find((s) => s.id === slotId);
        if (old && old.label) replacement.label = old.label;
        doc.slots = doc.slots.map((s) => (s.id === slotId ? replacement : s));
        return { vmk, slotId: replacement.id };
    }

    root.VaultKeyslots = {
        KEYS_TYPE,
        KEYS_VERSION,
        generateVaultKey,
        createDoc,
        unlockDoc,
        addSlot,
        removeSlot,
        changePassword,
        isKeysDoc
    };
})(typeof window !== 'undefined' ? window : globalThis);
