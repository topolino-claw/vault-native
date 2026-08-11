/**
 * Transports: the only code that knows how bytes reach the disk.
 *
 * APPEND CONTRACT: a torn append leaves a partial line with no terminator. If
 * the next append is concatenated onto it, that entry is corrupted too, so one
 * interrupted write costs two operations. Every append implementation must
 * therefore begin a fresh line when the file does not already end in one.
 *
 * The store is written against this four-method interface so the same merge
 * and durability logic runs unchanged on desktop, on Android, and in a Node
 * test against an in-memory disk. Keeping platform quirks here — and nowhere
 * else — is what makes the core portable enough to reuse in the Obsidian
 * plugin and in an eventual Kotlin port.
 *
 *   read(name)         -> Promise<string|null>   null when absent
 *   write(name, text)  -> Promise<void>          MUST be atomic and durable
 *   append(name, line) -> Promise<void>          MUST be durable, and MUST
 *                                                start a new line if the file
 *                                                does not end in one (see below)
 *   list()             -> Promise<string[]>      file names, not paths
 *   remove(name)       -> Promise<void>
 */
(function (root) {
    'use strict';

    /** Files whose loss is unrecoverable get rotating backups on write. */
    const BACKED_UP = new Set(['topolino-vault.json', 'topolino-vault.keys.json']);

    /**
     * Directory transport over the Tauri commands. The preferred layout: the
     * app can create its own per-device log beside the snapshot and list
     * siblings, which is what makes conflicts impossible rather than merely
     * survivable.
     */
    function tauriDirectory(invoke, dir) {
        const sep = dir.includes('\\') && !dir.includes('/') ? '\\' : '/';
        const join = (name) => dir.replace(/[/\\]+$/, '') + sep + name;

        return {
            kind: 'directory',
            dir,

            async read(name) {
                try {
                    return await invoke('read_vault_file', { path: join(name) });
                } catch (e) {
                    return null; // absent or unreadable — the caller decides
                }
            },

            async write(name, contents) {
                await invoke('write_vault_file', {
                    path: join(name),
                    contents,
                    keepBackups: BACKED_UP.has(name)
                });
            },

            async append(name, line) {
                await invoke('append_vault_line', { path: join(name), line });
            },

            async list() {
                try {
                    return await invoke('list_vault_dir', { dir });
                } catch (e) {
                    return [];
                }
            },

            async remove(name) {
                try {
                    await invoke('remove_vault_file', { path: join(name) });
                } catch (e) {
                    /* already gone */
                }
            }
        };
    }

    /**
     * Single-file transport, for an Android SAF `content://` URI.
     *
     * Such a URI names one document and nothing else: siblings cannot be
     * created or listed, so the per-device log layout is impossible here.
     *
     * The rule this follows is that **the shared file stays a plain vault
     * envelope**, byte-for-byte what every other platform and every older
     * build expects. An earlier version wrapped it in a private container
     * holding the virtual files; that broke a folder shared between a desktop
     * and a phone — the desktop could no longer read the file the phone had
     * rewritten, so the phone's changes became invisible to it.
     *
     * So the snapshot goes to the real file, and everything the other devices
     * do not need to see — keyslots, this device's operation log — is kept in
     * device-local storage instead. The phone therefore behaves, from the
     * folder's point of view, like a device that only publishes snapshots:
     * its edits still reach other devices through `users` and `records`, and
     * still merge by the same monotonic rules.
     */
    function tauriSingleFile(invoke, path, storage) {
        const SNAPSHOT = 'topolino-vault.json';
        const CONTAINER_MARK = '__tv_container__';
        const local = localStorageTransport(storage, 'tvfs:');

        /**
         * Read the shared file. Unwraps the container format written by the
         * one build that used it, so those installs keep their vault.
         */
        async function readSnapshot() {
            let text;
            try {
                text = await invoke('read_vault_file', { path });
            } catch (e) {
                return null;
            }
            if (!text) return null;
            try {
                const parsed = JSON.parse(text);
                if (parsed && parsed[CONTAINER_MARK]) {
                    const inner = (parsed.files || {})[SNAPSHOT];
                    return typeof inner === 'string' ? inner : null;
                }
            } catch (e) {
                /* not JSON we recognise; hand it back as-is */
            }
            return text;
        }

        return {
            kind: 'single-file',
            path,

            async read(name) {
                return name === SNAPSHOT ? readSnapshot() : local.read(name);
            },

            async write(name, contents) {
                if (name !== SNAPSHOT) return local.write(name, contents);
                // Always a bare envelope: never re-wrap.
                await invoke('write_vault_file', { path, contents, keepBackups: true });
            },

            async append(name, line) {
                // The snapshot is never appended to; logs are device-local.
                return local.append(name, line);
            },

            async list() {
                const names = await local.list();
                if ((await readSnapshot()) !== null && !names.includes(SNAPSHOT)) names.push(SNAPSHOT);
                return names;
            },

            async remove(name) {
                if (name !== SNAPSHOT) return local.remove(name);
                // Refuse: this is the user's vault file, not ours to delete.
            }
        };
    }

    /**
     * Browser-storage transport. Not the vault's home — it is the device-local
     * cache that lets the app open when the synced folder is unavailable
     * (an unmounted drive, a revoked Android permission, a laptop offline).
     */
    function localStorageTransport(storage, prefix) {
        const key = (name) => (prefix || 'tvfs:') + name;

        return {
            kind: 'directory',

            async read(name) {
                const value = storage.getItem(key(name));
                return value === null ? null : value;
            },

            async write(name, contents) {
                storage.setItem(key(name), contents);
            },

            async append(name, line) {
                const existing = storage.getItem(key(name)) || '';
                const separator = existing && !existing.endsWith('\n') ? '\n' : '';
                storage.setItem(key(name), existing + separator + line + '\n');
            },

            async list() {
                const out = [];
                const head = prefix || 'tvfs:';
                for (let i = 0; i < storage.length; i++) {
                    const k = storage.key(i);
                    if (k && k.startsWith(head)) out.push(k.slice(head.length));
                }
                return out;
            },

            async remove(name) {
                storage.removeItem(key(name));
            }
        };
    }

    root.VaultTransports = { tauriDirectory, tauriSingleFile, localStorageTransport, BACKED_UP };
})(typeof window !== 'undefined' ? window : globalThis);
