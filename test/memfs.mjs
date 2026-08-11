/**
 * In-memory transports for tests, plus the fault injection the Monte Carlo
 * suite needs. Mirrors the interface the Tauri transport implements in
 * vault/app.js, so what the tests exercise is the real store logic.
 *
 * A "disk" is a plain Map of name -> contents, shared by every device pointed
 * at the same sync folder. Syncthing is modelled as file-granular replication
 * between per-device disks, which is what it actually is.
 */

/**
 * A device's copy of the synced folder.
 *
 * Files carry a globally monotonic revision so replication can tell "this side
 * changed" from "that side changed" — without that, every differing file looks
 * like a conflict and the simulation would not be testing anything real.
 */
let REV = 0;

export class MemDisk {
    constructor() {
        this.files = new Map();
        this.revs = new Map(); // version of the content we hold, whoever wrote it
        this.localRevs = new Map(); // version of our own last LOCAL write
        this.writes = 0;
    }

    /**
     * Record a local modification. `localRevs` is tracked separately from
     * `revs` because "I changed this file" and "I received a change to this
     * file" are different events, and only the first can cause a conflict.
     * Conflating them made every replicated log look concurrently-edited.
     */
    bump(name) {
        const rev = ++REV;
        this.revs.set(name, rev);
        this.localRevs.set(name, rev);
    }

    set(name, contents) {
        this.files.set(name, contents);
        this.bump(name);
    }

    /** Accept a replicated version without claiming it as a local edit. */
    receive(name, contents, rev) {
        this.files.set(name, contents);
        this.revs.set(name, rev);
    }

    rev(name) {
        return this.revs.get(name) || 0;
    }

    localRev(name) {
        return this.localRevs.get(name) || 0;
    }

    clone() {
        const copy = new MemDisk();
        for (const [k, v] of this.files) copy.files.set(k, v);
        for (const [k, v] of this.revs) copy.revs.set(k, v);
        for (const [k, v] of this.localRevs) copy.localRevs.set(k, v);
        return copy;
    }
}

/**
 * Directory transport over a MemDisk.
 *
 * @param {MemDisk} disk
 * @param {{onWrite?: Function}} [hooks] - onWrite(name, contents) may return a
 *   replacement string to simulate a torn write, or throw to simulate a crash
 *   mid-write. Returning undefined writes normally.
 */
export function memTransport(disk, hooks = {}) {
    return {
        kind: 'directory',

        async read(name) {
            return disk.files.has(name) ? disk.files.get(name) : null;
        },

        async write(name, contents) {
            disk.writes++;
            const replacement = hooks.onWrite ? hooks.onWrite(name, contents, 'write') : undefined;
            // An atomic write either lands whole or not at all — a torn
            // *replacement* is only possible if the implementation is not
            // atomic, so the fault hook models interruption as "no change".
            if (replacement === null) return;
            disk.set(name, replacement === undefined ? contents : replacement);
        },

        async append(name, line) {
            disk.writes++;
            const previous = disk.files.get(name) || '';
            // Mirrors the transport append contract: never continue a torn line.
            const separator = previous && !previous.endsWith('\n') ? '\n' : '';
            const appended = previous + separator + line + '\n';
            const replacement = hooks.onWrite ? hooks.onWrite(name, appended, 'append') : undefined;
            if (replacement === null) {
                // Crash during append: the tail may be torn, never the head.
                disk.set(name, previous + line.slice(0, Math.floor(line.length / 2)));
                return;
            }
            disk.set(name, replacement === undefined ? appended : replacement);
        },

        async list() {
            return Array.from(disk.files.keys());
        },

        async remove(name) {
            disk.files.delete(name);
            disk.revs.delete(name);
        }
    };
}

/**
 * Replicate files between two disks the way Syncthing would: newest wins per
 * file, and a file changed on both sides since the last sync becomes a
 * `.sync-conflict-` sibling rather than being merged.
 *
 * @param {MemDisk} from
 * @param {MemDisk} to
 * @param {{conflictTag?: string, only?: (name: string) => boolean}} [opts]
 */
export function replicate(from, to, opts = {}) {
    const tag = opts.conflictTag || '20260809-120000-AAAAAAA';
    // Last revision this pair agreed on, per file. Without it every differing
    // file looks conflicted and the simulation stops modelling Syncthing.
    const since = opts.since || new Map();
    let copied = 0;
    let conflicted = 0;

    for (const [name, contents] of from.files) {
        if (opts.only && !opts.only(name)) continue;
        if (name.includes('.sync-conflict-')) continue;

        const existing = to.files.get(name);
        if (existing === contents) {
            since.set(name, Math.max(from.rev(name), to.rev(name)));
            continue;
        }

        const base = since.get(name) || 0;
        const senderChanged = from.rev(name) > base;
        // Only a LOCAL write by the receiver can conflict. A file the receiver
        // merely replicated from a third device is not a competing edit.
        const receiverChanged = to.localRev(name) > base;
        // The sender's copy must actually be newer to win. Without this a
        // stale third-hand copy overwrites a fresher one and silently drops
        // operations — which the simulation reports as a nonce going
        // backwards, exactly the failure the design must never allow.
        const senderNewer = from.rev(name) > to.rev(name);

        if (existing === undefined) {
            to.receive(name, contents, from.rev(name));
            since.set(name, from.rev(name));
            copied++;
            continue;
        }

        if (!(senderChanged && receiverChanged)) {
            // At most one side moved: a plain update, and only if the sender
            // is genuinely ahead. This is the path every per-device log takes,
            // because logs have exactly one writer.
            if (senderNewer) {
                to.receive(name, contents, from.rev(name));
                since.set(name, from.rev(name));
                copied++;
            }
            continue;
        }

        // Both sides wrote since they last agreed — a genuine conflict.
        const dot = name.lastIndexOf('.');
        const conflictName =
            (dot === -1 ? name : name.slice(0, dot)) +
            `.sync-conflict-${tag}` +
            (dot === -1 ? '' : name.slice(dot));
        to.set(conflictName, contents);
        since.set(name, Math.max(from.rev(name), to.rev(name)));
        conflicted++;
    }
    return { copied, conflicted, since };
}

/** Deterministic PRNG so a failing Monte Carlo seed is reproducible. */
export function rng(seed) {
    let s = seed >>> 0 || 1;
    return function next() {
        // xorshift32
        s ^= s << 13; s >>>= 0;
        s ^= s >>> 17;
        s ^= s << 5; s >>>= 0;
        return s / 0x100000000;
    };
}

export function pick(rand, arr) {
    return arr[Math.floor(rand() * arr.length) % arr.length];
}

export function int(rand, min, max) {
    return min + Math.floor(rand() * (max - min + 1));
}
