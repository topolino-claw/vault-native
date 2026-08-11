# The Monte Carlo suite

`test/montecarlo.test.mjs` — what it is, how it works, and how to drive it when
it fails.

Unit tests check the cases we thought of. This one checks the ones we didn't:
several devices sharing a Syncthing folder, doing random things in a random
order, syncing at random moments with partial delivery, restarting, crashing
mid-write, running clocks that disagree, and the Obsidian plugin rewriting the
snapshot underneath all of it. Every run is a seeded pseudo-random schedule, so
any failure is exactly reproducible.

It is the check to run after **any** change to `store.js`, `records.js`,
`oplog.js`, `hlc.js`, or the transports — it has caught four bugs that code
review did not (see [Bugs it has caught](#bugs-it-has-caught)).

---

## Running it

```bash
node test/montecarlo.test.mjs           # the default battery: 8 seeds × 90 steps × 3 devices
node test/run-all.mjs                    # runs it last, after the deterministic suites
```

It is deterministic given a seed. Everything is tunable by environment variable:

| Var | Default | Meaning |
| --- | --- | --- |
| `MC_SEEDS` | `1,7,13,42,99,2024,31337,8675309` | Comma-separated PRNG seeds. One simulation per seed. |
| `MC_STEPS` | `90` | Random actions per simulation before the final verify. |
| `MC_TRACE` | *(off)* | `user/site` — after every step, print which devices hold that credential and its nonce. Also dumps log/snapshot divergence if a convergence check fails. |
| `MC_FAILFAST` | *(off)* | Check the "must survive" set after **every** step and throw the instant a record is lost, instead of only at the end. Also logs each crash-reopen's held-record and log-byte deltas. Use it to localize *when* a loss happened. |

`DEVICE_COUNT` is a constant (`3`) in the file, not an env var. KDF cost is
dialled down to `TEST_ITERATIONS` (1000) so thousands of opens are fast; this is
the only thing that differs from production crypto.

### Reproducing and debugging a failure

A failure always prints its seed. Re-run just that seed, then turn on tracing:

```bash
MC_SEEDS=12345 node test/montecarlo.test.mjs                     # reproduce exactly
MC_SEEDS=12345 MC_TRACE=me/github.com node test/montecarlo.test.mjs   # follow one credential
MC_SEEDS=12345 MC_FAILFAST=1 node test/montecarlo.test.mjs       # stop at the step that loses data
```

Because the schedule is a pure function of the seed, the same seed replays the
same crashes, syncs, and plugin edits every time.

---

## The model

Each of the 3 devices has:

- a **`MemDisk`** — a `Map` of filename → contents standing in for its copy of
  the synced folder (see `test/memfs.mjs`);
- a **`Store`** opened over that disk via `memTransport`, with a crash hook;
- its **own clock offset**, so wall-clock skew is present in every run. The
  offsets are `[0, −45s, +120s]`.

Device 0 creates the vault and sets an identity; the others "join" by receiving
device 0's folder and opening it.

`virtualNow` starts at a fixed epoch and advances a random 1–60 s each step, so
"time" moves forward while the per-device skew keeps the HLC honest.

### One step

`step()` advances the clock, picks a random device, rolls once, and does one of:

| Probability | Action |
| ---: | --- |
| 22% | Create or **rotate a credential** (bump its nonce by 1). |
| 12% | Store a **note** (a non-nonce record — the point of the record model). |
| 6% | Store a **TOTP** record. |
| 5% | **Delete** a random note. |
| 7% | Change **settings** (`hashLength`). |
| 26% | **Sync** a random pair of devices (replicate both ways, then both merge). |
| 8% | **Restart** the device (drop in-memory state, reopen from disk). |
| 7% | **Crash** during the next write, then restart. |
| 7% | **Plugin edit** — the Obsidian plugin rewrites the snapshot. |

**Sync** is modelled by `replicate()` in `memfs.mjs`: file-granular, newest-wins,
with a genuine `.sync-conflict-*` sibling created when both sides changed the
same file since they last agreed — exactly what Syncthing does. Per-device logs
(`tv-<id>.tvlog`) have a single writer, so they replicate without conflict; only
the shared snapshot can conflict.

**Crash** is injected through the transport's `onWrite` hook: while
`device.crashing` is set, a write returns "no change" (an atomic write either
lands whole or not at all), and an append is left with a torn tail. The write
that crashes is deliberately **not acknowledged** — see the shadow model.

**Plugin edit** decrypts the snapshot with the master password, picks a
credential, and half the time advances its nonce (a legitimate edit) and half
the time rolls it back (a restored backup, which must be refused). It then
**deletes `records`** — the plugin doesn't model notes/TOTP/custom types, so it
drops them on save — re-encrypts, and writes the snapshot. This is the harshest
thing the suite does: a foreign writer that both moves nonces and discards
record types the app cares about.

---

## The invariants

These must hold no matter what the schedule does. They are the whole reason the
suite exists.

1. **Convergence.** Once every device has synced, all of them derive
   byte-identical state. Checked in `verify()` by comparing every device's
   `snapshotPayload()` against device 0's with `deepStrictEqual`.
2. **Monotonic nonces.** No device ever reports a *lower* nonce for a site than
   it reported before. A nonce going backwards silently re-issues a password the
   user rotated away from (ROADMAP §3) — this is the invariant with teeth.
   Checked *continuously* by `checkMonotonic()` (after every sync and at the end
   of every step), not just at the finish.
3. **Durability.** Every *acknowledged* write survives restarts, crashes,
   conflicts, and plugin interference.
4. **Readability.** The vault still decrypts, and the snapshot is still readable
   through the plugin-compatible envelope. The identity's `privateKey` must
   survive everything.

---

## The shadow model — what "must survive" means

The simulation keeps a separate, minimal record of what it *knows* must be true,
independent of the schedule:

- **`ackedNonce`** (`"user site" → highest nonce`): the highest nonce written
  **without a crash**. A crashed write is never added here.
- **`mustExist`** (set of record ids): notes/TOTP that were written without a
  crash and haven't been deleted.
- **`everDeleted`** (set of ids): anything deleted. Once deleted, existence is
  *undecidable* — a concurrent edit on another device may legitimately revive
  it — so the id leaves `mustExist` and only convergence covers it.
- **`lastSeen`** (per device): the last nonce each device reported per
  credential, for the monotonicity check.

The crucial rule: **only acknowledged writes are required to survive.** Losing
the single in-flight operation to a crash is acceptable (invariant 3 never
demands a torn write survived); losing anything else, or corrupting what came
before it, is not. This is why crash steps don't touch `ackedNonce` /
`mustExist`.

### The plugin-edit subtlety

A plugin edit is only *acked after* the owning device has synced and absorbed
it, and the sync's outcome is asserted on the spot: an advance must be taken
(`nonce ≥ next`), a rollback must be refused (`nonce ≥ what this device already
held`). Rollback is compared against the device's own prior value, not the
global acked value — a device that simply hasn't synced yet is *stale*, which is
not the same as an accepted rollback. Acking before absorption would demand the
app preserve a number nobody ever read, and the simulated plugin freely
overwrites its own edits, so no design could.

---

## Reaching a verdict: `quiesce()` and `fingerprint()`

`verify()` doesn't just sync once. It calls `quiesce()`, which replicates and
merges **all pairs repeatedly until the system stops changing** (a fixpoint),
then reopens every device from disk (nothing may live only in memory), then
quiesces again so the comparison happens at a true fixpoint.

Reaching a fixpoint is itself an assertion. A system where each device reacts to
the other's write by re-writing would never settle, and Syncthing would conflict
forever; `quiesce()` throws `never reached a fixpoint … devices are fighting
over writes` after 25 rounds. Stopping after a fixed number of rounds instead
would hide exactly that failure.

`fingerprint()` is a *semantic* snapshot of the whole system — each device's
`snapshotPayload()` plus its log filenames and sizes. It can't use snapshot
*bytes*, because every encryption uses a fresh IV, so identical state
re-encrypts to different ciphertext. What must stabilize is the state each
device derives, not the ciphertext it happens to produce.

---

## The two named tests

- **`seed N converges and loses nothing`** — one per `MC_SEEDS` entry: `start()`,
  `MC_STEPS` random steps, then `verify()`. Prints a one-line summary (records,
  crashes, conflict files, plugin edits).
- **`master password change mid-flight keeps every device working`** — a scripted
  adversarial run (seed 4242): 25 steps, then device 0 changes the master
  password, the others learn it only by syncing and reopening, then 25 more
  steps and a full `verify()`. Guards the keyslot rewrap under concurrent use.

---

## Bugs it has caught

Four that code review missed:

1. A non-hex device id silently invalidating every operation the device made
   (its stamps failed `isStamp`, so the vault "worked" and saved nothing).
2. A lost-update on the shared snapshot.
3. Unwritten log headers.
4. The torn-append bug (a crash mid-append corrupting the *next* entry too, so
   one interrupted write cost two operations).

---

## Extending it — gotchas

- **New record type?** Add it to the action mix in `step()` and, if it must
  survive, to `mustExist`. If deletes can race it, make sure it lands in
  `everDeleted` on delete.
- **Never ack a crashed write.** Anything added to `ackedNonce`/`mustExist` must
  be gated on `!device.crashing`, or invariant 3 will demand a torn write
  survive and the suite will (correctly, by its own rules) fail.
- **Keep comparisons semantic.** If you add state, extend `fingerprint()` and
  `snapshotPayload()` rather than comparing bytes — fresh IVs make ciphertext
  comparison meaningless.
- **A new "must reach a fixpoint" behaviour** (e.g. a background rewrite) can
  turn `quiesce()` into an infinite fight; if it starts throwing "devices are
  fighting over writes," that is the suite telling you two writers react to each
  other forever.
