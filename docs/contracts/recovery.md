# Recovery contract

How the node recovers an authoritative chainstate after a crash, a lost
write, a reorganization, or an incompatible datadir. The chainstate is
the single durable authority. `crates/chainstate` owns the ordered commit
protocol over the storage durable head. That head certifies ordering and
high-water bounds, not coin contents. If startup restores no chainstate while
a durable head still exists, `reconcile_at_boot` replays the head chain
from the newest accepted checkpoint out of the durable bodies it certifies
(or from genesis when no checkpoint is accepted). Coins are recovery artifacts
and the durable head remains the only surviving authority; a missing or
mismatched body fails closed. Every
other persisted component is derived and reconciles to it.

For an AssumeUTXO historical role, the durable head may name a complete
historical checkpoint in the isolated `assumeutxo-historical-checkpoints`
namespace. Startup restores that checkpoint before replaying any remaining
certified historical suffix; an unreferenced generation is ignored.

Owners:
- Authoritative durable root and ordered commit protocol:
  `crates/chainstate/src/connect.rs`, `disconnect.rs`, and `durable.rs`
- Recovery and schema admission: `crates/chainstate/src/recovery.rs`;
  process-composition tests remain in `crates/node/tests/unit/state/tests/`
- Persistent coin transition boundary: `crates/utxo/src/set.rs`
  (transition types); durable form in
  `crates/storage/src/durable_head.rs`
- Crash and lost-write fault tests:
  `crates/node/tests/crash_recovery.rs`
- Reorg and disconnect: `crates/chainstate/src/reorg.rs` and
  `crates/chainstate/src/disconnect.rs`
- Checkpoint publication and recovery:
  `crates/chainstate/src/checkpoint.rs`, its checkpoint companions,
  and `crates/storage/src/checkpoint/`
- Index worker recovery: `crates/index/src/runtime/recovery_tests.rs`
- Policy: `docs/policies/db-migration.md`

## Durable root

The authoritative durable root is:

```text
R = (tip, height, CommitId, coins_version, coins, body_extent, undo_extent, refs,
     historical_checkpoint)
```

- `tip` is the 32-byte block hash of the applied tip.
- `height` is the block height, a compact big-endian integer.
- `CommitId` is a strictly monotonic durable serial. It advances on every
  committed connect and every committed disconnect.
- `coins_version` equals the current `CommitId` at the time the coin set
  was committed; it is not computed from coin contents.
- `coins` is the authoritative UTXO set. It is keyed and valued as
  defined in `crates/utxo`.
- `body_extent` and `undo_extent` are the committed durable high-water
  bounds for body and undo segment files.
- `refs` is the authoritative map from `(height, block_hash, Body|Undo)` to
  the durable byte range in the corresponding segment file. Undo and body
  references include the block hash, not only the height.
- `historical_checkpoint` is an optional durable-head reference to a complete
  historical checkpoint generation, including its generation, height, and hash.

`DurableHead` is the persisted form, landed in
`crates/storage/src/durable_head.rs` as one versioned, CRC32C-framed row in
the `UtxoMeta` family of the chainstate key-value store:

```rust
struct DurableHead {
    commit_id: u64,
    height: u32,
    tip: Hash256,
    chain_tx_count: u64,
    body_extent: Option<BodyExtent { file_no: u32, offset: u64 }>,
    undo_extent: Option<(u32, Hash256)>,
    assumeutxo: AssumeUtxoDiskStatus,
}
```

The row carries a format version byte and a checksum over its payload; any
malformed row fails closed at load instead of decoding to absence. The head
record lives in the chainstate key-value store and the ordered protocol is
owned by `crates/chainstate`.

One connect or disconnect commits one atomic named-family batch whose
`write_durable_if` receipt covers the head row, the block's undo row, its
body locator row, and block-file maximum-height rows; the appended body bytes
and the blocks directory are synced before the batch may name them. The coins
themselves commit in memory and become durable through the checkpoint export;
the undo and body records in the batch are what make a committed tip
recoverable. The chainstate journal is derived from this batch and may lag it,
never lead it. `commit_id` is strictly monotonic on disconnect as well as on
connect: a reorg lowers `height`, never `commit_id`.

AssumeUTXO activation and historical archive updates use the same transition
reservation but separate recovery namespaces. The manager holds a required
persistent data directory; activation archive writes, full-revalidation marker
checks, reservation cleanup, and historical checkpoint maintenance always use
it. The required path guarantees a directory was supplied, not filesystem
health; missing or corrupt files fail at use. Activation first syncs immutable
`coins.dat` and `headers.dat` under `assumeutxo/<base_hash>/`, then commits the pinned base,
count, and lifecycle in the head. An unreferenced import is an orphan, not a
checkpoint or activation authority. Historical updates advance `commit_id`
without changing the active tip. Each new candidate body is synced and referenced
as pending before validation; its locator becomes visible to derived readers
only with the validated undo/progress batch. An unresolved pending check is
reconstructed and completed during startup, before service admission, even if
the preceding process could not persist its terminal failure. This applies below
the base as well: discarding an intermediate intent could forget a consensus
failure whose `Failed` receipt was lost. When the durable head names a historical
checkpoint, startup restores its UTXO, CoinStats, and applied tip, then replays
only the validated archive suffix. Checkpoint publication and its durable-head
reference are ordered so an unreferenced generation is ignored after a crash.
Publication retains older historical generations until the durable-head batch
accepts the replacement. Startup opens the generation named by that head
directly, even when `CURRENT` leads it; cleanup runs only after head commit.
A missing or corrupt named checkpoint fails closed rather than attaching an
unverified height to empty coins. Without an accepted checkpoint, reconstruction
can still delay startup by the full historical prefix. Already archived blocks
replay without another pending/archive write.

Snapshot activation refuses while the full-revalidation marker is present,
including a recheck under transition exclusion before committing its anchor.
The marker and pre-activation head remain intact on refusal.

Snapshot recovery validates the root's network pin, restores a compatible
 checkpoint or verifies the immutable snapshot archive, and replays the
 root-certified foreground suffix. A full-revalidation marker still overrides
 incremental recovery. The pre-activation journal cannot extend a snapshot jump
 and is detached. Historical coins are restored from the head-accepted
 checkpoint and retained bodies supply only the remaining suffix; durable archive
 progress never pretends to be a recovered coin set.
Finalized history supplies ordinary undo/reorg behavior. A disconnect below
the base clears the snapshot anchor in its head batch. These bytes use datadir
schema epoch 2; older datadirs are refused without conversion.

A checkpoint exactly at the pinned snapshot base must match its commitment and
transaction count and must contain no coin created above that base height.
Recovery uses the same height-bounded commitment traversal as snapshot activation
and immutable archive restoration; valid file checksums do not waive this rule.

Ordinary and historical checkpoints share the same generation and manifest-digest
reference and manifest/artifact verification. The ordinary owner selects that
reference through `CURRENT`; historical recovery uses the durable head's reference
directly, even when `CURRENT` is ahead. Historical publication explicitly retains
generations until the new reference commits. Retirement runs after that commit and
again at startup after the accepted generation has been validated, using the same
cleanup routine without a second durable cleanup record.
After `Finalized` commits, the historical namespace's recognized generations,
staging files and `CURRENT` are removed. Startup retries this cleanup for a
committed `Finalized` head. Cleanup failures are warnings, not recovery failures;
ordinary checkpoints and unknown files are preserved.

Snapshot recovery is exercised by
`crates/chainstate/tests/unit/assumeutxo_tests.rs` (commitment verification,
isolated replay, terminal-write failures and role guards) and
`crates/chainstate/tests/unit/assumeutxo_recovery_tests.rs` (real-storage
restart, process-kill boundaries, lost failure receipts, root-preserving
archive replay, checkpoint pin binding, pruning and below-base reorg restart).

## Clauses

### `RCV-01`: Authority and identity

- The chainstate is the only authoritative position. `crates/chainstate`
  owns that position and its commit/recovery protocol. Block bodies,
  `txindex`, `scriptindex`, and undo or lookup metadata are derived.
- Every derived position is a `(height, block_hash)` pair, not height alone.
- Off the active chain: stale `(height, block_hash)` pairs are rewound to the
  common ancestor, not to a height.
- Absent tip: headers-only start; every row is rewound.
- The chain does not own a position the chainstate has not durably
  committed.
- Checkpoints are a durable copy of the chainstate; block bodies, `txindex`,
  `scriptindex`, and undo or lookup metadata are derived.

### `RCV-02`: Ordered commit protocol

For one block, or a bounded fully verified prefix during IBD:

1. Hold the chain transition reservation; close admission and mixed
   reads with the generation fence.
2. Build exact forward and undo facts without mutating the public stable
   view.
3. Append required block-body frames. Sync the block files and required
   directory entries.
4. Apply one atomic storage batch containing the durable head row, undo rows,
   body locator records, and block-file maximum-height rows. Wait for durable
   completion. A successful commit on this nonempty batch makes prior deferred
   body-index writes on the same store durable with the head.
5. Publish the committed chain and coin view.
6. Feed the committed chain update into the mempool canonical lifecycle,
   update the fee estimator, and reconcile projections.
7. Publish the stable coherent generation only after mempool and projection
   alignment.
8. Dispatch notifications and relay in the declared observable order outside
   all domain locks.

Coins commit in memory rather than as rows in the durable-head batch; their
durability is achieved through checkpoint export.

Speculative template preparation is distinct from durable authority. Before the
block-file sync in step 3, chainstate fires an optional staged-tip hook to
enqueue prospective work:
- In `PublishMode::Now`, the hook fires only when the staged block is a direct
  child of the currently published tip. Reorg connects never match because the
  published tip stays on the old branch until settlement.
- In `PublishMode::Grouped`, the hook fires only for the newest block of the
  staged prefix, immediately before the group sync. If a window fails, only the
  last successful block before the failure is handed off.
- The node gates hook enqueuing by initial block download (IBD).
- In `PublishMode::Replay`, the hook never fires. Replaying committed gap blocks
  schedules no speculative preparation.

The hook enqueues work without waiting for preparation to finish. The existing commit order remains:
block-file sync (step 3), atomic storage batch commit (step 4), public chain and
coin view publication (step 5), and follower dispatch (step 8). Speculative
projections never advance `tip` or `DurableHead`. They publish no applied tip,
advance no durable serials, and expose no candidate before durable commit.

Cache installation requires an authoritative committed receipt for the exact
tip, matching txids and removal reasons, and the live full generation key. Any
mismatch, prioritisation, or failure discards the preparation and falls back to
lazy assembly. In follower dispatch (step 8), a gatewayless connect publishes a
truthful empty receipt at the same point. Receipt publication notifies
foreground waiters, including when the connect has no mempool gateway.

A failure before stable publication leaves the fence closed until explicit
recovery. A guard destructor must never quietly reopen the fence after an
error. A live `submitblock` success waits for durable body, undo, and head
completion: `apply_block` returns only after the batch receipt, and the
returned `ConnectOutcome.commit_id` is the receipt's id. IBD may group a
bounded verified prefix; only committed prefixes are published. The group
caps are stated constants, not emergent cadence:
`DURABLE_HEAD_GROUP_BLOCKS` = 64 blocks or `DURABLE_HEAD_GROUP_MAX_BYTES` =
8 MiB of block data, whichever first — one durable batch every one to two
seconds at IBD rates, and a crash-redo bound of at most 64 body re-applies.
Callers of `BlockBodyStore::sync` without a following durable batch on the
body-index store must call `flush_index` after syncing the block files.
This is the ordered commit protocol. It is also called the durable root
recovery contract.

Boot-time durable-head replay runs before the journal maintenance worker is
started. If journal retention pressure refuses a replay block, recovery releases its
transition, publishes a marker-preserving progress checkpoint to compact the
journal, reacquires the transition, verifies that the applied tip is unchanged,
and retries that same block once. The progress checkpoint does not retire the
disconnect or full-revalidation marker. Intermediate replay tips retain the
cumulative transaction count reconstructed from their parent; only the landing
tip adopts the durable head's certified count, so every progress checkpoint
agrees with CoinStats. Failure to publish the checkpoint, reacquire the
transition, preserve the captured tip, or apply the retry fails closed.
Before genesis, no progress checkpoint is possible. If an empty cold writer
hits retention pressure while the full-revalidation marker is present, it
removes only invalidated, non-active journal segment generations and syncs
the journal directory. It preserves the marker, head, and active cursor;
append-gap admission and filesystem errors still fail closed.
Other journal refusals (append gaps, unreadable state, corruption, or storage
and filesystem failures) do not enter this checkpoint-and-retry path.

### `RCV-03`: Prior-or-whole-proposed and orphan tails

- The storage engine resolves an outstanding atomic batch to the prior root
  or to the wholly proposed root. It never mixes a new head with old coins,
  or a new coins set with old head.
- A durable head never references a body or undo range that has not itself
  become durable.
- Files may have orphan append tails. Those tails are not authoritative.
  The root is installed only after the required file and directory syncs and
  the atomic batch finish.
- A partial append after the head is not a valid connect or disconnect.
- Startup loads the durable head before opening block files for tail recovery.
  The head's extent file must contain complete frames through its committed
  offset; a missing file, short prefix, or malformed frame refuses open with
  `StorageError::IncompatibleData`, preserving every block file. Only a torn
  append beyond that extent may be discarded, even if the restored checkpoint
  already matches the head. This framing admission scans the extent file and
  current append tail, not the historical archive; earlier pruned file gaps
  remain valid and locator/body integrity checks keep their existing owners.
- On disconnect, `DurableHead.commit_id` advances to a new value that is
  greater than the previous value. Monotonicity holds for both connect and
  disconnect.
- Undo records are keyed by `(height, block_hash)`. Replaying a side branch
  at the same height must not alias the undo record of the active branch.

### `RCV-04`: Crash matrix

The crash and error points in this contract and
`docs/policies/db-migration.md` produce exactly these results:

| Crash or error point | Recovery result |
|---|---|
| Body append mid-frame | The in-progress frame is discarded on next start; no durable head references it. |
| Undo row written, head batch not committed | An undo row without a committed head reference is not authoritative. The head batch atomically commits the head and the undo rows it names. |
| Sync before durable batch | The atomic batch contains only data that reached the OS; any missing body or undo prevents commit. |
| Durable batch complete, no publish | Restart sees the new head, coins, and `refs`; mempool and index reconcile. |
| Durable batch ambiguous | Recovery resolves the ambiguity by `CommitId` and full identity; no mixed head/coins. |
| Publication callback lost | The durable root is still authoritative; mempool and index reconcile after restart. |
| Reorg stage 1: disconnect | Apply the exact per-block inverse; hold the fence until all disconnects commit. |
| Reorg stage 2: reconnect | Apply the new branch using ordinary connect; each connect advances `CommitId`. |
| Index watermark commit failure | The failure does not block ordinary chain progress; the affected capability reconciles. |
| Incompatible `CURRENT_SCHEMA` | `incompatible_schema` error at open; existing datadirs stay untouched. |

Tests must exercise actual process death and storage fault semantics in an
isolated local environment. A process kill is not a substitute for simulated
power loss. Fault-injection storage tests must exercise lost writes, partial
writes, and failures around sync completion in addition to child-process kill
tests.

### `RCV-05`: Deep rollback and selective rebuild

- A rollback deeper than the configured cutover resets the affected
  capabilities and rebuilds them from the durable root, not from a
  checkpoint. The rebuild phase stays published until the reset
  capabilities reach the applied tip again.
- Independent capabilities carry their own watermarks, so one capability
  may rebuild while a sibling rewinds. The rebuild leg outlives the
  rollback loop and is published until the reset rows reach the applied
  tip.
- The index runtime reconciles against the durable applied tip from
  `chainstate` and canonical retained bodies. It does not derive
  authority from a checkpoint.

### `RCV-06`: Tip change during rebuild

- The applied tip moving while a rebuild is in flight does not restart or
  abort the rebuild. The worker converges on the new applied tip.
- The new target is identified by its full block hash and the durable
  `CommitId` from `chainstate`, not by height alone.
- A rebuild that has already consumed canonical bodies re-uses valid
  prepared work; stale work is discarded.

### `RCV-07`: Missing disconnected body routes to canonical rebuild

- A rewind whose disconnected body is missing cannot produce exact-identity
  deletions. The affected capabilities reset and rebuild from canonical
  bodies instead of failing the worker.
- The worker does not fabricate missing body bytes or substitute a
  different block at the same height.
- Rebuild uses retained canonical bodies from the durable `refs` or an
  explicit archive input. A pruned node reports unavailable history.

### `RCV-08`: Exact disconnect and reorg

- Disconnect restores the pre-connect live coins, consensus bookkeeping,
  and metadata. Reconnection applies the new branch using ordinary connect.
- Missing retained undo fails closed. Optional consumer lag cannot retain
  unlimited segments.
- Reorg memory stays bounded while depth grows. Restart at each
  intermediate committed ancestor is valid.
- Streaming reorg uses bounded descriptors, before-images, and committed
  ancestors with exact inverse transitions; no whole-branch preload.
- Chainstate owns planning, body loading, mutation, invalidation, and
  disconnect-debt settlement, and takes the mandatory retention pin each of
  those transitions needs; storage/pruning owns the retained-history
  authority those pins draw on (`ARCH-07`). Node-owned observers receive
  each committed connect/disconnect to reconcile mempool, mining, RPC/ZMQ,
  and index wakes. Those observers are not recovery authority and cannot
  widen chainstate's dependency graph.

### `RCV-09`: Fresh replay and schema refusal

- The changed durable format requires an increment of `CURRENT_SCHEMA` for
  the authoritative chainstate bytes. Keep no translator, no legacy reader,
  and no in-place converter. The one approved exception is the version-1
  checkpoint header artifact, still read as described in "Checkpoint header
  artifact and side branches" below.
- An incompatible datadir returns `incompatible_schema` at open. Existing
  operator datadirs stay untouched. A fresh replay uses a separately named
  directory with explicit resync instructions.
- `CURRENT_SCHEMA` covers only authoritative chainstate bytes.
  Estimator-only, discovery-only, and index-only format evolution keep
  `CURRENT_SCHEMA` unchanged. Each carries its own owner-local version.
- A corrupt, missing, or unknown owner-local version never fails
  authoritative startup. Estimator degrades to insufficient data,
  discovery degrades to seeded or empty with reseed or rebuild status, and
  an affected index capability reports unavailable or rebuilding through
  the existing `CapabilityState` vocabulary and rebuilds from retained
  canonical data.
- A rejected owner-local file is left in place until explicit authorized
  rebuild. It is never silently deleted.

### `RCV-10`: Checkpoint-worker removal

- Full-checkpoint publication is not recovery authority.
- The durable root and the ordered commit protocol are the only recovery
  authority. Checkpoints may remain as a maintenance and export command,
  but no code path treats a checkpoint as an authority for chainstate.
- Manual export and checkpoint commands still exist; they write a durable
  copy for operator convenience, not a new authority.

### `RCV-11`: Owner-local schema versions

- `CURRENT_SCHEMA` is the authoritative chainstate schema version. It
  increments only when the durable root format changes.
- The fee estimator carries its own estimator-owned version. The P2P
  discovery store carries its own discovery-owned version. The index
  carries its own durability marker (`[0x00, b'V']`, currently row-format 5),
  which recovery full-resets for rebuild on a mismatch. None of these
  increment `CURRENT_SCHEMA`.
- A missing or unknown owner-local version does not fail node startup.
  The affected owner degrades to a typed, logged state and rebuilds from
  canonical or seeded data.

### `RCV-12`: Recovery evidence warning and marker ordering

- The storage-owned `RecoveryEvidencePublisher`
  (`crates/storage/src/recovery_evidence.rs`) owns warning rendering, the
  warning snapshot, the marker/witness codec, and the atomic write
  protocol; it is evidence publication, not chainstate authority. It
  publishes a recovery fact only after the restored authoritative position is
  known; neither the warning store nor the marker may move chainstate. The
  node crate keeps `RecoveryReporter` (`crates/node/src/state/storage.rs`) as
  the composition adapter implementing `IndexAheadSink` and
  `RollbackWarningSource` alongside the storage capabilities it adapts.
- For checkpoint fallback and index-watermark-ahead evidence, the publisher
  first renders/logs the warning and updates the process-visible warning
  snapshot, then attempts the atomic durable marker write.
- Marker persistence failure is returned to the caller and keeps the warning
  visible for the lifetime of that process. Callers that require durable
  evidence fail closed rather than pretending the marker succeeded.
- Marker and applied-tip-witness payloads are checked against `MAX_FILE_BYTES`
  after being read; marker publication uses the owner-local atomic
  write/rename/directory-sync protocol. Corrupt or mismatched evidence is
  rejected instead of silently becoming authority.
- Tests for recovery evidence must cite this clause (and `RCV-04` where they
  exercise crash/failure behavior) so extracted test modules do not become an
  independent specification.

### `RCV-13`: Chain transaction count recovery

The in-memory chain transaction count uses zero as the durable-compatible
sentinel for unknown. Legacy datadirs that predate the counter, rewinds that
would underflow, and additions that would overflow must preserve or restore
zero; they must never clamp or wrap into a plausible known total. A known
count advances and rewinds by the exact transaction delta.

### `RCV-14`: Checkpoint reconcile against the durable head

The checkpoint publisher freezes the published state, which always trails or
meets the durable head: publication follows the batch. Before writing, the
publisher loads the head and refuses a checkpoint whose tip is at or above
the head without being certified by it. A tip below the head is the
committed-but-unpublished gap a crash can leave; checkpointing the older
state is harmless and keeps the node operating until replay closes the gap.

### `RCV-15`: Disconnect marker recovery

A surviving disconnect marker is recovery evidence, not a permanent
operator refusal. The durable head is the commit point. `RCV-14` freezes
each checkpoint against the head at its own moment, so a checkpoint can sit
above a head that a later disconnect rewound below it: the restored state
may lead the head, not only trail it. Recovery picks the one mode the
restored state allows, and the warning names it:

- `cold-replay` — nothing was restored. The certified head chain is the
  whole state, and `reconcile_at_boot` replays it from genesis.
- `gap-replay` — the restored tip lies on the certified head's ancestor
  chain (the head itself included). The ordinary gap walk closes the
  committed-but-unpublished lag onto it.
- `checkpoint-rewind` — the restored tip is not on the head's ancestor
  chain: it leads the head, meets its height with another hash, or sits
  below it on a branch a reorg already left. Recovery rolls the restored
  coins back block by block against the undo rows the head batch
  certified — to the head, or to the fork it descends from, where
  reconciliation takes over — and never re-commits the head.

Every mode warns with the marker identity and the mode chosen, publishes a
clean checkpoint, and retires the marker only after that publication is
durable.

- A restored tip that leads the head is recovery input, not divergence, and
  the rewind discards it. An unreadable marker or head, no head at all, a
  body or undo row the durable evidence does not hold, or a chain that is
  not an authenticated ancestor prefix of stored bodies is divergence:
  recovery fails closed, retains the marker, and startup stops. No partial
  success serves.
- `InFlight` stays barred from ordinary checkpoint publication; only the
  recovery transaction may publish over it, and only after the replay
  succeeded. Retirement is an unconditional clearing owned by that recovery
  path alone.
- Core v31.1 reconstructs interrupted branch state the same way:
  `Chainstate::ReplayBlocks` reads the two persisted heads, rolls the
  restored coins back to the fork point, replays the active chain forward,
  and flushes the result
  (`bitcoin-core/src/validation.cpp`). An interrupted disconnect
  is replayed, not deleted.

### Checkpoint header artifact and side branches

The checkpoint header artifact restores the block tree, not only the active
chain. `crates/chainstate/src/checkpoint/headers.rs` owns its layout; the
manifest-bound artifact SHA-256 authenticates every byte, and no other file
persists branch state.

- Version 2 is written: the active ancestry of the selected best tip, then
  every tree node off that ancestry that is not `Invalid`, whose chainwork
  does not exceed the selected best tip, and whose parent is retained
  (`BlockTree::replayable_side_nodes`), in insertion order. Invalid subtrees
  and branches heavier than the selected tip are excluded whole, so the
  restored tree selects the same best and applied tips as an active-only
  restore. Manifest `header_count` and both chain commitments still cover
  only the active ancestry.
- Restore replays the side section after the authenticated active section
  through the same historical contextual header validation. Each side header
  must add one new node under a restored valid parent and must not displace
  the best tip; a wrong length, duplicate or orphan header, failed
  validation, displaced tip, or manifest/artifact version mismatch is a
  corrupt checkpoint. Side nodes restore as header-valid with unknown chain
  transaction counts. Replay keeps their relative insertion order, which the
  stale-tip retainer uses as learn order.
- Version 1 (active ancestry only) remains readable and restores no side
  branches; the next publication writes version 2. No datadir epoch changes
  and no existing checkpoint is rewritten or deleted on load. A binary that
  predates version 2 refuses a version-2 checkpoint as corrupt, so downgrade
  needs a fresh resync into a separate datadir.
- Journal replay reuses a restored node with the record's hash and parent
  instead of inserting a duplicate, as block connection does.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
ordered commit protocol, durable root, `DurableHead`, `CommitId`,
`CapabilityState`.
