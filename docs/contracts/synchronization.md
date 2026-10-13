# Synchronization contract

The Node-level, cross-crate synchronization contract. Each domain owns its
local mechanics — `p2p` the peer and download policy, `chainstate` the
applied-chain transition, `chain` the header tree and IBD latch, `index` the
derived capabilities, `storage` the durable head, `node` the composition.
This page owns only the invariants across those boundaries. Local rules stay
with their owners; they are cited, not copied.

Its purpose is regression protection: a feature can be correct in isolation
and still stall or invalidate node-wide synchronization (AssumeUTXO and
historical backfill both did). New features and refactors must preserve the
guarantees here even when component-local correctness holds.

## Existing authoritative contracts

These remain authoritative. This page adds no second source of truth for
their content:

- [architecture.md](architecture.md) `ARCH-07`/`ARCH-07a`/`ARCH-07b`:
  authoritative chainstate transitions, one active chainstate, AssumeUTXO
  roles, historical validation and finalization; `ARCH-08`: pruning/retention;
  `ARCH-09`: read-only capability boundaries.
- [p2p-wire.md](p2p-wire.md) `P2P-03`/`P2P-05`/`P2P-06`/`P2P-10`: peer
  capability, download/frontier recovery, body/header admission, presync
  gating.
- [recovery.md](recovery.md) `RCV-01`–`RCV-15`: durable commit, restart,
  crash, reorg, schema-refusal guarantees.
- [indexing.md](indexing.md) `IDX-01`–`IDX-10`: capability gating, watermark
  identity, query consistency, backfill/reorg worker behavior.
- [chain-events.md](chain-events.md) `EVT-01`–`EVT-05`: ordered post-commit
  publication and consumer cursors.
- [mempool-mutations.md](mempool-mutations.md) `MPL-01`–`MPL-04`:
  chain-change generation fencing around admission.
- [embedding.md](embedding.md) `EMB-*`: startup/shutdown/worker lifecycle and
  readiness.
- [../CONSTRAINTS.md](../../CONSTRAINTS.md): repository-wide bounded-resource
  and data-safety invariants.

## Clauses

### `SYNC-01`: Independent progress authorities

The header tip, the applied/validated tip, the AssumeUTXO historical
validation frontier, and each derived-index watermark describe different
facts. One does not prove the others. Publication and query semantics name
the owning authority:

- Header tip: published by header admission inside the chainstate transition
  (`ARCH-07`), read through `SyncChain::chain_tip`.
- Applied tip: published only by a durable commit (`P2P-05`, `IDX-03`), read
  through `SyncChain::applied_tip`.
- Historical validation frontier: owned by the `AssumeUtxoManager` historical
  role (`ARCH-07b`), reported through `getchainstates` (`API-33`).
- Capability watermark: owned by `IndexWriter::commit_block` (`IDX-10`),
  surfaced by `getindexinfo` (`IDX-02`).

No consumer may derive "fully synchronized", "validated", or "ready" from a
different frontier. `sync_progress` reports blocks and headers separately for
this reason (`crates/rpc/src/context.rs`); a `blocks == headers` projection is
not validation progress when an AssumeUTXO historical role is still replaying.

### `SYNC-02`: Canonical applied progress; transient work is a hint

The selected header ancestry plus the chainstate's committed applied frontier
decide what block must be applied next. Download-window cursors, scheduled
requests, peer claims, staged bodies, and cached snapshots are transient work,
never a chain authority. `P2P-05` owns the rule that an unowned frontier
becomes requestable again after cancellation, peer replacement, rejection,
rollback, or reorg; this clause owns the system consequence: a stalled or
cancelled scheduler run never leaves the node without a discoverable next
block, and no transient completed state is read back as chain progress.

### `SYNC-03`: Foreground progress, resource, and failure isolation

Cross-feature obligation: optional subsystems — historical validation,
derived-index backfill, RPC/observer work, mining — must not prevent
authoritative chain synchronization from making progress under documented
resource, fairness, and data-availability assumptions.

- Optional components acquire no authority to publish active-chain
  transitions and never route historical effects through live mempool, mining,
  RPC/ZMQ, or index-event publication (the historical chainstate's events are
  detached, `ARCH-07b`).
- Slow or failed consumers must not hold chain-transition/storage locks
  through unbounded downstream work. Known contention paths carry their own
  evidence: the index seed's stable-view guard is bounded batched streaming
  (`crates/index/src/runtime/rollback.rs`), and apply holds fences only around
  the mutation window (`EVT-02`).
- Resource use and backpressure have an owner and a bound (`CONSTRAINTS.md`);
  component failure stays isolated unless it compromises shared authoritative
  data or a required commit (`IDX-07`, `EVT-04`).
- This clause warrants conditional progress only. It is not absolute
  scheduling fairness and not a throughput or latency SLA under globally
  saturated storage.

### `SYNC-04`: Failure classification and recovery semantics

Distinguish, and never conflate:

- **Invalid header** — rejected by header admission (`P2P-10`); the peer's
  ancestry is not admitted.
- **Invalid body** — rejected by the chain transition; the peer delivered a
  bad body. An otherwise valid header branch is not invalidated because a
  peer delivered a bad body; the body gate clears and another peer may serve
  it (`P2P-05`).
- **Peer/transient delivery failure** — strike/retry/handover under the
  existing header-request and window rules; no chain-state change.
- **Unavailable history** — missing or pruned bodies. Reported as unavailable
  or recoverable (`RCV-05`, `IDX-03` `TxQueryError::Unavailable`), never as an
  empty successful answer.
- **Durable corruption** — fail closed with the owning recovery story
  (`RCV-01`; assumeutxo mismatch fails closed across both roles,
  `crates/chainstate/src/assumeutxo.rs`).
- **Terminal validation failure** — the historical role stops; it never
  silently converts into successful synchronization.

Failed validation publishes nothing; settlement failure closes admission for
recovery and stays an error even when the anchor committed (`API-33`).

### `SYNC-05`: Validated/durable progress and coherent cross-consumer views

Received, staged, and decoded bytes are not validated or committed progress.
Only the authoritative validation plus durable commit publishes applied state
and corresponding ordered events. Historical validated progress has its own
durability authority and cannot advance the active tip (`ARCH-07b`).

RPC, mempool, mining, indexes, and other consumers must consume committed,
generation-coherent owner outcomes. Reconstructing success from a cursor, the
availability of stored bytes, or partial index history is a bug:

- Mempool admission is generation-fenced (`MPL-04`); a chain-change fence
  catches chain moves that land between snapshot capture and admission.
- Index queries gate on watermark identity and runtime revision and refuse
  torn reads (`IDX-03`).
- RPC tip reads use the retained applied publication; a moved chain
  generation returns the declared unavailable response, never a mixed-tip
  page (`WF-02`, `EVT-01`).

A feature must not introduce mixed-tip or mixed-generation responses, stale
admission, or false-ready projections.

### `SYNC-06`: Liveness assumptions and proof obligations

Distinguish:

- **Safety**: invalid or uncommitted states are never promoted, and stale
  cross-domain views are refused. Unconditional.
- **Conditional liveness**: given live capable peers, retained or retrievable
  required history, sufficient resources, and no terminal consensus/storage
  failure, bounded failed requests and lost work eventually permit fresh
  scheduling and progress. Not promised with unavailable block history
  (`MissingBody` needs the fetch path, `crates/p2p/src/sync/historical.rs`),
  unusable peers, or terminal fail-closed conditions.

Stalled-work ownership: the download orchestrators detect unreleased window
work each tick (`crates/p2p/src/sync.rs`, `P2P-05`); the index worker detects
its own unrested cursor each wake (`IDX-08`); the event loop's sync tick
drives both. Progress is observable through `getchainstates`, `getindexinfo`,
and `getblockchaininfo`; no new global sync manager, mirrored cursor,
persistent verdict, or extra state machine is implied by this clause.

### `SYNC-07`: Required history remains available until consumed

A new feature, optional index, snapshot workflow, or pruning optimization
must not remove, discard, or make unreachable block bodies, undo records,
validated historical receipts, or other history while an authoritative,
currently required synchronization/recovery operation still depends on them.

- Retained bytes alone do not certify historical validity; certification
  follows the owning durable/recovery policy (`RCV-*`, `ARCH-07b`).
- A missing prerequisite is reported as unavailable/recoverable, never as
  successful progress or a proven-absent object.
- The retention/pruning authority stays in `ARCH-08`/storage; the
  index-specific consequences stay in `IDX-*`. This clause owns only the
  system-level consequence: a feature must not destroy the prerequisites of
  already-supported sync, reorg, AssumeUTXO historical validation, or
  authorized catch-up/recovery.
- Explicitly permitted pruning and a documented inability to serve pruned
  history are not violations; do not promise archival availability on a pruned
  node.

## Ownership map

| Frontier/work item | Owning authority | Published by | Read by |
| :--- | :--- | :--- | :--- |
| Header tip | Chainstate transition (`ARCH-07`) | `SyncChain::chain_tip` / `TipReader` | download policy, `getblockchaininfo.headers` |
| Applied tip | Durable commit (`P2P-05`, `IDX-10`) | `SyncChain::applied_tip` / `ArcSwap<TipSnapshot>` | RPC tip reads, index gating, getchainstates |
| AssumeUTXO historical frontier | `AssumeUtxoManager` historical role (`ARCH-07b`) | `getchainstates`/`getindexinfo` via `API-33` | operators, `SYNC-06` observability |
| Capability watermark | `IndexWriter::commit_block` (`IDX-10`) | `getindexinfo`, `getcapabilities` (IDX-02) | RPC queries, wallet consumers |
| Download window/staging | P2P `BlockSync` (`P2P-05`) | — transient | header/body admission |
| Index worker cursor | `DerivedIndexRuntime` (`IDX-08`) | capability watermarks | query gate |

## Proven by

The clauses are cross-cutting; each inherits the owners' executable proof
plus the whole-node regression suites:

- `crates/chainstate/src/` connect/disconnect/window modules and the
  `RCV-04` crash matrix (`crates/node/tests/crash_recovery.rs`): durable
  commit and fail-closed recovery (`SYNC-04`, `SYNC-05`).
- `crates/p2p/src/sync/` module tests: frontier recovery, peer handover,
  historical fetch/fallback (`SYNC-02`, `SYNC-04`).
- `crates/index/src/runtime/{reconciliation,rollback,recovery_tests}.rs`:
  watermark reseed/restart/reorg behavior (`SYNC-05`, `SYNC-07`).
- `crates/chainstate/src/assumeutxo.rs` fail-closed paths and the assumeutxo
  process E2E (`e2e/tests/assumeutxo.rs`): historical-role isolation,
  finalization, and unavailability reporting (`SYNC-01`, `SYNC-04`).
- `crates/node/tests/unit/state/tests/events.rs`
  (`record_returns_hints_in_commit_order_and_advances_the_snapshot`,
  `active_chain_snapshot_anchors_at_restored_tip_after_restart`): applied-tip
  publication ordering across restart (`SYNC-01`, `SYNC-05`).
- `crates/rpc/tests/` capability and policy suites: coherent consumer views
  and refusal-on-incomplete (`SYNC-05`).
