# Test evidence ownership

Tests protect an observable contract or an independently checked result.
A test that only restates a constructor, field layout, historical task plan,
lookup count, or private call order is not a permanent compatibility rule.
Performance claims require measured evidence, not a source-shape assertion.

The [source and test organization policy](../policies/source-organization.md)
owns placement, naming, fixture scope, and exceptions. This contract owns the
proof boundary and retained guarantees; moving a test does not change them.

## Retained proof owners

The current suite is classified by owner family below. Every surviving test
belongs to one of these current-contract or externally anchored evidence
families. Tests may move with their owner without preserving an old module
layout; a new test that does not fit one of these families needs a contract or
regression invariant before it is retained.

| Owner | Contract and failure boundary | Disposition |
| --- | --- | --- |
| Primitives parsing, encoding, layout, arithmetic | Bitcoin wire identities, canonical bytes, malformed and truncated input; `P2P-01`, `VAL-02` | Keep independent golden/rust-bitcoin comparisons and rejection boundaries. Internal layout is not a public contract. |
| Script and consensus | `VAL-02`; Core vectors, signed-spend parity, witness and Merkle commitments, activation, missing coins and duplicate inputs | Keep. Remove lookup-count and parser-shape assertions when the same result has independent evidence. |
| Chain, chainstate and UTXO | `ARCH-07`, `RCV-01`..`RCV-15`, `EVT-01`..`EVT-06`; ancestry, authoritative mutation, branch selection, coin state, connect/disconnect, recovery and crash outcomes | Keep behavioral, differential and property tests with the owning crate. Do not retain node-local apply-shape tests or replace corruption refusals with fixture round trips. |
| Storage and index | `IDX-01`..`IDX-10`, `FP-01`..`FP-04`, recovery; backend persistence, capability errors, cursor/reorg recovery | Keep. Backend and restart tests cannot be replaced by in-memory mocks. |
| Mempool | `MPL-01`..`MPL-04`, `POL-01`..`POL-06`; admission, replacement, dependencies, sequence, fencing and bounded orphans | Keep mutation and concurrency scenarios; reorg admission must use the same current-chain evaluator. |
| P2P | `P2P-01`..`P2P-05`; independent wire envelopes, live peer identity, budgets, body attribution, stalled requests and branch recovery | Keep. Assert peer-visible requests and eventual application, not incidental message ordering. |
| Cross-crate synchronization | `SYNC-01`..`SYNC-07`; [clauses, change-class review guidance and proof gaps](synchronization.md) | Reuse the P2P recovery, node application/publication, chainstate, storage/index and process families in this table. Keep representative tests that cross real domain boundaries; a local `TestChain` scheduling fixture does not establish durable application, and a finite scenario does not prove unconditional progress. |
| Mining | External miner/API clauses, coherent template generations and invalid candidates | Keep independently valid blocks and public submission behavior. |
| RPC | `API-*`, `WF-*`, `MRPC-*`; requests, errors, values, capability refusal and coherent views | Keep public-boundary and pinned Core comparisons. A method inventory is not a successful call. |
| Node and binary | `EMB-*`, `EVT-*`, recovery; public process startup, shutdown, persistence, reorg and observer ordering | Keep process and durability scenarios. A successful `--help` exit does not prove lifecycle behavior. |
| Cargo dependency/feature graph | `ARCH-01`, `DEP-*`, `FEAT-*` | Keep the metadata-based dependency-direction gate, feature builds and cargo-deny. Do not add a second uniqueness checker. |
| Reference custody | `REF-*`, `CORP-*`, `QAC-01`; artifact identity and unavailable inputs | Keep typed refusal cases and real process/corpus custody. Mutate parsed fields rather than matching historical TOML text. |
| Benchmark evidence | `HPA-*`; identities, overlap and repeated samples | Run evidence-tool tests with `--bench evidence`; measured campaigns remain separate. No frozen path/cell inventory in normal Cargo tests. |
| Formal models | [Formal verification contract](formal-verification.md) | Run `scripts/check_models.py` in the manual lane. Custody checks and runner regressions are not model proofs. |

This table is the contract → proof matrix at suite-family granularity. Exact
test names are intentionally not normative: the executable evidence may be
consolidated or rewritten as long as the row's independent reference,
failure-path coverage, and named contracts remain proved.

## Evidence boundary

Retain tests for current contract proof or an independently established real
regression. The full dependency, feature, process, and recovery lanes own their
verification; a layout cleanup does not change those obligations. Production
APIs must not survive solely to satisfy a deleted fixture.

A formal runner test uses a synthetic executable and cannot establish a
model property. A successful evidence-parser test cannot establish a
performance improvement. Missing Core binaries, corpora, model completions
or measured comparisons remain unavailable evidence, never implied passes.
