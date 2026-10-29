# Contracts

`docs/contracts/` owns current normative behavior. Each page names its owners and behavioral proof boundaries. `CONCEPTS.md` owns vocabulary; `docs/benchmarks/` holds measured evidence.

## Precedence

1. `docs/contracts/`
2. Source comments for local invariants
3. `docs/policies/` for detailed domain matrices
4. Informative documents and historical evidence

When code and a contract disagree, fix the drift in the same change. Do not duplicate complete contract text into consumers; cite the owning clause instead.

## Index

| Contract | Clauses | Scope |
| --- | --- | --- |
| [architecture.md](architecture.md) | `ARCH-01`–`ARCH-09` | Layering, storage confinement and bounded prefix scans, composition, chainstate authority, single mutation owners, capability boundaries, immutable snapshot/replay seeding, one immutable `BlockPayload` |
| [validation-default.md](validation-default.md) | `VAL-01`–`VAL-03` | Kernel/native default decision and portable validation |
| [consensus-difficulty.md](consensus-difficulty.md) | `DAA-01` | Core 31.1 difficulty adjustment: clamped retarget timespan and testnet minimum-difficulty exception |
| [indexing.md](indexing.md) | `IDX-01`–`IDX-12` | Capability gating, coherent reads, reset/rebuild, reorg reconciliation, worker scheduling, canonical row cardinality, atomic commit durability, portable `TxLookup` bundle export/restore, historical prefix queries |
| [recovery.md](recovery.md) | `RCV-01`–`RCV-15` | Durable root, ordered commits, crash outcomes, reorgs, schema refusal |
| [chain-events.md](chain-events.md) | `EVT-01`–`EVT-06` | Applied-chain event seam, consumer cursors, and settled polling/positional replay (`crates/node/src/chain_feed.rs`: `ChainSubscription`, `ChainUpdate`, `ChainStep`, `ChainReplay`, `ChainTarget`) |
| [mempool-mutations.md](mempool-mutations.md) | `MPL-01`–`MPL-04` | Mutation ordering, sequence events, chain-change fencing |
| [mempool-policy.md](mempool-policy.md) | `POL-01`–`POL-06` | Admission owner, policy pins, preview/finality, replacement and package rules |
| [pool.md](pool.md) | `POOL-01`–`POOL-09` | Default-off experimental native SV1/SV2 pool, PPLNS accounting, and external-signer boundary |
| [external-api.md](external-api.md) | `API-01`–`API-35` | RPC/REST/ZMQ behavior, mining requests, errors, and reference provenance |
| [wallet-facing.md](wallet-facing.md) | `WF-01`–`WF-03` | Public wallet-facing surface and isolation from node internals |
| [p2p-wire.md](p2p-wire.md) | `P2P-01`–`P2P-11` | Wire compatibility, peer leases, demonstrated capability, canonical frontier recovery, connected-socket posture, body-carried header admission, header-led block announcements with bounded ingress, inbound admission and outbound service gating, block-body service eligibility, header presync admission gating, BIP324 v2 transport negotiation |
| [synchronization.md](synchronization.md) | `CONV-1`, `SYNC-01`–`SYNC-07` | Node-level, cross-crate synchronization: top-level conditional convergence property (`CONV-1`) with the pipeline obligations it discharges (discovery, scheduling/execution, recovery closure, non-starvation, durable convergence), independent progress authorities, transient-hint rule, work drivers, failure classification, coherent consumer views, retained-history availability; open contention/proof gaps recorded, not assumed away |
| [qa-corpus.md](qa-corpus.md) | `QAC-01` | Fuzz corpus provenance |
| [campaign-corpora.md](campaign-corpora.md) | `CORP-01`–`CORP-05` | C150/Cmodern custody and Core-framed corpus format |
| [muhash-rpc.md](muhash-rpc.md) | `MRPC-01`–`MRPC-03` | MuHash RPC arity and benchmark custody |
| [embedding.md](embedding.md) | `EMB-01`–`EMB-10` | Embedded lifecycle, shared node services and independent stall evidence |
| [storage-footprint.md](storage-footprint.md) | `FP-01`–`FP-04` | Offline apparent/allocated snapshot boundary and evidence limits |
| [hot-path-attribution.md](hot-path-attribution.md) | `HPA-01`–`HPA-13` | Product cells, overlap accounting, evidence identity, promotion thresholds |
| [dependency-range.md](dependency-range.md) | `DEP-01`–`DEP-02` | Declared Cargo ranges compile at their minimum and maximum resolvable versions; one copy each of `bitcoin`, `bitcoin_hashes`, `secp256k1`, `secp256k1-sys` |
| [feature-matrix.md](feature-matrix.md) | `FEAT-01`–`FEAT-02` | Named supported feature combinations; no empty backend markers on crates that do not own storage |
| [reference-set.md](reference-set.md) | `REF-01`–`REF-07` | Released Core, kernel, corpus, and formal-tool identities |
| [ecosystem-compatibility.md](ecosystem-compatibility.md) | `ECO-01`–`ECO-09` | External ecosystem compatibility strategy: black-box evidence, one representative consumer, evidence matrix and status vocabulary |
| [formal-verification.md](formal-verification.md) | Formal inventory | Model hashes, runner identity, return-code mapping, and proof status |
| [chainstate-journal-v1.md](chainstate-journal-v1.md) | `JW-*-1` | Chainstate journal writer: append ordering, durable head, rotation, retention, lifecycle |

## Vocabulary

Project-specific terms are defined once in [../../CONCEPTS.md](../../CONCEPTS.md).

The [documentation ownership policy](../policies/documentation.md) defines
where comments, numeric defaults, operator instructions, and verification
evidence belong. The [test-evidence contract](test-evidence.md) maps behavioral
obligations to proof families; exact test names are discovered from source and
Cargo test listings rather than copied into each clause.
