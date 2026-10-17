# Preserved block-body allocation audit

The measured change replaces the full-block serialization used only to check
the length of preserved bytes in `chainstate::connect` with
`ConsensusEncode::consensus_size`. This removes a temporary full-body buffer
after validation. The exact raw/decoded identity proof remains in
`prepare::bytes_are_block`; the debug serialization assertion and the
no-preserved-body fallback remain too.

This is a bounded native-engine allocation result for #1570. Historical
mainnet receive-to-commit and whole-node IBD non-regression are **BLOCKED**:
this run has no contiguous historical corpus with its predecessor UTXO state
or before/after release daemon IBD artifacts. It does not qualify a whole-node
speedup or close the issue. Kernel performance was not measured.

## Ownership and repeated work

The following are source-trace counts and ownership findings, not dynamic
decode/hash counters. Both single-block connect and the prepared-window path
reach the same `connect` persistence transaction.

| Boundary | Current work and decision |
| --- | --- |
| P2P `InboundBlock` | A wire block owns one decoded `Block` and its preserved `Bytes`. Local `from_decoded` injection instead serializes a supplied tree; that is fixture work, not an extra production receive serialization. |
| `BlockStager` / `sync::commit` | Staging moves the tree and bytes into `ReceivedBlock`, then `DrainedBlock`. Successful windows borrow `&Block` and shallow-clone `Bytes`; they do not deep-clone each tree. Partial-failure restoration clones the uncommitted suffix, intentionally keeping retry state. No staging changes. |
| `prepare::parse_block_for_apply` | One streaming canonical encode/compare binds raw bytes, including witness, to the tree without allocating a whole-body buffer. One native checked borrowed-layout parse derives facts; it is not another materialized transaction tree. Keep both independent checks. |
| Native `kernel::NativeBlock` | `txids()` copies the fact txids; `derive_facts()` clones facts for `BlockView`. Kernel derives facts from a txid-vector copy. These are real metadata copies, not repeated native transaction hashing. Lifetime/ownership changes were not measured here and are deferred. |
| Transaction planning / resolved UTXOs | One plan tracks same-block dependencies; ordered overlay/prevout resolution fixes each transaction's inputs before parallel scripts. Existing serial-lookup evidence remains authoritative. Structural prechecks currently follow window resolution; no rejection-order change. |
| Script preparation | Resolved `TxOut`s move into `TxPrep`; native `PreparedTransaction` validates ordered identities then clones outputs and scripts into its owned cache lifetime. Transaction-wide sighash material is shared across inputs. Borrowing prevouts would require changing the parallel-unit lifetime boundary; no such optimization or measured saving is claimed here. |
| `connect` / persistence | With a body consumer and preserved raw bytes, the old release guard called `consensus_bytes(block).len()`: one allocation and one complete output serialization per committed block. The candidate computes sizes, retaining the already-bound `Bytes`. No transaction precomputation, UTXO/undo mutation, journal ordering, head publication, or durable representation changes. |

The targeted output writes eliminated are exactly the serialized lengths of
the committed blocks (header, transaction fields and witness). Allocator
counters below measure requested heap bytes, not memcpy traffic, RSS, live
memory, database write volume, or CPU instructions. Other copy volumes and
dynamic decode/precompute counts remain unmeasured; the table must not be used
as a full-path profiler result.

## Reproduction and workload

Build the same harness at baseline `ed806ddec` and candidate `bc008b61a`:

```powershell
cargo +1.99.0 build --locked -p bitcoin-rs-node --no-default-features --features fjall --bench block_dataflow --profile quickstart
$env:RAYON_NUM_THREADS = '4'
# Run the produced executable directly with argument 6, on CPUs 0..3.
# Alternate baseline/candidate three times; retain each stdout as JSONL.
```

`block_dataflow` uses the existing `NodeState` test seam with fresh fjall
storage per sample, default regtest configuration, full native validation,
assume-valid height zero, no listeners and 32 MiB dbcache. Bootstrap and
header admission happen outside the timed region. `commit` connects each
block through the authoritative transition; `sync` sends local inbound
blocks through production BlockSync admission, bounded staging, window
verification and commit. Each sample asserts the exact final tip hash.
Commit durability is unchanged. Teardown is outside the measured interval.
The body index uses `write_deferred`; body/index sync precedes the final
`write_durable_if` head receipt (fjall `PersistMode::SyncAll`). Direct connects
retain per-block receipts and BlockSync retains its existing grouped
publication. The default journal policy is 500 blocks / 5 seconds.

| Corpus | Measured range | Blocks | Raw bytes | Scripts |
| --- | --- | ---: | ---: | --- |
| `early_coinbase` | regtest 1..32 | 32 | 4,592 | Small coinbase-only bodies |
| `legacy_512_inputs` | regtest 101..116 | 16 | 338,528 | One 512-input spend per block, mature funding coinbases, OP_TRUE |
| `witness_512_inputs` | regtest 101..116 | 16 | 4,657,072 | One 512-input P2WSH spend per block; 520-byte witness item followed by OP_DROP OP_TRUE; valid BIP141 commitment |

These are deterministic synthetic early-shaped and modern-shaped workloads,
not historical Bitcoin blocks. The scripts isolate body handling and do not
represent signature throughput. The separately timed
`decode_and_ingress_fixture` includes `deserialize` plus `from_decoded`'s local
serialization; production socket receive preserves bytes instead. Do not add
that interval to apply and call the result network IBD.

The global System allocator counts allocation/reallocation events and their
requested sizes across all threads while each interval is enabled. Body-size
buckets count any allocation of a corpus body length, not a tagged allocation
type: small coinbase sizes alias unrelated allocations. Metrics include
background allocation activity, so total requested bytes can vary even when
the removed serialization is deterministic. The instrumentation itself adds
atomic-counter overhead to both arms.

The `quickstart` profile is optimized without debug assertions, with LTO off
and 16 codegen units. Its wall times are diagnostic, not release-IBD
qualification. The retained manifest supplements the embedded Windows
`unknown-cpu` identity with CPU, affinity, RAM, OS, storage and toolchain.
Per-corpus identities include binary/config/corpus digests and stop hashes;
the config digest uses the common base config, excluding each fresh temporary
directory. See the shared [evidence rules](README.md) for qualification rules.

## Retained results

[Manifest](data/preserved-body-20261017/manifest.json) records both source
commits and binary hashes. [Summary](data/preserved-body-20261017/summary.json)
contains p50/p95/p99/max/min and counts for every metric and interval. Raw
stdout is retained in the same directory as `baseline-{1,2,3}.jsonl` and
`candidate-{1,2,3}.jsonl`, in alternating execution order. All six processes
exited successfully; no timing outliers were removed. Each arm has 18 timed
samples per corpus/mode, plus three excluded warmups. Quantiles use nearest
rank; p50 averages the middle two observations.

Apply allocation results, p50 per measured block group:

| Corpus / mode | Events baseline -> candidate | Requested bytes baseline -> candidate | Removed serialized output bytes |
| --- | ---: | ---: | ---: |
| Early / commit | 3,578 -> 3,546 | 2,401,022 -> 2,396,430 | 4,592 |
| Early / sync | 2,976 -> 2,944 | 2,540,678 -> 2,536,086 | 4,592 |
| Legacy / commit | 78,052 -> 78,036 | 22,662,652 -> 22,324,124 | 338,528 |
| Legacy / sync | 77,890.5 -> 77,874.5 | 26,832,950 -> 26,494,422 | 338,528 |
| Witness / commit | 95,174.5 -> 95,158.5 | 41,193,424 -> 36,536,352 | 4,657,072 |
| Witness / sync | 95,060 -> 95,044 | 45,365,274 -> 40,708,202 | 4,657,072 |

In both high-input corpora, every baseline apply sample has 16 body-length
bucket allocations; every candidate has zero. Each early candidate removes
32 events, but its remaining body-size bucket entries are aliases, not body
serializations. Fractional event medians reflect background-event variation,
not fractional allocations. Fixture decode/ingress event counts and requested
bytes are unchanged. Native layout parses, identity comparisons and
transaction precomputations were not altered.

Diagnostic apply wall in milliseconds (18 samples per arm/cell):

| Corpus / mode | Baseline p50 | Baseline p95/p99/max | Candidate p50 | Candidate p95/p99/max |
| --- | ---: | ---: | ---: | ---: |
| Early / commit | 152.014 | 190.257 | 149.282 | 194.660 |
| Early / sync | 19.844 | 49.069 | 21.599 | 28.574 |
| Legacy / commit | 249.896 | 345.441 | 260.761 | 2,872.231 |
| Legacy / sync | 183.792 | 226.394 | 187.779 | 661.307 |
| Witness / commit | 354.131 | 604.434 | 339.321 | 1,343.465 |
| Witness / sync | 279.728 | 351.789 | 290.468 | 900.758 |

Per-run apply medians in milliseconds, preserving execution order within
each arm:

| Corpus / mode | Baseline runs 1 / 2 / 3 | Candidate runs 1 / 2 / 3 |
| --- | --- | --- |
| Early / commit | 141.058 / 154.026 / 153.601 | 153.368 / 146.326 / 146.861 |
| Early / sync | 19.075 / 23.254 / 19.648 | 22.837 / 22.254 / 19.906 |
| Legacy / commit | 248.831 / 244.423 / 283.033 | 249.109 / 467.485 / 255.407 |
| Legacy / sync | 179.484 / 184.143 / 191.353 | 179.277 / 206.349 / 183.886 |
| Witness / commit | 363.457 / 349.993 / 368.534 | 332.527 / 903.982 / 322.051 |
| Witness / sync | 286.672 / 284.618 / 278.738 | 279.530 / 617.437 / 278.788 |

The allocation reduction exceeds background variation and matches one
serialized-body buffer per block. **The timing/non-regression gate did not
pass.** Candidate run 2 has large delays, stability exceeds the 5% rule, and
several pooled medians/tails regress beyond the shared guard limits. The
cause of the delays was not established. These observations neither qualify
a speedup nor establish IBD non-regression; they must not be dismissed as
noise to promote the change. This is a draft optimization pending a stable
release-profile comparison and the missing historical/whole-node cells.

## Regression evidence

The new owner-local `connect::tests` regression rejects equal-length
raw/decoded witness disagreement before commit, checks exact persisted and
returned bytes, rejects a matching-raw invalid body without advancing the
tip, then disconnects and reconnects through the no-raw fallback. It runs for
each compiled supported validation engine; this local run compiled native.
It is not a process-restart test.

The native fjall chainstate library suite passed 132 tests, including existing
checkpoint, replay/reopen, crash/failure and window tests. The shared-sighash
integration suite passed four tests. Strict Clippy covered the new node bench
and chainstate library; formatting passed. Existing CI/reference and daemon
journeys remain their own proof owners.
