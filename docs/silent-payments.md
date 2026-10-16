# Experimental BIP352 public scan material

The opt-in `silent-payments` build feature exposes the experimental
`getblocktweaks` JSON-RPC extension when `--silent-payments` is enabled.
It projects one certified retained block using the existing stateless
`bitcoin-rs-index/silent-payments` codec (`transaction_tweak` / `block_tweaks`).
There are no durable tweak rows, startup rescan, wallet subsystem or new server.

## Using the service

Build with `cargo build --locked -p bitcoin-rs --features silent-payments`,
then start with `--silent-payments` (default: off). The corresponding environment
variable is `BITCOIN_RS_SILENT_PAYMENTS`; the TOML key is `silent_payments`.
Requesting this runtime option without the build feature fails configuration
validation before opening node data. Existing RPC cookie/Basic authentication
applies; `--rest` is not required and does not expose this method anonymously.

Call `getblocktweaks` with one positional or named `block`: an integer height
or a 64-character block hash on the applied chain. For example:

```json
{"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":{"block":850000}}
```

The result has `height`, `hash`, `tip_height`, `tip_hash`, `taproot_active`,
and `transactions`. Each transaction has its display `txid`, a compressed
33-byte `tweak` in hex, and complete `outputs` with integer `vout` and hex
32-byte `output_key`. An empty transaction list means a complete block with
no eligible candidates, including pre-Taproot blocks. No candidate is filtered
by value, spent status or wallet interest. The result proves neither wallet
ownership nor unspentness; use existing complete-block/transaction APIs to
verify candidates, chain membership and subsequent spends.

There is no range, subscription, secret-key or filtering parameter. Unknown
parameters are rejected. Unknown hashes return `-5`; stale/header-only hashes
and heights above the applied tip return `-8`. Incomplete ancestry, absent or
pruned/certification-limited history, recovery closure, a changed chain and
resource/admission refusals return `-1` with the reason, never empty success.
Corrupt/inconsistent retained material returns `-32603`. Storage/undo read
failures use a fixed public `-32603` message; details go to the node log.
Disabled runtime configuration returns `-32603` with an explicit disabled message.
A build without this feature returns method-not-found
(`-32601`). Initial block download returns `-10` before history I/O.

The service resolves ancestry against one captured applied publication and
uses the requested height's native Taproot activation rule. After projection
and JSON construction, it tries transition exclusion without waiting, checks
recovery state and the exact applied hash, and publishes only on success.
This is the response's consistency point; a chain can move after it. Clients
must keep block identities and rewind their own scan when the chain changes.
Restart recomputes from existing certified data; there is no tweak cursor or
cache to recover. No full-history readiness watermark is invented: each
requested block must establish its own coverage through the retained owner.

All callers share one nonqueued work slot. Each request also acquires an existing
full-block materialization permit. Busy responses ask callers to retry;
sequential requests have no timer-based admission delay. CPU projection
and body I/O hold no transition/tree guard. The final transition check uses
`try_lock_for(Duration::ZERO)`, so it never queues behind validation. These bounds and refusal
during IBD protect serving capacity; they are not a measured latency or
mainnet throughput guarantee. The global limit is shared across credentials,
not an anonymous per-IP quota.

Missing/pruned/certification-limited history requires restoring/replaying the
required data or using another complete source.
The retained-input owner's separate 64 MiB verbose-projection budget can reject
a consensus-valid block with many outputs before BIP352 computation. This
extension therefore does not guarantee scanning every valid block. An unchanged
resource-limit refusal cannot be resolved by retrying or replaying: the client
must obtain that block and authenticated prevouts from another complete source
and compute its scan material there. `getblock` verbosity 3 and `/rest/spenttxouts`
share this owner and are not bypasses for its read limits. No empty or partial
response marks such a block as scanned.

Ancestry selection uses the tree's trusted height index when available and
refuses fallback walks exceeding 4,096 parent hops. Selection runs inside the
same admission slot, before body I/O; header sync running ahead of the applied
chain cannot trigger an unbounded ancestry walk under the tree read guard.

## Semantics and reference pins

[BIP352 and its reference code/vectors](https://github.com/bitcoin/bips/blob/8754690b725e9aa93ca8bd91bf0ac85dc44ce096/bip-0352.mediawiki)
are pinned to `8754690b725e9aa93ca8bd91bf0ac85dc44ce096`.
The [WIP index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification/blob/dc705a055e72024e332e232cf038c96afd42d50e/README.md)
is separately pinned to `dc705a055e72024e332e232cf038c96afd42d50e`.
Its JSON examples do not define BIP352 cryptography.

Given a **consensus-validated** transaction, exact input-ordered prevout scripts,
and an explicit Taproot activation status (`taproot_active`), the codec requires
a P2TR output and an eligible input. When Taproot is not active, pre-activation
native witness v1 scripts are unassigned programs rather than BIP341 Taproot
outputs: the transaction produces no tweaks, and blocks return empty tweaks
without misinterpreting pre-activation witness spends as corrupt. When Taproot
is active, spending a native witness program with version greater than one
excludes the whole transaction (`coin.out.scriptPubKey.IsWitnessProgram && version > 1`,
matching Core `src/common/bip352.cpp`). Inputs spending non-v0 P2SH programs (including
P2SH-wrapped future witness scripts) contribute no key to shared-secret derivation
rather than disqualifying other eligible inputs. It extracts compressed keys from
P2PKH (hash-matching even malleated scriptSigs), P2WPKH and P2SH-P2WPKH.
Unsupported scripts and uncompressed keys contribute no key. Taproot uses the
even lift of the output key; script-path spends with the BIP341 NUMS internal
key are excluded after inspecting an optional annex without mutating it.

Keys are summed with multiplicity; zero intermediate sums are permitted.
No keys or a final point at infinity means ineligibility. The input hash is
`hash_BIP0352/Inputs(lowest_outpoint || compressed_sum)`. The lowest outpoint
is among **all** inputs, including ineligible types, sorted by its 36
serialized little-endian bytes (not display txid or numeric vout). A
zero/out-of-range scalar fails explicitly. The result carries txid, sum,
input hash, the 33-byte compressed point `input_hash * sum`, and every P2TR
candidate with its output index. Dust, spent and duplicate outputs are kept.

The receiver performs ECDH, label/output derivation and discovery locally.
Candidates must be verified with complete block/transaction data and chain
membership. A tweak does not prove an output is unspent or a wallet balance.
This codec does not authenticate caller-supplied scripts or execute consensus
validation; full validity comes from the already-validated chainstate/input
contract. Only local structural checks are performed on Taproot witness and
control blocks (rejecting empty witnesses and invalid control-block lengths,
while accepting a correctly sized control block without validating its internal
key or leaf-version byte); shape violations produce an error rather than
consensus verification.

## Owners and coverage

Current UTXOs cannot answer historic spent prevouts. `TxLookup` stores
transaction locators, not coins; resolving a funding transaction additionally
needs its retained body and a ready watermark. A birthday scan can spend
funding outputs older than the birthday, and separate per-input queries do
not establish one coherent complete block view.

The existing `utxo::contract::BlockUndoSource`, implemented directly by
`Chainstate`, is the retained-window source. It authenticates body/witness
commitments, certifies native undo against durable receipts, resolves same-block
inputs from earlier transactions, and rechecks applied hash/receipt/retention
lease after reading. See the
[retained input contract](contracts/external-api.md#retained-block-inputs).
Call this owner directly with a captured applied hash, then project its
`BlockSpends`. No forwarding reader, availability store, txindex capability
or second UTXO owner is needed.

The codec checks row counts and outpoint alignment and returns the body's exact
hash. Height selection, activation and final publication checks belong to the
RPC adapter; `BlockSpends` itself carries neither height nor activation context.

| Situation | Coverage and error policy |
| --- | --- |
| Certified retained body/undo | One-block projection works without txindex or new durable rows. |
| Birthday / full Taproot-era scan | Every requested body and undo must be retained and certified. Being unpruned today does not prove an old missing prefix. |
| Pruned/reserved/missing history | Preserve the owner's typed history/read failure even for empty blocks; restore/replay required data before promising coverage. |
| Source read/projection budget | Return an error for the whole block. Use another complete block/prevout source; unchanged retries and the local APIs sharing this owner cannot bypass the limit. |
| Missing/unready txindex | No effect on the certified-undo codec path; cannot mask missing undo. |
| Snapshot prefix | Retained bytes are insufficient without certified archived validation progress. |
| Reorg/restart/full rescan | Recompute from the chosen body. Source receipts/leases own readiness; the adapter rejects stale selection or a moved applied tip. |

Partial-success lists are not returned. `None` means complete transaction
ineligibility or coinbase, never missing history. Source commit, recovery,
snapshot and lock/lease behavior remains covered by
`crates/chainstate/tests/unit/block_spends_tests.rs`; those paths are unchanged.
The process test in `bin/bitcoin-rs/tests/silent_payments.rs` uses the existing
`ProcessNode` harness. It mines a mature P2PKH coinbase, signs its spend into
11,000 P2TR candidates, and applies the block through consensus validation.
After confirming the funding output is spent, it checks the HTTP tweak against
an independent single-input tagged-hash/public-key calculation and every output
index/key. The block exceeds 1,890,000 weight units and its complete result fits
the source budgets. It also exercises invalidation, replacement and clean restart.

## Resources and consumer assessment

The codec stores zero durable bytes and admits at most 4,000,000 serialized
body bytes and 64 MiB aggregate prevout script bytes per projection. The existing
source separately bounds body/undo copies and spent-coin projection. Work scans
inputs/outputs, aggregates keys and multiplies one point per eligible transaction;
P2PKH extraction hashes 33-byte scriptSig windows. CPU, temporary memory and
mainnet throughput are unmeasured. These are input bounds, not latency or global
memory guarantees. Tweak points alone cost `33 * eligible_transaction_count`
bytes: hypothetically 115,500 bytes for 3,500 eligible transactions, before
framing/txids/candidates. Full history also retains native bodies/undo. No
mainnet disk-cost estimate follows from this arithmetic. A durable cache needs
measured benefit and the existing writer/fence/reconciliation/replay owners.

The integration target is [BlindBit Oracle](https://github.com/setavenger/blindbit-oracle/blob/f9ab7fd8bc35467c492324f743ba1b69049a2bb6/internal/server/README.md),
pinned to `f9ab7fd8bc35467c492324f743ba1b69049a2bb6`. Its node backend
uses existing REST data; its wallet-facing API prefers gRPC `OracleService`.
The legacy HTTP tweak response has `block_identifier`/`index`, unlike the WIP
specification's `/getinfo` and `height`/`hash`/`tweaks` shapes. The native RPC
prototype implements neither wallet-facing protocol.

The ignored `blindbit_indexes_existing_rest_without_the_tweak_service` process
case runs this **unmodified upstream binary**, with `--rest=true` on bitcoin-rs
and the native tweak RPC disabled. It confirms a signed mature P2PKH spend into
P2TR, then Oracle fetches `/rest/chaininfo.json`,
`/rest/blockhashbyheight/101.bin`, `/rest/block/<hash>.bin` and
`/rest/spenttxouts/<hash>.bin`. Oracle's `/tweaks/101` must return the exact
confirmed block hash and independently expected nonempty tweak. Configuration,
Oracle logs and the response are saved beside the existing process transcript
in `target/process-harness/e2e/run-*/blindbit*`.
Recorded on 2026-10-16 with Go 1.25.0 and Rust 1.99.0 under WSL/Linux: the case
passed, with one exact tweak and block identity match. The upstream tree was
unmodified; the Oracle binary's SHA256 was
`0d386c6920ed3582c38b9f541cf9e57c761e3c9979c63f07193ad42af6bde4f4`.

Reproduce outside the ordinary PR test lane (Go and a C compiler required):

```sh
git clone https://github.com/setavenger/blindbit-oracle target/consumer-evidence/blindbit-oracle
git -C target/consumer-evidence/blindbit-oracle checkout --detach f9ab7fd8bc35467c492324f743ba1b69049a2bb6
go -C target/consumer-evidence/blindbit-oracle build -o ../blindbit-oracle-bin ./cmd/blindbit-oracle
BLINDBIT_ORACLE="$PWD/target/consumer-evidence/blindbit-oracle-bin" cargo test --locked -p bitcoin-rs --no-default-features --features fjall,silent-payments --test silent_payments -- --ignored blindbit_indexes_existing_rest_without_the_tweak_service
```

This demonstrates the existing L1-to-sidecar path. It does **not** establish a
consumer for `getblocktweaks`, a receiver wallet discovering a funded Silent
Payment, complete-history coverage, or network/CPU savings over existing APIs.
The payment output in this probe is a P2TR candidate, not a wallet-derived
Silent Payment. Oracle's own disposable index remains outside the node.

**Merge remains deferred:** before promoting the native RPC, establish a real
wallet's required protocol and funded discovery/confirmation, measure its
benefit over the working REST/sidecar path, and resolve the source projection
limit for that workload. Adding a second storage reader or a wallet-specific
fork is not justified by this evidence. Existing REST shares the source limit;
the sidecar result does not make the unscannable-block limitation disappear.

## Evidence, privacy and API status

The Rust test checks 29 public receiving-vector projections against pinned
sums/tweaks, including labels/multiple outputs, NUMS, malleated P2PKH, invalid
P2SH, uncompressed keys and infinity cases. The unmodified pinned Python
reference passed the full vectors locally (WSL, Python 3.12.3). Additional
tests cover future witness versions, missing material/history, empty blocks,
output indices, limits and deterministic hash-scoped replay. Adapter tests
cover exact selection, unavailable history, publication races, recovery,
IBD and nonqueued admission. The production
process HTTP test covers the positive chain/undo/crypto path, dense-block result
completeness, authentication, runtime gating, invalidation/replacement and restart.
Extraction is
recorded in `crates/index/tests/data/bip352-PROVENANCE.md`.

No parameter accepts wallet private keys, addresses, subscriptions or payment
history, and the codec performs no I/O/logging. Network metadata, height queries
and logs can still reveal birthdays/access times/ranges: keyless computation
alone is not anonymity. Spent/dust filtering and scan-interest parameters are
absent. Query-log and traffic privacy policies remain deployment concerns.

`REGISTRY`/`MANIFEST` declare `getblocktweaks` as an optional `Extension`:
`/getinfo` and `/tweaks/:height` are not served and existing Core behavior is
unchanged. The [ecosystem inventory](api/ecosystem-compat.toml) marks it experimental,
not a Core RPC or finalized index-server protocol. Compact filters inherited
from PR #1554 remain a separate capability, not a codec requirement.
