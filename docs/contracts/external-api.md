# External API contract

`API-01`–`API-35` govern RPC, REST, Esplora and ZMQ under the
[contracts precedence rule](README.md). The clauses below own each behavior;
[Test evidence ownership](test-evidence.md) defines proof boundaries; current
execution results and planned comparisons belong to their CI/PR evidence.

## Clauses

The opt-in BIP352 `getblocktweaks` extension uses the retained-input owner
below. Its [service documentation](../silent-payments.md) owns the experimental
RPC shape, admission/publication checks, coverage limits and evidence. The
shared full-block permit ends when the adapter drops its source; its single-work
slot covers derived JSON rendering and the final consistency check. Complete
scanning and wallet interoperability remain unverified.

### `API-01`: Single manifest owner

- `REGISTRY` in `crates/rpc/src/registry.rs` is the single source of truth
  for RPC, REST, and ZMQ external interfaces: each row binds one dispatch
  arm to one compatibility claim. `MANIFEST` in
  `crates/rpc/src/manifest.rs` projects those rows. A JSON-RPC method
  answers only when a non-`Unimplemented` row carries its name. No second
  route inventory exists.
- Each `Entry` row carries `name`, `kind` (`Rpc`, `Rest`, `Zmq`),
  `status`, `feature`, `core_version`, `notes`, and `since`, extended
  with required capabilities, error behavior, consistency class, resource
  budget, and evidence scenario. The `Status` vocabulary is `Supported`,
  `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`,
  `Unimplemented`. `[reference].differential_harness` in
  [core-compat.toml](../../crates/rpc/core-compat.toml) gates `Supported`: no row
  may claim it while that flag is false. Compatibility class, runtime
  readiness, and observed proof stay separate row facts; an unverified
  implementation never reads as verified parity.
- Unsupported Core surfaces stay declared `Unimplemented` and answer
  `RpcError::MethodNotFound` (code `-32601`). No wallet-only RPC is a
  disguised successful no-op.
- [docs/rpc-reference.md](../rpc-reference.md) is generated from the
  registry and is never edited by hand.
  `crates/rpc/tests/manifest_coverage.rs` enforces set equality between
  the registry and the live dispatch table in both directions and
  regenerates the reference. Regenerate with:
  `REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test suite manifest_coverage::regenerate_reference -- --ignored`

### `API-02`: JSON-RPC mechanics and the wallet-free surface

- Parameter type and coercion rules, named and positional forms, the
  declared JSON-RPC 1 and 2 envelopes, notifications,
  authentication, and error ordering follow the pinned Core 31.1
  contract.
- The envelope is validated before any method dispatch
  (`crates/rpc/src/server.rs::handle_single_json`), mirroring Core's
  `JSONRPCRequest::parse` (`src/rpc/request.cpp`): a **non-null**
  `jsonrpc` field must be a string and must be `"1.0"` (accepted as legacy
  for compatibility) or `"2.0"`; a present `params` field must be an array,
  an object, or `null`; and `method` must be present and a string. Core
  checks `isNull()` before `isStr()`, so an explicit `null` method is
  "Missing method", not "Method must be a string". An absent or
  explicit-null `jsonrpc` is the legacy dialect, as in Core. A violation
  is `-32600` carrying Core's exact message, and the method never runs.
  A top-level JSON value that is neither an object nor an array is
  `-32700` "Top-level object parse error" (`src/httprpc.cpp`, the final
  `else` of `HTTPReq_JSONRPC`).
- HTTP status follows Core's mapping (`src/httprpc.cpp`). An
  envelope refusal — an error raised while `parse()` runs — is `-32600`
  at HTTP 400 whatever dialect the request claimed. Only the reply's
  envelope depends on how far parsing got: a rejected `jsonrpc` field
  falls back to the legacy envelope, while a `method`/`params` refusal
  after a clean `"2.0"` keeps the v2 envelope. Dispatch errors then
  follow the dialect: a legacy request answers with an HTTP error status
  (`-32600` → 400, `-32601` → 404, every other code → 500), and a v2
  request stays inside HTTP 200. A batch that produces replies answers HTTP 200
  with per-member errors carried in its array; an empty batch answers HTTP 200
  `[]`; an all-notification batch answers 204 with no body.
- Failures map through `RpcError` (`crates/rpc/src/error.rs`): standard
  JSON-RPC codes (`-32700`, `-32600`..=`-32603`) and Core codes `-1`
  (miscellaneous runtime failure), `-3` (invalid type), `-5` (not found), `-8` (invalid parameter), `-9`
  (not connected), `-10` (initial download), `-22` (deserialization),
  and `-25` plus `-26` (submission).
- `createrawtransaction` currently consumes only `inputs`, `outputs`,
  `locktime` and `replaceable`: transaction version stays 2 and replaceable
  defaults to false. A named `version` is unknown (`-8`); a supplied fifth
  positional or `args`-prefix entry, including null, is refused (`-32602`).
  Duplicate, collision and unknown-name validation precedes this method-owned
  arity check. The registry declares this transaction-creation deviation.
- Amounts are integer satoshis internally. Adapters render the exact
  external BTC or sat-per-vB units and precision. Shared transaction JSON
  interprets raw version bits as Core's unsigned 32-bit value and raw output
  amounts as signed 64-bit values. `decoderawtransaction`, verbose
  `getrawtransaction` and verbose block transaction entries reuse that owner;
  block `coinbase_tx.version` uses the same unsigned conversion, while block
  header versions keep their signed interpretation. Raw transaction chain
  times appear only for positive confirmations. The native transaction
  version is the unsigned wire value; relative-lock rules compare it
  unsigned; the block header version stays signed; stored bytes are
  unchanged.
- The node ships no wallet and holds no private key material. Methods
  that would reveal, import, create, or use private keys return
  `RpcError::MethodNotFound`. The key-free helpers `getdescriptorinfo`,
  `deriveaddresses`, `decodescript`, `scantxoutset`, `combinepsbt`, and `finalizepsbt`
  remain supported. `scantxoutset` is a bounded and cancellable domain
  query, not wallet access to a live mutable map.

- Verbose `getrawtransaction` uses the shared `tx_render::transaction_json`
  projection, preserving unsigned transaction versions across mempool,
  explicit-block, and txindex lookups. Inactive explicit blocks report zero
  confirmations and omit time fields; mempool replies omit chain fields.
  Numeric verbosity 2 extends that projection with certified fees and input
  prevouts; verbosity 1 and boolean true retain the ordinary projection.
- Core script JSON has one projection owner in `tx_render.rs`: decimal short
  pushes, malformed-instruction markers, checksummed inferred descriptors,
  and optional address/hex fields. Transaction inputs alone decode defined
  sighash suffixes. Esplora retains its separate opcode/push spelling.
- `decodescript` uses the native instruction parser and script validity
  predicates. Wrapper eligibility follows Core 31.1, and P2WSH inference
  receives only its redeem script, with no key provider. Parsed Miniscript
  properties enforce Core's sanity checks, including sane unsatisfiable
  scripts; no second script parser or signing state is introduced.
- `decodescript` accepts positional and named `hexstring` forms. Its
  declared differences are compact usage text for missing/extra arguments,
  a direct-call hex-input limit equal to the 16 MiB HTTP body budget, and
  address-descriptor fallback when a complex Miniscript contains an
  invalid-curve public key rejected by the Miniscript parser. Core can
  infer `wsh(...)` from that syntactically encoded key; the fallback retains
  the same script, addresses and wrappers. Bare P2PK/multisig inference
  keeps Core's syntactic key handling.
  This is an input/work limit, not a response-size limit: disassembly and
  descriptors can be larger than their input. No response-memory or
  performance claim follows from the input limit. The pinned process matrix
  in `overhaul_process_harness::script_decode_cases` covers script classes,
  invalid encodings, wrappers, descriptor checksums, parameters, network
  addresses, and shared RPC/REST/UTXO projections.

#### Retained block inputs

- `getblock` verbosity 2/3, `getrawtransaction` verbosity 2, and
  `/rest/spenttxouts` use the same read-only
  `utxo::contract::BlockUndoSource`, implemented by the chainstate owner.
  RPC captures one `AppliedView` for confirmations/next-block linkage and
  passes its hash into the owner. A moved applied hash, durable receipt
  (including archive-only commits), or expired retention lease refuses the
  response. There is no new availability store or generation counter.
- Successful undo is complete and input-ordered. Same-block inputs come from
  earlier transactions in the authenticated body; native net undo supplies
  external inputs. BIP30 overwritten-output restores are not input rows.
  No present-day UTXO lookup or invented coin is used. The native version-1
  undo format and its mutation/recovery path are unchanged.
- A retained body with uncertified or pruned undo can be returned without
  fee/prevout fields by `getblock` and `getrawtransaction`; REST reports undo
  unavailable. Missing or unreadable *expected* undo remains a typed error,
  never an empty success.
  A missing body under a granted lease retains `HistoryUnavailable::Missing`
  and is transient (REST 503). Pruned bodies/undo stay unavailable. Genesis
  has one empty spent-output row without requiring an undo record; getblock
  still requires its real retained body even when REST can return that row.
- REST binary/hex encode a CompactSize transaction count, then each input
  count and ordinary serialized TxOuts; they never expose disk undo encoding.
  JSON rows contain value/scriptPubKey. Verbosity 3 adds generated/height to
  per-input prevouts; verbosity 2 gains fees without prevouts. Coinbase fee
  and prevout fields stay omitted. Transaction JSON uses the shared wire
  projection (including unsigned high-bit versions), since the pinned verbose
  DTO cannot represent that complete integer range. Header versions and
  raw/txid payload shapes retain their existing semantics. Stale block
  headers omit the active competing branch's successor hash, matching Core.
  `getrawtransaction` verbosity 2 includes both fees and prevouts, pairing
  the requested transaction with its row in the authenticated block for
  explicit-block and txindex lookups. Mempool and coinbase replies omit both.
- Explicit-block `getrawtransaction` verbosity 2 authenticates the entire
  block/input view before selecting the transaction, including a requested
  coinbase. An expected missing or corrupt undo record therefore fails that
  coinbase lookup too; verbosity 1/boolean true and implicit txindex coinbase
  lookups do not require undo. This is a conservative availability deviation
  from Core's coinbase shortcut; the existing certified reader stays authoritative.
  The explicit-coinbase RPC regression covers this refusal with a readable
  block body containing a spend.
- This remains a declared deviation: after a later branch receipt replaces
  the retained undo extent, older stale rows lack current certification and
  their undo fields are omitted even if raw rows remain. Snapshot history
  is unavailable until its archive receipt certifies it. Transient absence
  and explicit resource limits can return retry responses unlike Core.
  `/rest/block` retains its separate projection without undo fields.
- Full block REST rendering, spent outputs, detailed getblock responses,
  and getrawtransaction verbosity 2 block reads share two materialization
  permits. The owner bounds body copies to
  4,000,000 bytes and undo copies to 64 MiB. Undo counts are bounded by the
  authenticated block and remaining record bytes; script lengths must fit the
  record before allocation. Spent-input rows derive from that block, and each
  spent script is copied once from the bounded body or undo. These bounds cover
  input materialization, not a 64 MiB heap or JSON limit: decoded metadata and
  script copies add allocations, and verbose JSON can expand further. Any
  format-specific response budget belongs to its renderer, not the reusable
  `BlockUndoSource`. Certification shares a 4,096-parent-hop budget, reusing
  the tree's trusted height index after joining its prefix. Retained-body witness
  checks use the existing bounded deployment query: an off-header-chain BIP9 read
  captures at most 2,000,000 ancestor IDs (at most 8 MB); missing bodies do not
  trigger deployment work. Both budget failures are explicit resource limits;
  these bounds are not throughput or global-RSS claims.
- A txindex hit for a non-coinbase `getrawtransaction` verbosity 2 request
  still decodes the complete authenticated body and retained undo, then
  searches the block for its transaction row under a shared render permit.
  Future performance qualification should measure body/undo bytes, decode
  cost, latency and permit refusals for single requests and concurrent load
  across representative block sizes and input counts. No measurement or
  throughput claim is established here; follow the benchmark evidence rules
  in [docs/benchmarks/README.md](../benchmarks/README.md).
- Existing storage boundaries provide bounded reads with safe unsupported
  defaults, never an unbounded fallback. Fjall checks its value, redb its
  read guard, and RocksDB its pinned value before the owned copy; backend
  internal pages, caches, decompression, or pinning allocation are outside
  that copy bound. Block reads bound the locator and frame length before
  allocation. Unsupported custom stores must implement the bounded reads
  before serving this capability.

#### Block database verification

- One owner verifies: `chainstate::verify::verify_recent_blocks` serves both
  the `verifychain` RPC (through the node-owned chain control) and the
  startup check, so RPC never walks storage itself. The walk follows parent
  links back from the applied tip, excluding genesis. Defaults remain level 3
  and six blocks; a nonpositive depth means every block above genesis, and a
  larger depth is clipped to the applied height. Both parameters are Core
  signed 32-bit integers: absent or null means the default, a non-number is a
  type error, and anything outside the signed 32-bit range is out of range;
  levels clamp to 0–4.

- Every requested body is read and decoded, including level 0, and its header
  must hash to the block the header chain names. Levels 1–4 additionally
  check the header's proof of work. Corrupt bytes, malformed or truncated
  referenced frames, mismatched headers, invalid work or failed Merkle checks
  return `false`.

- Level 1 reuses the consensus-owned context-free body checks: coinbase
  placement and scriptSig bounds, nonempty transaction inputs/outputs, output
  money ranges, null/duplicate inputs, a 1,000,000-byte stripped block limit,
  and aggregate legacy sigop cost. Failure returns `false` even when the
  stored header, PoW and Merkle root are valid. Shared shape/value rules
  retain the same owner as normal transaction validation; RPC has no copy of
  those rules.
  [Core 31.1 `CheckBlock`](https://github.com/bitcoin/bitcoin/blob/v31.1/src/validation.cpp#L3966-L4033)
  excludes contextual witness commitments, full witness weight, finality and
  UTXO/script execution. Level 1 therefore does not apply those checks, so a
  body that only mutates witness data still passes. The walk retains only the
  current block, rather than accumulating the requested history in memory.

- Level 2 additionally reads each undo record and decodes it against its
  block. The copy bound includes serialized block size, that block's input/output counts, the
  interpreter's spendable-script limit, and the persisted codec's overhead;
  the separate 64 MiB consumer-query budget does not limit startup or
  verification of valid undo. Levels 3 and 4 run the level-2 checks and do not replay disconnect
  or reconnect. A history lease pins the window for the whole walk so a
  concurrent prune pass cannot delete rows about to be read; the lease is
  released when the walk ends. Data this node never kept or intentionally no
  longer keeps — history below the executed prune line or an in-flight claim,
  history below an assumed-valid snapshot base, a store without block bodies,
  or a pin the retention owner withdrew — ends the walk as skipped once every
  block the node still holds has passed. Shutdown likewise skips instead of
  failing.

- The answer is `true` only when every block in the window was checked and
  passed. Any damaged block or undo record, and any window reaching history
  this node does not hold (pruned, snapshot-only, unreadable or missing
  bodies), answers `false`: Core's boolean failure for integrity and missing
  history. Missing history keeps the boolean surface: upstream's
  incomplete-verification `-1` for unavailable data stays out, and one owner
  keeps that mapping. Cancellation and recovery closure are the implemented
  `-1` errors, distinct from that boolean failure: a triggered request latch
  answers `-1` `Block verification interrupted`, and a chainstate closed for
  recovery answers `-1` `Chainstate is unavailable for verification`,
  including a closure that lands mid-walk, on the final read, or over an
  empty window. The boundary poll order is cancellation, then recovery
  closure, then process shutdown, then the history pin, so a process shutdown
  observed mid-walk still skips to `false` where the code takes that branch.
  No requested block is silently passed.

- Verification gap: socket shutdown coverage signals chainstate shutdown and exits the RPC handler; it does not establish end-to-end `Node::shutdown` behavior.

- The walk holds no tree or chain-transition guard during body reads, and
  needs none: an applied ancestor's body and undo record are immutable, so
  there is no captured publication for a concurrent transition to invalidate.
  A request that arrives after its RPCHandler stopped reports `-1`
  `Block verification interrupted` before touching chain state; the same
  latch is polled at every progress boundary and before reporting success, so
  a cancellation that lands mid-walk or on the final read still interrupts
  rather than passing or failing as damage. A chainstate closed for recovery
  is fail-closed at the same boundaries, including over an empty window, as
  `-1` `Chainstate is unavailable for verification`. The existing
  blocking-call budget applies.

- This is a read-only integrity check: it never changes the UTXO set, rewrites
  bodies, repairs storage, or advances a durable root. Startup verifies the
  last six applied blocks one level stronger than any RPC level, adding
  header-body binding (including the witness commitment) to the undo-level
  checks, and refuses to open on damage; the refusal names the block and
  states that verification repairs nothing. The RPC levels stay at Core's
  context-free scope so a witness-only mutation still passes them. Signet
  challenge validation and level-3/4 disconnect/reconnect verification remain
  outside `verifychain`.
  `Deviation` stays in the registry for those omissions; excess arguments
  retain the local `-32602` shape error.

#### Native deployment reporting

- `getdeploymentinfo` and `/rest/deploymentinfo` share one typed projection
  of `chain::deployment_statuses` and consensus `verify_flags`. The default
  hash is captured from one applied publication; explicit hashes select any
  known header ancestry, including a side branch or header without a body.
- `active` describes enforcement for the next block. BIP9 `status`, `since`,
  and signalling describe the queried block; `status_next` describes its
  successor. Script flags describe the queried block itself. Unavailable
  optional fields are omitted, never rendered as null.
- Header-chain lookups reuse the existing height index. An off-header-chain
  BIP9 query captures at most 2,000,000 ancestor IDs once (at most 8 MB), then
  uses direct height lookup with the existing BIP9 state machine/cache.
  Larger side histories return RPC -1 / REST 503 instead of unbounded
  repeated parent walks. This is a work bound, not a performance claim.
- This is a declared Core deviation, not a consensus change: native CSV and
  Segwit use historical BIP9 on mainnet/testnet3; native Taproot uses a fixed
  height; testdummy is not configured. Fixed activation heights on regtest
  and Segwit on testnet4/signet differ from Core 31.1. Historical script flags
  report the native validation flags, including its BIP16 exceptions, rather
  than Core 31.1's retroactive WITNESS/TAPROOT flags. No RPC-local activation
  table substitutes for those owners. Full deployment parity remains open.
- Unknown RPC hashes return -5; malformed hashes return -8. REST keeps its
  JSON-only format and 400 malformed/unknown-hash responses. Excess argument
  counts retain the local JSON-RPC parameter-shape error instead of Core's
  method-help message.

### `API-03`: REST dialect

- REST keeps its own HTTP semantics in `crates/rpc/src/rest.rs`: status
  codes, content types, empty bodies, and not-found behavior. No generic
  everything-is-JSON-RPC error handler spans the dialects.
- Formats are `json` (`application/json`), `hex` (`text/plain`), and
  `bin` (`application/octet-stream`). A disabled gateway and an unknown
  path return 404. Malformed parameters return 400. Unknown hashes follow
  the specific route: headers return an empty 200, spent outputs return 404,
  and deployment queries return 400.

- `/rest/getutxos` GET URI input and POST binary/hex input share one
  authoritative UTXO/mempool lookup. POST reads a bool and canonical
  CompactSize outpoint vector directly, limited to 15 outpoints and a
  2048-byte wire body before allocation. JSON bodies, mixed input sources,
  malformed/trailing data and oversized requests fail with HTTP 400.
  Empty serialized vectors are valid; URI requests still require outpoints.
- Plain coin reads capture tip and coins under the existing stable chain
  read role. Mixed reads retain one pool view and reject a changed/odd
  chain generation. Rendering happens after guards are dropped. Pool-created
  outputs use Core REST's `MEMPOOL_HEIGHT` value, 2147483647.
- The canonical POST decoder intentionally corrects Core 31.1's incoming
  string-length-prefix bug; the registry retains `Deviation`. Independent
  wire fixtures and same-tip Core GET establish intended response bytes;
  Core POST's measured different answer is an explicit known gap.


### `API-04`: ZMQ notification contract

- `crates/rpc/src/zmq.rs` owns the declared Core topics
  `hashblock`, `hashtx`, `rawblock`, `rawtx`, and `sequence`, with Core
  byte order, sequence counters, and connect, disconnect, and mempool
  ordering.
- The `sequence` body frame is reversed txid (32 bytes), label byte (1),
  and little-endian sequence (8): 41 bytes total. `BlockInclusion` emits
  no `R` frame; every other removal reason does. One event per change, in
  commit order (`mempool-mutations.md` `MPL-03`).
- Delivery is bounded and optional. Queue overflow records a sticky gap
  and a reconcile signal instead of growing memory. High-water marks stay
  per endpoint (`DEFAULT_ZMQ_HWM = 1_000`). Canonical estimator and relay
  accounting is never dropped (`MPL-04`).

### `API-05`: Solo-mining generate path

- **Owner**: `MiningControl::generate` in `crates/mining/src/control.rs`,
  implemented by `MiningCoordinator::generate` in
  `crates/node/src/mining.rs`, which assembles each block through
  `MiningService::assemble_fresh` in `crates/mining/src/coordinator.rs`.
- The operation assembles a fresh candidate (no GBT cache). `generateblock`
  validates the unsolved block first (`API-30`), then both generate paths
  solve and either submit through the chainstate owner or dry-validate
  through `Chainstate::validate_block` (`ARCH-07`). Persistence and tip
  advancement are conditional on `submit`; validation is not.
- Each submitted block is a separate commit. An error after *N* successful
  submissions leaves those *N* blocks durable. Callers own retry after reading
  the applied tip. `nblocks` is not capped; the result vector grows one block
  at a time.
- `generatetoaddress` accepts only a network-valid address, uses mempool
  package selection, collects fees, and always submits.
- `generateblock` accepts an address or descriptor (`require_checksum = false`;
  a supplied checksum is verified). Ranged and multipath descriptors are
  refused (`API-31`). The transactions array is required (an explicit `[]` is
  coinbase-only).
  Listed order is kept, those fees are not added to the coinbase, 64-character
  hex is a mempool txid, and decoded raw transactions are included without
  mempool admission. Raw transaction sigop costs use copied applied-chain
  prevouts and outputs of earlier listed transactions, with the candidate's
  witness activation. The node captures those inputs under the existing chain
  read fence and computes costs after releasing locks. Unselected or later
  mempool transactions do not supply previous outputs. Missing inputs still
  pass to authoritative block validation. Extra positional arguments are
  rejected. Output parse errors are `API-29`. Consensus failures before the
  nonce search are `API-30`.

### `API-06`: `getnetworkhashps` snapshot and invalid-height behavior

- **Owner**: `network_hash_ps` in `crates/mining/src/network_hashps.rs`.
  Node `MiningCoordinator::network_hash_ps` only supplies the locked block tree
  and one applied-tip snapshot.
- The method takes the block-tree read lock, then loads one applied-tip
  snapshot. Height checks and the hash-rate walk use that snapshot and that
  locked tree, not a second tip load.
- The hash-rate window is Core's parent walk: `lookup` parent pointers from
  the resolved start node, min/max header time, `chainwork` delta. It does not
  re-resolve each height through `node_at_height_from`.
- `nblocks` (`lookup`) must be a positive count or `-1` (since the last
  difficulty retarget). Otherwise the RPC is Core `-8`
  (`RpcError::InvalidParameter`) with
  `"Invalid nblocks. Must be a positive number or -1."`
- `height` must be `-1` (the snapshot tip) or an existing applied-chain height
  on that snapshot. Heights below `-1`, above the snapshot tip, or in range
  but unwalkable from that tip, are Core `-8` with
  `"Block does not exist at specified height"`, not a zero hash-rate.
- An empty chain with `height == -1` estimates `0.0`.
- `getmininginfo`'s `networkhashps` is best-effort from the applied tip and
  does not use this RPC height-validation error path.

### `API-07`: RPC fixture reference provenance

- **Owner**: the corpus loader in `crates/rpc/tests/support/fixture.rs` owns
  the `core_version` and `core_binary_sha256` provenance pins and their
  validation. Every fixture records the version and exact binary digest used
  for its capture; missing, empty, or mismatched values fail loading before
  replay starts.
- These pins describe the released Core node used for the recorded RPC
  responses. They are separate from the `bitcoinkernel` oracle and from the
  broader API family declared by `MANIFEST` (`API-01`). Changing either of
  those references cannot relabel existing captures.
- `core_parity` replays recorded responses against bitcoin-rs. It does not
  execute or hash a local `bitcoind`, and the fixture metadata does not attest
  a source commit or build configuration. Verifying process binaries and
  recording those missing identities remain work under #625 and #626.
- The loader requires each fixture's version and digest to match the pins,
  so a reference refresh must update the constants and affected fixtures
  together. It only checks that `provenance.evidence` is non-empty; it does
  not retrieve or authenticate the referenced evidence. Reviewing evidence
  from the selected Core build is a maintainer responsibility outside this
  automated gate.

### `API-08`: Bounded public exposure

- Administrative RPC stays private and authenticated by default. Public
  read and broadcast exposure, allowed hosts and origins, and rate and
  concurrency limits are independently configured.
- Request bodies, batch size, response assembly, scan rows, in-flight
  work, and long-poll clients are bounded. A public explorer read cannot
  consume the CPU or memory quota needed to validate new blocks.

### `API-09`: Esplora dialects

- `/api` exposes the public Esplora (electrs) contract. `/esplora` is the
  versioned mempool-backend superset of that tree. Both project the same
  node and index state. Neither is a separate node mode or a second
  blockchain database, and no electrs proxy exists.
- `/api` is a closed namespace: a request inside it never falls through
  to JSON-RPC, and unprefixed electrs paths 404 so JSON-RPC keeps `/`.
  `/api/v1` belongs to the external mempool application's own API, not to
  this node.
- Beyond the public routes, the backend dialect requires `GET /internal/mempool/txs`,
  `GET /internal/block/{hash}/txs`, `POST /internal/txs`,
  `POST /internal/mempool/txs`, the batched outspends
  `POST /internal/txs/outspends/by-txid` and
  `POST /internal/txs/outspends/by-outpoint`, and address summaries.
  Only declared backend-dialect routes exist; each backend route is marked
  as such.
- History reads use bounded pages and cursors that preserve public
    Esplora cursor semantics. Cursor values
   are the exact lowercase `txid` display text: malformed, noncanonical
   (including uppercase or prefixed), unknown, and missing cursors restart from
   the beginning; a valid known cursor strictly excludes that transaction and
   earlier entries.
  A richer internal revision token stays
  internal or is a documented extension. Lag, reorg, or a disabled
  capability returns the declared unavailable response, never an empty
  successful history.
- `/txs/chain[/<last_seen_txid>]` reads are bounded to the requested page
  (up to 25 items): confirmation status, block metadata, and transaction
  projections are hydrated only for the selected page slice, never for the entire
  confirmed history. Unselected older blocks being pruned or absent does not fail
  earlier pages.
- `/txs/chain` queries decouple from unspent queries: they do not enumerate
  `ScriptLive` UTXOs or query mempool state.
- Sentinel `last == Some("")` (`/txs/mempool`) queries resolve mempool activity
  directly from mempool locators without scanning confirmed history or taking
  block metadata snapshot locks.
- Index query refusals map to HTTP status by cause: `Retry` and `Unavailable`
  (lag, reorg, disabled capability, missing or pruned block body) are 503;
  `Storage` (a failed or corrupt body read, a corrupt index row) is 500.

### `API-10`: Broadcast and preview through the admission gateway

- `sendrawtransaction`, `submitpackage`, `testmempoolaccept`, Esplora `POST /tx`, and P2P
  ingress reach the single `MempoolGateway` (`mempool-policy.md` `POL-02`).
  Each committing producer carries an explicit `AdmissionOrigin` and its
  own request fee limits. Scoped `submitpackage` admits singletons and 1p1c
  through the existing atomic package owner, with Core's individual-first
  partial results (`POL-05`). Wider shapes and replacement are explicitly
  refused. Named or positional `package`, `maxfeerate`, and `maxburnamount`
  parameters feed the same owner; burn guards run before any mutation.
- Esplora `POST /tx` is implemented on both `/api` and `/esplora` with
  `AdmissionOrigin::Esplora` and an explicit, fixed 10,000,000 sat/kvB
  request ceiling. Its hex body provides no fee override. RPC keeps its
  own default and `maxfeerate` override; peer ingress has no request cap.
  The shared gateway owns fee verification and authoritative mutation.
- Preview runs the identical pipeline and mutates nothing: no membership,
  estimator, relay state, admission sequence, or victims (`POL-06`).
  `testmempoolaccept` returns preview rows in the frozen Core 31.1 shape
  with frozen reject-reason strings.
- Broadcast failures map to the Esplora error dialect: a rejected
  transaction is a 400 with the reject reason, not a retryable 503.

### `API-11`: BIP22/BIP23 template extras

- **Owner**: `template_from_candidate` in `crates/mining/src/coordinator.rs`,
  driven by `MiningService::get_block_template`; JSON projection in
  `crates/rpc/src/handlers/mining.rs` `render_block_template`.
- Capabilities are the producer’s implemented set (`proposal`, `longpoll`).
  Client-advertised names are not echoed.
- `submitold` and `workid` are BIP23 extras the pinned template contract
  does not model; neither is emitted.
- On signet, the template carries `signet` in `rules` (mandatory) and
  `signet_challenge`, the default challenge that `Network::signet_challenge`
  owns and block validation checks. Other networks omit `signet_challenge`.
- `longpollid` is `{tip_be_hex}{mempool_sequence}` when the fee-priority
  revision is zero. A nonzero revision adds `:{fee_delta_sequence}`.
  An id without the suffix represents fee revision zero. Malformed ids,
  including invalid UTF-8 split boundaries, are rejected without panicking.
- A successful `prioritisetransaction` publishes a new fee generation, so
  the next template keeps the tip and membership components and advances
  the fee component, and pending long-poll waiters return with that id.
  Admissions invalidate older membership generations and wake long-polls.
  The next template read captures membership and fee revisions together.
- `getblocktemplate` never carries a coinbase budget. The typed
  `BlockTemplateRequest.coinbase_budget` is `None` for every RPC request, so
  the template body, limits, `longpollid` and JSON are as above. Only an
  embedder of the typed `MiningControl` (the experimental SV2 regtest adapter
  in `tools/stratum-sv2`) sets it. A budgeted candidate is selected to leave
  that room in the coinbase and has an id qualified by the budget, or is the
  generation's ordinary candidate when that already admits the budget. The
  qualifier is not part of the RPC contract: an RPC caller never receives it,
  and a long-poll wait compares generations only.

### `API-12`: Mainnet template operational gates

- **Owner**: `ensure_template_ready` in `crates/rpc/src/handlers/mining.rs`.
- Template mode on mainnet requires at least one live peer (`PeerTable`) and
  that the node has left IBD
  (`!ctx.chain.ibd.is_active(now, ctx.chain.chain_network)`, the chain-crate
  latch in `crates/chain/src/ibd.rs` negated by the gate).
  Failures are Core `-9` (`bitcoin-rs is not connected!`) and `-10`
  (`bitcoin-rs is in initial sync and waiting for blocks...`).
- Proposal mode does not apply these gates. Networks other than mainnet skip
  them, matching Core `IsTestChain()`.

### `API-13`: `submitheader`

- **Owner**: `MiningCoordinator::submit_header` in `crates/node/src/mining.rs`.
  RPC decodes the hex and projects the result; it does not admit headers.
  The reject-reason projection is `header_reject_reason` in
  `crates/mining/src/bip22.rs`; authoritative admission runs through
  `Chainstate::admit_headers`.
- Decode failures (invalid hex, fewer than 80 bytes) are Core `-22`
  (`Block header decode failed`). Extra bytes after an 80-byte header are
  ignored, matching Core `DecodeHexBlockHeader`.
- For an unknown header, the previous header must already be in the block tree,
  except that an empty tree admits the network's genesis header as its root.
  Otherwise the RPC returns `-25` (`Must submit previous header (HASH) first`)
  before proof-of-work validation, including when the target is invalid.
- Admission uses `accept_headers`, the same consensus gate as inbound P2P
  headers, so `submitheader` cannot admit a header the network would reject.
  Known-valid duplicates (including genesis) succeed. Known-invalid
  duplicates return `-25` (`duplicate-invalid`); a header that extends one
  this node has marked invalid returns `-25` (`bad-prevblk`). Other invalid
  headers return `-25` with Core reject reasons (`high-hash`, `bad-diffbits`,
  `time-too-old`, `time-too-new`, `bad-version(0x%08x)`,
  `time-timewarp-attack`).
- Success is JSON `null`. Header-only admission does not apply the block or
  publish a mining generation.

### `API-14`: GBT client-rule negotiation

- **Owner**: `ensure_client_rules_for_template` and
  `ensure_client_supports_mandatory_rules` in
  `crates/rpc/src/handlers/mining.rs`.
- Template mode requires the client to list `segwit`. On signet it also
  requires `signet`. Failures are Core `-8` with Core's exact messages:
  `getblocktemplate must be called with the segwit rule set (call with {"rules": ["segwit"]})`
  and
  `getblocktemplate must be called with the signet rule set (call with {"rules": ["segwit", "signet"]})`.
  Signet is checked first, matching Core v31.0 `src/rpc/mining.cpp`.
- These checks run before template assembly. Proposal mode skips them.
- After assembly, any remaining mandatory template rule the client omitted
  is Core `-8`: `Support for 'NAME' rule requires explicit client support`.

### `API-15`: `submitblock` decode

- **Owner**: `decode_submitted_block` in `crates/rpc/src/handlers/mining.rs`.
  Admission stays on the single `MiningControl::submit_block(BlockPayload)`.
- The decoder hex-decodes, runs one shared decode via the codec-owned
  `BlockPayload::from_prefix`, retains only the consumed prefix as the
  payload, and discards the remainder. Invalid hex or a payload that is not
  a complete block is Core `-22` (`Block decode failed`), matching Core
  `DecodeHexBlk`. Extra bytes after a complete block are ignored, byte for
  byte as today; this decoder is the cooked external boundary and its bytes
  are not the exact request payload.
- A second dummy argument is accepted and ignored (BIP22). A third argument
  is JSON-RPC `-32602`.

### `API-16`: GBT proposal request parsing

- **Owner**: `parse_block_template_request` in
  `crates/rpc/src/handlers/mining.rs`.
- Unknown or non-string `mode` is Core `-8` (`Invalid mode`).
- Proposal mode does not require the client to list the `proposal`
  capability. Missing `data` is Core `-3`
  (`Missing data String key for proposal`) with no `invalid type:` prefix.
  Decode uses
  `decode_submitted_block` (`API-15`): `-22` `Block decode failed`, leftover
  bytes ignored. Proposal consumes the same decoder output with
  `payload.into_block()` into `BlockTemplateMode::Proposal`, discarding the
  retained bytes; proposal dry-validates and never persists.

### `API-17`: `submitblock` uncommitted witness nonce

- **Owner**: `update_uncommitted_block_structures` in
  `crates/mining/src/coinbase.rs`, called from
  `MiningCoordinator::submit_block(BlockPayload)` in `crates/node/src/mining.rs`.
  The miner first applies the existing read-only fill-need signals on the
  borrowed payload block and submits it directly when no fill applies (no
  re-encode, no clone); only when fill may apply does it trial-clone and
  submit `from_local` of the filled clone.
- When the previous header is known, SegWit is active for the submitted
  height, the coinbase already has a BIP141 commitment output, and the
  coinbase witness is empty, `submitblock` inserts the 32-byte reserved
  nonce. This matches Core `UpdateUncommittedBlockStructures`.
- An existing coinbase witness is left unchanged. Proposal mode does not
  apply this fill.

### `API-18`: `submitblock` and proposal duplicate vocabulary

- **Owner**: `MiningCoordinator::known_block_result` in
  `crates/node/src/mining.rs`.
- GBT proposal looks the block hash up first, matching Core
  `LookupBlockIndex`: a node whose body is connected (scripts-valid) is
  `duplicate`, `Invalid` is `duplicate-invalid`, and any other tree entry
  (including a header-only tip) is `duplicate-inconclusive`.
- `submitblock` matches Core v31 `ProcessNewBlock`: a previously connected
  body (scripts-valid), including after a later reorg, is `duplicate`. A
  header admitted by `submitheader` still receives the body.
- Duplicate classification holds the chain-transition lock through apply, so
  concurrent submissions of one body cannot race into a previous-tip refusal.

### `API-19`: BIP22 reject reasons

- **Owner**: `bip22_reject_reason` in `crates/node/src/mining.rs`
  for the `ApplyError` arms, delegating to `consensus_reject_reason` and
  `chain_reject_reason` in `crates/mining/src/bip22.rs`.
- Proposal and `submitblock` project apply/consensus failures as Core
  `GetRejectReason` strings (`bad-cb-missing`, `bad-txnmrklroot`,
  `bad-cb-amount`, `high-hash`, `time-too-old`, …). Operational apply
  refusals (`Shutdown`, journal backpressure) stay `inconclusive`.
- A body without a coinbase that holds a 64-byte witness-stripped transaction is a mutated
  body, not an invalid header, and still projects `bad-cb-missing`, as Core's
  first-transaction rule reports it.
- A signet block whose BIP325 solution fails is `bad-signet-blksig`. The
  solution is checked when a block commits, after the block rules, and not
  by `proposal` mode, as Core skips it when it is not checking proof of
  work.
- Storage, UTXO, durable-head, and internal verifier failures propagate as
  `MiningControlError::Failed`, never as a BIP22 block rejection. The same
  distinction applies to `generateblock` prevalidation.
- Consensus crate Display remains log text. This mapping is the BIP22
  wire owner.

### `API-20`: GBT `vbrequired` is always 0

- **Owner**: `template_from_candidate` in
  `crates/mining/src/coordinator.rs` (driven by
  `MiningService::get_block_template`); signalling deployments are read from
  the applied tree through the node-implemented `ChainContextSource`.
- Core v31 `getblocktemplate` hardcodes `vbrequired` to 0. Signalling
  deployments still appear in `vbavailable`; locked-in bits are not OR'd
  into `vbrequired`.

### `API-21`: BIP141 witness malleation reasons

- **Owner**: `check_witness_malleation` in
  `crates/consensus/src/verify_block.rs`.
- Core `CheckWitnessMalleation` distinguishes three BIP22 strings:
  - commitment present, coinbase witness not a single 32-byte element →
    `bad-witness-nonce-size`
  - commitment present, reserved nonce well-formed, hash mismatch →
    `bad-witness-merkle-match`
  - witness data without a commitment, or before SegWit →
    `unexpected-witness`
- Proposal does not fill an omitted reserved nonce (`API-17` is
  `submitblock`-only), so an empty coinbase witness with a commitment is
  miner-facing `bad-witness-nonce-size`.
- `bip22_reject_reason` maps the consensus variants; consensus Display
  remains log text.

### `API-22`: GBT `coinbaseaux.flags` is empty hex

- **Owner**: `render_block_template` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 emits `coinbaseaux: { "flags": HexStr(COINBASE_FLAGS) }`. The
  flags bytes are empty, so the hex string is `""`. An empty object is not
  the Core shape.

### `API-23`: `prioritisetransaction` dummy and `fee_delta`

- **Owner**: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core reads `fee_delta` from params[2] (`getInt<int64_t>`). The deprecated
  dummy (params[1]) must be omitted, null, or numeric zero; any other value
  is `-8` `Priority is no longer supported, dummy argument to
  prioritisetransaction must be 0.`
- Two-argument calls do not treat params[1] as `fee_delta`.

### `API-24`: `prioritisetransaction` refuses pooled dust

- **Owner**: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 rejects a mempool transaction with dust outputs when
  `require_standard` is set: `-8` `Priority is not supported for
  transactions with dust outputs.`
- `require_standard` follows Core's `-acceptnonstdtxn` default: enforced
  everywhere except regtest. Absent txids (fee-delta overlay only) are
  not checked. Dust classification uses the pool's dust-relay fee via
  `tx_has_dust_outputs`.

The wallet-facing subset of this surface — tip, fees, address/script
queries, and broadcast over Esplora, plus the key-free node RPCs — is
owned by [wallet-facing.md](wallet-facing.md).

### `API-25`: `getmininginfo` omits unset optional fields

- **Owner**: `render_mining_info` in `crates/rpc/src/handlers/mining.rs`.
- Core pushes `currentblockweight`, `currentblocktx`, and `signet_challenge`
  only when set. Unset optionals are omitted, not JSON `null`.
- Projection uses `typed_to_sonic_omitting_nulls`.

### `API-26`: `estimatesmartfee` parameters and Esplora fee estimates

- **Owners**: `estimatesmartfee` in `crates/rpc/src/handlers/util.rs`;
  Esplora `/fee-estimates` in `crates/rpc/src/esplora/public.rs`.
- `conf_target` must be in `1..=1008` (Core `MAX_CONFIRM_TARGET`). Otherwise
  `-8` `Invalid conf_target, must be between 1 and 1008`.
- `estimate_mode` is optional, case-insensitive `UNSET` / `ECONOMICAL` /
  `CONSERVATIVE` (Core `FeeModeFromString`). Unknown strings are `-8`
  `Invalid estimate_mode parameter, must be UNSET, ECONOMICAL or
  CONSERVATIVE`. A non-string is `-3`. Accepted modes are parsed only;
  this node's estimator does not differentiate ECONOMICAL from CONSERVATIVE.
- The estimator has a 25-block horizon (`MAX_CONF_TARGET = 25`), so a
  `conf_target` above 25 is answered with the 25-block fee rate.
- Insufficient data for the requested target omits `fee_rate` and returns an
  `errors` array containing `Insufficient data or no feerate found`.
- Trailing parameters are refused.
- Esplora `/fee-estimates` in `crates/rpc/src/esplora/public.rs` captures
  targets `1..=25`, `144`, `504`, and `1008` from one mempool read view, so
  concurrent pool updates cannot mix estimator states within a response.
  The guard is released before response formatting. It uses the same estimator
  and `sat_to_btc` projection as RPC, then multiplies BTC/kvB by `100_000` for
  sat/vB; targets with insufficient history are omitted.

### `API-27`: `generateblock` txid and raw-tx parse errors

- **Owner**: `parse_generateblock_transactions` in
  `crates/rpc/src/handlers/mining.rs`.
- 64-character hex is Core `Txid::FromHex`. A txid missing from the
  mempool is `-5` `Transaction {str} not in mempool.` using the caller's
  string.
- Anything else is Core `DecodeHexTx`. Invalid hex or a payload that is
  not a complete transaction is `-22`
  `Transaction decode failed for {str}. Make sure the tx has at least one
  input.`

### `API-28`: `getprioritisedtransactions` `modified_fee` is satoshis

- **Owner**: `getprioritisedtransactions` in
  `crates/rpc/src/handlers/mining.rs`.
- Core mining RPCs use satoshi amounts, not BTC. `fee_delta` is already
  an integer satoshi overlay. `modified_fee` (actual fee plus delta,
  present only when `in_mempool`) is the same unit: a JSON number in
  satoshis, matching Core `CAmount`.

### `API-29`: generate invalid-output text

- **Owner**: `generateblock_payout_script` in
  `crates/rpc/src/handlers/util.rs`; `generatetoaddress` in
  `crates/rpc/src/handlers/mining.rs`.
- `generatetoaddress` refuses a non-address with `-5`
  `Error: Invalid address`.
- `generateblock` tries a descriptor first (`require_checksum = false`).
  Ranged/multipath descriptors are `-8` (`API-31`). If Parse fails, the text is
  tried as an address; a miss is `-5`
  `Error: Invalid address or descriptor`, matching Core
  `src/rpc/mining.cpp`. A supplied checksum that fails Parse is refused
  through that fallback, not CheckChecksum's wording.

### `API-30`: `generateblock` `TestBlockValidity` before solve

- **Owner**: `MiningCoordinator::generate` in
  `crates/node/src/mining.rs`.
- Core v31 `generateblock` runs `TestBlockValidity` with
  `check_pow = false` and `check_merkle_root = false` before
  `GenerateBlock`. Failure is Core `-25`
  (`RpcError::TxVerifyError`) `TestBlockValidity failed: {reason}`,
  where `{reason}` is the BIP22 GetRejectReason string (`API-19`).
- This pre-check applies only to `GenerateSelection::Ordered`
  (`generateblock`). An ordered candidate refused by the mining sigop
  preflight also returns this `-25` envelope with `bad-blk-sigops`; it does
  not become an operational `Failed` result. `generatetoaddress` (`Mempool`)
  matches Core `generateBlocks` and does not run it.
- The check calls `apply::validate_block` directly.
  `ApplyIntent::Propose` already skips hash-meets-target. It does not
  go through GBT `propose` (`API-18` LookupBlockIndex vocabulary).
  Shutdown and journal backpressure stay `Unavailable`,
  not TestBlockValidity.

### `API-31`: `generateblock` multipath, ranged, and Expand errors

- **Owner**: `generateblock_payout_script` in
  `crates/rpc/src/handlers/util.rs`.
- Core `getScriptFromDescriptor` throws before the address fallback:
  - more than one parsed descriptor → `-8`
    `Multipath descriptor not accepted`
  - `IsRange()` → `-8`
    `Ranged descriptor not accepted. Maybe pass through deriveaddresses first?`
  - `Expand(0)` failure → `-5`
    `Cannot derive script without private keys`
- Multipath is checked first, matching Core `descs.size() > 1` before
  `IsRange()`. A descriptor that is both is the multipath error.

### `API-32`: `gettxspendingprevout` mempool snapshot

- **Owner**: `Mempool::outpoint_spender` owns the spending-index lookup and
  its typed consistency failure. The RPC adapter validates every input before
  taking one gateway read guard, captures spending transaction references for
  all outpoints under that guard, and serializes after releasing it.
- Results preserve query order, duplicates, and the caller's txid spelling.
  A row without a mempool spender contains only `txid` and `vout`; no
  confirmed-spend history is queried. Replacement and removal are visible
  through the existing mempool index, with no additional state.
- Positional and named `outputs` / `options`, flattened named options, and
  the `args` positional prefix accept Core 31.1's `mempool_only` and
  `return_spending_tx` options. The default is mempool-only; requested
  `spendingtx` uses full consensus serialization, including witness.
  With `mempool_only=false`, a missing mempool spender fails with Core's
  `-1` unavailable-txospenderindex error. An inconsistent spending index
  becomes an internal error, never an unspent result.
- Empty output lists, strict object keys, txid syntax, and signed 32-bit
  nonnegative vout validation follow the pinned reference. After successful
  named-argument binding, missing outputs and excess positional arguments
  retain local JSON-RPC `-32602` shape errors. Core returns `-1` help for no
  arguments or excess arity, but returns a `-3` null type error when named
  options create an omitted outputs hole. Native keeps its missing-outputs
  error for that hole; explicitly supplied null matches Core's `-3` type error.
  Duplicate/unknown names, option conflicts and positional/named collisions
  retain Core's earlier `-8` errors, including an overlong `args` prefix. The
  registry declares these method-validation deviations.
- The HTTP request-body limit bounds externally supplied queries; this
  handler retains O(number of requested outputs) rows and transaction
  references. It never scans or clones the full mempool.

### `API-33`: Core snapshot import, export and lifecycle reporting

`loadtxoutset(path)` synchronously reads an unmodified Bitcoin Core v2
`dumptxoutset` file. Positional `[path]` and named `{ "path": path }` parameters
are accepted. Relative paths resolve below the configured node datadir.
The input must be a regular file outside the node's `assumeutxo` recovery
namespace. The shared UTXO codec applies its finite resource limits and resolves
height, commitment, and cumulative transaction count only from the compiled
network anchor matching the header's base block hash. The complete decoded
state must reproduce `hash_serialized_3`; a parsed header is not authentication.
Only one file import per node may materialize a UTXO set at a time. Both the
portable RPC and native-v4 embedding entry claim that same permit and reject
an existing activation before opening or decoding input. The manager retains
its lifecycle-protected admission recheck before activation.
Archive publication and abandoned-reservation cleanup follow `ARCH-07b`;
cleanup does not reset the accepted head or modify source artifact contents.

Activation requires an empty mempool and retains operator fee prioritisation.
Its native orphan reconsideration policy, bounds, and mempool settlement rules
are owned by [MPL-04](mempool-mutations.md#mpl-04-generation-validated-admission-and-chain-change-fencing).
The node activates through `AssumeUtxoManager` and reconciles its consumers.
Successful return certifies the durable snapshot anchor and consumer settlement.
Settlement failure closes admission for recovery and is an error,
even if the anchor committed. Headers through the base must already be known.
The installation boundary, under chain-transition exclusion, rejects an invalid
base or a base outside the current best-work header ancestry before publishing
the lifecycle record. Repeated activation, missing headers, an existing
full-revalidation requirement, and a base without strictly greater cumulative
work than the settled active tip are also rejected. Height alone does not rank
competing branches. Equal work is refused; the native header tree does not
model Core's block-availability sequence/pointer tie-breaker, so this condition
is not full Core comparator parity. Existing native v4 checkpoints
remain internal recovery artifacts and are not accepted by this RPC.

The result contains `coins_loaded` (unspent **outputs**, not txid records),
`tip_hash`, `base_height`, and a UTF-8 display of the absolute input `path`.
The path is rendered before activation; non-UTF-8 filesystem bytes are replaced
only in this JSON display. Path/open failures return -8, malformed codec/trust
failures -22, and underlying read-I/O, lifecycle, storage or settlement failures
-32603. These explicit error-code deviations are not a full Core RPC parity
claim. A file that repeats txid groups returns `-22`; Core 31.1 accepts it,
reports `coins_loaded` 400, and keeps 200 unique outputs (`ARCH-07b`).
Historical validation continues through the existing P2P scheduler.

`getchainstates()` attempts lifecycle exclusion before capturing both roles.
If activation or historical lifecycle work owns it, the query reports typed
unavailability (`-32603`) instead of waiting or inventing a partial role set.
This is an availability deviation: Core can report its prior committed roles
while staging a snapshot. Ordinary active-chain transition exclusion can still
wait; this is not a claim that every query is nonblocking. The established
embedding summary retains its blocking contract. Successful reports share one
capture owner under lifecycle and active transition exclusion.
`headers` is the best admitted header height; the
historical role, when present, is first and the active role last. Each reports
`blocks`, `bestblockhash`, `validated`, and `verificationprogress` when a known
cumulative transaction count permits the existing transaction-based estimate.
Unknown progress, including a missing applied tip, is omitted rather than
replaced with a height fraction.
The historical role contains coins validated from genesis and reports
`validated: true`; the assumed active role reports false until finalization.
`snapshot_blockhash` identifies the compiled base for a snapshot-derived active
role, including after finalization or while a failed assumed role is still
observable before shutdown. Core's difficulty and cache-allocation
fields are omitted because this projection does not expose corresponding
owner facts. Role state and progress survive restart through the durable head
and the existing checkpoint/replay contract.

`dumptxoutset(path, "latest")` writes the applied tip's UTXO set as an
unmodified Core v2 snapshot. Positional `[path, type]` and named
`{ "path": path, "type": "latest" }` parameters are accepted.

The registry marks `dumptxoutset` as a Deviation from Core 31.1. Its note
records that only `type` `"latest"` is served, so rollback snapshots and the
`options` object (`rollback`, `in_memory`) are not accepted, and that the encode
holds chain-transition and stable-view exclusion for its whole duration, so
block commits wait. The note also states the cancellation and output rules
below.

`type` is required and MUST be `"latest"`, as in Core 31.1. A missing, null or
empty `type`, any other string, and an unknown named parameter such as
`rollback` return -8.

A relative `path` resolves below the configured datadir, and its final
component MUST be UTF-8. Nothing is ever replaced: an existing destination of
any kind, including a named pipe, is refused with -8, as is a destination under
the node's `assumeutxo` recovery namespace (activation may replace entries
there).

The export is one coherent view. It takes chain-transition exclusion and then
the stable UTXO view, reads the applied tip and its chain transaction count
while holding both, and holds both until the last coin is encoded. No immutable
capture of the set exists, so block commits wait for the whole encode. Once the
node holds chain-transition exclusion, it logs the hold, measured to the release
of both guards, for every outcome: an info message `snapshot export released the
chain transition` with the coin and byte counts on success, and a warning
`snapshot export released the chain transition without a snapshot` on failure.
This contract does not claim the hold is harmless on a large set.

The writer accumulates the `txoutset_hash` in the same pass that writes the
coins, and no second hashing or read-back pass runs. At most one export runs at
a time; a second request is refused with -32603 instead of queueing behind the
first. There is no producer-side check of the base against a compiled anchor:
the importing node supplies that trust.

The request latch (the dispatcher's cancellation latch) or node shutdown stops
the export. The node polls them before it creates the temporary file, the
encoder polls them before its first write and every 5,000 coins, and the node
polls them again before publication. Waiting for chain-transition exclusion and
sorting one shard are not polled, so a cancelled request can wait for an
in-flight chain transition before it stops. An interrupted export answers -1 and
publishes nothing. The call is classified as blocking: it takes one slot of the
dispatcher's bounded blocking quota (see `API-34`), and a full quota answers -1.

The output is a sibling temporary file (`<name>.<pid>.incomplete`) created with
`create_new`, written through a 64 KiB buffer, fsynced, and length-checked
against the encoder's byte count. The node then renames it into place with the
filesystem's atomic no-replace rename, because a prior existence check cannot
exclude a concurrent creator, and fsyncs the directory. A drop guard tries to
remove the temporary file whenever the export returns without publishing it. A
crash, kill, abort, power loss or failed removal (logged as a warning) can leave
one behind. A failure of the final directory fsync is reported although the file
is already in place. Only Linux, Android, Apple and Redox targets have an
atomic no-replace rename; other platforms refuse the export before it takes any
lock.

The result contains `coins_written` (unspent **outputs**), `base_hash` and
`base_height` of the applied tip, the absolute `path` (parent directory
canonicalized; non-UTF-8 bytes in it are replaced only in this JSON display),
`txoutset_hash` (`hash_serialized_3` in display order) and `nchaintx` (chain
transactions through the base block).

Error codes: -8 for a refused destination (including one created between the
existence check and the rename), an unusable output directory, a temporary file
that cannot be created, and the `type` and named-parameter refusals above. -1
for an interrupted export or a full blocking quota. -32603 for a platform
without an atomic no-replace rename, a closed admission, a missing applied tip,
an unestablished chain transaction count, a concurrent export, and any encode,
write, length or sync failure.

Evidence for the export needs the pinned Core 31.1 `bitcoind`. The test
`bitcoin_rs_export_is_accepted_by_a_fresh_core_node` in
`e2e/tests/assumeutxo.rs` submits the 200 blocks of the Core v2 fixture to this
node and checks that its export equals the committed
`crates/utxo/tests/fixtures/core-v2/core200.dat`, the unmodified Core 31.1
`dumptxoutset` output (fixture README). It then loads the export into a fresh
Core node, which accepts it. The test fails, not skips, when the pinned binary is
missing or its digest differs from the one in `crates/rpc/core-compat.toml`.
`scripts/install-bitcoind.sh` installs it. The evidence is regtest height 200
only. It does not establish mainnet memory, throughput, or commit-blocking time.

### `API-34`: Active-tip waits

- `waitfornewblock`, `waitforblock`, and `waitforblockheight` observe the
  Chainstate-owned durable applied tip through `chain::ActiveTipWait`.
  Header-only admission, mempool changes, and historical AssumeUTXO replay
  do not publish the active tip. No mining capability is required.
- New-block waits compare hashes, including the optional Core 31.1
  `current_tip`; block waits require the target to be the current tip;
  height waits compare the signed target with the current height. A missing
  `current_tip` captures the starting hash once. Deadlines are absolute and
  use milliseconds; zero/null means indefinite and negative timeouts are
  Core `-1`. Timeout and cancellation return the current tip.
- The owner's notification gate serializes applied-tip publication, shutdown,
  predicate checks and parking. It holds no duplicate tip value and performs
  no I/O. A satisfied predicate releases this gate before acquiring transition
  exclusion and rechecks the settled tip, so an intermediate reorg prefix
  cannot satisfy normal success as if it were the completed transition.
  Timeout, caller cancellation, normal shutdown, recovery closure and explicit
  owner closure return the latest durable published prefix without waiting for
  a busy transition to finish. Connect, grouped-connect and disconnect publish
  only after their durable-head commit; a published prefix can be durable
  without being the final tip of an in-flight reorg. This bounded return
  differs from Core's final `GetTip` acquiring `cs_main`, and is an explicit
  deviation. Transition acquisition uses bounded cancellation checks;
  unsatisfied predicates sleep on a condition variable without periodically
  reading the chain.
- Normal shutdown, recovery closure, and explicit owner closure wake waiters.
  RPC-server-only shutdown sets the bound dispatcher's cancellation latch before
  waking the owner, and does not stop chainstate. The listener retains its
  existing detached connection-worker lifecycle; this change adds no joins.
  Each binding owns its dispatcher latch and quota. Rebinding the same Context
  creates a fresh dispatcher, while old requests retain the old cancellation
  latch; an old server's shutdown cannot cancel or revive the new service.
- Registry execution metadata classifies the three wait methods,
  `scantxoutset`'s `start` action, and a template `getblocktemplate` request
  carrying a string `longpollid`. The registry rows of `verifychain`
  and `dumptxoutset` carry
  the same `Blocking` class; the proof tests below pin only the wait,
  scan-start and long-poll classes. Every `Handler::dispatch` of a classified
  call, including direct callers, batch entries and notifications, acquires its
  dispatcher's bounded blocking quota. A bound listener permits one fewer such
  call than one source address may hold (`max_connections - max_connections / 4 - 1`,
  95 of the node's 128; zero with one worker). Blocking calls therefore never
  take a source's last connection or the whole pool. The total connection
  bound is unchanged: once the pool is full, every source is refused, as
  before; reserving ordinary capacity per source is not provided.
  A standalone dispatcher defaults to 16 blocking calls. Admission never
  waits for capacity. Scan status/abort remain ordinary calls.
- Connection admission: a listener holds at most `max_connections` live
  connections. One source address holds at most `max_connections -
  max_connections / 4` of them (96 of the node's 128), so a quarter, rounded
  down, stays open to other sources. A refused connection gets HTTP 503
  `busy`. A source is an address, so clients behind loopback, a Docker gateway
  or a reverse proxy share one. Pools below four workers keep no per-source
  share.
  The node defaults to one shared listener with 128 connections. Opting into
  `public_bind` moves the HTTP query/broadcast surfaces to an independently
  bounded listener and leaves authenticated JSON-RPC on `rpc_bind` (WF-02).
  `rpc_max_connections` and `public_max_connections` independently default to
  128 and must be positive. All admitted connections, including incomplete
  heads, idle keep-alives and blocking requests, count against their binding.
  Public occupancy cannot consume management permits; neither binding is
  exempt from admission. Each accept loop can additionally hold one refused
  socket while writing its 503, bounded by the configured idle timeout.
  This isolates connection capacity, not shared CPU, process descriptors,
  storage or lock contention. Each binding retains the
  existing dispatcher-owned blocking quota and shutdown latch. Both listeners
  bind before either starts; startup rollback and normal teardown own both.
  - An empty accept queue waits on listener readiness, rather than sleeping
    before retrying accept. Connections wake that wait immediately. The
    existing read-only atomic shutdown latch has no notifier, so the wait
    uses a 20-ms readiness timeout to inspect it (subject to OS scheduling);
    timeout alone does not retry accept.
    Accepted streams retain blocking worker I/O and the configured idle
    timeout. Readiness setup/wait failures stop the listener through its
    existing exit path.
  - Interrupted and aborted accepts retry immediately. Other accept errors,
    including descriptor exhaustion and Linux's pending-connection `EOPNOTSUPP`
    (`Unsupported`), warn and retry after 100 ms; shutdown is checked before
    each attempt. Invalid-input and not-connected
    listener errors remain fatal. Accepted-socket setup failures drop only that
    connection. The node logs a listener exit before shutdown immediately,
    while retaining the I/O result for its normal shutdown join.
  - Once the server starts reading a request, its head must complete within
    10 s and its body within 60 s, however slowly the bytes arrive.
  - Waiting for the next keep-alive request keeps the listener's idle timeout
    (30 s in the node, Core's `-rpcservertimeout` default).
  - A request body's buffer grows with the bytes received, as in Core's HTTP
    server: to at most twice those bytes or 8 KiB past them, and never beyond
    the declared `Content-Length` (at most 16 MiB). A body cut short is a
    framing error.
- Admission exhaustion is the intentional `-1` error
  `RPC blocking request limit reached`. HTTP requests containing a classified
  blocking call close keep-alive after their response, including refusals, so
  a refused call cannot retain the last ordinary worker as an idle connection.
  Notification-only calls retain HTTP 204; mixed batches retain response order.
  A template `getblocktemplate` request with a string `longpollid` counts
  toward the blocking quota and closes keep-alive like any classified call;
  overload answers the same `-1` quota error, not Core's HTTP `503`, so
  long-poll clients reconnect per poll. A long-poll is not on the RPC
  cancellation latch. An absent or null `longpollid` uses ordinary template
  handling; any other non-string value fails with InvalidType before waiting;
  a string id is blocking-classified, and a malformed string id fails fast.
- Arity errors retain Core's `-1` but return concise method usage rather than
  its generated help body. These cancellation, overload, transport and help
  differences are declared `Deviation`; no full compatibility promotion is made.
- Evidence: `chainstate::tip_wait::tests`,
  `crates/rpc/tests/tip_wait_admission.rs`, `rpc::registry::tests`,
  `rpc::handlers::registry_tests`, and the live pinned-Core process comparisons
  in `e2e/tests/rpc_tip_waits.rs` exercise reorgs, deadlines, shutdown responses,
  parameter errors and restored startup. Header-only process checks complete
  finite waits after admission and compare the applied tip; deterministic
  waiter registration/publication and admitted cancellation are proved by the
  owner and real-server tests, which also prove ordinary HTTP availability.

### `API-35`: Bounded public-descriptor UTXO scans

- `scantxoutset` accepts strings and `{desc, range}` objects with optional
  verified checksums. Fixed `addr` and `raw`, and public `pkh`, `wpkh`,
  `sh(wpkh)` and key-only `tr` are supported, including public wildcard and
  multipath derivation. Scalar ranges mean `[0,end]`; array ranges include
  both endpoints. An omitted or null range on a wildcard uses `[0,1000]`
  on each path, matching Core. A valid range on a descriptor without a
  wildcard is checked and ignored, including fixed multipath descriptors.
  Private keys, derivations requiring private keys, Taproot trees and other
  descriptors are refused; these remain explicit Core deviations. Repeated
  alternatives within one multipath specifier are rejected with -5, like Core,
  with an implementation-specific diagnostic rather than identical error text.

- One transient reservation belongs to the authoritative `UtxoSet`. A second
  start returns -8. Status is null when idle, otherwise approximate progress;
  abort requests cancellation and returns whether a reservation exists.
  Abort produces `success: false` with actual visited `txouts` and only fully
  projected unspents; abort during ancestry resolution may leave these empty.
  The amount sums only that projected prefix.
  Errors and guard drop release the reservation; restart has no active scan.
- Input limits are 1,024 descriptors, 16 KiB per descriptor, 1 MiB combined
  descriptor bytes, 1,024 script expansions across all objects and paths
  before deduplication, and 1 MiB of distinct scripts. The aggregate expansion
  count is checked before public-key derivation. A two-path wildcard with
  omitted range exceeds this budget and requires a smaller explicit range;
  duplicate expansions also consume work budget. The reservation has a
  60-second deadline, checked during parsing and before each script expansion,
  while waiting for exclusion and every 256 coins or shard boundary. Traversal
  permits at most 250 million coins, 10,000 matches and 8 MiB of matched script
  bytes; projection additionally caps estimated JSON materialization at 16 MiB,
  including repeated descriptors.
  Retained-branch ancestry resolves requested distinct heights in one walk
  capped at 2 million nodes, with timed lock acquisition and cancellation
  checks every 256 nodes; sorting and projection also recheck cancellation.
  Limit failures return errors, never a complete/truncated success.


- Script lookup uses one bounded set; duplicate scripts preserve the first
  descriptor's inferred attribution. Unspents follow Core outpoint order.
  `raw` and `addr` use shared script descriptor inference; public key
  descriptors retain specialized key/origin data and checksums.
- The applied publication and UTXO view are captured under the existing
  chain-transition read exclusion. Coin creation hashes and confirmations use
  that retained publication even if a reorg happens during projection.
  Missing ancestry is unavailable, never a fabricated hash. This bounded read
  blocks chain transitions; it is not Core's independently retained DB cursor.
- Active traversal observes the shared RPC shutdown lifecycle. Blocking scan
  starts share the server's bounded blocking-operation admission; status and
  abort remain ordinary requests. No second HTTP worker pool or scan index is
  introduced.
- Evidence owners: UTXO scan unit tests, RPC `scantxoutset_tests`, and
  `e2e/tests/scantxoutset.rs`, which runs the pinned unmodified Core
  process and retains exact request/reply comparisons in process evidence.
  The presence of these tests is not itself a successful execution claim.

## Live gaps

- **Full Core differential suite**: Versioned Core response structs, golden fixtures, and differential test lanes across all RPC methods are tracked under #78 (open).
- **Typed embedding surface**: Direct in-process application API as an alternative to localhost JSON-RPC daemon boundary is tracked under #145 (open).

## Vocabulary
