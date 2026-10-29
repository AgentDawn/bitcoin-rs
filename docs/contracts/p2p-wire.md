# P2P wire contract

This page assigns ownership and cites proof under the
[contracts precedence rule](README.md).

- [`crates/p2p/src/compat.rs`](../../crates/p2p/src/compat.rs) owns the
  decoded command inventory and the pinned Core version.
- [docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md)
  owns the handshake fields, reject-or-ignore matrix, deviation ledger,
  and verification process. The §5 table is a checked projection of
  `COMMANDS`.

## Clauses

### `P2P-01`: Protocol wire framing and handshake compatibility

- **Owner**: `crates/p2p/src/compat.rs` owns the 42-command inventory (the 36
  Core-compatibility commands plus the extensions `feature`, the four BIP331
  package messages, and `staletip`, which Core 31.1 does not have) and
  `PINNED_CORE_VERSION` (Bitcoin Core 31.1). The policy document owns handshake
  fields, reject-or-ignore semantics, and recorded deviations.
- **Scope**: `crates/p2p` wire, handshake, protocol FSM, and message policy; the
  chain-serving query `crates/p2p/src/chain_query.rs`; and node network flags.
- Message framing, envelope decoder, service flags, and network magic follow
  the inventory and the policy document. v1 frames for handshake and inventory
  commands are byte-identical to rust-bitcoin's `RawNetworkMessage`.
  `getdata` block serving validates the stored body and answers
  `MSG_WITNESS_BLOCK` with its exact stored consensus payload bytes
  (`Message::BlockPayload`). `MSG_BLOCK` copies the checked header, transaction
  count, and stripped transaction spans into its payload, following BIP144.
  Both forms validate the complete borrowed layout without materializing
  scripts or witnesses; malformed bodies are never forwarded. Both forms
  resolve `(height, hash)` directly and recheck serving eligibility after
  preparing the payload.   Stored stale blocks remain servable under the policy
  document's validation and age bounds; unsolicited announcements remain
  active-only. Response depth uses the applied frontier rather than unapplied
  headers. Locator-based `getheaders` replies walk the applied chain:
  `ActiveChainQuery::headers_after` resolves the locator order, stop hash,
  and height walk against the validated applied tip, never the header-best
  tip; the empty-locator single-header direct lookup stays on the header-best
  chain. The wire decoder types inbound `block` as
  `Message::Block(BlockPayload)`, constructed once via
  `BlockPayload::from_raw` on the frame bytes with no second decode; the
  serving `Message::BlockPayload(Bytes)` envelope stays raw-only with no
  decoded field. `InboundBlock` owns the one payload while peer/source and
  `forward_credit` stay outer; `check_body_binding` runs on the decoded
  block and credit is released at the existing handoff.
- Handshake boundary proof: `peer::tests::bip434_send_window_uses_remote_version_and_local_verack`
  and `bip434_send_window_closes_only_after_a_successful_verack_write`;
  `connection::tests::bip434_features_never_enter_the_post_handshake_queue`;
  `dispatch::tests::version_reply_sends_the_offered_sendpackages_once_before_verack`;
  `listener::v2_transport_tests::bip434_windows_preserve_bip332_and_package_negotiation_on_v1_and_v2`
  exercises both transports with BIP332/BIP331 enabled. These are local and
  loopback proofs, not live interoperability evidence against a BIP434 Core.

### `P2P-02`: Connection lifecycle and peer lease ownership

- Peer connection sessions and `PeerLease` lifecycle are owned by `crates/p2p`.
  `connection::PeerRemote` distinguishes a destination from an anonymous
  inbound Tor circuit identified by its lease's `ConnectionId`. Address-book
  and dial APIs accept only `PeerEndpoint` destinations. Transaction attribution
  retains the connection id even when no destination is known.
- Automatic discouragement is owned by the P2P service's `BannedReader` and
  bounded ephemeral policy. The listener records only typed remote violations
  from a current lease. Immutable exclusion snapshots precede address-book
  locks; socket admission rechecks them. Manual/local/operator protection and
  the exact Core deviations are specified in policy §6, with deterministic
  ownership/expiry tests and the real-process `peer_discouragement` comparison.
- The node-side synchronization coordinator consumes peer lifecycle events
  without duplicating connection replacement or cancellation rules.
- Parent requests validate the delivering connection and enqueue under the
  same peer-table authority that serializes replacement. Requests from an
  already cancelled lease enqueue nothing.
- Every queued outbound message is paid for before it exists. A charge takes
  one message and its full wire bytes from the connection's own budget and the
  same bytes from the node's aggregate budget (`SharedOutboundBudget`, 64 MiB
  per `P2pService`, strict: the pending total is never above the cap at any
  instant). The charge has one owner at every moment (the reservation, then the
  `QueuedFrame` carrying it through the lease's channel, then the writer's
  burst) and is released exactly once when that owner drops, whether the frame
  was written, refused, discarded with the channel, or drained at writer exit.
  A bulk body reservation must also fit under the cap less one maximum frame.
- A refused charge takes nothing. A refusal by the connection's own bounds
  (`Local`) cancels the lease. A refusal by the node aggregate (`Shared`) is
  backpressure only: the lease stays live, and the sender defers the request,
  parks the unserved items, returns the claim to its owner, or retries on the
  next tick. The aggregate never ends a session, and the time it refuses a
  session is a stall that is not silence for keepalive, not the age of a
  parked request, and not charged to a compact-filter request's allowance.
- Scheduler ownership is keyed on connection identity. Every tick runs two
  sweep passes over the peer table's live session set, and a ready event
  from a live connection runs one; a stale ready event runs none. Each
  sweep releases every window assignment, election, probe racer, header
  request and deferred body fetch owned by a connection outside that set,
  so a same-address replacement never inherits or loses its predecessor's
  work.

For the process comparison, set `BITCOIN_RS_NODE` to a binary built from the
tested commit and `BITCOIN_RS_REFERENCE_BITCOIND` to the pinned Core binary.
`cargo test -p bitcoin-rs-e2e --test peer_discouragement` runs
`e2e/tests/peer_discouragement.rs` against pinned Core 31.1 and the candidate on
loopback: protected oversized-headers senders remain connected, unprotected
local senders disconnect and can reconnect, RPC reflects `noban`, and no manual
ban is added. It does not test nonlocal Core avoidance, retention capacity or
expiry.

### `P2P-03`: Demonstrated best-known-height credit and request eligibility

- **Owner**: `crates/p2p/src/peer_table.rs` owns the per-connection credit
  record (`PeerInfo.best_known_height` plus the accepted header tips retained
  by the live session) and its identity-checked mutation
  (`PeerTable::note_announced_tip`, `PeerTable::note_announced_height`).
  `crates/p2p/src/sync.rs` owns the eligibility/ordering consumption
  (`sync_peer_candidate`, `outranks`) and the active-branch filter that
  decides which accepted headers establish credit.
- Credit is initialized from the handshake `start_height`, raised
  monotonically (never lowered), raisable only by the delivering connection
  (a same-address replacement never inherits its predecessor's credit), and
  raised only for accepted headers whose retained tip shares ancestry with
  the currently selected best chain (the best chain is re-selected during
  acceptance, so a winning fork announcement earns credit in the same tick).
  A retained tip attests the deepest active-chain node that is its ancestor
  — `shared_active_height`: an on-active tip attests its own height, while a
  losing fork tip still attests the shared prefix it proved the peer holds.
  When a later announcement makes a previously losing retained tip active,
  its delivering connection is re-evaluated before request selection. Body
  and hedge selection may ask a connection up to the greater of its
  handshake credit and the deepest shared ancestor across its retained
  tips: branch evidence can raise what a peer may serve, never lower it
  below the credit the connection already carries. A peer that cannot serve
  what it claimed is judged by the request that times out, not by being
  skipped without ever being asked (issue #1153). Retained-tip evidence is
  compacted at each credit
  refresh: a tip that resolves on the active chain at or below the recorded
  maximum can never raise it again, so only unresolved (fork) tips and the
  max-resolving tip are kept. Unresolved tips are deduplicated to the
  maximal tip per branch and capped (`MAX_UNRESOLVED_DEMONSTRATED_TIPS`),
  so a peer cannot grow the record by announcing distinct side chains.

### `P2P-04`: Connected-socket posture and vectored emission

- **Owner**: `CountingStream::from_connected` (`crates/p2p/src/counters.rs`).
- Every accepted or dialed P2P `TcpStream` is wrapped by that constructor
  before handshake bytes move. The constructor disables Nagle (`TCP_NODELAY`).
- `CountingStream` forwards `write_vectored` so `wire::write_message` emits
  header plus payload as one syscall. A wrapper that only implemented `write`
  would split the frame again.
- Handshake, the connection reader, and the writer-thread clone share one
  `PeerCounters`. Timeouts stay with the listener: handshake and the message
  loop use different poll intervals.
- A poll timeout never loses inbound bytes. `Peer::read_message` reads through
  the peer's `wire::V1Receiver`, which keeps a partial header or payload across
  `TimedOut`/`WouldBlock`, so the retrying handshake and message loops continue
  the same frame instead of resuming mid-frame. The retained buffer holds only
  received bytes: a stalled frame never pins the declared payload length.

### `P2P-05`: Canonical frontier recovery without invented peer credit

- The applied chain and selected header ancestry own the next required body.
  The download cursor is a scan hint. An unowned frontier behind that hint
  becomes requestable again, including an applied rollback with unchanged
  headers. Existing pending and staged bodies retain their ownership.
- A known-header gap whose apply-frontier block is neither in flight nor
  staged triggers a header probe from the applied chain; staged successors
  behind an unowned frontier are stuck inventory, not progress. Beyond the
  initial handshake capability (P2P-03), only a subsequent accepted
  active-branch announcement grants body capability. Losing the last credited
  peer must not require restart or an unsolicited announcement from a
  surviving peer.
- The existing header request and timeout pace discovery. Empty wire
  responses mark a request answered without changing its original timestamp;
  an identical retry is paced only until five seconds from that timestamp,
  and answered requests are not blamed as silence. Frontier requests use the
  same five-second deadline while unanswered. An unanswered chain-sync
  eviction probe keeps its request gate for the existing two-minute
  `HEADERS_RESPONSE_TIME`, aligned with its eviction response window.
  A nonempty batch consumes its matching request only when it is a usable
  answer: admitted, or already known in full. A batch this node rejects keeps
  the gate and moves its deadline to the answer, because that connection did
  respond.
- Header-request expiry is a strike against the exact connection only while
  its request is unanswered. On ordinary frontier expiry the gate clears,
  that connection is marked unresponsive, and it is disconnected while
  another usable peer remains, so the next tick elects a different peer.
  Strikes lower that connection's header rank below peers that advertise as
  much, and the sweep that releases a dead connection's work drops its
  strikes with it, so a same-address replacement starts clean. Only silence
  is blamed (Core `net_processing.cpp` clears the outstanding
  request when a connecting header lands). The below-floor and live
  download-twice timeout in P2P-10 retires its source even when it is the last
  usable peer.
- A delivered body whose embedded header cannot attach releases the gate that
  connection owns before it asks for the missing ancestry
  (`clear_header_request_for`), so the recovery request reaches the wire with
  the delivery instead of waiting for the deadline. A wire `headers` answer
  keeps its gate, and the live request suppresses a replay of the same
  locator.
- A `headers` batch that fills the wire page and connects continues from that
  batch's own last header, so the peer resumes where the page stopped instead
  of waiting one scheduler round trip. Core asks the same peer for the next
  page after a maximum-size connected response (`net_processing.cpp`,
  `MAX_HEADERS_RESULTS` from `net_processing.h`).
- The block locator doubles its step only after the locator holds more than
  ten entries, and the indexed walk and the parent-walk fallback produce the
  same schedule (Core `GetLocator`, `chain.cpp`).
- Session validation and request publication hold the peer table before
  download or header-request state. A cancelled ready event does not wait for
  the download writer or modify its replacement's state.
- Body/header binding failures reject the delivery, not the header branch.
  Rejection logs carry source, byte/transaction counts and coinbase witness
  shape. Compact reconstruction logs include the same block hash for joining
  evidence. A header ahead of the applied chain is not evidence that the
  applied-chain `getblockhash` RPC should return it.

### `P2P-06`: Body-carried announcements reach header admission

- **Owner**: `ConnectionShared::send_block` (`crates/p2p/src/listener.rs`)
  forwards every inbound body's embedded header through the headers sink;
  `BlockSync::admit_staged_headers` (`crates/p2p/src/sync/receive.rs`) retries
  admission for staged bodies still lacking a tree node.
- A block body can never become the apply frontier's expected block while
  the tree does not know its hash. Every delivery path — `block` messages
  (`inv` getdata answers or unsolicited pushes), reconstructed compact
  blocks, and `cmpctblock` announcements — routes its embedded header into
  the same admission drain as `headers` messages, so credit (P2P-03),
  peer-fault disconnection, and ancestry requests apply uniformly.
- A batch that cannot attach (`MissingParent`) or cannot be admitted
  (`Refused`) requests the header ancestry from the delivering peer — or an
  eligible full-witness peer when no source was recorded — rather than
  silently dropping the announcement and leaving the live tip wedged behind
  one missed header. `Refused` re-requests are paced to the request timeout
  (`refused_rerequest_at`): a paused admission would otherwise replay the
  same locator at round-trip pace.
- The forwarded header is marked as such (`InboundHeaders::wire_response =
  false`): it is not a `getheaders` response, so it must not consume the
  outstanding request's pending slot as an answer — otherwise every delivered
  body would reset request pacing and redeem a peer that never answered. The
  one release it earns is the recovery path above: a body-carried header that
  cannot attach frees its owner's gate, so the ancestry request that delivery
  motivates reaches the wire with it (P2P-05).
- The stager MUST hold one `BlockPayload` per entry (`insert(payload)`). The
  staged retry carries the delivering connection
  (`ReceivedBlock::source`): a retry that admits credits that peer exactly
  as the headers drain would (`note_announced_tip`), and a peer-fault
  rejection drops the staged body (`stager.discard`, never re-queued;
  its download-window record is only released when the delivery drains), disconnects the source, and marks
  it unresponsive — the same outcome a rejected `headers` batch produces.
  A staged body's recorded source is retained for work-floor validation and
  header retry after that source disconnects, but exact-source checks prevent
  the retry from crediting or faulting a same-address replacement
  (`staged_body_retries_after_source_replacement_without_replacement_credit`).
  The inbound body drain drops deliveries whose source is already retired
  when checked at dequeue, before historical or foreground routing
  (`queued_body_from_replaced_source_cannot_enter_staging`).
  This check does not hold peer-table authority through body validation or
  staging: a body accepted while its source is current may finish staging
  after concurrent retirement. Credit and fault attribution still require
  the exact source to be current.
- A `cmpctblock` outcome that fetches the body itself (`RequestMissing`'s
  `getblocktxn`, `Fallback`'s `getdata`) is marked
  (`InboundHeaders::body_fetch_owned`): once the tip admits, the window
  records the hash pending under the delivering connection
  (`DownloadWindow::mark_owned_fetch`) so normal scheduling does not issue
  a duplicate `getdata`. The mark honours the same gates a real request
  faces — window request capacity, the owner's per-peer inflight share,
  and the request frontier (a below-frontier mark could never be scheduled
  and its expiry would drag `next_request_height` back into a re-request
  sweep of applied heights). A tip that has not attached yet is retained
  in the bounded `SchedulerState::owned_body_fetches` set and resolved
  once ancestry admits it; marks whose source went stale are dropped, and
  delivery resolves the mark like any window request while expiry or
  disconnect hands it back to scheduling — a silently dropped compact
  fetch re-requests instead of wedging the tip.
- Every peer-removal path releases a `getheaders` gate the peer owned —
  wire-response consumption, send failure, and peer-fault disconnects in
  both the headers drain and the staged-header retry
  (`clear_header_request_for`, identity-exact), and otherwise the live-set
  sweep (P2P-02) — so a same-address reconnect cannot inherit a dead
  request deadline.

### `P2P-07`: Block announcements lead with headers; ingress is bounded twice

- **Owner**: the block branch of `dispatch_inbound_full`
  (`crates/p2p/src/dispatch.rs`), `BlockSync::announce_block`
  (`crates/p2p/src/sync.rs`) and `BlockSync::drain_block_announcements`
  (`crates/p2p/src/sync/headers.rs`).
- `MSG_BLOCK` and `MSG_WITNESS_BLOCK` inventory vectors are availability
  information, never a body request: each one is queued against the
  announcing connection and drained by the header drain, which credits that
  connection with the hash when the tree already knows it
  (`note_announced_tip`, P2P-03) and asks it for headers when the tree does
  not. Body requests belong to header admission and the download window
  alone (Core 31.1 `net_processing.cpp`). Transaction vectors keep
  the relay gate, the have-filter, and the witness upgrade unchanged.
- The queue holds one entry per connection — the first unprocessed
  announcement wins — so a later vector cannot replace an unknown tip before
  the drain sees it, and a peer cannot grow scheduler state by announcing.
  While the frontier-owned `getheaders` request is outstanding, further
  unknown announcements stay queued for a later drain: the frontier request
  owner never changes mid-flight.
- **Near-tip direct fetch**: `BlockSync::direct_fetch_announced_tip` asks the
  connection that just proved a header for its body, inside the same drain
  that admitted it, instead of waiting for the next scheduler tick (Core
  `HeadersDirectFetchBlocks`, `net_processing.cpp`, gated by
  `CanDirectFetch` at `:1450-1453`). The request goes through
  `send_getdata_for_pending_blocks`, so the window's budget, the per-peer
  in-flight cap, the pending ownership stamp, and the compact-block flavor
  for a single near-tip fetch from a BIP152 peer all apply unchanged. A tip
  that is not on the branch the header tip ends at, or that leaves the apply
  frontier more than `COMPACT_RELAY_NEAR_TIP_BLOCKS` below it, is a bulk
  download or a large reorg and stays with the ordinary scheduler.
- **Ingress bounds**: the shared inbound block channel is bounded once for
  the node (`P2pServiceConfig::inbound_block_queue_limit`, set from
  `INBOUND_BLOCK_CHANNEL_LIMIT`), and
  `PeerLease::admit_block_forward` bounds each connection's unsolicited
  share of it at `MAX_UNSOLICITED_BLOCK_FORWARDS`
  (`crates/p2p/src/connection.rs`) before that channel. A body the download
  window owns for that exact connection — a window request or a deferred
  compact fetch (`BlockSync::owns_body_fetch`) — is always admitted. An
  over-bound unsolicited body is dropped together with its carried header —
  refused bodies must not grow the header queue either — with a debug record
  and a `node.sync.dropped_unsolicited_blocks` counter: the listener never
  waits on the shared channel for it and the connection is never
  disconnected for this bound alone. The credit rides the inbound payload and is released
  when sync takes the body, so staging, discarding, and rejecting all return
  the slot; ownership and credits are per connection, so a same-address
  replacement inherits neither.
- **Permanent consensus failure**: when a staged body's commit settles with
  `WindowCommitDisposition::Permanent` — in the apply pass or inside a
  branch switch (`BranchSwitchError::ConnectFailed`, attributed through the
  staged entry's recorded source) —
  `BlockSync::punish_permanent_delivery_source` disconnects the delivering
  connection — in the apply pass, after the invalidated hashes are purged;
  in a branch switch, before the purge drops the staged entry that carries
  the source — and releases its
  `getheaders` gate and marks it unresponsive only when that exact
  connection was current and removed (Core `net_processing.cpp`).
  Each punishment increments `node.sync.invalid_block_disconnects`. A
  `BodyMutated` or `Operational` settlement failure stays retryable and
  non-punitive, and a `Fatal` settlement halts admission without peer blame.
  `BodyMutated` names only the delivered bytes, so the header stays valid and
  the body is fetched again: a Merkle or witness mismatch, and a body without a
  coinbase that holds a 64-byte witness-stripped transaction (`SixtyFourByteMutation`; inner
  Merkle nodes posing as transactions, CVE-2017-12842, Core `IsBlockMutated`).
  Any other body without a coinbase is `Permanent`.
  A body that fails header binding before it can be staged keeps its
  existing delivery-rejection policy.
- **Unresolved-body quota**: a body staged while the tree cannot resolve its
  hash owes the admission clauses later (`gate_pending`); the staged
  `gate_pending` population is capped at `MAX_UNRESOLVED_STAGED_BODIES`
  (`crates/p2p/src/sync/receive.rs`), so a multi-peer orphan flood cannot
  fill the shared staging budget and evict valid progress.

### `P2P-08`: Inbound admission and the outbound service gate

- **Owner**: `PeerTable::try_register_inbound` (`crates/p2p/src/peer_table.rs`)
  owns the capacity and eviction decision, `select_inbound_to_evict`
  (`crates/p2p/src/eviction.rs`) owns the choice of connection, and the accept
  loop in `serve` (`crates/p2p/src/listener.rs`) is the only inbound caller.
  `has_all_desirable_service_flags` (`crates/p2p/src/listener.rs`) is the only
  ordinary outbound desirable-service predicate.
- The accept loop reserves the connection's inbound lease before it spawns the
  handshake thread, and the reservation, the live inbound count and any
  eviction are one table write operation. A socket that arrives at
  `max_inbound = max_peer_connections - outbound_full_relay_slots -
  outbound_block_relay_slots` first removes and cancels the inbound connection
  chosen by a port of Core's `SelectNodeToEvict` (Core derives the same
  remainder at `bitcoin-core/src/net.h` and evicts at
  `net.cpp`). Outbound and `NoBan` connections are never chosen.
  Every read on an inbound socket fails once its lease is cancelled, so an
  evicted connection stops even while its peer keeps trickling a payload,
  as Core closes an evicted socket at once. When every candidate is protected,
  or the address holds a live outbound connection the newcomer would also
  replace, the socket is closed with no lease and no thread. A replacement at
  an address already holding a live inbound connection is admitted without
  eviction: it takes the slot its predecessor held. The live count is always
  derived from the live entry set, so no independent counter can drift from
  it. A failed spawn releases the reservation it took.
- Eviction protects, in Core's order: four connections by a process-keyed
  netgroup hash, the four that most recently delivered a transaction the
  mempool accepted, up to eight block-relay-only connections with wanted
  services that most recently delivered a committed block, the four that most
  recently delivered a committed block, and then half of the rest by uptime,
  up to a quarter of the candidates reserved for localhost. It then evicts the
  newest connection of the netgroup with the most remaining candidates.
  `docs/policies/p2p-compatibility.md` section 7 item 12 lists where this
  differs from Core.
- `PeerTable::set_network_active` and conditional inbound/outbound socket
  registration share the table write lock. If disable wins first, registration
  returns no lease without replacement or capacity mutation. If registration
  wins first, disable cancels that admitted lease for its connection owner to
  remove. Re-enabling permits fresh leases without reviving cancelled ones.
  Socket I/O, metadata queries and logging remain outside the write lock. TCP
  already in progress may finish after disable; rejected registration closes
  it before publishing metadata or sending handshake messages.
- Ordinary `run_outbound_handshake` ends the connection when the remote `version` does
  not offer the desirable set (`net_processing.cpp`, read for
  an outbound connection at `:3864-3871`): `NETWORK | WITNESS`, or
  `NETWORK_LIMITED | WITNESS` while the local tip is younger than 144 blocks.
  The check runs before the peer is published as usable, so a dial that cannot
  serve blocks never occupies a selection slot that maintenance cannot replace.
  Inbound handshakes and VERSION-only feelers are not service-gated, as in Core.
- Ordinary automatic selection, anchor admission, dispatch and the final
  pre-TCP check reuse that predicate against current AddrMan service metadata.
  Accepted ordinary VERSION updates metadata before service rejection without
  marking Good. Unknown DNS service metadata retains its bootstrap exemption;
  an observed VERSION, including zero services, is known metadata. Representation
  and persistence are owned by `docs/policies/p2p-compatibility.md` section 7;
  manual dials and feelers bypass this metadata prefilter.
- The advertised set follows the prune setting (`init.cpp`):
  `WITNESS | NETWORK` normally, `WITNESS | NETWORK_LIMITED` when
  `storage.prune_target_mb > 0`, and both handshake paths use the same set from
  `P2pServiceConfig::local_services`.

### `P2P-09`: Block-body service eligibility

- **Owner**: `statically_fanout_eligible` (`crates/p2p/src/download_window.rs`)
  is the only predicate that decides whether a connection may serve block
  bodies. The request, fan-out, prefix-probe, and cold-front-hedge paths all
  read it, and none re-derives a witness-only rule.
- It consumes a `BlockDownloadPolicy` carrying the node's one
  `InitialBlockDownload` latch and the height being requested. During initial
  block download only a `NODE_NETWORK` peer qualifies
  (`net_processing.cpp`). Afterwards a peer without it qualifies only
  inside the last 288 blocks of its own demonstrated chain
  (`NODE_NETWORK_LIMITED_MIN_BLOCKS` at `net_processing.cpp`, applied at
  `:1637`), and a peer below the requested height never qualifies. Inbound
  peers stay outside the set: they are attacker-chosen, and counting them is the
  recorded under-fill regression.
- The service clause and the window's soft-block clause stay separate on
  `FanoutCandidate`, so each path combines them as it always did: fan-out, the
  probe set, and the counted threshold require both, and a soft-blocked peer
  still serves as the single-deep-peer last resort. Header requests stay open
  to every peer above the applied height regardless of services.

### `P2P-10`: Header presync gates admission on committed work

- **Owner**: `HeadersSyncState` (`crates/p2p/src/sync/headers_presync.rs`)
  is the only place that decides whether a connection's header chain is
  worth admitting; `BlockSync::route_headers_batch`
  (`crates/p2p/src/sync/headers.rs`) is the only caller, and
  `SyncChain::admit_headers` is reached either directly (a fork already at
  the network's assumed work, or a released chain) or with the committed
  headers, never with a collected-but-unverified batch. Core's
  `HeadersSync` (`bitcoin-core/src/headerssync.h`,
  `headerssync.cpp`, wired in `net_processing.cpp`) is the
  authority.
- A connection whose chain starts below `Network::minimum_chain_work` is
  collected first: each header is checked for continuity, its own proof of
  work, and a permitted difficulty transition, then reduced to one salted
  commitment bit every `commitment_period` heights. Nothing is inserted and
  no body is requested during this pass. When the cumulative work crosses
  the floor the sync restarts at the fork point and re-verifies every
  header against those commitments; only then are headers admitted, in wire
  order. The download-twice rule is what stops one unsynced connection from
  installing an endless minimum-difficulty chain that is cheaper to extend
  than the honest chain.
- The state is keyed by `PeerSource`, not address: a replacement connection
  never inherits a predecessor's collection, and a spent or faulted state
  is removed so the next batch starts a fresh sync with a fresh salt. A
  lost-continuity break is treated as possibly benign (the peer keeps its
  connection, `headerssync.cpp`); every other failure — bad proof of
  work, an impermitted difficulty transition, a commitment divergence, or
  the commitment and buffer bounds — disconnects the connection.
- One per-connection lifecycle entry owns both the optional presync cursor
  and optional wire request. A nonempty wire answer clears only the request;
  an empty answer ends presync but retains an answered request with its
  original request timestamp; exact-source teardown removes the entry. A
  request excludes competing `getheaders` on that exact connection while
  unanswered: ordinary frontier requests, including PRESYNC/REDOWNLOAD
  continuations, use five seconds, while a chain-sync eviction probe uses its
  existing two-minute response window. An answered request paces only
  identical locator/target requests until five seconds from that same original
  timestamp. Only an
  unanswered timeout below the work floor or during PRESYNC/REDOWNLOAD
  retires the connection and its sync state before queued headers are
  processed, even when it is the last usable peer. Recovery starts on another
  connection. Wire deliveries whose source is retired or replaced at the
  ingress identity check are ignored, never admitted or attributed to the
  replacement. Foreground bodies accepted while their source is current may
  finish staging and retry their embedded header after retirement through the
  body-carried path, retaining their source for work-floor validation while
  exact-source credit and fault checks exclude the replacement. The wire has
  no request identifier with which to reconcile overlapping responses.
- The serving side is the mirror rule: below the network's assumed work the
  node answers `getheaders` with the empty response
  (`ActiveChainQuery::headers_after`, `net_processing.cpp`), so a
  syncing node does not spread its low-work branch.

### `P2P-11`: BIP324 v2 transport negotiation

- **Owner**: `crates/p2p/src/transport.rs` owns negotiation and the split
  transport halves; `crates/p2p/src/bip324.rs` owns the key schedule, the
  ciphers, the handshake state machine, the packet reader, and the message
  type encoding.
- **Default**: the node runs with `v2transport` on, as Core's `-v2transport`
  defaults on, and advertises `NODE_P2P_V2`; `P2pServiceConfig::v2_transport`
  itself defaults off for direct `bitcoin-rs-p2p` users. With it off, every
  connection is v1 and the node does not advertise `NODE_P2P_V2`. A peer that
  opens with a v2 key then fails the v1 magic check and is disconnected
  without discouragement, as Core closes a transport on a wrong message start
  (`PeerError::inbound`).
- **Inbound**: with v2 on, the responder reads the first 16 bytes. A v1
  `version` header under this node's magic hands those bytes to the v1
  decoder, a v1 `version` header under another magic is refused, and anything
  else is a v2 key, answered with this node's key and garbage. Nothing is sent
  before v1 is ruled out.
- **Outbound**: with v2 on, a manual connection, and an automatic one to an
  address whose last known services include `NODE_P2P_V2`, start v2. When the
  peer closes without sending a byte, the dial retries once over v1; the
  unanswered attempt is neither a failure count nor misbehavior.
- **One deadline**: the transport and version handshakes share the 60 s
  handshake deadline, and a peer is never ready before its transport
  handshake completes.
- **Split halves**: the connection thread keeps the receive half and the
  writer thread takes the send half when the session starts. Lease budgets
  stay in v1 frame lengths for either transport; `CountingStream` counts the
  bytes actually sent and received.
- **Failures**: a transport error (no garbage terminator within the limit, an
  authentication failure, an oversized packet) ends the connection without
  discouraging the peer, because BIP324 does not authenticate peers. A
  malformed message inside an authenticated packet keeps the v1 misbehavior
  rules. A message of an empty or undefined type is dropped without
  disconnecting.
- **Observability**: the negotiated transport is published with the
  handshake (`PeerInfo::transport`), and `getpeerinfo` reports it as Core
  does: `transport_protocol_type` `v1` or `v2`, and for v2 the session id as
  hex in byte order (empty for v1). Both ends of a session derive the same id.
- **Bounds**: garbage is at most 4095 bytes; the terminator scan reads only up
  to the terminator's earliest possible end; contents above 1 + 12 +
  4,000,000 bytes are refused before their body is read, and a v2 payload is
  sent only up to 4,000,000 bytes; a stalled packet retains only the bytes it
  received.

## Live gaps

- **Peer lifecycle boundary**: Header-request planning and getdata fan-out
  execute in `crates/p2p/src/sync.rs` `BlockSync` behind the node-provided
  `SyncChain` seam. Node retains applied-chain mutation; `P2pService` no longer
  holds a shadow download window.
- **Inbound eviction protections**: eviction at the inbound cap lacks Core's
  minimum-ping protection, because no ping round trip is measured; see
  `docs/policies/p2p-compatibility.md` section 7 item 12.
