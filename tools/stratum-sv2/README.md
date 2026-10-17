# Embedded bitcoin-rs behind the SRI Stratum V2 stack

This regtest example runs the production `bitcoin_rs_node::Node` and its SV2
Template Distribution adapter in one process. The unchanged pinned SRI pool,
translator and two mining devices remain external. The adapter borrows the
existing `MiningControl`, retains `Arc<Candidate>` jobs, and submits native
blocks through canonical validation and publication. There is no internal
HTTP, JSON, transaction hex, `NodeState`, or `test-seam` dependency.

```text
device-direct-1 -- SV2 --+
                       +--> SRI pool -- TDP/Noise --> adapter + embedded Node
device-direct-2 -- SV2 --+                                  |
                                                     MiningControl
```

## Run

Requires Docker Compose and the repository checkout. From the repository root:

```sh
docker compose -f tools/stratum-sv2/compose.yaml up --build -d
docker compose -f tools/stratum-sv2/compose.yaml logs -f template-provider pool
# After repeated accepted solutions, stop and join workers, retaining data:
docker compose -f tools/stratum-sv2/compose.yaml down --timeout 30
```

The provider builds from the repository root with Rust 1.99 and the standalone
lockfile. It uses native validation and Fjall, and stores its regtest node in
the existing `bitcoin-rs-data` volume. Do not run the previous separate node
against that volume concurrently. No volume is reset by startup or shutdown.
The optional SV1 translator still listens on host loopback port 3333. Pool
monitoring remains on loopback port 9090. Device core counts are deliberately
small; increase them only for the test host's capacity.

The default Noise key is example material, unchanged from the previous
example. `config/pool.toml` pins its public key:
`9bWTZifgp9aVa23vtHqGT74UwK9bDRQxm77jf3u2tZ3ysM2ncMW`.
If `TP_PRIVATE_KEY_HEX` is overridden, update that pin from the provider's
startup log before reconnecting the pool. External SRI image and source pins
remain in Compose and `device/Dockerfile`.

The pinned CPU devices cache the pool's resolved address. If a restart changes
the pool container's IP, restart the devices after the pool is ready. Their
upstream shutdown does not handle SIGTERM; Compose can kill those device
processes after its timeout. The embedded provider handles SIGINT and joins
its node workers before exiting.

For a local build without Docker:

```sh
cargo run --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml
```

Configuration: `TP_LISTEN` (default `0.0.0.0:8442`), `TP_PRIVATE_KEY_HEX`,
`TP_CERT_VALIDITY_SECS` (default `3600`),
`BITCOINRS_DATA_DIR`, `BITCOINRS_P2P_LISTEN` and `BITCOINRS_RPC_BIND`.
The normal node lifecycle binds its diagnostic RPC listener to an ephemeral
loopback port by default; mining never contacts it. The example network is
fixed to regtest. Standard output contains diagnostic projection/job/submission
microseconds, canonical submission results, and the resulting applied height.

## Ownership and bounds

- A dedicated OS thread performs typed template long polls, using the mining
  owner's opaque template identity. Tip and same-tip membership changes reuse
  existing generation publication; there is no timer-based template poll.
  Generation races during acquisition retry after 100 milliseconds with the
  last published identity. Shutdown and other errors end the worker.
- The hub retains the most recent 16 issued IDs. Old IDs remain resolvable while
  retained, then transaction-data requests receive `template-not-found`.
- At most eight pool sessions are served. Solution assembly/validation and
  transaction-data serialization run on awaited blocking tasks. Sessions finish
  these tasks before Node teardown; no blocking Node call runs on a Tokio I/O
  worker.
- Shutdown stops accepts, closes incomplete session reads, drains submissions,
  signals the normal node shutdown input, joins the long-poll worker, and calls
  consuming `Node::shutdown`. Compose uses SIGINT and a 30-second grace period.
- The exact Noise read future survives template refreshes. Cancellation on
  shutdown closes the entire connection; a partial record is never resumed with
  a new decoder. Writes have a deadline and a failed write closes the session.
- Templates are sent only after `CoinbaseOutputConstraints`. The adapter checks
  conservative size/weight and sigop headroom including a full scriptSig and
  output-count expansion. It refuses a tight candidate rather than constructing
  a second transaction selector. This can reject templates a more complete
  reservation-aware producer could serve.
- Coinbase prefix, version, sequence, locktime, required outputs and commitment
  come from the native candidate. The pool adds its payout outputs; native
  submission supplies the ordinary witness reserved value if required. The node
  owns actual fee accounting, transaction selection, PoW, consensus validation,
  mempool removal, tip publication and announcements. Superseded solutions get
  those same checks rather than an adapter-defined stale-job verdict.

## Validation and measurement

```sh
cargo test --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml
cargo clippy --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml --all-targets -- -D warnings
```

The public-Node test uses a real datadir without a mock or test feature. It
checks wire coinbase outputs, independent block merkle reconstruction, typed
submission/duplicates, same-tip mempool refresh, a valid superseded solution,
stale-parent refusal, retention eviction, recovery from injected generation
races before initial publication and refresh, and cancellation on shutdown. Its
100-block history is required to spend a matured coinbase.

The [retained interoperability run](evidence/interop.md) records the final
provider image with two real SRI devices, pool reconnect, and checkpoint
restore. It is functional evidence, not a comparative benchmark.

This is limited regtest interoperability support, not production pool
qualification or a mining-throughput claim. For before/after measurements,
build the RPC example from base revision `a11021788` in a separate checkout;
its adapter is removed here rather than kept as a second production path.
Use the same node validation engine/backend, candidate transactions, host and
external SRI pins. Capture raw timestamps and command/build identities, CPU,
allocations and peak RSS. Compare fresh and reused HTTP connections separately.
Projection, job-write and canonical-submission durations are diagnostic spans;
they do not measure mutation-to-candidate or first P2P announcement latency and
cannot establish an end-to-end speedup. Full matched percentile measurements
remain required before making performance claims.
