# MuHash RPC campaign contract

The production full-UTXO query comparator. `gettxoutsetinfo` owns the measured
RPC arity. `tools/benchmark-campaign/muhash_rpc.py` owns trial transport,
campaign spawn, and receipt identity.

Owners:
- `crates/rpc/src/handlers/chain.rs` (`gettxoutsetinfo`)
- `tools/benchmark-campaign/muhash_rpc.py`

Operator procedure: [`docs/benchmarks/muhash-rpc.md`](../benchmarks/muhash-rpc.md).

## Clauses

### `MRPC-01`: Production triplet arity

`gettxoutsetinfo` accepts at most three parameters. The measured call is
`["muhash", null, false]`. A fourth positional argument is `InvalidParams`.

### `MRPC-02`: Attested child owns the RPC connection

Before the trial writes the `Authorization` header, the client looks up the
unique ESTABLISHED loopback row for that connection in `/proc/net/tcp` or
`/proc/net/tcp6` and requires its inode in `/proc/<attested_pid>/fd`. The
attested starttime must still match. A LISTEN snapshot taken earlier is not
the send-time proof.

### `MRPC-03`: Spawned `{config}` is the pinned bytes

Campaign command templates include `{config}`. `run_campaign` copies the
pinned config into the workspace with `O_EXCL` and mode `0o400`. Every spawn
opens that copy through `_read_regular_file`, re-hashes the bytes, copies
them into a write-sealed memfd, and passes `/proc/self/fd/<n>` to the child.
Binary snapshots request `MFD_EXEC`; config snapshots request
`MFD_NOEXEC_SEAL`. `memfd_create(2)` returns `EINVAL` for unknown flag
bits; Linux 6.3 introduced those two flags, so older kernels retry with
`MFD_ALLOW_SEALING` only. A rename of the workspace pathname or a later
write to that inode cannot change the bytes the daemon reads. Receipts
keep the original FileRef identity.
