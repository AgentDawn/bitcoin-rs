#[expect(
    dead_code,
    reason = "the binary suite uses the release daemon identity; the capture identity is consumed by the RPC fixture adapter"
)]
pub(crate) mod reference_set;
pub(crate) mod regtest_blocks;
pub(crate) mod wire_peer;
