//! Derived statistics over the live set owned by `crate::set`.
//! `MuHash3072` owns the Core-compatible accumulator; `CoinStats` owns scalar
//! folds and its byte codec. `CoinStatsListener` applies committed events and
//! explicit disconnect rewinds; `CoinStatsAccumulator` serves checkpoints with
//! ordered parallel MuHash partials or hashing disabled. `scan_coin_stats`
//! recomputes from a stable view. See "Owed derived state" in `CONCEPTS.md`.
//!
//! The durable codec id `bitcoin-rs-coinstats-v1` requires a datadir schema epoch
//! bump if changed.

/// Running UTXO statistics.
pub mod coin_stats;
/// `MuHash3072` accumulator.
mod muhash3072;

pub use coin_stats::{
    CoinStats, CoinStatsAccumulator, CoinStatsDecodeError, CoinStatsListener, CoinStatsRewindError,
    scan_coin_stats,
};
pub use muhash3072::MuHash3072;
