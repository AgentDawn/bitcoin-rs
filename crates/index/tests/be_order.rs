//! Big-endian key-order vs numeric-height-order contract tests.
//!
//! The 4-byte height suffix in `HashPrefixRow` is big-endian (format 5), so
//! lexicographic key-byte order matches numeric height order within one
//! 8-byte prefix. Height 1 (`00 00 00 01`) sorts before height 256
//! (`00 00 01 00`) in byte order.
//!
//! These tests pin the row-iteration contract: `iter_funding_rows` and
//! `iter_spending_rows` return prefix-range scans in chronological order
//! without a numeric re-sort. Exact identity resolution against full blocks
//! lives in the runtime query engine, not in these row scans.

#[path = "support/common.rs"]
mod common;

use std::sync::Arc;

use bitcoin_rs_index::{Indexer, ScriptHash};
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};

use common::{MemoryStore, put_funding_row, put_spending_row};

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

/// Two funding rows with the same 8-byte prefix at heights 1 and 256 iterate
/// in numeric order under BE keys.
#[test]
fn funding_rows_iterate_in_numeric_height_order() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let store = Arc::new(MemoryStore::default());
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    // Direct keys at heights 1 and 256: both produce a funding row with the
    // same 8-byte prefix; only the height suffix differs. `commit_block`
    // cannot write a gapped height, so these tests own the keys themselves.
    let rows = indexer.iter_funding_rows(scripthash)?;
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    // Height 1 is [0x00, 0x00, 0x00, 0x01]; height 256 is
    // [0x00, 0x00, 0x01, 0x00]. BE byte order puts 1 before 256.
    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256],
        "BE byte order matches numeric height order"
    );
    Ok(())
}

/// This test confirms the on-disk key for spending rows also uses BE height,
/// so `iter_spending_rows` returns numeric order.
#[test]
fn spending_rows_also_use_numeric_height_order() -> Result<(), Box<dyn std::error::Error>> {
    let outpoint = spent_outpoint(7, 0);
    let store = Arc::new(MemoryStore::default());
    put_spending_row(&store, &outpoint, 1)?;
    put_spending_row(&store, &outpoint, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_spending_rows(&outpoint)?;
    assert_eq!(rows.len(), 2, "two spending rows at two heights");

    // BE byte order: 1 before 256.
    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256]
    );
    Ok(())
}
