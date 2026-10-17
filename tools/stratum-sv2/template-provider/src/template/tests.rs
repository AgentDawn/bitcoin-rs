use super::*;

#[test]
fn coinbase_headroom_uses_bytes_for_size_and_weight_units_for_weight() {
    let mut candidate = crate::tests::empty_candidate();
    // Include a witness-bearing body transaction in the byte and sigop budgets.
    let mut tx = candidate.coinbase.clone();
    tx.inputs[0].previous_output.vout = 0;
    candidate.weight += tx.weight();
    candidate
        .transactions
        .push(bitcoin_rs_mining::CandidateTransaction {
            txid: tx.txid(),
            wtxid: tx.wtxid(),
            weight: tx.weight(),
            tx: Arc::new(tx),
            fee: 0,
            sigop_cost: 4,
            depends: vec![],
        });
    let size = consensus_bytes(&candidate.into_unsolved_block().unwrap()).len() as u64;
    let additional = 1000;
    let reserved_bytes = u64::from(additional) + 109;
    candidate.max_size = size + reserved_bytes;
    candidate.max_weight = candidate.weight + reserved_bytes * 4;
    candidate.max_sigops = 8;
    let mut state = TemplateState::new(1, Arc::new(candidate));
    // Different byte/WU limits catch the former comparison of weight to size.
    assert!(state.fits_constraints(additional, 1));
    Arc::get_mut(&mut state.candidate).unwrap().max_size -= 1;
    assert!(!state.fits_constraints(additional, 1));
    Arc::get_mut(&mut state.candidate).unwrap().max_size += 1;
    Arc::get_mut(&mut state.candidate).unwrap().max_weight -= 1;
    assert!(!state.fits_constraints(additional, 1));
    Arc::get_mut(&mut state.candidate).unwrap().max_weight += 1;
    assert!(!state.fits_constraints(additional, 2));
}
