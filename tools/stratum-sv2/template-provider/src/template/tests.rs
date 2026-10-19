use super::*;

#[test]
fn coinbase_headroom_uses_sri_advertised_sigop_cost_without_rescaling() {
    use stratum_apps::{
        coinbase_output_constraints::coinbase_output_constraints_message,
        stratum_core::bitcoin::{Amount, ScriptBuf, TxOut},
    };

    let constraints = coinbase_output_constraints_message(vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
    }]);
    let sigop_cost = u32::from(constraints.coinbase_output_max_additional_sigops);
    assert_eq!(sigop_cost, 4, "SRI already scales legacy sigops to cost");

    let mut candidate = crate::tests::empty_candidate();
    candidate.max_sigops = u64::from(sigop_cost);
    let state = TemplateState::new(1, Arc::new(candidate));
    assert!(state.fits_constraints(constraints.coinbase_output_max_additional_size, sigop_cost));
    assert!(!state.fits_constraints(
        constraints.coinbase_output_max_additional_size,
        sigop_cost + 1
    ));
}

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
            data_hex: bitcoin_rs_primitives::encode::hex_encode(&consensus_bytes(&tx)),
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
    // The body costs 4 and the advertised additional cost of 4 exactly fits 8.
    assert!(state.fits_constraints(additional, 4));
    Arc::get_mut(&mut state.candidate).unwrap().max_size -= 1;
    assert!(!state.fits_constraints(additional, 4));
    Arc::get_mut(&mut state.candidate).unwrap().max_size += 1;
    Arc::get_mut(&mut state.candidate).unwrap().max_weight -= 1;
    assert!(!state.fits_constraints(additional, 4));
    Arc::get_mut(&mut state.candidate).unwrap().max_weight += 1;
    assert!(!state.fits_constraints(additional, 5));
}
