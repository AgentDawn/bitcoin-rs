use anyhow::Result;
use bitcoin_rs_mining::{BlockTemplateMode, BlockTemplateRequest, MiningCapability, MiningControl};
use bitcoin_rs_node::Network;

use super::support::{
    coordinator, expect_template, open_at_genesis, regtest_mining, template_request,
};

// CONTRACT: API-07
#[test]
fn template_does_not_echo_client_capabilities() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: vec![
            MiningCapability::new("coinbasetxn"),
            MiningCapability::new("unknown-client-only"),
            MiningCapability::new("proposal"),
        ],
        rules: Vec::new(),
        long_poll_id: None,
    })?);
    // API-11 advertises only implemented server capabilities,
    // and omits Signet metadata on networks that are not Signet.
    assert_eq!(
        template
            .capabilities
            .iter()
            .map(MiningCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["proposal", "longpoll"]
    );
    assert_eq!(template.version_bits_required, 0);
    assert!(template.signet.is_none());
    Ok(())
}

// CONTRACT: API-07
#[test]
fn signet_template_includes_challenge_and_signet_rule() -> Result<()> {
    let state = open_at_genesis(Network::Signet)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(template_request(None))?);
    // Bitcoin Core's Signet getblocktemplate contract requires the signet rule
    // and challenge metadata for Signet templates.
    assert!(template.rules.iter().any(|rule| rule.as_str() == "signet"));
    assert!(template.signet.is_some());
    Ok(())
}
