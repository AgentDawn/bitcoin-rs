use std::net::SocketAddr;
use std::path::PathBuf;

use super::{Auth, NetworkSelection, NodeConfig, ScriptIndexMode, ValidationEngine};
use crate::options::{
    ChainstateJournalOverrides, P2pOverrides, RpcOverrides, StorageOverrides, UserConfig,
    ValidationOverrides,
};

fn pool_layer() -> UserConfig {
    UserConfig {
        pool: crate::options::PoolOverrides {
            enabled: Some(true),
            datadir: Some(PathBuf::from("/nonexistent/operator-pool-ledger")),
            v1_bind: Some(SocketAddr::from(([127, 0, 0, 1], 3333))),
            share_difficulty: Some("1".to_owned()),
            window_work: Some(1000),
            reward_script: Some("51".to_owned()),
            ..Default::default()
        },
        mining: crate::options::MiningOverrides {
            payout_address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_owned()),
        },
        ..Default::default()
    }
}

#[test]
fn pool_defaults_off_and_suboptions_require_enablement() {
    assert!(resolved(&[]).pool.is_none());
    let mut layer = pool_layer();
    layer.pool.enabled = Some(false);
    assert!(super::resolve(&[&layer]).is_err());
    layer.pool = crate::options::PoolOverrides::default();
    assert!(super::resolve(&[&layer]).is_ok());
}

#[cfg(not(feature = "pool"))]
#[test]
fn pool_requires_compiled_feature() {
    match super::resolve(&[&pool_layer()]) {
        Ok(config) => {
            panic!("pool configuration must be refused without the pool build feature: {config:?}")
        }
        Err(error) => assert!(error.to_string().contains("pool build feature"), "{error}"),
    }
}

#[cfg(feature = "pool")]
#[test]
fn pool_requires_explicit_policy_and_listener() {
    for missing in 0..7 {
        let mut layer = pool_layer();
        match missing {
            0 => layer.pool.datadir = None,
            1 => layer.pool.v1_bind = None,
            2 => layer.pool.share_difficulty = None,
            3 => layer.pool.window_work = None,
            4 => layer.pool.reward_script = None,
            5 => layer.mining.payout_address = None,
            6 => layer.pool.datadir = Some(PathBuf::new()),
            _ => unreachable!(),
        }
        assert!(
            super::resolve(&[&layer]).is_err(),
            "missing explicit input {missing}"
        );
    }
}

#[cfg(feature = "pool")]
#[test]
fn pool_composed_connection_defaults_are_pinned() {
    let config = resolved(&[&pool_layer()]);
    let pool = config
        .pool
        .as_ref()
        .unwrap_or_else(|| panic!("pool layer must enable the pool"));
    assert_eq!(
        pool.max_connections, 128,
        "shared total connection default must stay 128"
    );
    assert_eq!(
        pool.max_connections_per_ip, 8,
        "shared per-IP connection default must stay 8"
    );
}

#[cfg(feature = "pool")]
#[test]
fn pool_layers_preserve_explicit_fields_and_override_policy() -> anyhow::Result<()> {
    let base = pool_layer();
    let later = UserConfig {
        pool: crate::options::PoolOverrides {
            fee_bps: Some(125),
            share_difficulty: Some("2.5".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = super::resolve(&[&base, &later])?;
    let pool = config
        .pool
        .ok_or_else(|| anyhow::anyhow!("enabled pool must resolve"))?;
    let expected_datadir = base
        .pool
        .datadir
        .ok_or_else(|| anyhow::anyhow!("fixture must specify a pool directory"))?;
    assert_eq!(pool.datadir, expected_datadir);
    assert_eq!(pool.v1_bind, base.pool.v1_bind);
    assert!(pool.sv2_bind.is_none());
    assert_eq!(pool.fee_bps, 125);
    assert_eq!(pool.share_difficulty, "2.5");
    assert_eq!(
        pool.share_target,
        bitcoin_rs_stratum::ShareTarget::from_pool_difficulty_decimal("2.5")?
    );
    assert_eq!(pool.ledger_config().window_work, 1000);
    assert_eq!(pool.ledger_config().pool_fee_bps, 125);
    Ok(())
}

#[cfg(feature = "pool")]
#[test]
fn pool_non_loopback_requires_explicit_opt_in() {
    let mut layer = pool_layer();
    layer.pool.v1_bind = Some(SocketAddr::from(([0, 0, 0, 0], 3333)));
    assert!(super::resolve(&[&layer]).is_err());
    layer.pool.allow_non_loopback = Some(true);
    assert!(super::resolve(&[&layer]).is_ok());
    layer.pool.v1_bind = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    assert!(super::resolve(&[&layer]).is_err());
}

#[cfg(feature = "pool")]
#[test]
fn pool_money_depth_and_capacity_bounds_are_validated() {
    for invalid in 0..15 {
        let mut layer = pool_layer();
        match invalid {
            0 => layer.pool.window_work = Some(0),
            1 => layer.pool.fee_bps = Some(10_001),
            2 => layer.pool.maturity = Some(99),
            3 => layer.pool.payout_confirmations = Some(0),
            4 => layer.pool.reorg_watch_depth = Some(99),
            5 => layer.pool.payout_confirmations = Some(1001),
            6 => layer.pool.min_payout_sat = Some(545),
            7 => layer.pool.min_payout_sat = Some(u64::MAX),
            8 => layer.pool.max_payout_outputs = Some(0),
            9 => layer.pool.max_payout_outputs = Some(2501),
            10 => layer.pool.max_connections = Some(0),
            11 => layer.pool.max_connections_per_ip = Some(0),
            12 => layer.pool.max_connections_per_ip = Some(129),
            13 => layer.pool.reward_script = Some("6a".to_owned()),
            14 => layer.pool.reward_script = Some("4c0151".to_owned()),
            _ => unreachable!(),
        }
        assert!(
            super::resolve(&[&layer]).is_err(),
            "invalid policy {invalid}"
        );
    }
    let mut boundary = pool_layer();
    boundary.pool.fee_bps = Some(10_000);
    boundary.pool.max_payout_outputs = Some(2500);
    assert!(super::resolve(&[&boundary]).is_ok());
}

#[cfg(feature = "pool")]
#[test]
fn pool_exact_difficulty_and_script_parsing_reject_invalid_inputs() {
    for value in [
        "",
        "0",
        "-1",
        "NaN",
        "1e3",
        "18446744073709551616",
        "1.00000000000000000000",
    ] {
        let mut layer = pool_layer();
        layer.pool.share_difficulty = Some(value.to_owned());
        assert!(super::resolve(&[&layer]).is_err(), "difficulty {value}");
    }
    for script in ["", "0", "zz", "4c"] {
        let mut layer = pool_layer();
        layer.pool.reward_script = Some(script.to_owned());
        assert!(super::resolve(&[&layer]).is_err(), "script {script}");
    }
}

#[cfg(feature = "pool")]
#[test]
fn pool_sv2_requires_feature_and_paired_authority_path_without_opening_it() {
    let mut layer = pool_layer();
    layer.pool.sv2_bind = Some(SocketAddr::from(([127, 0, 0, 1], 3334)));
    assert!(super::resolve(&[&layer]).is_err());
    layer.pool.sv2_authority_key = Some(PathBuf::from("/nonexistent/pool-authority-key"));
    #[cfg(feature = "pool-sv2")]
    {
        assert!(
            super::resolve(&[&layer]).is_ok(),
            "key IO belongs to service startup"
        );
        layer.pool.sv2_bind = layer.pool.v1_bind;
        assert!(super::resolve(&[&layer]).is_err());
    }
    #[cfg(not(feature = "pool-sv2"))]
    assert!(
        super::resolve(&[&layer])
            .unwrap_err()
            .to_string()
            .contains("pool-sv2")
    );
    layer.pool.sv2_bind = None;
    assert!(super::resolve(&[&layer]).is_err());
}

#[test]
fn auth_debug_redacts_secrets() {
    let auth = Auth::basic("operator", "s3cret");
    let rendered = format!("{auth:?}");
    assert!(rendered.contains("operator"));
    assert!(!rendered.contains("s3cret"));
    assert!(rendered.contains("<redacted>"));

    let auth = Auth::Cookie {
        path: PathBuf::from("/secret/.cookie"),
    };
    let rendered = format!("{auth:?}");
    assert!(!rendered.contains("/secret/.cookie"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn mempool_persistence_can_be_disabled_without_changing_other_settings() {
    assert!(
        NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest).persist_mempool
    );
    let layer = UserConfig {
        persist_mempool: Some(false),
        ..Default::default()
    };
    let config = resolved(&[&layer]);
    assert!(!config.persist_mempool);
    assert_eq!(config.storage.dbcache_mb, 450);
    let enable = UserConfig {
        persist_mempool: Some(true),
        ..Default::default()
    };
    assert!(resolved(&[&layer, &enable]).persist_mempool);
}

#[test]
fn mempool_snapshot_budget_is_configurable_and_bounded() {
    let defaults = resolved(&[]);
    assert_eq!(
        defaults.mempool_snapshot_max_bytes,
        bitcoin_rs_mempool::snapshot::DEFAULT_MAX_BYTES
    );
    let layer = UserConfig {
        mempool_snapshot_max_mb: Some(2048),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&layer]).mempool_snapshot_max_bytes,
        2048 * 1024 * 1024
    );
    for mb in [0, u64::MAX] {
        let layer = UserConfig {
            mempool_snapshot_max_mb: Some(mb),
            ..Default::default()
        };
        assert!(super::resolve(&[&layer]).is_err());
    }
}

#[test]
fn mempool_snapshot_restore_timeout_is_configurable_and_scales_with_budget() {
    let defaults = resolved(&[]);
    assert_eq!(defaults.mempool_snapshot_restore_timeout_secs, 64);

    let large_budget = UserConfig {
        mempool_snapshot_max_mb: Some(120),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&large_budget]).mempool_snapshot_restore_timeout_secs,
        120
    );

    let explicit = UserConfig {
        mempool_snapshot_max_mb: Some(120),
        mempool_snapshot_restore_timeout_secs: Some(300),
        ..Default::default()
    };
    assert_eq!(
        resolved(&[&explicit]).mempool_snapshot_restore_timeout_secs,
        300
    );

    for seconds in [0, u64::MAX] {
        let invalid = UserConfig {
            mempool_snapshot_restore_timeout_secs: Some(seconds),
            ..Default::default()
        };
        assert!(super::resolve(&[&invalid]).is_err());
        let mut config = NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        config.mempool_snapshot_restore_timeout_secs = seconds;
        assert!(
            config.validate().is_err(),
            "direct embedding config must also reject {seconds}"
        );
    }
}

#[test]
fn default_rpc_auth_uses_a_generated_cookie() {
    let layer = UserConfig {
        data_dir: Some(PathBuf::from("test-node")),
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.rpc.auth, Auth::GeneratedCookie);
}

#[test]
fn generated_rpc_cookie_is_private_and_rotates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(".cookie");
    // A temporary file left by an interrupted start must not block the next.
    std::fs::write(dir.path().join(".cookie.tmp"), "stale")?;
    let auth = Auth::GeneratedCookie;

    auth.to_rpc_auth(dir.path())?;
    let first = std::fs::read_to_string(&path)?;
    assert!(!dir.path().join(".cookie.tmp").exists());
    assert!(first.starts_with("__cookie__:"));
    assert_eq!(first.len(), "__cookie__:".len() + 64);
    assert!(
        !first.ends_with('\n'),
        "the generated cookie carries no trailing newline"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }

    auth.to_rpc_auth(dir.path())?;
    let second = std::fs::read_to_string(&path)?;
    assert_ne!(first, second, "each startup must rotate the cookie");
    Ok(())
}

#[test]
fn rpc_rejects_missing_or_public_credentials() {
    let binding = SocketAddr::from(([0, 0, 0, 0], 8332));
    let exposed = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&exposed]) else {
        panic!("a non-loopback bind without credentials must fail validation");
    };
    assert!(
        error.to_string().contains("non-loopback RPC bind"),
        "{error}"
    );

    let user_without_password = UserConfig {
        rpc: RpcOverrides {
            user: Some("operator".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&user_without_password]) else {
        panic!("a user without a password must fail validation");
    };
    assert!(
        error.to_string().contains("nonempty username and password"),
        "{error}"
    );

    let legacy_password = UserConfig {
        rpc: RpcOverrides {
            user: Some("bitcoin-rs".to_owned()),
            password: Some("bitcoin-rs".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&legacy_password]) else {
        panic!("the legacy public password must fail validation");
    };
    assert!(
        error.to_string().contains("publicly known legacy default"),
        "{error}"
    );

    let explicit_password = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            password: Some("non-default-secret".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&explicit_password]);
    assert_eq!(
        basic_auth(&config.rpc.auth),
        ("bitcoin-rs".to_owned(), "non-default-secret".to_owned())
    );

    let explicit_cookie = UserConfig {
        rpc: RpcOverrides {
            bind: Some(binding),
            cookie: Some(PathBuf::from("/operator/auth.cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    assert!(matches!(
        resolved(&[&explicit_cookie]).rpc.auth,
        Auth::Cookie { .. }
    ));
}

// ---- Named config-option coverage -------------------------------------
//
// Retained source precedence, absent nested overrides, and cross-field
// validation are exercised here at the one resolver every input layer
// feeds, so no adapter can bypass the named rules.

fn resolved(layers: &[&UserConfig]) -> NodeConfig {
    super::resolve(layers).unwrap_or_else(|error| panic!("valid layered configuration: {error}"))
}

/// Reads the two halves of Basic authentication, failing on cookie auth.
fn basic_auth(auth: &Auth) -> (String, String) {
    match auth {
        Auth::Basic { user, password } => (user.clone(), password.clone()),
        Auth::Cookie { .. } | Auth::GeneratedCookie => panic!("expected basic auth"),
    }
}

#[test]
fn resolve_prefers_higher_layers_field_by_field() {
    let base = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(550),
            dbcache_mb: Some(300),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            user: Some("lower-user".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        storage: StorageOverrides {
            prune_target_mb: Some(900),
            ..StorageOverrides::default()
        },
        rpc: RpcOverrides {
            password: Some("higher-password".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(config.storage.prune_target_mb, 900);
    assert_eq!(
        config.storage.dbcache_mb, 300,
        "a field absent in the higher layer keeps the lower layer's value"
    );
    let (user, password) = basic_auth(&config.rpc.auth);
    assert_eq!(user, "lower-user");
    assert_eq!(password, "higher-password");
}

#[test]
fn resolve_keeps_absent_nested_fields_at_their_network_defaults() {
    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        storage: StorageOverrides {
            dbcache_mb: Some(120),
            ..StorageOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.storage.dbcache_mb, 120);
    assert_eq!(config.storage.prune_target_mb, 0);
    assert!(!config.indexes.txindex);
    assert_eq!(config.indexes.script_index, ScriptIndexMode::Disabled);
    assert_eq!(config.observability.metrics_bind, None);
    assert!(config.chainstate_journal.enabled);
    assert_eq!(
        config.validation.assume_valid_height, 0,
        "regtest pins no assume-valid anchor"
    );
}

// ---- Unified validation engine ----------------------------------------
//
// The `kernel` feature is capability ("bitcoinkernel support is compiled
// in"), not selection. `validation.engine` is the one authoritative engine
// setting: it resolves once here, defaults to `native` in every build, and a
// build without kernel support must reject `kernel` before any node state,
// chainstate, or worker exists.

#[test]
fn validation_engine_defaults_to_native_and_layers_field_by_field() {
    let config = resolved(&[]);
    assert_eq!(config.validation.engine, ValidationEngine::Native);

    // An explicit `native` setting resolves in every build. The
    // lower-layer-wins claim needs a non-default engine to be observable and
    // lives in the kernel-gated layering test below.
    let base = UserConfig {
        network: Some(NetworkSelection::Regtest),
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Native),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig::default();
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Native,
        "an explicit `native` setting resolves in every build"
    );
}

#[test]
#[cfg(feature = "kernel")]
fn validation_engine_kernel_is_supported_when_compiled() {
    let layer = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&layer]);
    assert_eq!(config.validation.engine, ValidationEngine::Kernel);
}

/// The two-layer absent case, observable only where `kernel` is a usable
/// non-default value: the lower layer's engine survives a higher layer that
/// omits the field, and a higher layer that names one wins. The always-on
/// test above cannot show this — both `native` and the fallback land on the
/// default.
#[test]
#[cfg(feature = "kernel")]
fn validation_engine_layering_keeps_the_lower_layer_value() {
    let base = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig::default();
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Kernel,
        "an engine absent in the higher layer keeps the lower layer's value"
    );

    let higher = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Native),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(
        config.validation.engine,
        ValidationEngine::Native,
        "a higher layer that names an engine wins"
    );
}

#[test]
#[cfg(not(feature = "kernel"))]
fn validation_engine_kernel_is_rejected_without_kernel_support() {
    let layer = UserConfig {
        validation: ValidationOverrides {
            engine: Some(ValidationEngine::Kernel),
            ..ValidationOverrides::default()
        },
        ..UserConfig::default()
    };
    let error = match super::resolve(&[&layer]) {
        Ok(_) => panic!("a build without kernel support must reject engine = kernel"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("not compiled") && message.contains("kernel"),
        "unsupported-build error must name the missing capability, got {message}"
    );
}

#[test]
fn journal_nested_overrides_apply_field_by_field_across_layers() {
    let base = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            blocks: Some(200),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let higher = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            seconds: Some(45),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&base, &higher]);
    assert_eq!(config.chainstate_journal.blocks, 200);
    assert_eq!(config.chainstate_journal.seconds, 45);
    assert_eq!(
        config.chainstate_journal.rotate_mib, 256,
        "untouched bounds keep the network defaults"
    );
    assert_eq!(config.chainstate_journal.max_journal_mib, 2048);
}

#[test]
fn rpc_cookie_and_credential_layers_keep_one_auth_source() {
    let cookie = UserConfig {
        rpc: RpcOverrides {
            cookie: Some(PathBuf::from("/secure/.cookie")),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let credentials = UserConfig {
        rpc: RpcOverrides {
            user: Some("later-user".to_owned()),
            password: Some("later-password".to_owned()),
            ..RpcOverrides::default()
        },
        ..UserConfig::default()
    };
    let config = resolved(&[&credentials, &cookie]);
    assert!(
        matches!(config.rpc.auth, Auth::Cookie { .. }),
        "a higher cookie layer wins over lower credentials"
    );
    let config = resolved(&[&cookie, &credentials]);
    let (user, password) = basic_auth(&config.rpc.auth);
    assert_eq!(user, "later-user");
    assert_eq!(password, "later-password");
}

#[test]
fn p2p_magic_override_is_cross_field_validated() {
    let magic = [1, 2, 3, 4];
    let connect = || vec!["127.0.0.1:8333".to_owned()];

    let regtest = UserConfig {
        network: Some(NetworkSelection::Regtest),
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&regtest]) else {
        panic!("a non-mainnet magic override must fail validation");
    };
    assert!(
        error.to_string().contains("require --network mainnet"),
        "{error}"
    );

    let without_connect = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&without_connect]) else {
        panic!("a magic override without a connect peer must fail validation");
    };
    assert!(
        error.to_string().contains("at least one --connect peer"),
        "{error}"
    );

    let with_dns_seeds = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&with_dns_seeds]) else {
        panic!("a magic override with dns seeds on must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("require --dns-seeds-enabled=false"),
        "{error}"
    );

    let valid = UserConfig {
        p2p: P2pOverrides {
            magic: Some(magic),
            connect: Some(connect()),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        ..UserConfig::default()
    };
    assert_eq!(resolved(&[&valid]).p2p.magic, magic);
}

#[test]
fn journal_retention_and_lag_bounds_are_cross_field_validated() {
    let inverted_retention = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            rotate_mib: Some(4096),
            max_journal_mib: Some(2048),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&inverted_retention]) else {
        panic!("retention below rotation must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("max_journal_mib must be >= rotate_mib"),
        "{error}"
    );

    let inverted_lag = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            blocks: Some(500),
            max_lag_blocks: Some(100),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&inverted_lag]) else {
        panic!("a lag bound below the batch size must fail validation");
    };
    assert!(
        error
            .to_string()
            .contains("max_lag_blocks must be >= blocks"),
        "{error}"
    );

    let zero_period = UserConfig {
        chainstate_journal: ChainstateJournalOverrides {
            seconds: Some(0),
            ..ChainstateJournalOverrides::default()
        },
        ..UserConfig::default()
    };
    let Err(error) = super::resolve(&[&zero_period]) else {
        panic!("a non-positive period must fail validation");
    };
    assert!(
        error.to_string().contains("seconds must be positive"),
        "{error}"
    );
}

#[test]
fn earlier_set_fields_survive_a_later_bare_network_selection() {
    let overrides = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            dns_seeds: Some(false),
            ..P2pOverrides::default()
        },
        validation: ValidationOverrides {
            assume_valid_height: Some(7),
            mode: None,
            engine: None,
        },
        ..UserConfig::default()
    };
    let selection = UserConfig {
        network: Some(NetworkSelection::Regtest),
        ..UserConfig::default()
    };
    let config = resolved(&[&overrides, &selection]);
    assert_eq!(config.network, bitcoin_rs_primitives::Network::Regtest);
    assert_eq!(
        config.p2p.connect,
        vec!["127.0.0.1:8333"],
        "a later bare network selection keeps the peer list an operator set"
    );
    assert!(
        !config.p2p.dns_seeds_enabled,
        "a later bare network selection keeps the seed choice an operator set"
    );
    assert_eq!(
        config.validation.assume_valid_height, 7,
        "a later bare network selection keeps the height an operator pinned"
    );
    assert_eq!(
        config.p2p.magic,
        bitcoin_rs_primitives::Network::Regtest.magic(),
        "a field no layer set still fills from the winning profile"
    );
}
