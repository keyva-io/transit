//! Keyva Transit — encryption-as-a-service server.
//!
//! Binary entry point: CLI argument parsing, config loading, and server startup.

mod config;
mod connection;
mod server;

use std::sync::Arc;

use clap::Parser;
use keyva_crypto::SecretBytes;
use keyva_storage::{ChainedMasterKeySource, MasterKeySource, StorageEngine};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(
    name = "keyva-transit",
    about = "Encryption-as-a-service server",
    version
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "transit.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 0. Disable core dumps to prevent leaking secrets (Linux only).
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // 1. Parse CLI arguments.
    let cli = Cli::parse();

    // 2. Load configuration (or use defaults if no config file).
    let cfg = match config::load(&cli.config)? {
        Some(cfg) => {
            let data_dir = &cfg.storage.data_dir;
            std::fs::create_dir_all(data_dir)?;

            let env_filter = tracing_subscriber::EnvFilter::from_default_env();
            let console_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_filter(env_filter);

            tracing_subscriber::registry().with(console_layer).init();

            tracing::info!(config = %cli.config.display(), "configuration loaded");
            cfg
        }
        None => {
            let data_dir = std::path::PathBuf::from("./transit-data");
            std::fs::create_dir_all(&data_dir)?;

            let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            let console_layer = tracing_subscriber::fmt::layer().with_filter(env_filter);

            tracing_subscriber::registry().with(console_layer).init();

            tracing::info!("no config file found, starting with defaults");
            config::TransitConfig::default()
        }
    };

    // 3. Resolve master key source.
    let key_source = resolve_master_key()?;

    // 4. Convert storage section to engine config.
    let engine_config = config::to_engine_config(&cfg);

    // 5. Open storage engine (runs WAL recovery).
    let engine = StorageEngine::open(engine_config, &*key_source).await?;
    let engine = Arc::new(engine);
    tracing::info!("storage engine ready");

    // 6. Register keyring metadata from config (no key material yet).
    let keyrings = Arc::new(transit_protocol::KeyringIndex::new());
    for (name, kr_config) in &cfg.keyrings {
        let keyring = config::to_keyring(name, kr_config)?;
        keyrings.register_metadata_only(keyring);
        tracing::info!(
            keyring = %name,
            algorithm = %kr_config.algorithm,
            rotation_days = kr_config.rotation_days,
            convergent = kr_config.convergent,
            "registered keyring metadata"
        );
    }

    // 7. Replay Transit WAL entries to restore key versions.
    let replayed = transit_protocol::recovery::replay_transit_wal(&engine, &keyrings).await?;
    if replayed > 0 {
        tracing::info!(entries = replayed, "transit WAL replay complete");
    }

    // 8. Seed any keyrings that have no key versions after replay (fresh start).
    let seeded = transit_protocol::recovery::seed_empty_keyrings(&engine, &keyrings).await?;
    if seeded > 0 {
        tracing::info!(count = seeded, "seeded initial keys for new keyrings");
    }
    tracing::info!(count = keyrings.len(), "keyrings ready");

    // 9. Create transit dispatcher.
    let dispatcher = Arc::new(transit_protocol::CommandDispatcher::new(
        Arc::clone(&engine),
        Arc::clone(&keyrings),
    ));

    // 10. Install Prometheus metrics recorder.
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install metrics recorder");

    // 11. Set up shutdown signal (SIGTERM + SIGINT).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // 12. Run server (blocks until shutdown).
    tracing::info!(bind = %cfg.server.bind, "keyva-transit ready");
    server::run(&cfg.server, dispatcher, metrics_handle, shutdown_rx).await?;

    // 13. Shut down storage engine (flush WAL, fsync).
    engine.shutdown().await?;

    tracing::info!("keyva-transit shut down cleanly");
    Ok(())
}

/// Resolve the master key source: try env/file first, fall back to ephemeral.
fn resolve_master_key() -> anyhow::Result<Box<dyn MasterKeySource>> {
    if std::env::var("KEYVA_MASTER_KEY").is_ok() || std::env::var("KEYVA_MASTER_KEY_FILE").is_ok() {
        return Ok(Box::new(ChainedMasterKeySource::default_chain()));
    }

    tracing::warn!(
        "no master key configured (set KEYVA_MASTER_KEY or KEYVA_MASTER_KEY_FILE for persistence)"
    );
    tracing::warn!("using ephemeral master key — data will NOT survive restart");
    Ok(Box::new(EphemeralMasterKey::generate()))
}

/// An ephemeral in-memory master key for development mode.
struct EphemeralMasterKey {
    key: SecretBytes,
}

impl EphemeralMasterKey {
    fn generate() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; 32];
        rng.fill(&mut bytes).expect("CSPRNG fill failed");
        Self {
            key: SecretBytes::new(bytes),
        }
    }
}

impl MasterKeySource for EphemeralMasterKey {
    fn load(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<SecretBytes, keyva_storage::StorageError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(self.key.clone()) })
    }

    fn source_name(&self) -> &str {
        "ephemeral"
    }
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
