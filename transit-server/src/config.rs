use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use keyva_storage::{StorageEngineConfig, wal::writer::FsyncMode};
use serde::Deserialize;
use transit_core::{Keyring, KeyringAlgorithm};

// ---------------------------------------------------------------------------
// TOML config structs
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct TransitConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub keyrings: HashMap<String, KeyringConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default)]
    pub tls_client_ca: Option<PathBuf>,
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            rate_limit: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_fsync_mode")]
    pub wal_fsync_mode: String,
    #[serde(default = "default_fsync_interval")]
    pub wal_fsync_interval_ms: u64,
    #[serde(default = "default_segment_size")]
    pub wal_segment_max_bytes: u64,
    #[serde(default = "default_snapshot_entries")]
    pub snapshot_interval_entries: u64,
    #[serde(default = "default_snapshot_minutes")]
    pub snapshot_interval_minutes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            wal_fsync_mode: default_fsync_mode(),
            wal_fsync_interval_ms: default_fsync_interval(),
            wal_segment_max_bytes: default_segment_size(),
            snapshot_interval_entries: default_snapshot_entries(),
            snapshot_interval_minutes: default_snapshot_minutes(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct KeyringConfig {
    pub algorithm: String,
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default)]
    pub convergent: bool,
}

// ---------------------------------------------------------------------------
// Serde defaults
// ---------------------------------------------------------------------------

fn default_bind() -> SocketAddr {
    "0.0.0.0:6499".parse().unwrap()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./transit-data")
}

fn default_fsync_mode() -> String {
    "batched".to_string()
}

fn default_fsync_interval() -> u64 {
    10
}

fn default_segment_size() -> u64 {
    64 * 1024 * 1024
}

fn default_snapshot_entries() -> u64 {
    100_000
}

fn default_snapshot_minutes() -> u64 {
    60
}

fn default_rotation_days() -> u32 {
    90
}

fn default_drain_days() -> u32 {
    30
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load config from a TOML file. Returns None if the file doesn't exist.
pub fn load(path: &Path) -> anyhow::Result<Option<TransitConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let expanded = expand_env_vars(&contents);
    let config: TransitConfig =
        toml::from_str(&expanded).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

/// Expand all `${VAR}` patterns in a string with environment variable values.
fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut found_closing = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_closing = true;
                    break;
                }
                var_name.push(c);
            }
            if !found_closing {
                result.push_str("${");
                result.push_str(&var_name);
            } else {
                match std::env::var(&var_name) {
                    Ok(val) => result.push_str(&val),
                    Err(_) => {
                        result.push_str("${");
                        result.push_str(&var_name);
                        result.push('}');
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

pub fn to_engine_config(config: &TransitConfig) -> StorageEngineConfig {
    let fsync_mode = to_fsync_mode(
        &config.storage.wal_fsync_mode,
        config.storage.wal_fsync_interval_ms,
    );
    StorageEngineConfig {
        data_dir: config.storage.data_dir.clone(),
        fsync_mode,
        max_segment_bytes: config.storage.wal_segment_max_bytes,
        snapshot_entry_threshold: config.storage.snapshot_interval_entries,
        snapshot_time_threshold_secs: config.storage.snapshot_interval_minutes * 60,
        ..StorageEngineConfig::default()
    }
}

fn to_fsync_mode(mode: &str, interval_ms: u64) -> FsyncMode {
    match mode {
        "per_write" => FsyncMode::PerWrite,
        "batched" => FsyncMode::Batched { interval_ms },
        "periodic" => FsyncMode::Periodic { interval_ms },
        _ => {
            tracing::warn!(mode, "unknown wal_fsync_mode, defaulting to batched");
            FsyncMode::Batched { interval_ms }
        }
    }
}

pub fn parse_algorithm(s: &str) -> anyhow::Result<KeyringAlgorithm> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "aes_256_gcm" | "aes256gcm" => Ok(KeyringAlgorithm::Aes256Gcm),
        "chacha20_poly1305" | "chacha20poly1305" => Ok(KeyringAlgorithm::ChaCha20Poly1305),
        "ed25519" => Ok(KeyringAlgorithm::Ed25519),
        "ecdsa_p256" | "ecdsap256" => Ok(KeyringAlgorithm::EcdsaP256),
        "hmac_sha256" | "hmacsha256" => Ok(KeyringAlgorithm::HmacSha256),
        _ => bail!("unknown algorithm: {s}"),
    }
}

pub fn to_keyring(name: &str, config: &KeyringConfig) -> anyhow::Result<Keyring> {
    let algorithm = parse_algorithm(&config.algorithm)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(Keyring {
        name: name.to_string(),
        algorithm,
        rotation_days: config.rotation_days,
        drain_days: config.drain_days,
        convergent: config.convergent,
        created_at: now,
        disabled: false,
        key_versions: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let cfg = TransitConfig::default();
        assert_eq!(cfg.server.bind, default_bind());
        assert_eq!(cfg.storage.data_dir, default_data_dir());
        assert!(cfg.keyrings.is_empty());
    }

    #[test]
    fn minimal_toml_parses() {
        let toml_str = r#"
[keyrings.payments]
algorithm = "aes-256-gcm"
"#;
        let cfg: TransitConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.keyrings.contains_key("payments"));
        let keyring = to_keyring("payments", &cfg.keyrings["payments"]).unwrap();
        assert_eq!(keyring.algorithm, KeyringAlgorithm::Aes256Gcm);
        assert_eq!(keyring.rotation_days, 90);
    }

    #[test]
    fn convergent_config() {
        let toml_str = r#"
[keyrings.pii]
algorithm = "aes-256-gcm"
convergent = true
rotation_days = 30
"#;
        let cfg: TransitConfig = toml::from_str(toml_str).unwrap();
        let keyring = to_keyring("pii", &cfg.keyrings["pii"]).unwrap();
        assert!(keyring.convergent);
        assert_eq!(keyring.rotation_days, 30);
    }

    #[test]
    fn expand_env_vars_works() {
        // SAFETY: test-only; no other threads rely on this variable.
        unsafe {
            std::env::set_var("TEST_TRANSIT_EXPAND", "hello");
        }
        assert_eq!(
            expand_env_vars("prefix_${TEST_TRANSIT_EXPAND}_suffix"),
            "prefix_hello_suffix"
        );
        assert_eq!(expand_env_vars("no_vars_here"), "no_vars_here");
        // SAFETY: test-only cleanup.
        unsafe {
            std::env::remove_var("TEST_TRANSIT_EXPAND");
        }
    }

    #[test]
    fn parse_algorithms() {
        assert_eq!(
            parse_algorithm("aes-256-gcm").unwrap(),
            KeyringAlgorithm::Aes256Gcm
        );
        assert_eq!(
            parse_algorithm("chacha20-poly1305").unwrap(),
            KeyringAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            parse_algorithm("ed25519").unwrap(),
            KeyringAlgorithm::Ed25519
        );
        assert_eq!(
            parse_algorithm("ecdsa-p256").unwrap(),
            KeyringAlgorithm::EcdsaP256
        );
        assert_eq!(
            parse_algorithm("hmac-sha256").unwrap(),
            KeyringAlgorithm::HmacSha256
        );
        assert!(parse_algorithm("unknown").is_err());
    }
}
