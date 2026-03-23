//! WAL replay for Transit keyring key versions.
//!
//! On startup, after registering keyring metadata from config, this module
//! replays `KeyVersionCreated` and `KeyVersionStateChanged` WAL entries to
//! restore key material and version states. If a keyring has no versions
//! after replay (fresh start), an initial Active key is generated and
//! persisted to WAL.

use std::time::{SystemTime, UNIX_EPOCH};

use keyva_storage::wal::reader::RecoveryMode;
use keyva_storage::{OpType, StorageEngine, WalPayload};
use transit_core::{KeyState, KeyVersion};

use crate::error::CommandError;
use crate::keyring_index::{KeyringIndex, generate_key_material};

/// Replay Transit WAL entries to restore key versions into the keyring index.
///
/// Returns the number of entries replayed.
pub async fn replay_transit_wal(
    engine: &StorageEngine,
    keyrings: &KeyringIndex,
) -> Result<u64, CommandError> {
    let reader = keyva_storage::wal::WalReader::new(
        engine.data_dir().to_path_buf(),
        engine.namespace().clone(),
    );

    let (entries, _corrupt) = reader
        .entries_after_checkpoint(None, RecoveryMode::Recover)
        .await?;

    let mut replayed = 0u64;

    for entry in &entries {
        match entry.header.op_type {
            OpType::KeyVersionCreated | OpType::KeyVersionStateChanged => {
                // Decrypt the payload using the per-keyring derived key.
                let ks_key = engine.keyspace_key(&entry.header.keyspace_id)?;
                let payload = entry.decrypt_payload(ks_key.as_bytes())?;
                replay_payload(engine, keyrings, &payload)?;
                replayed += 1;
            }
            _ => {
                // Not a transit entry — skip.
            }
        }
    }

    Ok(replayed)
}

/// Apply a single decoded WAL payload to the keyring index.
fn replay_payload(
    engine: &StorageEngine,
    keyrings: &KeyringIndex,
    payload: &WalPayload,
) -> Result<(), CommandError> {
    match payload {
        WalPayload::KeyVersionCreated {
            keyring,
            version,
            state,
            encrypted_key_material,
            created_at,
        } => {
            let mut kr = keyrings.get_mut(keyring)?;
            // Remove any existing version with this number (idempotent replay).
            kr.key_versions.retain(|v| v.version != *version);

            let key_bytes = engine.decrypt_private_key(keyring, encrypted_key_material)?;
            let key_material = keyva_crypto::SecretBytes::new(key_bytes);
            let key_state = parse_key_state(state);

            let kv = KeyVersion {
                version: *version,
                state: key_state,
                key_material: Some(key_material),
                created_at: *created_at,
                activated_at: if key_state == KeyState::Active {
                    Some(*created_at)
                } else {
                    None
                },
                draining_since: None,
                retired_at: None,
            };
            kr.key_versions.push(kv);
        }
        WalPayload::KeyVersionStateChanged {
            keyring,
            version,
            new_state,
            timestamp,
        } => {
            let mut kr = keyrings.get_mut(keyring)?;
            if let Some(kv) = kr.key_versions.iter_mut().find(|v| v.version == *version) {
                let new = parse_key_state(new_state);
                kv.state = new;
                match new {
                    KeyState::Active => kv.activated_at = Some(*timestamp),
                    KeyState::Draining => kv.draining_since = Some(*timestamp),
                    KeyState::Retired => kv.retired_at = Some(*timestamp),
                    KeyState::Staged => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// After WAL replay, generate and persist initial keys for any keyrings
/// that have no key versions (fresh start or first time for that keyring).
pub async fn seed_empty_keyrings(
    engine: &StorageEngine,
    keyrings: &KeyringIndex,
) -> Result<u64, CommandError> {
    let empty_names = keyrings.keyrings_without_versions();
    let mut seeded = 0u64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for name in &empty_names {
        let algorithm = {
            let kr = keyrings.get(name)?;
            kr.algorithm
        };

        let key_material = generate_key_material(&algorithm)?;
        let encrypted = engine.encrypt_private_key(name, key_material.as_bytes())?;

        // Write to WAL first for durability.
        engine
            .apply_wal_only(
                name,
                OpType::KeyVersionCreated,
                WalPayload::KeyVersionCreated {
                    keyring: name.clone(),
                    version: 1,
                    state: "Active".into(),
                    encrypted_key_material: encrypted,
                    created_at: now,
                },
            )
            .await?;

        // Update in-memory index.
        let mut kr = keyrings.get_mut(name)?;
        kr.key_versions.push(KeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some(key_material),
            created_at: now,
            activated_at: Some(now),
            draining_since: None,
            retired_at: None,
        });

        seeded += 1;
    }

    Ok(seeded)
}

fn parse_key_state(s: &str) -> KeyState {
    match s {
        "Staged" => KeyState::Staged,
        "Active" => KeyState::Active,
        "Draining" => KeyState::Draining,
        "Retired" => KeyState::Retired,
        _ => KeyState::Active, // fallback
    }
}
