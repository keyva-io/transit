use std::time::{SystemTime, UNIX_EPOCH};

use keyva_storage::{OpType, StorageEngine, WalPayload};
use transit_core::{KeyState, KeyVersion, TransitError};

use crate::error::CommandError;
use crate::keyring_index::{KeyringIndex, generate_key_material};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_rotate(
    keyrings: &KeyringIndex,
    engine: &StorageEngine,
    keyring_name: &str,
    _force: bool,
    dryrun: bool,
) -> Result<ResponseMap, CommandError> {
    // Get a mutable reference to the keyring
    let mut kr = keyrings.get_mut(keyring_name)?;

    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    let now = now_secs();

    // Find current states
    let has_staged = kr.key_versions.iter().any(|v| v.state == KeyState::Staged);
    let active_idx = kr
        .key_versions
        .iter()
        .position(|v| v.state == KeyState::Active);

    // Next version number
    let next_version = kr.key_versions.iter().map(|v| v.version).max().unwrap_or(0) + 1;

    if dryrun {
        let mut plan = Vec::new();
        if has_staged {
            plan.push("promote Staged -> Active".to_string());
        }
        if active_idx.is_some() {
            plan.push("demote Active -> Draining".to_string());
        }
        plan.push(format!("create new Active key v{next_version}"));

        let plan_values: Vec<ResponseValue> = plan.into_iter().map(ResponseValue::String).collect();

        return Ok(ResponseMap::ok()
            .with("dryrun", ResponseValue::Boolean(true))
            .with("plan", ResponseValue::Array(plan_values))
            .with("next_version", ResponseValue::Integer(next_version as i64)));
    }

    // Collect state transitions to write to WAL after in-memory updates.
    let mut state_changes: Vec<(u32, String)> = Vec::new();

    // Execute rotation:
    // 1. If Staged exists, promote Staged -> Active
    if has_staged {
        for v in &mut kr.key_versions {
            if v.state == KeyState::Staged {
                v.state = KeyState::Active;
                v.activated_at = Some(now);
                state_changes.push((v.version, "Active".into()));
            }
        }
    }

    // 2. Demote current Active -> Draining
    for v in &mut kr.key_versions {
        if v.state == KeyState::Active {
            v.state = KeyState::Draining;
            v.draining_since = Some(now);
            state_changes.push((v.version, "Draining".into()));
        }
    }

    // 3. Generate new Active key
    let new_key_material = generate_key_material(&kr.algorithm)?;
    let new_version = KeyVersion {
        version: next_version,
        state: KeyState::Active,
        key_material: Some(new_key_material.clone()),
        created_at: now,
        activated_at: Some(now),
        draining_since: None,
        retired_at: None,
    };
    kr.key_versions.push(new_version);

    let total_versions = kr.key_versions.len() as i64;

    // Drop the mutable ref before async WAL writes.
    drop(kr);

    // Write WAL entries for durability.

    // Write state change entries for any transitions (Staged->Active, Active->Draining).
    for (version, new_state) in &state_changes {
        engine
            .apply_wal_only(
                keyring_name,
                OpType::KeyVersionStateChanged,
                WalPayload::KeyVersionStateChanged {
                    keyring: keyring_name.to_string(),
                    version: *version,
                    new_state: new_state.clone(),
                    timestamp: now,
                },
            )
            .await?;
    }

    // Write the new key version entry.
    let encrypted_key_material =
        engine.encrypt_private_key(keyring_name, new_key_material.as_bytes())?;
    engine
        .apply_wal_only(
            keyring_name,
            OpType::KeyVersionCreated,
            WalPayload::KeyVersionCreated {
                keyring: keyring_name.to_string(),
                version: next_version,
                state: "Active".into(),
                encrypted_key_material,
                created_at: now,
            },
        )
        .await?;

    Ok(ResponseMap::ok()
        .with("new_version", ResponseValue::Integer(next_version as i64))
        .with("total_versions", ResponseValue::Integer(total_versions)))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
