//! Integration test: Transit keyring rotation survives restart via WAL replay.

use std::path::Path;
use std::pin::Pin;

use keyva_crypto::SecretBytes;
use keyva_storage::{
    MasterKeySource, RecoveryMode, StorageEngine, StorageEngineConfig, StorageError,
};
use transit_core::{KeyState, Keyring, KeyringAlgorithm};
use transit_protocol::keyring_index::KeyringIndex;
use transit_protocol::recovery;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestKeySource;

impl MasterKeySource for TestKeySource {
    fn load(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, StorageError>> + Send + '_>>
    {
        Box::pin(async { Ok(SecretBytes::new(vec![0x42; 32])) })
    }

    fn source_name(&self) -> &str {
        "test"
    }
}

fn test_config(dir: &Path) -> StorageEngineConfig {
    StorageEngineConfig {
        data_dir: dir.to_path_buf(),
        recovery_mode: RecoveryMode::Recover,
        fsync_mode: keyva_storage::FsyncMode::PerWrite,
        ..Default::default()
    }
}

async fn open_engine(dir: &Path) -> StorageEngine {
    StorageEngine::open(test_config(dir), &TestKeySource)
        .await
        .unwrap()
}

fn test_keyring(name: &str) -> Keyring {
    Keyring {
        name: name.to_string(),
        algorithm: KeyringAlgorithm::Aes256Gcm,
        rotation_days: 90,
        drain_days: 30,
        convergent: false,
        created_at: 1000,
        disabled: false,
        key_versions: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotation_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // --- Phase 1: initial startup, seed, encrypt, rotate ---

    let engine = open_engine(dir).await;
    let keyrings = KeyringIndex::new();
    keyrings.register_metadata_only(test_keyring("payments"));

    // No WAL entries yet, so replay returns 0.
    let replayed = recovery::replay_transit_wal(&engine, &keyrings)
        .await
        .unwrap();
    assert_eq!(replayed, 0);

    // Seed initial key (fresh start).
    let seeded = recovery::seed_empty_keyrings(&engine, &keyrings)
        .await
        .unwrap();
    assert_eq!(seeded, 1);

    // Verify initial state: 1 key version, Active.
    {
        let kr = keyrings.get("payments").unwrap();
        assert_eq!(kr.key_versions.len(), 1);
        assert_eq!(kr.key_versions[0].version, 1);
        assert_eq!(kr.key_versions[0].state, KeyState::Active);
        assert!(kr.key_versions[0].key_material.is_some());
    }

    // Encrypt some data with version 1.
    let v1_ciphertext = {
        let kr = keyrings.get("payments").unwrap();
        let key = kr.key_versions[0].key_material.as_ref().unwrap();
        keyva_crypto::aes_gcm_encrypt(key.as_bytes(), b"hello-v1", b"test-aad").unwrap()
    };

    // Rotate the key.
    let result = transit_protocol::handlers::rotate::handle_rotate(
        &keyrings, &engine, "payments", false, false,
    )
    .await
    .unwrap();
    let new_version = result
        .fields
        .iter()
        .find(|(k, _)| k == "new_version")
        .map(|(_, v)| v);
    match new_version {
        Some(transit_protocol::ResponseValue::Integer(2)) => {}
        other => panic!("expected new_version=2, got {other:?}"),
    }

    // Verify post-rotation state: 2 versions.
    let v2_ciphertext = {
        let kr = keyrings.get("payments").unwrap();
        assert_eq!(kr.key_versions.len(), 2);

        // v1 should be Draining
        let v1 = kr.key_versions.iter().find(|v| v.version == 1).unwrap();
        assert_eq!(v1.state, KeyState::Draining);

        // v2 should be Active
        let v2 = kr.key_versions.iter().find(|v| v.version == 2).unwrap();
        assert_eq!(v2.state, KeyState::Active);

        let key = v2.key_material.as_ref().unwrap();
        keyva_crypto::aes_gcm_encrypt(key.as_bytes(), b"hello-v2", b"test-aad").unwrap()
    };

    // Flush and shut down.
    engine.shutdown().await.unwrap();
    drop(keyrings);

    // --- Phase 2: restart and verify recovery ---

    let engine2 = open_engine(dir).await;
    let keyrings2 = KeyringIndex::new();
    keyrings2.register_metadata_only(test_keyring("payments"));

    // Replay WAL — should recover all key versions.
    let replayed2 = recovery::replay_transit_wal(&engine2, &keyrings2)
        .await
        .unwrap();
    assert!(replayed2 > 0, "expected WAL entries to replay, got 0");

    // No seeding needed — keys were recovered from WAL.
    let seeded2 = recovery::seed_empty_keyrings(&engine2, &keyrings2)
        .await
        .unwrap();
    assert_eq!(seeded2, 0);

    // Verify recovered state.
    let kr = keyrings2.get("payments").unwrap();
    assert_eq!(
        kr.key_versions.len(),
        2,
        "expected 2 key versions after recovery"
    );

    let v1 = kr.key_versions.iter().find(|v| v.version == 1).unwrap();
    assert_eq!(v1.state, KeyState::Draining);
    assert!(
        v1.key_material.is_some(),
        "v1 key material should be recovered"
    );

    let v2 = kr.key_versions.iter().find(|v| v.version == 2).unwrap();
    assert_eq!(v2.state, KeyState::Active);
    assert!(
        v2.key_material.is_some(),
        "v2 key material should be recovered"
    );

    // Verify old ciphertext still decrypts with recovered v1 key.
    let v1_key = v1.key_material.as_ref().unwrap();
    let plaintext1 =
        keyva_crypto::aes_gcm_decrypt(v1_key.as_bytes(), &v1_ciphertext, b"test-aad").unwrap();
    assert_eq!(plaintext1, b"hello-v1");

    // Verify new ciphertext still decrypts with recovered v2 key.
    let v2_key = v2.key_material.as_ref().unwrap();
    let plaintext2 =
        keyva_crypto::aes_gcm_decrypt(v2_key.as_bytes(), &v2_ciphertext, b"test-aad").unwrap();
    assert_eq!(plaintext2, b"hello-v2");

    engine2.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_start_seeds_initial_key() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let engine = open_engine(dir).await;
    let keyrings = KeyringIndex::new();
    keyrings.register_metadata_only(test_keyring("secrets"));

    // Empty WAL — replay does nothing.
    let replayed = recovery::replay_transit_wal(&engine, &keyrings)
        .await
        .unwrap();
    assert_eq!(replayed, 0);

    // Seed creates the initial key.
    let seeded = recovery::seed_empty_keyrings(&engine, &keyrings)
        .await
        .unwrap();
    assert_eq!(seeded, 1);

    let kr = keyrings.get("secrets").unwrap();
    assert_eq!(kr.key_versions.len(), 1);
    assert_eq!(kr.key_versions[0].version, 1);
    assert_eq!(kr.key_versions[0].state, KeyState::Active);

    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn double_rotation_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Setup: seed + rotate twice.
    let engine = open_engine(dir).await;
    let keyrings = KeyringIndex::new();
    keyrings.register_metadata_only(test_keyring("multi"));
    recovery::replay_transit_wal(&engine, &keyrings)
        .await
        .unwrap();
    recovery::seed_empty_keyrings(&engine, &keyrings)
        .await
        .unwrap();

    // Rotate #1
    transit_protocol::handlers::rotate::handle_rotate(&keyrings, &engine, "multi", false, false)
        .await
        .unwrap();

    // Rotate #2
    transit_protocol::handlers::rotate::handle_rotate(&keyrings, &engine, "multi", false, false)
        .await
        .unwrap();

    {
        let kr = keyrings.get("multi").unwrap();
        assert_eq!(kr.key_versions.len(), 3);
    }

    engine.shutdown().await.unwrap();
    drop(keyrings);

    // Restart and verify.
    let engine2 = open_engine(dir).await;
    let keyrings2 = KeyringIndex::new();
    keyrings2.register_metadata_only(test_keyring("multi"));
    recovery::replay_transit_wal(&engine2, &keyrings2)
        .await
        .unwrap();
    recovery::seed_empty_keyrings(&engine2, &keyrings2)
        .await
        .unwrap();

    let kr = keyrings2.get("multi").unwrap();
    assert_eq!(
        kr.key_versions.len(),
        3,
        "expected 3 key versions after double rotation recovery"
    );

    // v1 = Draining, v2 = Draining, v3 = Active
    let v1 = kr.key_versions.iter().find(|v| v.version == 1).unwrap();
    assert_eq!(v1.state, KeyState::Draining);
    let v2 = kr.key_versions.iter().find(|v| v.version == 2).unwrap();
    assert_eq!(v2.state, KeyState::Draining);
    let v3 = kr.key_versions.iter().find(|v| v.version == 3).unwrap();
    assert_eq!(v3.state, KeyState::Active);

    engine2.shutdown().await.unwrap();
}
