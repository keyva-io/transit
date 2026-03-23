use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ring::rand::{SecureRandom, SystemRandom};
use transit_core::{KeyState, KeyVersion, Keyring, KeyringAlgorithm, TransitError};

/// In-memory index of Transit keyrings and their versioned keys.
pub struct KeyringIndex {
    keyrings: DashMap<String, Keyring>,
}

impl Default for KeyringIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringIndex {
    pub fn new() -> Self {
        Self {
            keyrings: DashMap::new(),
        }
    }

    /// Get a keyring by name.
    pub fn get(
        &self,
        name: &str,
    ) -> Result<dashmap::mapref::one::Ref<'_, String, Keyring>, TransitError> {
        self.keyrings
            .get(name)
            .ok_or_else(|| TransitError::KeyringNotFound(name.to_string()))
    }

    /// Insert or replace a keyring.
    pub fn insert(&self, keyring: Keyring) {
        self.keyrings.insert(keyring.name.clone(), keyring);
    }

    /// Get a mutable reference to a keyring.
    pub fn get_mut(
        &self,
        name: &str,
    ) -> Result<dashmap::mapref::one::RefMut<'_, String, Keyring>, TransitError> {
        self.keyrings
            .get_mut(name)
            .ok_or_else(|| TransitError::KeyringNotFound(name.to_string()))
    }

    /// Register a keyring from config, generating its first Active key version.
    /// If a keyring with this name already exists, this is a no-op.
    pub fn register_from_config(&self, mut keyring: Keyring) -> Result<(), TransitError> {
        if self.keyrings.contains_key(&keyring.name) {
            return Ok(());
        }

        // Generate the first key version (immediately Active).
        let key_material = generate_key_material(&keyring.algorithm)?;
        let now = now_secs();
        let version = KeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some(key_material),
            created_at: now,
            activated_at: Some(now),
            draining_since: None,
            retired_at: None,
        };
        keyring.key_versions.push(version);
        self.keyrings.insert(keyring.name.clone(), keyring);
        Ok(())
    }

    /// Register keyring metadata from config without generating any key material.
    /// Key versions will be populated from WAL replay.
    /// If a keyring with this name already exists, this is a no-op.
    pub fn register_metadata_only(&self, keyring: Keyring) {
        if !self.keyrings.contains_key(&keyring.name) {
            self.keyrings.insert(keyring.name.clone(), keyring);
        }
    }

    /// Returns the names of all keyrings that currently have no key versions.
    pub fn keyrings_without_versions(&self) -> Vec<String> {
        self.keyrings
            .iter()
            .filter(|entry| entry.value().key_versions.is_empty())
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Returns the number of keyrings stored.
    pub fn len(&self) -> usize {
        self.keyrings.len()
    }

    /// Returns true if the index contains no keyrings.
    pub fn is_empty(&self) -> bool {
        self.keyrings.is_empty()
    }
}

/// Generate random key material for a given algorithm.
pub fn generate_key_material(
    algorithm: &KeyringAlgorithm,
) -> Result<keyva_crypto::SecretBytes, TransitError> {
    let key_len = match algorithm {
        KeyringAlgorithm::Aes256Gcm | KeyringAlgorithm::ChaCha20Poly1305 => 32,
        KeyringAlgorithm::HmacSha256 => 32,
        KeyringAlgorithm::Ed25519 | KeyringAlgorithm::EcdsaP256 => {
            // Asymmetric keys are not yet supported for Transit keyrings.
            return Err(TransitError::AlgorithmMismatch {
                expected: format!("{algorithm:?}"),
                required: "symmetric algorithm".into(),
            });
        }
    };
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; key_len];
    rng.fill(&mut bytes).map_err(|_| {
        TransitError::Crypto(keyva_crypto::CryptoError::Encryption(
            "CSPRNG failed".into(),
        ))
    })?;
    Ok(keyva_crypto::SecretBytes::new(bytes))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Find the active key version in a keyring.
pub fn find_active_key(keyring: &Keyring) -> Result<&KeyVersion, TransitError> {
    keyring
        .key_versions
        .iter()
        .find(|v| v.state == KeyState::Active)
        .ok_or_else(|| TransitError::NoActiveKey(keyring.name.clone()))
}

/// Find a specific key version by number.
pub fn find_key_version(keyring: &Keyring, version: u32) -> Result<&KeyVersion, TransitError> {
    keyring
        .key_versions
        .iter()
        .find(|v| v.version == version)
        .ok_or_else(|| TransitError::KeyVersionNotFound {
            keyring: keyring.name.clone(),
            version,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn register_generates_active_key() {
        let index = KeyringIndex::new();
        let kr = test_keyring("payments");
        index.register_from_config(kr).unwrap();

        let kr = index.get("payments").unwrap();
        assert_eq!(kr.key_versions.len(), 1);
        assert_eq!(kr.key_versions[0].state, KeyState::Active);
        assert_eq!(kr.key_versions[0].version, 1);
        assert!(kr.key_versions[0].key_material.is_some());
    }

    #[test]
    fn register_idempotent() {
        let index = KeyringIndex::new();
        let kr = test_keyring("payments");
        index.register_from_config(kr).unwrap();
        let kr = test_keyring("payments");
        index.register_from_config(kr).unwrap();
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn get_missing_returns_error() {
        let index = KeyringIndex::new();
        let err = index.get("nope").unwrap_err();
        assert!(matches!(err, TransitError::KeyringNotFound(_)));
    }

    #[test]
    fn find_active_key_works() {
        let index = KeyringIndex::new();
        index.register_from_config(test_keyring("test")).unwrap();
        let kr = index.get("test").unwrap();
        let active = find_active_key(&kr).unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.state, KeyState::Active);
    }

    #[test]
    fn find_key_version_works() {
        let index = KeyringIndex::new();
        index.register_from_config(test_keyring("test")).unwrap();
        let kr = index.get("test").unwrap();
        let v = find_key_version(&kr, 1).unwrap();
        assert_eq!(v.version, 1);
    }

    #[test]
    fn find_key_version_missing() {
        let index = KeyringIndex::new();
        index.register_from_config(test_keyring("test")).unwrap();
        let kr = index.get("test").unwrap();
        let err = find_key_version(&kr, 99).unwrap_err();
        assert!(matches!(err, TransitError::KeyVersionNotFound { .. }));
    }
}
