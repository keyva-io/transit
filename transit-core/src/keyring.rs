use serde::{Deserialize, Serialize};

use crate::key_version::KeyVersion;

/// A keyring holds versioned encryption keys for a single purpose.
#[derive(Debug, Clone)]
pub struct Keyring {
    pub name: String,
    pub algorithm: KeyringAlgorithm,
    pub rotation_days: u32,
    pub drain_days: u32,
    pub convergent: bool,
    pub created_at: u64,
    pub disabled: bool,
    pub key_versions: Vec<KeyVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyringAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Ed25519,
    EcdsaP256,
    HmacSha256,
}

impl KeyringAlgorithm {
    /// Returns true if this algorithm uses symmetric keys.
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::HmacSha256
        )
    }

    /// Returns true if this algorithm supports signing operations.
    pub fn is_signing(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::EcdsaP256 | Self::HmacSha256)
    }

    /// Returns true if this algorithm supports encrypt/decrypt operations.
    pub fn is_encryption(&self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::ChaCha20Poly1305)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_classification_symmetric() {
        assert!(KeyringAlgorithm::Aes256Gcm.is_symmetric());
        assert!(KeyringAlgorithm::ChaCha20Poly1305.is_symmetric());
        assert!(KeyringAlgorithm::HmacSha256.is_symmetric());
        assert!(!KeyringAlgorithm::Ed25519.is_symmetric());
        assert!(!KeyringAlgorithm::EcdsaP256.is_symmetric());
    }

    #[test]
    fn algorithm_classification_signing() {
        assert!(KeyringAlgorithm::Ed25519.is_signing());
        assert!(KeyringAlgorithm::EcdsaP256.is_signing());
        assert!(KeyringAlgorithm::HmacSha256.is_signing());
        assert!(!KeyringAlgorithm::Aes256Gcm.is_signing());
        assert!(!KeyringAlgorithm::ChaCha20Poly1305.is_signing());
    }

    #[test]
    fn algorithm_classification_encryption() {
        assert!(KeyringAlgorithm::Aes256Gcm.is_encryption());
        assert!(KeyringAlgorithm::ChaCha20Poly1305.is_encryption());
        assert!(!KeyringAlgorithm::Ed25519.is_encryption());
        assert!(!KeyringAlgorithm::EcdsaP256.is_encryption());
        assert!(!KeyringAlgorithm::HmacSha256.is_encryption());
    }

    #[test]
    fn hmac_is_both_symmetric_and_signing() {
        let algo = KeyringAlgorithm::HmacSha256;
        assert!(algo.is_symmetric());
        assert!(algo.is_signing());
        assert!(!algo.is_encryption());
    }
}
