use crate::key_version::KeyState;

#[derive(Debug, thiserror::Error)]
pub enum TransitError {
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: KeyState, to: KeyState },

    #[error("keyring not found: {0}")]
    KeyringNotFound(String),

    #[error("key version not found: {keyring} v{version}")]
    KeyVersionNotFound { keyring: String, version: u32 },

    #[error("key version retired: {keyring} v{version} — use REWRAP")]
    KeyVersionRetired { keyring: String, version: u32 },

    #[error("no active key in keyring: {0}")]
    NoActiveKey(String),

    #[error("invalid ciphertext format: {0}")]
    InvalidCiphertext(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("algorithm mismatch: keyring is {expected}, operation requires {required}")]
    AlgorithmMismatch { expected: String, required: String },

    #[error("keyring disabled: {0}")]
    Disabled(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] keyva_crypto::CryptoError),
}
