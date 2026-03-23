/// Command execution errors with machine-parseable code prefixes.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("DENIED {reason}")]
    Denied { reason: String },

    #[error("NOTFOUND {entity}: {id}")]
    NotFound { entity: String, id: String },

    #[error("BADARG {message}")]
    BadArg { message: String },

    #[error("DISABLED keyring={keyring}")]
    Disabled { keyring: String },

    #[error("NOTREADY {0}")]
    NotReady(String),

    #[error("TRANSIT {0}")]
    Transit(#[from] transit_core::TransitError),

    #[error("STORAGE {0}")]
    Storage(#[from] keyva_storage::StorageError),

    #[error("CRYPTO {0}")]
    Crypto(#[from] keyva_crypto::CryptoError),

    #[error("INTERNAL {0}")]
    Internal(String),
}
