/// Protocol-agnostic command representation for Keyva Transit.
/// Produced by RESP3 parser, REST deserializer, or gRPC deserializer.
#[derive(Debug, Clone)]
pub enum Command {
    Encrypt {
        keyring: String,
        plaintext: String,
        context: Option<String>,
        key_version: Option<u32>,
    },
    Decrypt {
        keyring: String,
        ciphertext: String,
        context: Option<String>,
    },
    Rewrap {
        keyring: String,
        ciphertext: String,
        context: Option<String>,
    },
    GenerateDataKey {
        keyring: String,
        bits: Option<u32>,
    },
    Sign {
        keyring: String,
        data: String,
        algorithm: Option<String>,
    },
    VerifySignature {
        keyring: String,
        data: String,
        signature: String,
    },
    Hash {
        algorithm: String,
        data: String,
    },
    Rotate {
        keyring: String,
        force: bool,
        dryrun: bool,
    },
    KeyInfo {
        keyring: String,
    },
    Health {
        keyring: Option<String>,
    },
    Auth {
        token: String,
    },
    Pipeline(Vec<Command>),
}

impl Command {
    /// Returns the keyring name, if applicable.
    pub fn keyring(&self) -> Option<&str> {
        match self {
            Command::Encrypt { keyring, .. }
            | Command::Decrypt { keyring, .. }
            | Command::Rewrap { keyring, .. }
            | Command::GenerateDataKey { keyring, .. }
            | Command::Sign { keyring, .. }
            | Command::VerifySignature { keyring, .. }
            | Command::Rotate { keyring, .. }
            | Command::KeyInfo { keyring, .. } => Some(keyring),
            Command::Health { keyring, .. } => keyring.as_deref(),
            Command::Hash { .. } | Command::Auth { .. } | Command::Pipeline(_) => None,
        }
    }

    /// Returns true if this is a read-only command (no state mutation).
    pub fn is_read(&self) -> bool {
        matches!(
            self,
            Command::Decrypt { .. }
                | Command::KeyInfo { .. }
                | Command::Health { .. }
                | Command::Hash { .. }
                | Command::VerifySignature { .. }
                | Command::Auth { .. }
        )
    }
}

/// Returns the verb string for metrics/logging.
pub fn command_verb(cmd: &Command) -> &'static str {
    match cmd {
        Command::Encrypt { .. } => "ENCRYPT",
        Command::Decrypt { .. } => "DECRYPT",
        Command::Rewrap { .. } => "REWRAP",
        Command::GenerateDataKey { .. } => "GENERATE_DATA_KEY",
        Command::Sign { .. } => "SIGN",
        Command::VerifySignature { .. } => "VERIFY_SIGNATURE",
        Command::Hash { .. } => "HASH",
        Command::Rotate { .. } => "ROTATE",
        Command::KeyInfo { .. } => "KEY_INFO",
        Command::Health { .. } => "HEALTH",
        Command::Auth { .. } => "AUTH",
        Command::Pipeline(_) => "PIPELINE",
    }
}
