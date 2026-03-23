use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::rand::{SecureRandom, SystemRandom};

use transit_core::TransitError;

use crate::error::CommandError;
use crate::handlers::encrypt::encrypt_with_key;
use crate::keyring_index::{KeyringIndex, find_active_key};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_generate_data_key(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    bits: Option<u32>,
) -> Result<ResponseMap, CommandError> {
    let key_len = match bits {
        Some(128) => 16,
        Some(256) | None => 32,
        Some(512) => 64,
        Some(other) => {
            return Err(CommandError::BadArg {
                message: format!("unsupported bit length: {other} (supported: 128, 256, 512)"),
            });
        }
    };

    // Look up keyring
    let kr = keyrings.get(keyring_name)?;

    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    if !kr.algorithm.is_encryption() {
        return Err(CommandError::Transit(TransitError::AlgorithmMismatch {
            expected: format!("{:?}", kr.algorithm),
            required: "encryption algorithm (Aes256Gcm or ChaCha20Poly1305)".into(),
        }));
    }

    // Find the active key version
    let active = find_active_key(&kr)?;
    let key_material = active
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    // Generate random data key
    let rng = SystemRandom::new();
    let mut plaintext_key = vec![0u8; key_len];
    rng.fill(&mut plaintext_key)
        .map_err(|_| CommandError::Internal("CSPRNG failed generating data key".into()))?;

    // Encrypt the data key with the active key version
    let envelope = encrypt_with_key(key_material.as_bytes(), active.version, &plaintext_key, b"")?;

    let plaintext_b64 = STANDARD.encode(&plaintext_key);
    let wrapped_key = envelope.encode();

    Ok(ResponseMap::ok()
        .with("plaintext_key", ResponseValue::String(plaintext_b64))
        .with("wrapped_key", ResponseValue::String(wrapped_key))
        .with("key_version", ResponseValue::Integer(active.version as i64))
        .with("bits", ResponseValue::Integer((key_len * 8) as i64)))
}
