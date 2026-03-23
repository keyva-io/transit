use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use transit_core::{CiphertextEnvelope, KeyState, TransitError};

use crate::error::CommandError;
use crate::keyring_index::{KeyringIndex, find_active_key, find_key_version};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_encrypt(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    plaintext_b64: &str,
    context: Option<&str>,
    requested_version: Option<u32>,
) -> Result<ResponseMap, CommandError> {
    // Decode plaintext from base64
    let plaintext = STANDARD
        .decode(plaintext_b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 plaintext: {e}"),
        })?;

    let context_bytes = context.unwrap_or("").as_bytes();

    // Look up keyring
    let kr = keyrings.get(keyring_name)?;

    // Check not disabled
    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    // Check algorithm supports encryption
    if !kr.algorithm.is_encryption() {
        return Err(CommandError::Transit(TransitError::AlgorithmMismatch {
            expected: format!("{:?}", kr.algorithm),
            required: "encryption algorithm (Aes256Gcm or ChaCha20Poly1305)".into(),
        }));
    }

    // Find the key version to use
    let version = match requested_version {
        Some(v) => find_key_version(&kr, v)?,
        None => find_active_key(&kr)?,
    };

    // Get key material
    let key_material = version
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    // Encrypt
    let envelope = encrypt_with_key(
        key_material.as_bytes(),
        version.version,
        &plaintext,
        context_bytes,
    )?;

    let ciphertext = envelope.encode();

    Ok(ResponseMap::ok()
        .with("ciphertext", ResponseValue::String(ciphertext))
        .with(
            "key_version",
            ResponseValue::Integer(version.version as i64),
        ))
}

/// Encrypt plaintext bytes with a key, returning a CiphertextEnvelope.
///
/// This is the core encryption logic, separated for reuse by rewrap and generate_data_key.
pub fn encrypt_with_key(
    key_material: &[u8],
    key_version: u32,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<CiphertextEnvelope, TransitError> {
    let payload = keyva_crypto::aes_gcm_encrypt(key_material, plaintext, aad)?;
    Ok(CiphertextEnvelope {
        key_version,
        payload,
    })
}

/// Decrypt a CiphertextEnvelope with a key, returning plaintext bytes.
///
/// Checks that the key version state allows decryption.
pub fn decrypt_with_key(
    key_material: &[u8],
    key_state: KeyState,
    keyring_name: &str,
    key_version: u32,
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, TransitError> {
    if key_state == KeyState::Retired {
        return Err(TransitError::KeyVersionRetired {
            keyring: keyring_name.to_string(),
            version: key_version,
        });
    }

    keyva_crypto::aes_gcm_decrypt(key_material, payload, aad)
        .map_err(|e| TransitError::DecryptionFailed(e.to_string()))
}
