use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use transit_core::{CiphertextEnvelope, TransitError};

use crate::error::CommandError;
use crate::handlers::encrypt::decrypt_with_key;
use crate::keyring_index::{KeyringIndex, find_key_version};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_decrypt(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    ciphertext_str: &str,
    context: Option<&str>,
) -> Result<ResponseMap, CommandError> {
    let context_bytes = context.unwrap_or("").as_bytes();

    // Parse the ciphertext envelope to extract key version
    let envelope = CiphertextEnvelope::decode(ciphertext_str)?;

    // Look up keyring
    let kr = keyrings.get(keyring_name)?;

    // Check not disabled
    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    // Find the key version used during encryption
    let version = find_key_version(&kr, envelope.key_version)?;

    // Get key material
    let key_material = version
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    // Decrypt (checks for Retired state)
    let plaintext = decrypt_with_key(
        key_material.as_bytes(),
        version.state,
        keyring_name,
        version.version,
        &envelope.payload,
        context_bytes,
    )?;

    let plaintext_b64 = STANDARD.encode(&plaintext);

    Ok(ResponseMap::ok().with("plaintext", ResponseValue::String(plaintext_b64)))
}
