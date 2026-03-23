use transit_core::{CiphertextEnvelope, TransitError};

use crate::error::CommandError;
use crate::handlers::encrypt::{decrypt_with_key, encrypt_with_key};
use crate::keyring_index::{KeyringIndex, find_active_key, find_key_version};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_rewrap(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    ciphertext_str: &str,
    context: Option<&str>,
) -> Result<ResponseMap, CommandError> {
    let context_bytes = context.unwrap_or("").as_bytes();

    // Parse the ciphertext envelope
    let envelope = CiphertextEnvelope::decode(ciphertext_str)?;

    // Look up keyring
    let kr = keyrings.get(keyring_name)?;

    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    // 1. Decrypt with old version
    let old_version = find_key_version(&kr, envelope.key_version)?;
    let old_key = old_version
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    // Allow decryption from Draining keys for rewrap (the whole point is to migrate them)
    let plaintext = decrypt_with_key(
        old_key.as_bytes(),
        old_version.state,
        keyring_name,
        old_version.version,
        &envelope.payload,
        context_bytes,
    )?;

    // 2. Re-encrypt with current active version
    let active = find_active_key(&kr)?;
    let active_key = active
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    let new_envelope = encrypt_with_key(
        active_key.as_bytes(),
        active.version,
        &plaintext,
        context_bytes,
    )?;

    let new_ciphertext = new_envelope.encode();

    Ok(ResponseMap::ok()
        .with("ciphertext", ResponseValue::String(new_ciphertext))
        .with("key_version", ResponseValue::Integer(active.version as i64)))
}
