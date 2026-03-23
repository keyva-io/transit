use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use transit_core::{KeyState, KeyringAlgorithm, TransitError};

use crate::error::CommandError;
use crate::keyring_index::KeyringIndex;
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_verify_signature(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    data_b64: &str,
    signature_hex: &str,
) -> Result<ResponseMap, CommandError> {
    let data = STANDARD
        .decode(data_b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 data: {e}"),
        })?;

    let signature = hex::decode(signature_hex).map_err(|e| CommandError::BadArg {
        message: format!("invalid hex signature: {e}"),
    })?;

    // Look up keyring
    let kr = keyrings.get(keyring_name)?;

    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    if !kr.algorithm.is_signing() {
        return Err(CommandError::Transit(TransitError::AlgorithmMismatch {
            expected: format!("{:?}", kr.algorithm),
            required: "signing algorithm".into(),
        }));
    }

    // Try Active and Draining key versions (those are valid for verification)
    let verifiable_states = [KeyState::Active, KeyState::Draining];

    for version in &kr.key_versions {
        if !verifiable_states.contains(&version.state) {
            continue;
        }

        let key_material = match &version.key_material {
            Some(km) => km,
            None => continue,
        };

        let valid = match kr.algorithm {
            KeyringAlgorithm::HmacSha256 => keyva_crypto::hmac_verify(
                keyva_crypto::HmacAlgorithm::Sha256,
                key_material.as_bytes(),
                &data,
                &signature,
            )?,
            _ => continue,
        };

        if valid {
            return Ok(ResponseMap::ok()
                .with("valid", ResponseValue::Boolean(true))
                .with(
                    "key_version",
                    ResponseValue::Integer(version.version as i64),
                ));
        }
    }

    // No version verified the signature
    Ok(ResponseMap::ok().with("valid", ResponseValue::Boolean(false)))
}
