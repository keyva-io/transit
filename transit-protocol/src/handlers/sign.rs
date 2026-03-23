use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use transit_core::{KeyringAlgorithm, TransitError};

use crate::error::CommandError;
use crate::keyring_index::{KeyringIndex, find_active_key};
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_sign(
    keyrings: &KeyringIndex,
    keyring_name: &str,
    data_b64: &str,
    _algorithm: Option<&str>,
) -> Result<ResponseMap, CommandError> {
    let data = STANDARD
        .decode(data_b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 data: {e}"),
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
            required: "signing algorithm (HmacSha256, Ed25519, or EcdsaP256)".into(),
        }));
    }

    let active = find_active_key(&kr)?;
    let key_material = active
        .key_material
        .as_ref()
        .ok_or_else(|| TransitError::NoActiveKey(keyring_name.to_string()))?;

    // Currently only HMAC signing is supported for symmetric keyrings
    let (signature, algo_name) = match kr.algorithm {
        KeyringAlgorithm::HmacSha256 => {
            let sig = keyva_crypto::hmac_sign(
                keyva_crypto::HmacAlgorithm::Sha256,
                key_material.as_bytes(),
                &data,
            )?;
            (sig, "hmac-sha256")
        }
        _ => {
            return Err(CommandError::Transit(TransitError::AlgorithmMismatch {
                expected: format!("{:?}", kr.algorithm),
                required: "HmacSha256 (only supported signing algorithm)".into(),
            }));
        }
    };

    let signature_hex = hex::encode(&signature);

    Ok(ResponseMap::ok()
        .with("signature", ResponseValue::String(signature_hex))
        .with("key_version", ResponseValue::Integer(active.version as i64))
        .with("algorithm", ResponseValue::String(algo_name.to_string())))
}
