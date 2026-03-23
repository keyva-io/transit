use transit_core::TransitError;

use crate::error::CommandError;
use crate::keyring_index::KeyringIndex;
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_key_info(
    keyrings: &KeyringIndex,
    keyring_name: &str,
) -> Result<ResponseMap, CommandError> {
    let kr = keyrings.get(keyring_name)?;

    if kr.disabled {
        return Err(CommandError::Transit(TransitError::Disabled(
            keyring_name.to_string(),
        )));
    }

    let versions: Vec<ResponseValue> = kr
        .key_versions
        .iter()
        .map(|v| {
            let version_map = ResponseMap::ok()
                .with("version", ResponseValue::Integer(v.version as i64))
                .with("state", ResponseValue::String(format!("{:?}", v.state)))
                .with("created_at", ResponseValue::Integer(v.created_at as i64))
                .with(
                    "activated_at",
                    match v.activated_at {
                        Some(t) => ResponseValue::Integer(t as i64),
                        None => ResponseValue::Null,
                    },
                )
                .with(
                    "draining_since",
                    match v.draining_since {
                        Some(t) => ResponseValue::Integer(t as i64),
                        None => ResponseValue::Null,
                    },
                )
                .with(
                    "retired_at",
                    match v.retired_at {
                        Some(t) => ResponseValue::Integer(t as i64),
                        None => ResponseValue::Null,
                    },
                );
            ResponseValue::Map(version_map)
        })
        .collect();

    Ok(ResponseMap::ok()
        .with("name", ResponseValue::String(kr.name.clone()))
        .with(
            "algorithm",
            ResponseValue::String(format!("{:?}", kr.algorithm)),
        )
        .with(
            "rotation_days",
            ResponseValue::Integer(kr.rotation_days as i64),
        )
        .with("drain_days", ResponseValue::Integer(kr.drain_days as i64))
        .with("convergent", ResponseValue::Boolean(kr.convergent))
        .with("versions", ResponseValue::Array(versions))
        .with(
            "total_versions",
            ResponseValue::Integer(kr.key_versions.len() as i64),
        ))
}
