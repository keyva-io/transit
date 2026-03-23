use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};

/// Handle a stateless hash operation. No keyring needed.
pub async fn handle_hash(algorithm: &str, data_b64: &str) -> Result<ResponseMap, CommandError> {
    let data = STANDARD
        .decode(data_b64)
        .map_err(|e| CommandError::BadArg {
            message: format!("invalid base64 data: {e}"),
        })?;

    let hash_hex = match algorithm.to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => {
            let hash = keyva_crypto::sha256(&data);
            hex::encode(hash)
        }
        "sha384" | "sha-384" => {
            use ring::digest;
            let d = digest::digest(&digest::SHA384, &data);
            hex::encode(d.as_ref())
        }
        "sha512" | "sha-512" => {
            use ring::digest;
            let d = digest::digest(&digest::SHA512, &data);
            hex::encode(d.as_ref())
        }
        other => {
            return Err(CommandError::BadArg {
                message: format!(
                    "unsupported hash algorithm: {other} (supported: sha256, sha384, sha512)"
                ),
            });
        }
    };

    Ok(ResponseMap::ok()
        .with("hash", ResponseValue::String(hash_hex))
        .with(
            "algorithm",
            ResponseValue::String(algorithm.to_ascii_lowercase()),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_sha256_empty() {
        // SHA-256 of empty string
        let data_b64 = STANDARD.encode(b"");
        let resp = handle_hash("sha256", &data_b64).await.unwrap();
        let hash = resp
            .fields
            .iter()
            .find(|(k, _)| k == "hash")
            .map(|(_, v)| match v {
                ResponseValue::String(s) => s.as_str(),
                _ => panic!("expected string"),
            })
            .unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn hash_sha256_abc() {
        let data_b64 = STANDARD.encode(b"abc");
        let resp = handle_hash("sha256", &data_b64).await.unwrap();
        let hash = resp
            .fields
            .iter()
            .find(|(k, _)| k == "hash")
            .map(|(_, v)| match v {
                ResponseValue::String(s) => s.as_str(),
                _ => panic!("expected string"),
            })
            .unwrap();
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn hash_unsupported_algorithm() {
        let data_b64 = STANDARD.encode(b"test");
        let err = handle_hash("md5", &data_b64).await.unwrap_err();
        assert!(matches!(err, CommandError::BadArg { .. }));
    }

    #[tokio::test]
    async fn hash_invalid_base64() {
        let err = handle_hash("sha256", "!!!invalid!!!").await.unwrap_err();
        assert!(matches!(err, CommandError::BadArg { .. }));
    }
}
