use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::TransitError;

/// Ciphertext envelope: `v{version}:{base64url(nonce || ciphertext || tag)}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextEnvelope {
    pub key_version: u32,
    pub payload: Vec<u8>,
}

impl CiphertextEnvelope {
    /// Encode the envelope to its wire format.
    pub fn encode(&self) -> String {
        let encoded = URL_SAFE_NO_PAD.encode(&self.payload);
        format!("v{}:{}", self.key_version, encoded)
    }

    /// Decode an envelope from its wire format.
    pub fn decode(s: &str) -> Result<Self, TransitError> {
        let s = s
            .strip_prefix('v')
            .ok_or_else(|| TransitError::InvalidCiphertext("missing 'v' prefix".into()))?;

        let colon_pos = s
            .find(':')
            .ok_or_else(|| TransitError::InvalidCiphertext("missing ':' separator".into()))?;

        let version_str = &s[..colon_pos];
        let key_version = version_str
            .parse::<u32>()
            .map_err(|e| TransitError::InvalidCiphertext(format!("invalid version number: {e}")))?;

        let payload_str = &s[colon_pos + 1..];
        let payload = URL_SAFE_NO_PAD
            .decode(payload_str)
            .map_err(|e| TransitError::InvalidCiphertext(format!("invalid base64url: {e}")))?;

        Ok(Self {
            key_version,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let envelope = CiphertextEnvelope {
            key_version: 3,
            payload: vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD],
        };
        let encoded = envelope.encode();
        assert!(encoded.starts_with("v3:"));

        let decoded = CiphertextEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.key_version, 3);
        assert_eq!(decoded.payload, envelope.payload);
    }

    #[test]
    fn encode_format() {
        let envelope = CiphertextEnvelope {
            key_version: 1,
            payload: b"hello".to_vec(),
        };
        let encoded = envelope.encode();
        assert!(encoded.starts_with("v1:"));
        // base64url of "hello" is "aGVsbG8"
        assert_eq!(encoded, "v1:aGVsbG8");
    }

    #[test]
    fn decode_missing_prefix() {
        let err = CiphertextEnvelope::decode("3:abc").unwrap_err();
        assert!(matches!(err, TransitError::InvalidCiphertext(_)));
    }

    #[test]
    fn decode_missing_separator() {
        let err = CiphertextEnvelope::decode("v3abc").unwrap_err();
        assert!(matches!(err, TransitError::InvalidCiphertext(_)));
    }

    #[test]
    fn decode_invalid_version() {
        let err = CiphertextEnvelope::decode("vXYZ:abc").unwrap_err();
        assert!(matches!(err, TransitError::InvalidCiphertext(_)));
    }

    #[test]
    fn decode_invalid_base64() {
        let err = CiphertextEnvelope::decode("v1:!!!invalid!!!").unwrap_err();
        assert!(matches!(err, TransitError::InvalidCiphertext(_)));
    }

    #[test]
    fn roundtrip_empty_payload() {
        let envelope = CiphertextEnvelope {
            key_version: 0,
            payload: vec![],
        };
        let decoded = CiphertextEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn roundtrip_large_version() {
        let envelope = CiphertextEnvelope {
            key_version: u32::MAX,
            payload: vec![42; 64],
        };
        let decoded = CiphertextEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
    }
}
