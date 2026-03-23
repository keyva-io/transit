//! `transit-client` — typed Rust client library for Keyva Transit.
//!
//! Provides a high-level async API for interacting with a Transit server over TCP.
//! The RESP3 protocol is handled internally — callers never deal with raw frames.
//!
//! # Example
//!
//! ```no_run
//! use transit_client::TransitClient;
//!
//! # async fn example() -> Result<(), transit_client::ClientError> {
//! let mut client = TransitClient::connect("127.0.0.1:6499").await?;
//!
//! // Encrypt data
//! let result = client.encrypt("payments", b"secret data", None).await?;
//! let ciphertext = result.ciphertext.as_ref().unwrap();
//! println!("Ciphertext: {ciphertext}");
//!
//! // Decrypt it back
//! let decrypted = client.decrypt("payments", ciphertext, None).await?;
//! println!("Plaintext: {:?}", decrypted.plaintext);
//! # Ok(())
//! # }
//! ```

pub mod connection;
pub mod error;
pub mod response;

pub use error::ClientError;
pub use response::{
    DataKeyResult, DecryptResult, EncryptResult, HashResult, HealthResult, KeyInfoResult, Response,
    RotateResult, SignResult, VerifyResult,
};

use connection::Connection;

/// Default Transit server port.
const DEFAULT_PORT: u16 = 6499;

/// Parsed components of a Transit connection URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub auth_token: Option<String>,
}

/// Parse a Transit connection URI.
///
/// Format: `kvt://[token@]host[:port]`
///         `kvt+tls://[token@]host[:port]`
///
/// # Examples
///
/// ```
/// use transit_client::parse_uri;
///
/// let cfg = parse_uri("kvt://localhost").unwrap();
/// assert_eq!(cfg.host, "localhost");
/// assert_eq!(cfg.port, 6499);
/// assert!(!cfg.tls);
///
/// let cfg = parse_uri("kvt+tls://mytoken@prod.example.com:7000").unwrap();
/// assert!(cfg.tls);
/// assert_eq!(cfg.auth_token.as_deref(), Some("mytoken"));
/// assert_eq!(cfg.host, "prod.example.com");
/// assert_eq!(cfg.port, 7000);
/// ```
pub fn parse_uri(uri: &str) -> Result<ConnectionConfig, ClientError> {
    let (tls, rest) = if let Some(rest) = uri.strip_prefix("kvt+tls://") {
        (true, rest)
    } else if let Some(rest) = uri.strip_prefix("kvt://") {
        (false, rest)
    } else if let Some(rest) = uri.strip_prefix("keyva-transit+tls://") {
        (true, rest)
    } else if let Some(rest) = uri.strip_prefix("keyva-transit://") {
        (false, rest)
    } else {
        return Err(ClientError::Protocol(format!("invalid URI scheme: {uri}")));
    };

    let (auth_token, hostport) = if let Some(at_pos) = rest.find('@') {
        (Some(rest[..at_pos].to_string()), &rest[at_pos + 1..])
    } else {
        (None, rest)
    };

    // Strip trailing path if present
    let hostport = hostport.split('/').next().unwrap_or(hostport);

    let (host, port) = if let Some(colon_pos) = hostport.rfind(':') {
        let port_str = &hostport[colon_pos + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (hostport[..colon_pos].to_string(), p),
            Err(_) => (hostport.to_string(), DEFAULT_PORT),
        }
    } else {
        (hostport.to_string(), DEFAULT_PORT)
    };

    Ok(ConnectionConfig {
        host,
        port,
        tls,
        auth_token,
    })
}

/// A client for interacting with a Keyva Transit server.
pub struct TransitClient {
    connection: Connection,
}

impl TransitClient {
    /// Connect to a Transit server at the given address (e.g. `"127.0.0.1:6499"`).
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let connection = Connection::connect(addr).await?;
        Ok(Self { connection })
    }

    /// Connect to a Transit server over TLS.
    pub async fn connect_tls(addr: &str) -> Result<Self, ClientError> {
        let connection = Connection::connect_tls(addr).await?;
        Ok(Self { connection })
    }

    /// Connect using a URI string.
    ///
    /// Format: `kvt://[token@]host[:port]`
    ///         `kvt+tls://[token@]host[:port]`
    pub async fn from_uri(uri: &str) -> Result<Self, ClientError> {
        let config = parse_uri(uri)?;
        let addr = format!("{}:{}", config.host, config.port);
        let mut client = if config.tls {
            Self::connect_tls(&addr).await?
        } else {
            Self::connect(&addr).await?
        };
        if let Some(token) = &config.auth_token {
            client.auth(token).await?;
        }
        Ok(client)
    }

    /// Authenticate the connection with a bearer token.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.connection.send_command_strs(&["AUTH", token]).await?;
        check_ok_status(resp)
    }

    /// Encrypt plaintext with the named keyring.
    pub async fn encrypt(
        &mut self,
        keyring: &str,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> Result<EncryptResult, ClientError> {
        use base64::Engine;
        let pt_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
        let mut args: Vec<&str> = vec!["ENCRYPT", keyring, &pt_b64];
        let ctx_string;
        if let Some(ctx) = context {
            args.push("CONTEXT");
            ctx_string = ctx.to_string();
            args.push(&ctx_string);
        }
        let resp = self.connection.send_command_strs(&args).await?;
        EncryptResult::from_response(resp)
    }

    /// Decrypt ciphertext with the named keyring.
    pub async fn decrypt(
        &mut self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptResult, ClientError> {
        let mut args: Vec<&str> = vec!["DECRYPT", keyring, ciphertext];
        let ctx_string;
        if let Some(ctx) = context {
            args.push("CONTEXT");
            ctx_string = ctx.to_string();
            args.push(&ctx_string);
        }
        let resp = self.connection.send_command_strs(&args).await?;
        DecryptResult::from_response(resp)
    }

    /// Re-encrypt ciphertext with the current active key.
    pub async fn rewrap(
        &mut self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<EncryptResult, ClientError> {
        let mut args: Vec<&str> = vec!["REWRAP", keyring, ciphertext];
        let ctx_string;
        if let Some(ctx) = context {
            args.push("CONTEXT");
            ctx_string = ctx.to_string();
            args.push(&ctx_string);
        }
        let resp = self.connection.send_command_strs(&args).await?;
        EncryptResult::from_response(resp)
    }

    /// Generate a data encryption key.
    pub async fn generate_data_key(
        &mut self,
        keyring: &str,
        bits: Option<u32>,
    ) -> Result<DataKeyResult, ClientError> {
        let bits_str;
        let mut args: Vec<&str> = vec!["GENERATE_DATA_KEY", keyring];
        if let Some(b) = bits {
            args.push("BITS");
            bits_str = b.to_string();
            args.push(&bits_str);
        }
        let resp = self.connection.send_command_strs(&args).await?;
        DataKeyResult::from_response(resp)
    }

    /// Create a detached signature.
    pub async fn sign(&mut self, keyring: &str, data: &[u8]) -> Result<SignResult, ClientError> {
        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let args: Vec<&str> = vec!["SIGN", keyring, &data_b64];
        let resp = self.connection.send_command_strs(&args).await?;
        SignResult::from_response(resp)
    }

    /// Verify a detached signature.
    pub async fn verify_signature(
        &mut self,
        keyring: &str,
        data: &[u8],
        signature: &str,
    ) -> Result<VerifyResult, ClientError> {
        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let args: Vec<&str> = vec!["VERIFY_SIGNATURE", keyring, &data_b64, signature];
        let resp = self.connection.send_command_strs(&args).await?;
        VerifyResult::from_response(resp)
    }

    /// Compute a one-way hash.
    pub async fn hash(&mut self, algorithm: &str, data: &[u8]) -> Result<HashResult, ClientError> {
        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let args: Vec<&str> = vec!["HASH", algorithm, &data_b64];
        let resp = self.connection.send_command_strs(&args).await?;
        HashResult::from_response(resp)
    }

    /// Trigger key rotation.
    pub async fn rotate(&mut self, keyring: &str) -> Result<RotateResult, ClientError> {
        let resp = self
            .connection
            .send_command_strs(&["ROTATE", keyring])
            .await?;
        RotateResult::from_response(resp)
    }

    /// Get key info for a keyring.
    pub async fn key_info(&mut self, keyring: &str) -> Result<KeyInfoResult, ClientError> {
        let resp = self
            .connection
            .send_command_strs(&["KEY_INFO", keyring])
            .await?;
        KeyInfoResult::from_response(resp)
    }

    /// Check server health.
    pub async fn health(&mut self) -> Result<HealthResult, ClientError> {
        let resp = self.connection.send_command_strs(&["HEALTH"]).await?;
        HealthResult::from_response(resp)
    }

    /// Send an arbitrary command and return the raw RESP3 response.
    pub async fn raw_command(&mut self, args: &[&str]) -> Result<Response, ClientError> {
        self.connection.send_command_strs(args).await
    }
}

/// Check that a response indicates success (not an error).
fn check_ok_status(resp: Response) -> Result<(), ClientError> {
    match &resp {
        Response::Error(e) => {
            if e.contains("DENIED") {
                Err(ClientError::AuthRequired)
            } else {
                Err(ClientError::Server(e.clone()))
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_plain_host() {
        let cfg = parse_uri("kvt://localhost").unwrap();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 6499);
        assert!(!cfg.tls);
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn parse_uri_with_port() {
        let cfg = parse_uri("kvt://localhost:7000").unwrap();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 7000);
    }

    #[test]
    fn parse_uri_tls() {
        let cfg = parse_uri("kvt+tls://prod.example.com").unwrap();
        assert!(cfg.tls);
        assert_eq!(cfg.host, "prod.example.com");
        assert_eq!(cfg.port, 6499);
    }

    #[test]
    fn parse_uri_with_auth() {
        let cfg = parse_uri("kvt://mytoken@localhost:6499").unwrap();
        assert_eq!(cfg.auth_token.as_deref(), Some("mytoken"));
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 6499);
    }

    #[test]
    fn parse_uri_full_form() {
        let cfg = parse_uri("kvt+tls://tok@host:7000").unwrap();
        assert!(cfg.tls);
        assert_eq!(cfg.auth_token.as_deref(), Some("tok"));
        assert_eq!(cfg.host, "host");
        assert_eq!(cfg.port, 7000);
    }

    #[test]
    fn parse_uri_keyva_transit_scheme() {
        let cfg = parse_uri("keyva-transit://localhost").unwrap();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 6499);
        assert!(!cfg.tls);
    }

    #[test]
    fn parse_uri_invalid_scheme() {
        assert!(parse_uri("redis://localhost").is_err());
        assert!(parse_uri("http://localhost").is_err());
    }

    #[test]
    fn parse_uri_default_port_on_invalid_port() {
        let cfg = parse_uri("kvt://localhost:notaport").unwrap();
        assert_eq!(cfg.port, 6499);
    }
}
