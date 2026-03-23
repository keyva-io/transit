use axum::Json;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use transit_protocol::{CommandResponse, ResponseMap, ResponseValue};

use crate::error::error_to_status;

// ---------------------------------------------------------------------------
// Request body structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EncryptBody {
    pub plaintext: String,
    pub context: Option<String>,
    pub key_version: Option<u32>,
}

#[derive(Deserialize)]
pub struct DecryptBody {
    pub ciphertext: String,
    pub context: Option<String>,
}

#[derive(Deserialize)]
pub struct RewrapBody {
    pub ciphertext: String,
    pub context: Option<String>,
}

#[derive(Deserialize)]
pub struct GenerateDataKeyBody {
    pub bits: Option<u32>,
}

#[derive(Deserialize)]
pub struct SignBody {
    pub data: String,
    pub algorithm: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifySignatureBody {
    pub data: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct HashBody {
    pub data: String,
}

#[derive(Deserialize)]
pub struct RotateBody {
    pub force: Option<bool>,
    pub dryrun: Option<bool>,
}

// ---------------------------------------------------------------------------
// Response serialization
// ---------------------------------------------------------------------------

fn response_value_to_json(v: &ResponseValue) -> Value {
    match v {
        ResponseValue::String(s) => Value::String(s.clone()),
        ResponseValue::Integer(n) => serde_json::json!(*n),
        ResponseValue::Float(f) => serde_json::json!(*f),
        ResponseValue::Boolean(b) => Value::Bool(*b),
        ResponseValue::Bytes(b) => {
            use base64::Engine;
            Value::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
        ResponseValue::Null => Value::Null,
        ResponseValue::Map(m) => response_map_to_value(m),
        ResponseValue::Array(arr) => Value::Array(arr.iter().map(response_value_to_json).collect()),
        ResponseValue::Json(v) => v.clone(),
    }
}

fn response_map_to_value(map: &ResponseMap) -> Value {
    let obj: serde_json::Map<String, Value> = map
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), response_value_to_json(v)))
        .collect();
    Value::Object(obj)
}

fn command_response_to_json(resp: &CommandResponse) -> Value {
    match resp {
        CommandResponse::Success(map) => response_map_to_value(map),
        CommandResponse::Error(err) => {
            let code = error_code_string(err);
            serde_json::json!({ "error": code, "message": err.to_string() })
        }
        CommandResponse::Array(items) => {
            Value::Array(items.iter().map(command_response_to_json).collect())
        }
    }
}

/// Converts a `CommandResponse` into an HTTP status code and JSON body.
pub fn response_to_json(resp: &CommandResponse) -> (StatusCode, Json<Value>) {
    match resp {
        CommandResponse::Success(_) | CommandResponse::Array(_) => {
            (StatusCode::OK, Json(command_response_to_json(resp)))
        }
        CommandResponse::Error(err) => {
            let status = error_to_status(err);
            (status, Json(command_response_to_json(resp)))
        }
    }
}

/// Returns a short machine-readable error code for the variant.
fn error_code_string(err: &transit_protocol::CommandError) -> &'static str {
    use transit_protocol::CommandError;
    match err {
        CommandError::BadArg { .. } => "BAD_ARG",
        CommandError::NotFound { .. } => "NOT_FOUND",
        CommandError::Denied { .. } => "DENIED",
        CommandError::Disabled { .. } => "DISABLED",
        CommandError::NotReady(_) => "NOT_READY",
        CommandError::Transit(_) => "TRANSIT",
        CommandError::Storage(_) => "STORAGE",
        CommandError::Crypto(_) => "CRYPTO",
        CommandError::Internal(_) => "INTERNAL",
    }
}
