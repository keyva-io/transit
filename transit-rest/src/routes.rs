use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use transit_protocol::Command;

use crate::AppState;
use crate::json::{
    DecryptBody, EncryptBody, GenerateDataKeyBody, HashBody, RewrapBody, RotateBody, SignBody,
    VerifySignatureBody,
};

pub async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics_handle.render();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

pub async fn post_encrypt(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<EncryptBody>,
) -> impl IntoResponse {
    let cmd = Command::Encrypt {
        keyring,
        plaintext: body.plaintext,
        context: body.context,
        key_version: body.key_version,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_decrypt(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<DecryptBody>,
) -> impl IntoResponse {
    let cmd = Command::Decrypt {
        keyring,
        ciphertext: body.ciphertext,
        context: body.context,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_rewrap(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<RewrapBody>,
) -> impl IntoResponse {
    let cmd = Command::Rewrap {
        keyring,
        ciphertext: body.ciphertext,
        context: body.context,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_generate_data_key(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<GenerateDataKeyBody>,
) -> impl IntoResponse {
    let cmd = Command::GenerateDataKey {
        keyring,
        bits: body.bits,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_sign(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<SignBody>,
) -> impl IntoResponse {
    let cmd = Command::Sign {
        keyring,
        data: body.data,
        algorithm: body.algorithm,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_verify_signature(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<VerifySignatureBody>,
) -> impl IntoResponse {
    let cmd = Command::VerifySignature {
        keyring,
        data: body.data,
        signature: body.signature,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_hash(
    State(state): State<AppState>,
    Path(algorithm): Path<String>,
    Json(body): Json<HashBody>,
) -> impl IntoResponse {
    let cmd = Command::Hash {
        algorithm,
        data: body.data,
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn post_rotate(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
    Json(body): Json<RotateBody>,
) -> impl IntoResponse {
    let cmd = Command::Rotate {
        keyring,
        force: body.force.unwrap_or(false),
        dryrun: body.dryrun.unwrap_or(false),
    };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn get_key_info(
    State(state): State<AppState>,
    Path(keyring): Path<String>,
) -> impl IntoResponse {
    let cmd = Command::KeyInfo { keyring };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}

pub async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let cmd = Command::Health { keyring: None };
    let resp = state.dispatcher.execute(cmd).await;
    crate::json::response_to_json(&resp).into_response()
}
