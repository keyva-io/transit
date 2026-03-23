//! REST adapter for Keyva Transit.
//!
//! HTTP server (axum) providing REST endpoints for all Transit operations.

mod error;
mod json;
mod routes;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use transit_protocol::CommandDispatcher;

/// Shared application state for all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub dispatcher: Arc<CommandDispatcher>,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// Builds the axum `Router` with all Transit REST endpoints wired to the dispatcher.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/{keyring}/encrypt", post(routes::post_encrypt))
        .route("/v1/{keyring}/decrypt", post(routes::post_decrypt))
        .route("/v1/{keyring}/rewrap", post(routes::post_rewrap))
        .route(
            "/v1/{keyring}/generate-data-key",
            post(routes::post_generate_data_key),
        )
        .route("/v1/{keyring}/sign", post(routes::post_sign))
        .route("/v1/{keyring}/verify", post(routes::post_verify_signature))
        .route("/v1/hash/{algorithm}", post(routes::post_hash))
        .route("/v1/{keyring}/rotate", post(routes::post_rotate))
        .route("/v1/{keyring}/info", get(routes::get_key_info))
        .route("/v1/health", get(routes::get_health))
        .route("/metrics", get(routes::get_metrics))
        .with_state(state)
}
