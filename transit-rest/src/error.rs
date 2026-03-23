use axum::http::StatusCode;
use transit_protocol::CommandError;

/// Maps a `CommandError` variant to the appropriate HTTP status code.
pub fn error_to_status(err: &CommandError) -> StatusCode {
    match err {
        CommandError::BadArg { .. } => StatusCode::BAD_REQUEST,
        CommandError::NotFound { .. } => StatusCode::NOT_FOUND,
        CommandError::Denied { .. } => StatusCode::FORBIDDEN,
        CommandError::Disabled { .. } | CommandError::NotReady(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        CommandError::Transit(_)
        | CommandError::Storage(_)
        | CommandError::Crypto(_)
        | CommandError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
