use keyva_storage::StorageEngine;

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};

pub async fn handle_health(
    engine: &StorageEngine,
    _keyring_name: Option<&str>,
) -> Result<ResponseMap, CommandError> {
    let state = engine.health();
    Ok(ResponseMap::ok().with("state", ResponseValue::String(state.to_string())))
}
