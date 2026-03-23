use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, histogram};

use keyva_storage::{HealthState, StorageEngine};

use crate::command::{Command, command_verb};
use crate::error::CommandError;
use crate::handlers;
use crate::keyring_index::KeyringIndex;
use crate::response::{CommandResponse, ResponseMap};

/// Routes parsed Transit commands to the appropriate handler.
pub struct CommandDispatcher {
    engine: Arc<StorageEngine>,
    keyrings: Arc<KeyringIndex>,
}

impl CommandDispatcher {
    pub fn new(engine: Arc<StorageEngine>, keyrings: Arc<KeyringIndex>) -> Self {
        Self { engine, keyrings }
    }

    /// Returns a reference to the underlying storage engine.
    pub fn engine(&self) -> &StorageEngine {
        &self.engine
    }

    /// Returns a reference to the keyring index.
    pub fn keyrings(&self) -> &KeyringIndex {
        &self.keyrings
    }

    pub async fn execute(&self, cmd: Command) -> CommandResponse {
        // Handle pipeline recursively
        if let Command::Pipeline(commands) = cmd {
            let mut results = Vec::with_capacity(commands.len());
            for c in commands {
                results.push(Box::pin(self.execute(c)).await);
            }
            return CommandResponse::Array(results);
        }

        // Check engine health (allow Health commands through)
        if !matches!(cmd, Command::Health { .. }) && self.engine.health() != HealthState::Ready {
            return CommandResponse::Error(CommandError::NotReady(
                self.engine.health().to_string(),
            ));
        }

        let verb = command_verb(&cmd);
        let keyring_label = cmd.keyring().unwrap_or("_global").to_string();

        let start = Instant::now();
        let result = self.dispatch(cmd).await;
        let duration = start.elapsed();

        let result_label = match &result {
            Ok(_) => "ok",
            Err(_) => "error",
        };

        counter!("transit_commands_total", "command" => verb, "keyring" => keyring_label.clone(), "result" => result_label).increment(1);
        histogram!("transit_command_duration_seconds", "command" => verb, "keyring" => keyring_label).record(duration.as_secs_f64());

        match result {
            Ok(resp) => CommandResponse::Success(resp),
            Err(e) => CommandResponse::Error(e),
        }
    }

    async fn dispatch(&self, cmd: Command) -> Result<ResponseMap, CommandError> {
        match cmd {
            Command::Encrypt {
                keyring,
                plaintext,
                context,
                key_version,
            } => {
                handlers::encrypt::handle_encrypt(
                    &self.keyrings,
                    &keyring,
                    &plaintext,
                    context.as_deref(),
                    key_version,
                )
                .await
            }

            Command::Decrypt {
                keyring,
                ciphertext,
                context,
            } => {
                handlers::decrypt::handle_decrypt(
                    &self.keyrings,
                    &keyring,
                    &ciphertext,
                    context.as_deref(),
                )
                .await
            }

            Command::Rewrap {
                keyring,
                ciphertext,
                context,
            } => {
                handlers::rewrap::handle_rewrap(
                    &self.keyrings,
                    &keyring,
                    &ciphertext,
                    context.as_deref(),
                )
                .await
            }

            Command::GenerateDataKey { keyring, bits } => {
                handlers::generate_data_key::handle_generate_data_key(
                    &self.keyrings,
                    &keyring,
                    bits,
                )
                .await
            }

            Command::Sign {
                keyring,
                data,
                algorithm,
            } => {
                handlers::sign::handle_sign(&self.keyrings, &keyring, &data, algorithm.as_deref())
                    .await
            }

            Command::VerifySignature {
                keyring,
                data,
                signature,
            } => {
                handlers::verify_signature::handle_verify_signature(
                    &self.keyrings,
                    &keyring,
                    &data,
                    &signature,
                )
                .await
            }

            Command::Hash { algorithm, data } => {
                handlers::hash::handle_hash(&algorithm, &data).await
            }

            Command::Rotate {
                keyring,
                force,
                dryrun,
            } => {
                handlers::rotate::handle_rotate(
                    &self.keyrings,
                    &self.engine,
                    &keyring,
                    force,
                    dryrun,
                )
                .await
            }

            Command::KeyInfo { keyring } => {
                handlers::key_info::handle_key_info(&self.keyrings, &keyring).await
            }

            Command::Health { keyring } => {
                handlers::health::handle_health(&self.engine, keyring.as_deref()).await
            }

            Command::Auth { .. } => {
                // AUTH is handled at the connection/request level, not here
                Ok(ResponseMap::ok())
            }

            Command::Pipeline(_) => unreachable!("pipeline handled above"),
        }
    }
}
