//! Protocol layer for Keyva Transit.
//!
//! Command parsing, dispatch, handler execution, and response serialization.

pub mod command;
pub mod dispatch;
pub mod error;
pub mod handlers;
pub mod keyring_index;
pub mod recovery;
pub mod resp3;
pub mod response;

pub use command::Command;
pub use dispatch::CommandDispatcher;
pub use error::CommandError;
pub use keyring_index::KeyringIndex;
pub use resp3::{ProtocolError, Resp3Frame};
pub use response::{CommandResponse, ResponseMap, ResponseValue};
