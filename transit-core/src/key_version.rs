use serde::{Deserialize, Serialize};

use crate::error::TransitError;

/// A single version of a key within a keyring.
#[derive(Debug, Clone)]
pub struct KeyVersion {
    pub version: u32,
    pub state: KeyState,
    pub key_material: Option<keyva_crypto::SecretBytes>,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    pub draining_since: Option<u64>,
    pub retired_at: Option<u64>,
}

/// Key lifecycle state machine: Staged -> Active -> Draining -> Retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Staged,
    Active,
    Draining,
    Retired,
}

impl KeyState {
    /// Returns whether this state can transition to the target state.
    pub fn can_transition_to(self, target: KeyState) -> bool {
        matches!(
            (self, target),
            (KeyState::Staged, KeyState::Active)
                | (KeyState::Active, KeyState::Draining)
                | (KeyState::Draining, KeyState::Retired)
        )
    }

    /// Attempt to transition to the target state.
    pub fn transition_to(self, target: KeyState) -> Result<KeyState, TransitError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(TransitError::InvalidStateTransition {
                from: self,
                to: target,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions() {
        assert!(KeyState::Staged.can_transition_to(KeyState::Active));
        assert!(KeyState::Active.can_transition_to(KeyState::Draining));
        assert!(KeyState::Draining.can_transition_to(KeyState::Retired));
    }

    #[test]
    fn invalid_transitions() {
        // Cannot skip states
        assert!(!KeyState::Staged.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Staged.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Retired));
        // Cannot go backwards
        assert!(!KeyState::Active.can_transition_to(KeyState::Staged));
        assert!(!KeyState::Draining.can_transition_to(KeyState::Active));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Draining));
        // Cannot self-transition
        assert!(!KeyState::Active.can_transition_to(KeyState::Active));
    }

    #[test]
    fn transition_to_ok() {
        let state = KeyState::Staged.transition_to(KeyState::Active).unwrap();
        assert_eq!(state, KeyState::Active);
    }

    #[test]
    fn transition_to_err() {
        let err = KeyState::Staged
            .transition_to(KeyState::Retired)
            .unwrap_err();
        assert!(matches!(
            err,
            TransitError::InvalidStateTransition {
                from: KeyState::Staged,
                to: KeyState::Retired,
            }
        ));
    }
}
