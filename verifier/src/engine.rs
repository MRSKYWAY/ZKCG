use common::{
    errors::ProtocolError,
    state::ProtocolState,
    types::Commitment,
};

use crate::{policy, proof};

pub struct VerifierEngine {
    state: ProtocolState,
}

impl VerifierEngine {
    pub fn new(state: ProtocolState) -> Self {
        Self { state }
    }
    
    pub fn state(&self) -> &ProtocolState {
        &self.state
    }


    pub fn process_transition(
        &mut self,
        proof_bytes: &[u8],
        public_inputs: PublicInputs,
        commitment: Commitment,
    ) -> Result<(), ProtocolError> {
        // 1. Check state root
        if public_inputs.old_state_root != self.state.state_root {
            return Err(ProtocolError::StateMismatch);
        }

        // 2. Check nonce
        if public_inputs.nonce != self.state.nonce + 1 {
            return Err(ProtocolError::InvalidNonce);
        }

        // 3. Verify proof
        proof::verify(proof_bytes, &public_inputs)?;

        // 4. Enforce policy
        policy::enforce(&public_inputs)?;

        // 5. Update state
        self.state.state_root = commitment.0;
        self.state.nonce += 1;

        Ok(())
    }
}

#[derive(Debug)]
pub struct PublicInputs {
    pub threshold: u64,
    pub old_state_root: [u8; 32],
    pub nonce: u64,
}
