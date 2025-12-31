#![cfg(feature = "zk-vm")]

use crate::{
    backend_zkvm::ZkVmBackend,
    engine::{PublicInputs, VerifierEngine},
};
use common::{
    errors::ProtocolError,
    state::ProtocolState,
    types::Commitment,
};

/// Helper commitment
fn commitment() -> Commitment {
    Commitment([42u8; 32])
}

/// Helper: produce a zkVM proof via host API
/// IMPORTANT: this returns opaque bytes
fn prove(score: u64, threshold: u64) -> Vec<u8> {
    zkcg_zkvm_host::prove(score, threshold)
}

#[test]
fn zkvm_valid_transition_succeeds() {
    let proof = prove(5, 10);

    let state = ProtocolState::genesis();
    let mut engine = VerifierEngine::new(
        state.clone(),
        Box::new(ZkVmBackend),
    );

    let inputs = PublicInputs {
        threshold: 10,
        old_state_root: state.state_root,
        nonce: state.nonce + 1,
    };

    let result = engine.process_transition(
        &proof,
        inputs,
        commitment(),
    );

    assert!(result.is_ok());
}

#[test]
fn zkvm_policy_violation_is_rejected() {
    let proof = prove(20, 10); // score > threshold

    let state = ProtocolState::genesis();
    let mut engine = VerifierEngine::new(
        state.clone(),
        Box::new(ZkVmBackend),
    );

    let inputs = PublicInputs {
        threshold: 10,
        old_state_root: state.state_root,
        nonce: state.nonce + 1,
    };

    let result = engine.process_transition(
        &proof,
        inputs,
        commitment(),
    );

    assert!(result.is_err());

    if let Err(e) = result {
        assert!(
            matches!(e, ProtocolError::InvalidProof | ProtocolError::PolicyViolation),
            "unexpected error: {:?}",
            e
        );
    }
}

#[test]
fn zkvm_tampered_proof_is_rejected() {
    let mut proof = prove(5, 10);

    // Flip some bytes
    if proof.len() > 16 {
        proof[8] ^= 0xFF;
        proof[15] ^= 0xAA;
    }

    let state = ProtocolState::genesis();
    let mut engine = VerifierEngine::new(
        state.clone(),
        Box::new(ZkVmBackend),
    );

    let inputs = PublicInputs {
        threshold: 10,
        old_state_root: state.state_root,
        nonce: state.nonce + 1,
    };

    let result = engine.process_transition(
        &proof,
        inputs,
        commitment(),
    );

    assert!(result.is_err(), "tampered proof accepted");
}

#[test]
fn zkvm_empty_proof_is_rejected() {
    let state = ProtocolState::genesis();
    let mut engine = VerifierEngine::new(
        state.clone(),
        Box::new(ZkVmBackend),
    );

    let inputs = PublicInputs {
        threshold: 10,
        old_state_root: state.state_root,
        nonce: state.nonce + 1,
    };

    let result = engine.process_transition(
        &[],
        inputs,
        commitment(),
    );

    assert!(result.is_err());
}

#[test]
fn zkvm_overflow_inputs_rejected() {
    let max_score = u64::MAX;
    let threshold = u64::MAX - 1;

    let proof_result = std::panic::catch_unwind(|| prove(max_score, threshold));

    match proof_result {
        Err(_) => {
            // guest panicked → acceptable
        }
        Ok(proof) => {
            let state = ProtocolState::genesis();
            let mut engine = VerifierEngine::new(
                state.clone(),
                Box::new(ZkVmBackend),
            );

            let inputs = PublicInputs {
                threshold,
                old_state_root: state.state_root,
                nonce: state.nonce + 1,
            };

            let result = engine.process_transition(
                &proof,
                inputs,
                commitment(),
            );

            assert!(result.is_err(), "overflow proof accepted");
        }
    }
}
