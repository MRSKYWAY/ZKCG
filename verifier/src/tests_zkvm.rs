#![cfg(feature = "zk-vm")]

use crate::{
    engine::{PublicInputs, VerifierEngine},
    backend_zkvm::ZkVmBackend,
};
use common::{
    errors::ProtocolError,
    state::ProtocolState,
    types::Commitment,
};
use zkcg_zkvm_host::{prove, ZkVmProverError};

fn commitment() -> Commitment {
    Commitment([42u8; 32])
}

#[test]
fn zkvm_valid_transition_succeeds() {
    let proof = prove(5, 10).expect("valid proof");

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
    let result = prove(20, 10);

    assert!(matches!(
        result,
        Err(ZkVmProverError::PolicyViolation)
    ));
}

#[test]
fn zkvm_tampered_proof_is_rejected() {
    let mut proof = prove(5, 10).unwrap();

    proof[0] ^= 0xFF; // corrupt method id

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

    assert!(matches!(result, Err(ProtocolError::InvalidProof)));
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
    let result = prove(u64::MAX, u64::MAX - 1);
    assert!(result.is_err());
}
