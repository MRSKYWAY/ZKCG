use crate::{
    engine::{PublicInputs, VerifierEngine},
    backend_zkvm::ZkVmBackend,
};
use common::{state::ProtocolState, types::Commitment};

fn commitment() -> Commitment {
    Commitment([42u8; 32])
}

#[test]
fn zkvm_valid_transition_succeeds() {
    let proof = zkcg_zkvm_host::prove(5, 10);

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
fn zkvm_invalid_transition_fails() {
    let proof = zkcg_zkvm_host::prove(20, 10);

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
}
