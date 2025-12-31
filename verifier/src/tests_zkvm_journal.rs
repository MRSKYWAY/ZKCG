#![cfg(feature = "zk-vm")]

use crate::{
    backend::ProofBackend,
    backend_zkvm::ZkVmBackend,
    engine::PublicInputs,
};

use common::errors::ProtocolError;
use common::types::Commitment;

use zkcg_zkvm_host::prove;

fn commitment() -> Commitment {
    Commitment([1u8; 32])
}

fn valid_inputs() -> PublicInputs {
    PublicInputs {
        threshold: 10,
        old_state_root: [9u8; 32],
        nonce: 7,
    }
}

#[test]
fn zkvm_valid_proof_is_accepted() {
    let mut inputs = valid_inputs();
    let proof = prove(5, 10, inputs.old_state_root, inputs.nonce).expect("proof generation failed");
    let backend = ZkVmBackend;

    let result = backend.verify(&proof, &valid_inputs());
    assert!(result.is_ok());
}

#[test]
fn zkvm_threshold_tampering_is_rejected() {
    
    let backend = ZkVmBackend;

    let mut inputs = valid_inputs();
    inputs.threshold = 11; // 🔴 tamper
    let proof = prove(5, 10, inputs.old_state_root, inputs.nonce).expect("proof generation failed");
    let result = backend.verify(&proof, &inputs);
    assert!(matches!(result, Err(ProtocolError::InvalidProof)));
}

#[test]
fn zkvm_nonce_tampering_is_rejected() {
    let mut inputs = valid_inputs();
    let proof = prove(5, 10, inputs.old_state_root, inputs.nonce).expect("proof generation failed");
    let backend = ZkVmBackend;

    let mut inputs = valid_inputs();
    inputs.nonce += 1; // 🔴 replay attack

    let result = backend.verify(&proof, &inputs);
    assert!(matches!(result, Err(ProtocolError::InvalidProof)));
}

#[test]
fn zkvm_state_root_tampering_is_rejected() {
    let inputs = valid_inputs();
    let proof = prove(5, 10, inputs.old_state_root, inputs.nonce).expect("proof generation failed");
    let backend = ZkVmBackend;

    let mut inputs = valid_inputs();
    inputs.old_state_root[0] ^= 0xFF;

    let result = backend.verify(&proof, &inputs);
    assert!(matches!(result, Err(ProtocolError::InvalidProof)));
}

#[test]
fn zkvm_proof_bytes_tampering_is_rejected() {
    let inputs = valid_inputs();
    let mut proof = prove(5, 10, inputs.old_state_root, inputs.nonce).expect("proof generation failed");
    let backend = ZkVmBackend;

    proof[3] ^= 0xAA; //  corrupt bytes

    let result = backend.verify(&proof, &valid_inputs());
    assert!(matches!(result, Err(ProtocolError::InvalidProof)));
}
