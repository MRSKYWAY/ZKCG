#[cfg(feature = "zk-vm")]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

use risc0_zkp::core::digest::Digest;
use serde::{Serialize, Deserialize};


use risc0_zkvm::{ExecutorEnv, default_prover};
use risc0_binfmt::Digestible;
use zkcg_common::types::ZkVmInput;

#[derive(Debug)]
pub enum ZkVmProverError {
    PolicyViolation,
    ExecutionFailed,
}

pub fn prove(score: u64, threshold: u64, old_state_root: [u8; 32],
    nonce: u64) -> Result<Vec<u8>, ZkVmProverError> {
    let result =std::panic::catch_unwind(|| {let mut builder = ExecutorEnv::builder();
            builder
                .write(&ZkVmInput { score, threshold, old_state_root,
                nonce })
                .expect("failed to write zkVM input");

            let env = builder.build().expect("failed to build executor env");

            let prove_info = default_prover()
                .prove(env, elf())
                .expect("zkVM execution failed");

            let receipt = prove_info.receipt;

            let proof = ZkVmProof {
                method_id: method_id(),
                journal_digest: receipt.journal.digest::<risc0_zkvm::sha::Impl>(),
            };

            bincode::serialize(&proof).expect("failed to serialize proof")});

            match result {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(ZkVmProverError::PolicyViolation),
    }
}

/// Opaque proof envelope produced by the prover
#[derive(Serialize, Deserialize)]
pub struct ZkVmProof {
    pub method_id: Digest,
    pub journal_digest: Digest,
}

#[cfg(feature = "zk-vm")]
pub fn method_id() -> Digest {
    Digest::from(methods::ZKCG_ZKVM_GUEST_ID)
}

#[cfg(feature = "zk-vm")]
pub fn elf() -> &'static [u8] {
    methods::ZKCG_ZKVM_GUEST_ELF
}
