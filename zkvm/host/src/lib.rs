mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

use risc0_zkvm::{ExecutorEnv, default_prover};
use zkcg_zkvm_guest::ZkVmInput;
use methods::{ELF, ID};

pub fn prove(score: u64, threshold: u64) -> Vec<u8> {
    let mut builder = ExecutorEnv::builder();

    builder
        .write(&ZkVmInput { score, threshold })
        .expect("failed to write zkVM input");

    let env = builder.build().expect("failed to build executor env");

    let prover = default_prover();
    let receipt = prover
        .prove(env, ELF)
        .expect("zkVM proof failed");

    bincode::serialize(&receipt).expect("failed to serialize receipt")
}
