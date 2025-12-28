use risc0_zkvm::{ExecutorEnv, default_prover};
use zkcg_zkvm_guest::{ZkVmInput, ZkVmOutput};

pub fn prove(score: u64, threshold: u64) -> Vec<u8> {
    let env = ExecutorEnv::builder()
        .write(&ZkVmInput { score, threshold })
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover
        .prove(env, zkcg_zkvm_guest::ELF)
        .unwrap();

    bincode::serialize(&receipt).unwrap()
}
