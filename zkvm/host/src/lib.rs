#[cfg(feature = "zk-vm")]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

#[cfg(feature = "zk-vm")]
use methods::{ELF, ID};

use risc0_zkvm::{ExecutorEnv, default_prover};
use common::types::ZkVmInput;

#[cfg(feature = "zk-vm")]
pub fn method_id() -> &'static risc0_zkvm::MethodId {
    &methods::ID
}

#[cfg(feature = "zk-vm")]
pub fn prove(score: u64, threshold: u64) -> Vec<u8> {
    use risc0_zkvm::{ExecutorEnv, default_prover};
    use common::types::ZkVmInput;

    let mut builder = ExecutorEnv::builder();
    builder
        .write(&ZkVmInput { score, threshold })
        .expect("failed to write input");

    let env = builder.build().expect("failed to build env");

    let receipt = default_prover()
        .prove(env, ELF)
        .expect("zkVM proof failed");

    bincode::serialize(&receipt).expect("serialize receipt")
}

#[cfg(not(feature = "zk-vm"))]
pub fn prove(_: u64, _: u64) -> Vec<u8> {
    unreachable!("zkVM feature not enabled")
}
