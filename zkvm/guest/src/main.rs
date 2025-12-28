#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ZkVmInput {
    pub score: u64,
    pub threshold: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ZkVmOutput {
    pub ok: bool,
}

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: ZkVmInput = env::read();

    // 🔐 This is the cryptographic rule
    assert!(
        input.score <= input.threshold,
        "score exceeds threshold"
    );

    env::commit(&ZkVmOutput { ok: true });
}
