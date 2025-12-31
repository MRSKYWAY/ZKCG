#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use common::types::ZkVmInput;

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

    // 🔐 PHASE 8: Bind proof to state + inputs
    //
    // Order matters: verifier must hash in same order
    env::commit(&input.threshold);
    env::commit(&input.old_state_root);
    env::commit(&input.nonce);

    env::commit(&ZkVmOutput { ok: true });
}
