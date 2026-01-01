#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use common::types::ZkVmInput;
use risc0_zkvm::sha::{Sha256, Digest};


#[derive(Serialize, Deserialize)]
pub struct ZkVmOutput {
    pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ZkVmJournal {
    pub threshold: u64,
    pub old_state_root: [u8; 32],
    pub nonce: u64,
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
    env::commit(&true);
}
