use risc0_zkvm::{ExecutorEnv, default_prover};

use common::types::ZkVmInput;
use zkcg_zkvm_host::{method_id, ZkVmProof};

fn main() {
    // Example inputs (replace with CLI / RPC later)
    let score: u64 = 42;
    let threshold: u64 = 40;

    // 1️⃣ Build zkVM execution environment
    let mut builder = ExecutorEnv::builder();
    builder
        .write(&ZkVmInput { score, threshold })
        .expect("failed to write zkVM input");

    let env = builder.build().expect("failed to build executor env");

    // 2️⃣ Execute guest program
    let receipt = default_prover()
        .prove(env, zkcg_zkvm_host::ELF)
        .expect("zkVM execution failed");

    // 3️⃣ Produce opaque proof envelope
    let proof = ZkVmProof {
        method_id: receipt.method_id,
        journal_digest: receipt.journal.digest(),
    };

    // 4️⃣ Serialize proof
    let bytes = bincode::serialize(&proof)
        .expect("failed to serialize proof");

    // For now just print length (or write to file / stdout)
    println!("Proof generated ({} bytes)", bytes.len());
}
