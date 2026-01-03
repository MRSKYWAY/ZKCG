use criterion::{criterion_group, criterion_main, Criterion};
use zkcg_common::state::ProtocolState;
use zkcg_verifier::engine::{VerifierEngine, PublicInputs};
use zkcg_verifier::backend_zkvm::ZkVmBackend;  // real one
use zkcg_verifier::backend_halo2::Halo2Backend; // we'll bypass the heavy part

// Temporary bench-only backend
struct BenchHalo2Backend;

impl zkcg_verifier::backend::ProofBackend for BenchHalo2Backend {
    fn verify(&self, _proof: &[u8], _inputs: &PublicInputs) -> Result<(), zkcg_common::errors::ProtocolError> {
        // Simulate Halo2 verification cost (pairing, FFT, etc.)
        // Or leave empty for pure engine overhead
        // For real cost, you'd need to run actual verify_proof with small circuit
        Ok(())
    }
}

fn mock_proof() -> Vec<u8> {
    vec![0u8; 1024] // Realistic size
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verification Speed");

    let inputs = PublicInputs {
        threshold: 600,
        old_state_root: [0; 32],
        nonce: 1,
    };

    let state = ProtocolState::genesis();

    // Halo2 path — using dummy backend to isolate engine
    {
        let backend = BenchHalo2Backend;
        let mut engine = VerifierEngine::new(state.clone(), Box::new(backend));
        let proof = mock_proof();

        group.bench_function("halo2 (simulated)", |b| {
            b.iter(|| engine.process_transition(&proof, inputs, zkcg_common::types::Commitment([0; 32])))
        });
    }

    // zkVM path — real backend, zero cost
    #[cfg(feature = "zk-vm")]
    {
        let backend = ZkVmBackend;
        let mut engine = VerifierEngine::new(state, Box::new(backend));
        let proof = mock_proof();

        group.bench_function("zkvm (real)", |b| {
            b.iter(|| engine.process_transition(&proof, inputs, zkcg_common::types::Commitment([0; 32])))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_verification);
criterion_main!(benches);