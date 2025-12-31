#![cfg(all(feature = "zk-halo2", feature = "zk-zkvm"))]

use crate::{
    backend::{Halo2Backend, ProofBackend, ZkvmBackend},
    engine::PublicInputs,
};
use common::errors::ProtocolError;
use halo2_proofs::poly::commitment::Params;
use std::any::TypeId;
use zkvm::prover::prove_transition; // From zkvm/prover
use crate::tests_halo2::generate_valid_proof_with_params; // Reuse Halo2 gen

// Shared test scenarios: Same inputs → same outcome across backends
#[derive(Clone)]
struct TestScenario {
    score: u64,
    threshold: u64,
    expected: Result<(), ProtocolError>,
    desc: &'static str,
}

fn scenarios() -> Vec<TestScenario> {
    vec![
        TestScenario {
            score: 39,
            threshold: 40,
            expected: Ok(()),
            desc: "Valid transition: score <= threshold",
        },
        TestScenario {
            score: 41,
            threshold: 40,
            expected: Err(ProtocolError::InvalidProof), // zkVM panics → invalid receipt
            desc: "Invalid transition: score > threshold",
        },
        TestScenario {
            score: 0,
            threshold: 0,
            expected: Ok(()),
            desc: "Boundary: zero values",
        },
        TestScenario {
            score: u64::MAX,
            threshold: u64::MAX,
            expected: Ok(()),
            desc: "Boundary: max values (no overflow)",
        },
        TestScenario {
            score: u64::MAX - 1,
            threshold: u64::MAX,
            expected: Ok(()),
            desc: "Boundary: near-max diff",
        },
    ]
}

// Harness: Generate proof for backend type, verify against expected
fn run_scenario_on_backend<B: ProofBackend + 'static + std::fmt::Debug>(
    backend_factory: impl FnOnce() -> B,
    scenario: &TestScenario,
) -> Result<(), ProtocolError> {
    let inputs = PublicInputs {
        threshold: scenario.threshold,
        old_state_root: [0u8; 32],
        nonce: 1,
    };

    // Generate proof bytes (backend-specific)
    let proof_bytes = if TypeId::of::<B>() == TypeId::of::<Halo2Backend>() {
        let params = Params::new(9u32);
        let backend = backend_factory(); // Temp for VK/params
        // Note: For invalid, Halo2 needs adjusted circuit—here assume prover gen handles (or skip invalid for Halo2 if not wired)
        generate_valid_proof_with_params(scenario.score, scenario.threshold, &params)
    } else if TypeId::of::<B>() == TypeId::of::<ZkvmBackend>() {
        let receipt = prove_transition(&inputs, scenario.score); // Panics in guest if invalid → test fails early
        bincode::serialize(&receipt).map_err(|_| ProtocolError::SerializationError)?
    } else {
        unreachable!("Unsupported backend");
    };

    let backend = backend_factory();
    backend.verify(&proof_bytes, &inputs)
}

// Rust-only sim: Inline policy check (for equivalence baseline)
fn rust_only_sim(scenario: &TestScenario) -> Result<(), ProtocolError> {
    if scenario.score > scenario.threshold {
        Err(ProtocolError::PolicyViolation)
    } else {
        Ok(())
    }
}

#[test]
fn cross_backend_equivalence() {
    for scenario in scenarios() {
        println!("Testing: {}", scenario.desc);

        // Halo2
        let halo2_result = run_scenario_on_backend::<Halo2Backend>(|| {
            // Factory: Init with dummy params/VK
            let params = Params::new(9u32);
            let empty_circuit = circuits::score_circuit::ScoreCircuit::without_witnesses();
            let vk = halo2_proofs::plonk::keygen_vk(&params, &empty_circuit).unwrap();
            Halo2Backend { vk, params }
        }, &scenario);
        assert_eq!(halo2_result, scenario.expected, "Halo2 failed: {}", scenario.desc);

        // zkVM
        let zkvm_result = run_scenario_on_backend::<ZkvmBackend>(|| ZkvmBackend, &scenario);
        assert_eq!(zkvm_result, scenario.expected, "zkVM failed: {}", scenario.desc);

        // Rust-only
        let rust_result = rust_only_sim(&scenario);
        assert_eq!(rust_result, scenario.expected, "Rust sim failed: {}", scenario.desc);

        println!("✅ Passed: {}", scenario.desc);
    }
}