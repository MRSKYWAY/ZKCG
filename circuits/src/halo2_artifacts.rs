use halo2_proofs::{
    plonk::{keygen_vk, VerifyingKey},
    poly::commitment::Params,
};
use halo2curves::bn256::{Fr, G1Affine};

use crate::score_circuit::ScoreCircuit;

/// Canonical verifier artifacts for the ScoreCircuit
#[derive(Clone)]
pub struct Halo2Artifacts {
    pub params: Params<G1Affine>,
    pub vk: VerifyingKey<G1Affine>,
}

impl Halo2Artifacts {
    pub fn for_score_circuit() -> Self {
        // MUST match prover + verifier
        let k: u32 = 9;

        let params: Params<G1Affine> = Params::new(k);

        let empty = ScoreCircuit::<Fr> {
            score: halo2_proofs::circuit::Value::unknown(),
            threshold: halo2_proofs::circuit::Value::unknown(),
        };

        let vk =
            keygen_vk(&params, &empty).expect("verifying key generation failed");

        Self { params, vk }
    }
}

/// Generate verifier artifacts at runtime
pub fn verifier_artifacts() -> Halo2Artifacts {
    let k: u32 = 9;

    let params: Params<G1Affine> = Params::new(k);

    let empty_circuit = ScoreCircuit::<Fr> {
        score: halo2_proofs::circuit::Value::unknown(),
        threshold: halo2_proofs::circuit::Value::unknown(),
    };

    let vk = keygen_vk(&params, &empty_circuit)
        .expect("failed to generate verifying key");

    Halo2Artifacts { params, vk }
}
