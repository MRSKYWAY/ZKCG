#![cfg(feature = "zk-halo2")]

use common::errors::ProtocolError;
use crate::{
    backend::ProofBackend,
    engine::PublicInputs,
};

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey, SingleVerifier, create_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};

use halo2curves::bn256::{Fr, G1Affine};

/// Real Halo2 verifier backend (runtime keys, KZG implicit)
pub struct Halo2Backend {
    pub vk: VerifyingKey<G1Affine>,
    pub params: Params<G1Affine>,
}

impl ProofBackend for Halo2Backend {
    fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> Result<(), ProtocolError> {
        // --- public inputs (instance columns)
        let threshold = Fr::from(public_inputs.threshold as u64);

        let instance_values = vec![vec![threshold]];
        let instance_slices: Vec<&[Fr]> =
            instance_values.iter().map(|v| v.as_slice()).collect();
        let all_instances: Vec<&[&[Fr]]> =
            vec![instance_slices.as_slice()];

        // --- transcript
        let mut transcript =
            Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes);

        // --- verification strategy
        let strategy = SingleVerifier::new(&self.params);
        println!("Starting proof verification...");
        println!("Public inputs: {:?}", all_instances);
        println!("Proof bytes length: {}", proof_bytes.len());
        // println!("Params: {:?}", self.params);
        // println!("Transcript state: {:?}", transcript);
        println!("Using SingleVerifier strategy.");
        // --- verify
        verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &all_instances,
            &mut transcript,
        )
        .map_err(|_| ProtocolError::InvalidProof)?;

        Ok(())
    }
}
#[test]
fn halo2_malleability_rejected() {
    let k = 9;
    let params: Params<G1Affine> = Params::new(k);
    let circuit = circuits::score_circuit::ScoreCircuit::<Fr> {
        score: Value::known(Fr::from(39u64)),
        threshold: Value::known(Fr::from(40u64)),
    };
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let public_inputs = vec![vec![Fr::from(40u64)]];
    let instance_slices: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();
    let all_instances: Vec<&[&[Fr]]> = vec![instance_slices.as_slice()];

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof(&params, &pk, &[circuit], &all_instances, OsRng, &mut transcript).unwrap();
    let mut proof = transcript.finalize();

    // Malleate: Flip a bit in a commitment (simulates poly eval tweak; should invalidate without transcript break)
    if proof.len() > 200 {
        proof[150] ^= 0x01; // Target potential eval point
    }

    let backend = backend(params);
    let inputs = PublicInputs { threshold: 40, old_state_root: [0u8; 32], nonce: 1 };
    assert!(backend.verify(&proof, &inputs).is_err(), "Malleated proof accepted!");
}

#[test]
fn halo2_serialization_corruption_rejected() {
    let k = 9;
    let params: Params<G1Affine> = Params::new(k);
    let proof = generate_valid_proof_with_params(39, 40, &params);

    // Corrupt: Truncate or inject invalid Borsh (Halo2 uses Blake2b, but sim as byte mess)
    let mut corrupt_proof = proof.clone();
    corrupt_proof.truncate(proof.len() - 10); // Incomplete transcript
    let backend = backend(params);
    let inputs = PublicInputs { threshold: 40, old_state_root: [0u8; 32], nonce: 1 };
    assert!(backend.verify(&corrupt_proof, &inputs).is_err(), "Corrupt serialization accepted!");
}
