#![cfg(feature = "zk-halo2")]

use common::errors::ProtocolError;
use crate::{
    backend::ProofBackend,
    engine::PublicInputs,
};

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255},
};

use halo2curves::bn256::{Bn256, Fr, G1Affine};
use circuits::score_circuit::ScoreCircuit;

/// Real Halo2 verifier using KZG + SHPLONK
pub struct Halo2Backend {
    /// Verifying key must be pre-generated and stored
    pub vk: VerifyingKey<G1Affine>,
    /// KZG parameters (same `k` as prover)
    pub params: ParamsKZG<Bn256>,
}

impl ProofBackend for Halo2Backend {
    fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> Result<(), ProtocolError> {
        // --- 1️⃣ Reconstruct public inputs ---
        // Must EXACTLY match circuit instance layout
        let threshold = Fr::from(public_inputs.threshold as u64);
        let instances = vec![vec![threshold]];

        // --- 2️⃣ Prepare transcript ---
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof_bytes);

        // --- 3️⃣ Verification strategy ---
        let strategy = SingleStrategy::new(&self.params);

        // --- 4️⃣ Verify proof ---
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<Bn256>,
            _,
            _,
        >(
            &self.params,
            &self.vk,
            strategy,
            &[&instances],
            &mut transcript,
        )
        .map_err(|_| ProtocolError::InvalidProof)?;

        Ok(())
    }
}
