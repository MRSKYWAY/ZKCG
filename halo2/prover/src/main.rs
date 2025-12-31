use rand::rngs::OsRng;

use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk,
    },
    poly::{
        kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::ProverSHPLONK,
            strategy::SingleStrategy,
            ParamsKZG,
        },
    },
    transcript::{
        Blake2bWrite, Challenge255,
    },
};

use halo2curves::bn256::Bn256;

use circuits::score_circuit::ScoreCircuit;
use common::types::ZkVmInput;

mod proof;
use proof::Halo2Proof;

fn main() {
    // ---- real inputs (replace with CLI / API later)
    let score: u64 = 42;
    let threshold: u64 = 40;

    // ---- build the circuit
    let circuit = ScoreCircuit {
        score,
        threshold,
    };

    // ---- circuit parameters
    // must match what verifier will use
    let k: u32 = 9;

    let params = ParamsKZG::<Bn256>::new(k);

    // ---- key generation
    let vk = keygen_vk(&params, &circuit)
        .expect("vk generation failed");

    let pk = keygen_pk(&params, vk, &circuit)
        .expect("pk generation failed");

    // ---- public inputs
    // IMPORTANT: only public columns go here
    let public_inputs = vec![vec![threshold]];

    // ---- proof creation
    let mut proof_bytes = Vec::new();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(&mut proof_bytes);

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<_>,
        _,
        _,
        _,
        _,
    >(
        &params,
        &pk,
        &[circuit],
        &[&public_inputs],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation failed");

    let proof = Halo2Proof { proof_bytes };

    let encoded = bincode::serialize(&proof)
        .expect("proof serialization failed");

    println!("Halo2 proof generated ({} bytes)", encoded.len());
}
