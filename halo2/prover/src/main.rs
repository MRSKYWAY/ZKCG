use rand::rngs::OsRng;

use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};

use halo2curves::bn256::{Fr, G1Affine};

use circuits::score_circuit::ScoreCircuit;

mod proof;
use proof::Halo2Proof;

fn main() {
    // ---- real inputs
    let score: u64 = 42;
    let threshold: u64 = 40;

    // ---- circuit with witnesses
    let circuit = ScoreCircuit::<Fr> {
        score: Value::known(Fr::from(score)),
        threshold: Value::known(Fr::from(threshold)),
    };

    // ---- security parameter
    let k: u32 = 9;

    // ---- KZG params (commitment curve = G1Affine)
    let params: Params<G1Affine> = Params::new(k);

    // ---- key generation
    let vk = keygen_vk(&params, &circuit)
        .expect("vk generation failed");

    let pk = keygen_pk(&params, vk, &circuit)
        .expect("pk generation failed");

    // ---- public inputs (instance column)
    let public_inputs: Vec<Vec<Fr>> = vec![vec![Fr::from(threshold)]];
    let instance_slices: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();
    let all_instances: Vec<&[&[Fr]]> = vec![instance_slices.as_slice()];


    // ---- proof creation
    let mut proof_bytes = Vec::new();
    let mut transcript =
        Blake2bWrite::<_, G1Affine, Challenge255<G1Affine>>::init(&mut proof_bytes);

    create_proof(
    &params,
    &pk,
    &[circuit],
    &all_instances,
    OsRng,
    &mut transcript,
    )
    .expect("proof generation failed");

    let proof = Halo2Proof { proof_bytes };

    let encoded =
        bincode::serialize(&proof).expect("proof serialization failed");

    println!("Halo2 proof generated ({} bytes)", encoded.len());
}
