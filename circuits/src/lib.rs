pub mod score_circuit;

pub mod score_circuit;

use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::{Bn256, G1Affine};

#[derive(Clone)]
pub struct Halo2Artifacts {
    pub params: ParamsKZG<Bn256>,
    pub vk: VerifyingKey<G1Affine>,
}

#[cfg(test)]
mod tests;