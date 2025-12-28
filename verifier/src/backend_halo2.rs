#[cfg(feature = "zk-halo2")]
use common::errors::ProtocolError;

#[cfg(feature = "zk-halo2")]
use crate::{
    backend::ProofBackend,
    engine::PublicInputs,
};

#[cfg(feature = "zk-halo2")]
pub struct Halo2Backend;

#[cfg(feature = "zk-halo2")]
impl ProofBackend for Halo2Backend {
    fn verify(
        &self,
        _proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> Result<(), ProtocolError> {
        use halo2_proofs::{
            dev::MockProver,
            pasta::Fp,
            circuit::Value,
        };

        use circuits::score_circuit::ScoreCircuit;

        let threshold = Fp::from(public_inputs.threshold);

        let circuit = ScoreCircuit::<Fp> {
            score: Value::unknown(),
            threshold: Value::known(threshold),
        };

        let prover = MockProver::run(
            4,
            &circuit,
            vec![vec![threshold]],
        )
        .map_err(|_| ProtocolError::InvalidProof)?;

        prover.verify().map_err(|_| ProtocolError::InvalidProof)
    }
}
