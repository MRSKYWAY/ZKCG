use common::errors::ProtocolError;

pub struct ProofInput<'a> {
    pub proof_bytes: &'a [u8],
    pub public_threshold: u64,
}

pub fn verify(
    proof: ProofInput<'_>,
) -> Result<(), ProtocolError> {
    #[cfg(feature = "zk-halo2")]
    {
        return verify_halo2(proof);
    }

    #[cfg(not(feature = "zk-halo2"))]
    {
        // Stub verifier path
        Ok(())
    }
}

#[cfg(feature = "zk-halo2")]
fn verify_halo2(
    input: ProofInput<'_>,
) -> Result<(), ProtocolError> {
    use halo2_proofs::{
        dev::MockProver,
        pasta::Fp,
        circuit::Value,
    };

    use circuits::score_circuit::ScoreCircuit;

    let threshold = Fp::from(input.public_threshold);

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
