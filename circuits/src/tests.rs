/*
These tests were designed for MockProver 
Do Not Run These Tests
*/

use halo2_proofs::{
    dev::MockProver,
    pasta::Fp,
};

use crate::score_circuit::ScoreCircuit;

#[test]
fn score_below_threshold_passes() {
    let threshold = Fp::from(10);

    let circuit = ScoreCircuit::<Fp> {
        score: halo2_proofs::circuit::Value::known(Fp::from(5)),
        threshold: halo2_proofs::circuit::Value::known(threshold),
    };

    let prover = MockProver::run(
        4,
        &circuit,
        vec![vec![threshold]], // 👈 PUBLIC INPUT
    )
    .unwrap();

    prover.assert_satisfied();
}

#[test]
fn score_above_threshold_is_satisfiable_without_score_binding() {
    let threshold = Fp::from(10);

    let circuit = ScoreCircuit::<Fp> {
        score: halo2_proofs::circuit::Value::known(Fp::from(15)),
        threshold: halo2_proofs::circuit::Value::known(threshold),
    };

    let prover = MockProver::run(
        4,
        &circuit,
        vec![vec![threshold]],
    )
    .unwrap();

    prover.assert_satisfied();

}
