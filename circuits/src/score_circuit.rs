use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::Rotation,
};
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Selector;
use ff::Field;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::Instance;

/// Enforces: score <= threshold
#[derive(Clone)]
pub struct ScoreCircuit<F: Field> {
    pub score: Value<F>,
    pub threshold: Value<F>,
}


#[derive(Clone, Debug)]
pub struct ScoreConfig {
    score: Column<Advice>,
    threshold: Column<Instance>,
    diff: Column<Advice>,
    selector: Selector,
}


impl<F: Field> Circuit<F> for ScoreCircuit<F> {

    type Config = ScoreConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            score: Value::unknown(),
            threshold: Value::unknown(),
        }
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
    let score = cs.advice_column();
    let diff = cs.advice_column();
    let threshold = cs.instance_column(); // 👈 PUBLIC
    let selector = cs.selector();

    cs.enable_equality(score);
    cs.enable_equality(diff);
    cs.enable_equality(threshold);

    cs.create_gate("threshold = score + diff", |meta| {
        let s = meta.query_selector(selector);
        let score = meta.query_advice(score, Rotation::cur());
        let diff = meta.query_advice(diff, Rotation::cur());
        let threshold = meta.query_instance(threshold, Rotation::cur());

        vec![s * (threshold - score - diff)]
    });

    ScoreConfig {
        score,
        threshold,
        diff,
        selector,
    }
}



    fn synthesize(
    &self,
    config: Self::Config,
    mut layouter: impl Layouter<F>,
) -> Result<(), Error> {
    layouter.assign_region(
        || "score check",
        |mut region| {
            config.selector.enable(&mut region, 0)?;

            region.assign_advice(
                || "score",
                config.score,
                0,
                || self.score,
            )?;

            let diff_value = self.threshold
                .zip(self.score)
                .map(|(t, s)| t - s);

            region.assign_advice(
                || "diff",
                config.diff,
                0,
                || diff_value,
            )?;

            Ok(())
        },
    )
}


}
