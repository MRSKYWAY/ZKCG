use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
    },
    poly::Rotation,
};

use halo2curves::ff::PrimeField;

const DIFF_BITS: usize = 16;

/// Enforces: score <= threshold
///
/// Constraint model:
///   threshold = score + diff
///   diff >= 0
///   diff decomposed into bits
#[derive(Clone)]
pub struct ScoreCircuit<F: PrimeField> {
    pub score: Value<F>,
    pub threshold: Value<F>,
}

#[derive(Clone, Debug)]
pub struct ScoreConfig {
    score: Column<Advice>,
    diff: Column<Advice>,
    diff_bits: [Column<Advice>; DIFF_BITS],
    threshold_advice: Column<Advice>,
    threshold: Column<Instance>,
    selector: Selector,
}

impl<F: PrimeField> Circuit<F> for ScoreCircuit<F> {
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
        let threshold = cs.instance_column();
        let selector = cs.selector();
        let threshold_advice = cs.advice_column();

        let diff_bits = [(); DIFF_BITS].map(|_| cs.advice_column());

        cs.enable_equality(threshold_advice);
        cs.enable_equality(score);
        cs.enable_equality(diff);
        cs.enable_equality(threshold);

        for bit in diff_bits.iter() {
            cs.enable_equality(*bit);

            // bit ∈ {0,1}
            cs.create_gate("bit is boolean", |meta| {
                let b = meta.query_advice(*bit, Rotation::cur());
                vec![b.clone() * (Expression::Constant(F::ONE) - b)]
            });
        }

        // threshold = score + diff
        cs.create_gate("threshold = score + diff", |meta| {
            let s = meta.query_selector(selector);
            let score = meta.query_advice(score, Rotation::cur());
            let diff = meta.query_advice(diff, Rotation::cur());
            let threshold = meta.query_instance(threshold, Rotation::cur());

            vec![s * (threshold - score - diff)]
        });

        // diff == sum(bits * 2^i)
        cs.create_gate("diff reconstruction", |meta| {
            let s = meta.query_selector(selector);
            let diff = meta.query_advice(diff, Rotation::cur());

            let reconstructed = diff_bits.iter().enumerate().fold(
                Expression::Constant(F::ZERO),
                |acc, (i, bit)| {
                    acc
                        + meta.query_advice(*bit, Rotation::cur())
                            * Expression::Constant(F::from_u128(1u128 << i))
                },
            );

            vec![s * (diff - reconstructed)]
        });

        ScoreConfig {
            score,
            diff,
            diff_bits,
            threshold_advice,
            threshold,
            selector,
        }
    }

    fn synthesize(
    &self,
    config: Self::Config,
    mut layouter: impl Layouter<F>,
) -> Result<(), Error> {
    let threshold_cell = layouter.assign_region(
        || "score <= threshold",
        |mut region| {
            config.selector.enable(&mut region, 0)?;

            region.assign_advice(
                || "score",
                config.score,
                0,
                || self.score,
            )?;

            let diff_value = self
                .threshold
                .zip(self.score)
                .map(|(t, s)| t - s);

            region.assign_advice(
                || "diff",
                config.diff,
                0,
                || diff_value,
            )?;

            // Assign diff bits
            for i in 0..DIFF_BITS {
                let bit = diff_value.map(|diff| {
                    let mut bytes = diff.to_repr();
                    let mut acc = 0u64;

                    for (j, b) in bytes.as_ref().iter().take(8).enumerate() {
                        acc |= (*b as u64) << (8 * j);
                    }

                    (acc >> i) & 1
                });

                region.assign_advice(
                    || format!("diff bit {}", i),
                    config.diff_bits[i],
                    0,
                    || bit.map(F::from),
                )?;
            }

            // ✅ assign threshold into advice
            let threshold_cell = region.assign_advice(
                || "threshold advice",
                config.threshold_advice,
                0,
                || self.threshold,
            )?;

            Ok(threshold_cell)
        },
    )?;

    // ✅ constrain advice cell to instance column
    layouter.constrain_instance(
        threshold_cell.cell(),
        config.threshold,
        0,
    )?;

    Ok(())
}


}
