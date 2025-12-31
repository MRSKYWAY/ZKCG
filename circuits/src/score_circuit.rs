use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use ff::PrimeField;

const DIFF_BITS: usize = 16;

/// Enforces: score <= threshold (sound)
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

        let diff_bits = [(); DIFF_BITS].map(|_| cs.advice_column());

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
                    acc + meta.query_advice(*bit, Rotation::cur())
                        * Expression::Constant(F::from(1u64 << i))
                },
            );

            vec![s * (diff - reconstructed)]
        });

        ScoreConfig {
            score,
            diff,
            diff_bits,
            threshold,
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

                // Assign diff bits
                for i in 0..DIFF_BITS {
                    let bit = diff_value.map(|diff| {
                        let diff_u64 = diff.to_repr()
                            .as_ref()
                            .iter()
                            .take(8)
                            .enumerate()
                            .fold(0u64, |acc, (j, b)| acc | ((*b as u64) << (8 * j)));
                        (diff_u64 >> i) & 1
                    });
                    region.assign_advice(
                        || format!("diff bit {}", i),
                        config.diff_bits[i],
                        0,
                        || bit.map(F::from),
                    )?;
                }

                Ok(())
            },
        )
    }
}

use halo2_proofs::{
    plonk::keygen_vk,
    poly::kzg::ParamsKZG,
};
use halo2curves::bn256::Bn256;
use rand::thread_rng;

use crate::Halo2Artifacts;

impl<F: PrimeField> ScoreCircuit<F> {
    pub fn verifier_artifacts() -> Halo2Artifacts {
        let k = 10;
        let params = ParamsKZG::<Bn256>::setup(k, thread_rng());

        let empty = ScoreCircuit {
            score: Value::unknown(),
            threshold: Value::unknown(),
        };

        let vk = keygen_vk(&params, &empty)
            .expect("failed to generate verifying key");

        Halo2Artifacts { params, vk }
    }
}

