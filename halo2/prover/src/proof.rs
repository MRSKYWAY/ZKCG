use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Halo2Proof {
    pub proof_bytes: Vec<u8>,
}
