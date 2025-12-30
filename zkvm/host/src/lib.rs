#[cfg(feature = "zk-vm")]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

#[cfg(feature = "zk-vm")]
use methods::{ELF, ID};

use risc0_zkp::core::digest::Digest;
use serde::{Serialize, Deserialize};

/// Opaque proof envelope produced by a prover
#[derive(Serialize, Deserialize)]
pub struct ZkVmProof {
    pub method_id: Digest,
    pub journal_digest: Digest,
}

#[cfg(feature = "zk-vm")]
pub fn method_id() -> &'static Digest {
    &ID
}
