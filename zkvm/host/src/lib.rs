#[cfg(feature = "zk-vm")]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

use risc0_zkp::core::digest::Digest;
use serde::{Serialize, Deserialize};

/// Opaque proof envelope produced by the prover
#[derive(Serialize, Deserialize)]
pub struct ZkVmProof {
    pub method_id: Digest,
    pub journal_digest: Digest,
}

#[cfg(feature = "zk-vm")]
pub fn method_id() -> Digest {
    Digest::from(methods::ZKCG_ZKVM_GUEST_ID)
}

#[cfg(feature = "zk-vm")]
pub fn elf() -> &'static [u8] {
    methods::ZKCG_ZKVM_GUEST_ELF
}
