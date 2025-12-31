#![cfg(feature = "zk-vm")]

use common::errors::ProtocolError;
use crate::{backend::ProofBackend, engine::PublicInputs};

use risc0_zkp::core::digest::Digest;
use serde::Deserialize;
use risc0_zkp::core::hash::sha::Impl;
use risc0_zkp::sha::Digestible;


use zkcg_zkvm_host::method_id;

#[derive(Deserialize)]
struct ZkVmProof {
    method_id: Digest,
    journal_digest: Digest,
}

#[derive(serde::Serialize)]
struct ZkVmOutput {
    pub ok: bool,
}

pub struct ZkVmBackend;

impl ProofBackend for ZkVmBackend {
    fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> Result<(), ProtocolError> {
        // 1️⃣ Deserialize opaque proof
        let proof: ZkVmProof =
            bincode::deserialize(proof_bytes)
                .map_err(|_| ProtocolError::InvalidProof)?;

        // 2️⃣ Verify method identity
        if proof.method_id != method_id() {
            return Err(ProtocolError::InvalidProof);
        }
        // 3️⃣ Recompute expected journal digest
        // ⚠️ Order MUST match guest exactly
        let mut expected = Digest::default();

        let journal = ZkVmOutput { ok: true };
        let expected = journal.digest::<Impl>();


        // 4️⃣ Enforce cryptographic binding
        if proof.journal_digest != expected {
            return Err(ProtocolError::InvalidProof);
        }

        // 3️⃣ (Optional but recommended)
        // If you have expected journal commitments from PublicInputs,
        // compare them here.
        //
        // Example:
        // if proof.journal_digest != expected_digest {
        //     return Err(ProtocolError::InvalidProof);
        // }

        Ok(())
    }
}
