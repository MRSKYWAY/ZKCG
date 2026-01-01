#![cfg(feature = "zk-vm")]

use common::errors::ProtocolError;
use crate::{backend::ProofBackend, engine::PublicInputs};

use risc0_zkp::core::digest::Digest;
use serde::Deserialize;
use risc0_zkvm::sha::Impl;
use risc0_zkvm::sha::Digestible;
use serde::Serialize;
use zkcg_zkvm_host::method_id;
use sha2::{Sha256, Digest as Sha2Digest};
use bincode;

#[derive(Deserialize, Debug)]
struct ZkVmProof {
    method_id: Digest,
    journal_digest: Digest,
}

#[derive(serde::Serialize)]
struct ZkVmOutput {
    pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ZkVmJournal {
    pub threshold: u64,
    pub old_state_root: [u8; 32],
    pub nonce: u64,
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
        println!("Verifying zkVM proof: {:?}", proof);
        // 2️⃣ Verify method identity
        if proof.method_id != method_id() {
            return Err(ProtocolError::InvalidProof);
        }
        // 3️⃣ Recompute expected journal digest
        // ⚠️ Order MUST match guest exactly
        let threshold_bytes = bincode::serialize(&public_inputs.threshold).map_err(|_| ProtocolError::InvalidProof)?;
        let threshold_hash = Sha256::digest(&threshold_bytes);
        let threshold_d_bytes = threshold_hash.as_slice();
        let threshold_d = Digest::try_from(threshold_d_bytes).map_err(|_| ProtocolError::InvalidProof)?;

        let root_bytes = public_inputs.old_state_root.as_ref(); // Already bytes
        let root_hash = Sha256::digest(root_bytes);
        let root_d_bytes = root_hash.as_slice();
        let root_d = Digest::try_from(root_d_bytes).map_err(|_| ProtocolError::InvalidProof)?;

        let nonce_bytes = bincode::serialize(&public_inputs.nonce).map_err(|_| ProtocolError::InvalidProof)?;
        let nonce_hash = Sha256::digest(&nonce_bytes);
        let nonce_d_bytes = nonce_hash.as_slice();
        let nonce_d = Digest::try_from(nonce_d_bytes).map_err(|_| ProtocolError::InvalidProof)?;

        let ok_bytes = bincode::serialize(&true).map_err(|_| ProtocolError::InvalidProof)?;
        let ok_hash = Sha256::digest(&ok_bytes);
        let ok_d_bytes = ok_hash.as_slice();
        let ok_d = Digest::try_from(ok_d_bytes).map_err(|_| ProtocolError::InvalidProof)?;

        // Concat individual digests (128 bytes: 4 x [u8;32])
        let mut journal_digests_bytes = [0u8; 128];
        journal_digests_bytes[0..32].copy_from_slice(threshold_d.as_bytes());
        journal_digests_bytes[32..64].copy_from_slice(root_d.as_bytes());
        journal_digests_bytes[64..96].copy_from_slice(nonce_d.as_bytes());
        journal_digests_bytes[96..128].copy_from_slice(ok_d.as_bytes());

        // Final journal digest: SHA256 of concat (flat for small journal; scalable to tree)
        let expected_hash = Sha256::digest(&journal_digests_bytes);
        let expected_bytes = expected_hash.as_slice();
        let expected = Digest::try_from(expected_bytes).map_err(|_| ProtocolError::InvalidProof)?;
        println!("Expected journal digest: {:?}", expected);
        println!("Proof journal digest:    {:?}", proof.journal_digest);

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
