#![cfg(feature = "zk-vm")]

use common::errors::ProtocolError;
use crate::{backend::ProofBackend, engine::PublicInputs};

use risc0_zkvm::Receipt;
use serde::Deserialize;

use zkcg_zkvm_host::method_id;



#[derive(Deserialize)]
struct ZkVmOutput {
    ok: bool,
}

pub struct ZkVmBackend;

impl ProofBackend for ZkVmBackend {
    fn verify(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &PublicInputs,
    ) -> Result<(), ProtocolError> {
        let receipt: Receipt =
            bincode::deserialize(proof_bytes)
                .map_err(|_| ProtocolError::InvalidProof)?;

        receipt.verify(method_id())
            .map_err(|_| ProtocolError::InvalidProof)?;

        let output: ZkVmOutput =
            receipt.journal.decode()
                .map_err(|_| ProtocolError::InvalidProof)?;

        if !output.ok {
            return Err(ProtocolError::InvalidProof);
        }

        Ok(())
    }
}
