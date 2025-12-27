use common::errors::ProtocolError;
use crate::engine::PublicInputs;

pub fn verify(
    _proof: &[u8],
    _public_inputs: &PublicInputs,
) -> Result<(), ProtocolError> {
    // Phase 1 stub
    // Phase 2: Halo2
    // Phase 3: zkVM backend

    Ok(())
}
