use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid message format")]
    InvalidFormat,

    #[error("state mismatch")]
    StateMismatch,

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("proof verification failed")]
    InvalidProof,

    #[error("policy violation")]
    PolicyViolation,

    #[error("commitment mismatch")]
    CommitmentMismatch,
}
