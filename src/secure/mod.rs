//! HACP Secure: public wire/client surface, with key custody compiled only for guardians.
pub mod client;
pub mod workflow;
#[cfg(feature = "guardian")]
mod crypto;
pub mod envelope;
#[cfg(feature = "guardian")]
pub mod guardian;
#[cfg(feature = "guardian")]
pub mod session;
#[cfg(feature = "guardian")]
pub mod transport;

/// Fixed, non-secret failures. No error can carry key bytes, plaintext or library state.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, thiserror::Error,
)]
pub enum SecureError {
    #[error("SchemaViolation")]
    SchemaViolation,
    #[error("DowngradeDetected")]
    DowngradeDetected,
    #[error("SessionUnknown")]
    SessionUnknown,
    #[error("SessionExpired")]
    SessionExpired,
    #[error("SessionExhausted")]
    SessionExhausted,
    #[error("IdentityMismatch")]
    IdentityMismatch,
    #[error("BadHandshakeSignature")]
    BadHandshakeSignature,
    #[error("BadMessageSignature")]
    BadMessageSignature,
    #[error("ReplayRejected")]
    ReplayRejected,
    #[error("SequenceGap")]
    SequenceGap,
    #[error("HoldOverflow")]
    HoldOverflow,
    #[error("TamperDetected")]
    TamperDetected,
    #[error("ContractPending")]
    ContractPending,
    #[error("ContractMismatch")]
    ContractMismatch,
    #[error("GuardianUnavailable")]
    GuardianUnavailable,
    #[error("RateLimited")]
    RateLimited,
    #[error("UnknownOperation")]
    UnknownOperation,
}
