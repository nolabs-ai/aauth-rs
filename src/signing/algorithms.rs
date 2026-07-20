//! Signature algorithm identifiers used by the AAuth profile.
//!
//! Implementations MUST support ed25519 and MAY support others. This crate
//! implements ed25519, ecdsa-p256-sha256, and ecdsa-p384-sha384; the RSA-PSS
//! identifiers are declared for completeness but RSA keys are not supported.

pub use httpsig::{
    is_supported, ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, RSA_PSS_SHA256, RSA_PSS_SHA512,
    SUPPORTED_ALGORITHMS,
};

/// The algorithm every implementation MUST support.
pub const REQUIRED_ALGORITHM: &str = ED25519;
