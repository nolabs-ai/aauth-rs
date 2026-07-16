//! Signature algorithm identifiers per AAuth spec Section 10.2.
//!
//! Implementations MUST support ed25519 and MAY support others. This crate
//! implements ed25519, ecdsa-p256-sha256, and ecdsa-p384-sha384; the RSA-PSS
//! identifiers are declared for completeness but RSA keys are not supported.

pub const ED25519: &str = "ed25519";
pub const RSA_PSS_SHA512: &str = "rsa-pss-sha512";
pub const RSA_PSS_SHA256: &str = "rsa-pss-sha256";
pub const ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
pub const ECDSA_P384_SHA384: &str = "ecdsa-p384-sha384";

/// The algorithm every implementation MUST support.
pub const REQUIRED_ALGORITHM: &str = ED25519;

/// All algorithm identifiers recognized by the spec.
pub const SUPPORTED_ALGORITHMS: [&str; 5] = [
    ED25519,
    RSA_PSS_SHA512,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
];

/// Check whether an algorithm identifier is recognized (case-insensitive).
pub fn is_supported(algorithm: &str) -> bool {
    SUPPORTED_ALGORITHMS
        .iter()
        .any(|a| a.eq_ignore_ascii_case(algorithm))
}
