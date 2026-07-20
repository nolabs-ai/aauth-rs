//! HTTP Message Signature algorithm identifiers.

pub const ED25519: &str = "ed25519";
pub const RSA_PSS_SHA512: &str = "rsa-pss-sha512";
pub const RSA_PSS_SHA256: &str = "rsa-pss-sha256";
pub const ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
pub const ECDSA_P384_SHA384: &str = "ecdsa-p384-sha384";

/// Algorithms recognized by the API. RSA identifiers are reserved but RSA
/// keys are not currently implemented.
pub const SUPPORTED_ALGORITHMS: [&str; 5] = [
    ED25519,
    RSA_PSS_SHA512,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
];

pub fn is_supported(algorithm: &str) -> bool {
    SUPPORTED_ALGORITHMS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(algorithm))
}
