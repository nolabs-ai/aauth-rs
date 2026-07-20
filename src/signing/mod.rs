//! HTTP Message Signatures (RFC 9421) with the `Signature-Key` header
//! extension (draft-hardt-httpbis-signature-key).
//!
//! This is the low-level signing layer: it can be used standalone if you only
//! need RFC 9421 signatures with the `hwk`, `jwks_uri`, `jwt`, or `jkt-jwt`
//! key discovery schemes.

mod algorithms;
mod base;
mod input;
mod signature;
mod signer;
mod verifier;

pub use algorithms::{
    is_supported, ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, REQUIRED_ALGORITHM,
    RSA_PSS_SHA256, RSA_PSS_SHA512, SUPPORTED_ALGORITHMS,
};
pub use base::{
    build_signature_base, build_signature_params, calculate_content_digest,
    determine_covered_components,
};
pub use httpsig::{
    build_signature_key_header, parse_signature_key, parse_signature_keys, ParsedSignatureKey,
    SigScheme,
};
pub use input::{build_signature_input_header, parse_signature_input, SignatureInputParams};
pub use signature::{build_signature_header, parse_signature};
pub use signer::{sign_request, SignOptions, SignatureHeaders};
pub use verifier::{verify_signature, VerifyOptions};
