//! Framework-independent HTTP Message Signatures ([RFC 9421]) with the
//! `Signature-Key` extension.
//!
//! This crate implements mechanism, not application trust policy:
//! parsing, signature-base construction, key representation, signing, and
//! cryptographic verification. Applications should validate schemes,
//! timestamps, and required covered components with a policy before resolving
//! external keys or treating a valid signature as an identity assertion.
//!
//! [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421

mod algorithms;
mod error;
mod fields;
pub mod keys;
mod message;

pub use algorithms::{
    is_supported, ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, RSA_PSS_SHA256, RSA_PSS_SHA512,
    SUPPORTED_ALGORITHMS,
};
pub use error::{Error, Result};
pub use fields::{
    build_signature_header, build_signature_input_header, build_signature_key_header,
    parse_signature, parse_signature_input, parse_signature_key, parse_signature_keys,
    ParsedSignatureKey, SigScheme, SignatureInput,
};
pub use keys::{
    calculate_jwk_thumbprint, calculate_jwk_thumbprint_sha512, generate_ed25519_keypair,
    generate_jwks, generate_p256_keypair, generate_p384_keypair, jwk_to_public_key,
    private_key_to_jwk, public_key_to_jwk, Jwk, PrivateKey, PublicKey,
};
pub use message::{
    build_signature_base, calculate_content_digest, prepare_verification, sign_request,
    RequestParts, SignOptions, SignatureHeaders, UnverifiedSignature,
};

pub const HEADER_SIGNATURE: &str = "Signature";
pub const HEADER_SIGNATURE_INPUT: &str = "Signature-Input";
pub const HEADER_SIGNATURE_KEY: &str = "Signature-Key";
