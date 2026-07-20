//! Key pair types and generation.
//!
//! AAuth requires Ed25519 support; ECDSA P-256 and P-384 are also supported.

use crate::errors::{AAuthError, Result};
use p256::elliptic_curve::Generate as _;
use rand_core::UnwrapErr;

/// A private signing key (Ed25519, ECDSA P-256, or ECDSA P-384).
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

/// A public verification key (Ed25519, ECDSA P-256, or ECDSA P-384).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            PrivateKey::Ed25519(_) => "Ed25519",
            PrivateKey::P256(_) => "P-256",
            PrivateKey::P384(_) => "P-384",
        };
        write!(f, "PrivateKey({kind})")
    }
}

impl PrivateKey {
    /// The corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(sk) => PublicKey::Ed25519(sk.verifying_key()),
            PrivateKey::P256(sk) => PublicKey::P256(*sk.verifying_key()),
            PrivateKey::P384(sk) => PublicKey::P384(*sk.verifying_key()),
        }
    }

    /// Sign `message`, returning raw signature bytes.
    ///
    /// Ed25519 produces a 64-byte signature. ECDSA keys produce DER-encoded
    /// signatures. verifiers in this crate accept both DER and IEEE P1363 (`r || s`).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(sk) => ed25519_dalek::Signer::sign(sk, message).to_bytes().to_vec(),
            PrivateKey::P256(sk) => {
                let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(sk, message);
                sig.to_der().as_bytes().to_vec()
            }
            PrivateKey::P384(sk) => {
                let sig: p384::ecdsa::Signature = p384::ecdsa::signature::Signer::sign(sk, message);
                sig.to_der().as_bytes().to_vec()
            }
        }
    }

    /// Sign `message`, returning an IEEE P1363 (`r || s`) signature.
    ///
    /// This is the signature format JWS (RFC 7515) requires for ES256/ES384.
    /// For Ed25519 this is identical to [`PrivateKey::sign`].
    pub fn sign_p1363(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(sk) => ed25519_dalek::Signer::sign(sk, message).to_bytes().to_vec(),
            PrivateKey::P256(sk) => {
                let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(sk, message);
                sig.to_bytes().to_vec()
            }
            PrivateKey::P384(sk) => {
                let sig: p384::ecdsa::Signature = p384::ecdsa::signature::Signer::sign(sk, message);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// The JWS algorithm identifier for this key ("EdDSA", "ES256", "ES384").
    pub fn jws_algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Ed25519(_) => "EdDSA",
            PrivateKey::P256(_) => "ES256",
            PrivateKey::P384(_) => "ES384",
        }
    }

    /// The RFC 9421 HTTP signature algorithm identifier for this key.
    pub fn http_sig_algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Ed25519(_) => crate::signing::ED25519,
            PrivateKey::P256(_) => crate::signing::ECDSA_P256_SHA256,
            PrivateKey::P384(_) => crate::signing::ECDSA_P384_SHA384,
        }
    }
}

impl PublicKey {
    /// Verify `signature` over `message`.
    ///
    /// For ECDSA keys both DER and IEEE P1363 (raw `r || s`) signature
    /// encodings are accepted.
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<()> {
        let fail = || AAuthError::signature("signature verification failed");
        match self {
            PublicKey::Ed25519(vk) => {
                let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| fail())?;
                ed25519_dalek::Verifier::verify(vk, message, &sig).map_err(|_| fail())
            }
            PublicKey::P256(vk) => {
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| fail())?;
                p256::ecdsa::signature::Verifier::verify(vk, message, &sig).map_err(|_| fail())
            }
            PublicKey::P384(vk) => {
                let sig = p384::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p384::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| fail())?;
                p384::ecdsa::signature::Verifier::verify(vk, message, &sig).map_err(|_| fail())
            }
        }
    }
}

/// Generate a new Ed25519 key pair.
pub fn generate_ed25519_keypair() -> (PrivateKey, PublicKey) {
    let sk = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(getrandom::SysRng));
    let pk = PublicKey::Ed25519(sk.verifying_key());
    (PrivateKey::Ed25519(sk), pk)
}

/// Generate a new ECDSA P-256 key pair.
pub fn generate_p256_keypair() -> (PrivateKey, PublicKey) {
    let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut UnwrapErr(getrandom::SysRng));
    let pk = PublicKey::P256(*sk.verifying_key());
    (PrivateKey::P256(sk), pk)
}

/// Generate a new ECDSA P-384 key pair.
pub fn generate_p384_keypair() -> (PrivateKey, PublicKey) {
    let sk = p384::ecdsa::SigningKey::generate_from_rng(&mut UnwrapErr(getrandom::SysRng));
    let pk = PublicKey::P384(*sk.verifying_key());
    (PrivateKey::P384(sk), pk)
}
