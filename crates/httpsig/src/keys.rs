//! Signing keys, verification keys, and JSON Web Keys.

use crate::{Error, Result, ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::elliptic_curve::Generate as _;
use rand_core::UnwrapErr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

/// A private signing key supported by the built-in crypto provider.
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

/// A public verification key supported by the built-in crypto provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Ed25519(_) => "Ed25519",
            Self::P256(_) => "P-256",
            Self::P384(_) => "P-384",
        };
        write!(f, "PrivateKey({kind})")
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Ed25519(key) => PublicKey::Ed25519(key.verifying_key()),
            Self::P256(key) => PublicKey::P256(*key.verifying_key()),
            Self::P384(key) => PublicKey::P384(*key.verifying_key()),
        }
    }

    /// Sign bytes in the encoding used by HTTP Message Signatures.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => ed25519_dalek::Signer::sign(key, message)
                .to_bytes()
                .to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(key, message);
                signature.to_der().as_bytes().to_vec()
            }
            Self::P384(key) => {
                let signature: p384::ecdsa::Signature =
                    p384::ecdsa::signature::Signer::sign(key, message);
                signature.to_der().as_bytes().to_vec()
            }
        }
    }

    /// Sign bytes in IEEE P1363 (`r || s`) encoding for JWS.
    pub fn sign_p1363(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => ed25519_dalek::Signer::sign(key, message)
                .to_bytes()
                .to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(key, message);
                signature.to_bytes().to_vec()
            }
            Self::P384(key) => {
                let signature: p384::ecdsa::Signature =
                    p384::ecdsa::signature::Signer::sign(key, message);
                signature.to_bytes().to_vec()
            }
        }
    }

    pub fn jws_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
            Self::P384(_) => "ES384",
        }
    }

    pub fn http_sig_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519,
            Self::P256(_) => ECDSA_P256_SHA256,
            Self::P384(_) => ECDSA_P384_SHA384,
        }
    }
}

impl PublicKey {
    /// Verify Ed25519 or ECDSA signature bytes.
    ///
    /// ECDSA accepts both DER and IEEE P1363 encodings.
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<()> {
        let verified = match self {
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Error::VerificationFailed)?;
                ed25519_dalek::Verifier::verify(key, message, &signature)
            }
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| Error::VerificationFailed)?;
                p256::ecdsa::signature::Verifier::verify(key, message, &signature)
            }
            Self::P384(key) => {
                let signature = p384::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p384::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| Error::VerificationFailed)?;
                p384::ecdsa::signature::Verifier::verify(key, message, &signature)
            }
        };
        verified.map_err(|_| Error::VerificationFailed)
    }
}

pub fn generate_ed25519_keypair() -> (PrivateKey, PublicKey) {
    let key = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(getrandom::SysRng));
    let public = PublicKey::Ed25519(key.verifying_key());
    (PrivateKey::Ed25519(key), public)
}

pub fn generate_p256_keypair() -> (PrivateKey, PublicKey) {
    let key = p256::ecdsa::SigningKey::generate_from_rng(&mut UnwrapErr(getrandom::SysRng));
    let public = PublicKey::P256(*key.verifying_key());
    (PrivateKey::P256(key), public)
}

pub fn generate_p384_keypair() -> (PrivateKey, PublicKey) {
    let key = p384::ecdsa::SigningKey::generate_from_rng(&mut UnwrapErr(getrandom::SysRng));
    let public = PublicKey::P384(*key.verifying_key());
    (PrivateKey::P384(key), public)
}

/// JSON Web Key members used by Signature-Key and the supported algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    pub fn from_value(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone())
            .map_err(|error| Error::key(format!("invalid JWK: {error}")))
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("JWK serialization is infallible")
    }

    pub fn to_public_key(&self) -> Result<PublicKey> {
        jwk_to_public_key(self)
    }

    pub fn thumbprint(&self) -> Result<String> {
        calculate_jwk_thumbprint(self)
    }

    pub fn same_key_material(&self, other: &Self) -> bool {
        self.kty == other.kty
            && self.crv == other.crv
            && self.x == other.x
            && self.y == other.y
            && self.n == other.n
            && self.e == other.e
    }
}

pub fn private_key_to_jwk(private_key: &PrivateKey, kid: Option<&str>) -> Jwk {
    public_key_to_jwk(&private_key.public_key(), kid)
}

pub fn public_key_to_jwk(public_key: &PublicKey, kid: Option<&str>) -> Jwk {
    let mut jwk = match public_key {
        PublicKey::Ed25519(key) => Jwk {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            x: Some(URL_SAFE_NO_PAD.encode(key.as_bytes())),
            ..Default::default()
        },
        PublicKey::P256(key) => {
            let point = key.to_sec1_point(false);
            Jwk {
                kty: "EC".into(),
                crv: Some("P-256".into()),
                x: Some(URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point"))),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point"))),
                ..Default::default()
            }
        }
        PublicKey::P384(key) => {
            let point = key.to_sec1_point(false);
            Jwk {
                kty: "EC".into(),
                crv: Some("P-384".into()),
                x: Some(URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point"))),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point"))),
                ..Default::default()
            }
        }
    };
    jwk.kid = kid.map(str::to_owned);
    jwk
}

fn required_b64(jwk: &Jwk, field: &Option<String>, name: &str) -> Result<Vec<u8>> {
    let value = field
        .as_deref()
        .ok_or_else(|| Error::key(format!("JWK ({}) missing '{name}'", jwk.kty)))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| Error::key(format!("invalid base64url in '{name}': {error}")))
}

pub fn jwk_to_public_key(jwk: &Jwk) -> Result<PublicKey> {
    match jwk.kty.as_str() {
        "OKP" if jwk.crv.as_deref() == Some("Ed25519") => {
            let bytes: [u8; 32] = required_b64(jwk, &jwk.x, "x")?
                .try_into()
                .map_err(|_| Error::key("Ed25519 JWK 'x' must be 32 bytes"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|error| Error::key(format!("invalid Ed25519 key: {error}")))?;
            Ok(PublicKey::Ed25519(key))
        }
        "EC" => {
            let x = required_b64(jwk, &jwk.x, "x")?;
            let y = required_b64(jwk, &jwk.y, "y")?;
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            match jwk.crv.as_deref() {
                Some("P-256") => p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(PublicKey::P256)
                    .map_err(|_| Error::key("invalid P-256 public key")),
                Some("P-384") => p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(PublicKey::P384)
                    .map_err(|_| Error::key("invalid P-384 public key")),
                curve => Err(Error::key(format!("unsupported EC curve: {curve:?}"))),
            }
        }
        key_type => Err(Error::key(format!(
            "unsupported JWK kty/crv: {key_type}/{:?}",
            jwk.crv
        ))),
    }
}

fn canonical_thumbprint_json(jwk: &Jwk) -> Result<String> {
    fn required<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str> {
        value
            .as_deref()
            .ok_or_else(|| Error::key(format!("JWK missing '{name}'")))
    }
    match jwk.kty.as_str() {
        "OKP" => Ok(format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            required(&jwk.crv, "crv")?,
            required(&jwk.x, "x")?
        )),
        "EC" => Ok(format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            required(&jwk.crv, "crv")?,
            required(&jwk.x, "x")?,
            required(&jwk.y, "y")?
        )),
        "RSA" => Ok(format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            required(&jwk.e, "e")?,
            required(&jwk.n, "n")?
        )),
        key_type => Err(Error::key(format!(
            "unsupported kty for thumbprint: {key_type}"
        ))),
    }
}

pub fn calculate_jwk_thumbprint(jwk: &Jwk) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_thumbprint_json(jwk)?.as_bytes())))
}

pub fn calculate_jwk_thumbprint_sha512(jwk: &Jwk) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha512::digest(canonical_thumbprint_json(jwk)?.as_bytes())))
}

pub fn generate_jwks(keys: &[Jwk]) -> Value {
    serde_json::json!({ "keys": keys })
}
