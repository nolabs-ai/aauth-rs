//! JWK (JSON Web Key) operations.

use crate::errors::{AAuthError, Result};
use crate::keys::{PrivateKey, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::elliptic_curve::sec1::FromEncodedPoint as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

/// A JSON Web Key (RFC 7517), covering the members AAuth uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// RSA modulus (thumbprint support only; RSA keys cannot sign/verify here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (thumbprint support only).
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
    /// Parse a JWK from a JSON value.
    pub fn from_value(value: &Value) -> Result<Jwk> {
        serde_json::from_value(value.clone())
            .map_err(|e| AAuthError::signature(format!("Invalid JWK: {e}")))
    }

    /// Serialize to a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("Jwk serialization is infallible")
    }

    /// Convert to a [`PublicKey`]. Fails for unsupported key types.
    pub fn to_public_key(&self) -> Result<PublicKey> {
        jwk_to_public_key(self)
    }

    /// RFC 7638 SHA-256 thumbprint (base64url, no padding).
    pub fn thumbprint(&self) -> Result<String> {
        calculate_jwk_thumbprint(self)
    }

    /// True if the key material (kty/crv/x/y/n/e) matches `other`,
    /// ignoring kid, alg, and use.
    pub fn same_key_material(&self, other: &Jwk) -> bool {
        self.kty == other.kty
            && self.crv == other.crv
            && self.x == other.x
            && self.y == other.y
            && self.n == other.n
            && self.e == other.e
    }
}

/// Convert a private key to JWK format (public part).
pub fn private_key_to_jwk(private_key: &PrivateKey, kid: Option<&str>) -> Jwk {
    public_key_to_jwk(&private_key.public_key(), kid)
}

/// Convert a public key to JWK format (Ed25519 or EC P-256/P-384).
pub fn public_key_to_jwk(public_key: &PublicKey, kid: Option<&str>) -> Jwk {
    let mut jwk = match public_key {
        PublicKey::Ed25519(vk) => Jwk {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            x: Some(URL_SAFE_NO_PAD.encode(vk.as_bytes())),
            ..Default::default()
        },
        PublicKey::P256(vk) => {
            let point = vk.to_encoded_point(false);
            Jwk {
                kty: "EC".into(),
                crv: Some("P-256".into()),
                x: Some(URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point"))),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point"))),
                ..Default::default()
            }
        }
        PublicKey::P384(vk) => {
            let point = vk.to_encoded_point(false);
            Jwk {
                kty: "EC".into(),
                crv: Some("P-384".into()),
                x: Some(URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point"))),
                y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point"))),
                ..Default::default()
            }
        }
    };
    if let Some(kid) = kid {
        jwk.kid = Some(kid.to_string());
    }
    jwk
}

fn b64_field(jwk: &Jwk, field: &Option<String>, name: &str) -> Result<Vec<u8>> {
    let value = field.as_deref().ok_or_else(|| {
        AAuthError::signature(format!("JWK ({}) missing '{name}' member", jwk.kty))
    })?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| AAuthError::signature(format!("Invalid base64url in JWK '{name}': {e}")))
}

/// Convert a JWK to a [`PublicKey`] (Ed25519 or EC P-256/P-384).
pub fn jwk_to_public_key(jwk: &Jwk) -> Result<PublicKey> {
    match jwk.kty.as_str() {
        "OKP" => {
            if jwk.crv.as_deref() != Some("Ed25519") {
                return Err(AAuthError::signature(format!(
                    "Unsupported OKP curve: {:?}",
                    jwk.crv
                )));
            }
            let x = b64_field(jwk, &jwk.x, "x")?;
            let bytes: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| AAuthError::signature("Ed25519 JWK 'x' must be 32 bytes"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|e| AAuthError::signature(format!("Invalid Ed25519 public key: {e}")))?;
            Ok(PublicKey::Ed25519(vk))
        }
        "EC" => {
            let x = b64_field(jwk, &jwk.x, "x")?;
            let y = b64_field(jwk, &jwk.y, "y")?;
            match jwk.crv.as_deref() {
                Some("P-256") => {
                    let point = p256::EncodedPoint::from_affine_coordinates(
                        x.as_slice().into(),
                        y.as_slice().into(),
                        false,
                    );
                    let pk_opt = p256::PublicKey::from_encoded_point(&point);
                    let pk = Option::<p256::PublicKey>::from(pk_opt)
                        .ok_or_else(|| AAuthError::signature("Invalid P-256 public key"))?;
                    Ok(PublicKey::P256(p256::ecdsa::VerifyingKey::from(pk)))
                }
                Some("P-384") => {
                    let point = p384::EncodedPoint::from_affine_coordinates(
                        x.as_slice().into(),
                        y.as_slice().into(),
                        false,
                    );
                    let pk_opt = p384::PublicKey::from_encoded_point(&point);
                    let pk = Option::<p384::PublicKey>::from(pk_opt)
                        .ok_or_else(|| AAuthError::signature("Invalid P-384 public key"))?;
                    Ok(PublicKey::P384(p384::ecdsa::VerifyingKey::from(pk)))
                }
                other => Err(AAuthError::signature(format!(
                    "Unsupported EC curve: {other:?}"
                ))),
            }
        }
        other => Err(AAuthError::signature(format!(
            "Unsupported JWK kty: {other:?}"
        ))),
    }
}

/// The RFC 7638 §3.2 canonical JSON for a JWK: only the required members,
/// lexicographically sorted, no whitespace.
fn canonical_thumbprint_json(jwk: &Jwk) -> Result<String> {
    let missing =
        |name: &str| AAuthError::signature(format!("JWK missing '{name}' member for thumbprint"));
    match jwk.kty.as_str() {
        "OKP" => {
            let crv = jwk.crv.as_deref().ok_or_else(|| missing("crv"))?;
            let x = jwk.x.as_deref().ok_or_else(|| missing("x"))?;
            Ok(format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#))
        }
        "EC" => {
            let crv = jwk.crv.as_deref().ok_or_else(|| missing("crv"))?;
            let x = jwk.x.as_deref().ok_or_else(|| missing("x"))?;
            let y = jwk.y.as_deref().ok_or_else(|| missing("y"))?;
            Ok(format!(
                r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#
            ))
        }
        "RSA" => {
            let e = jwk.e.as_deref().ok_or_else(|| missing("e"))?;
            let n = jwk.n.as_deref().ok_or_else(|| missing("n"))?;
            Ok(format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#))
        }
        other => Err(AAuthError::signature(format!(
            "Unsupported kty for thumbprint: {other:?}"
        ))),
    }
}

/// Calculate the JWK Thumbprint per RFC 7638 (SHA-256, base64url, no padding).
pub fn calculate_jwk_thumbprint(jwk: &Jwk) -> Result<String> {
    let canonical = canonical_thumbprint_json(jwk)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Calculate the JWK Thumbprint per RFC 7638 using SHA-512 (for `jkt-s512+jwt`).
pub fn calculate_jwk_thumbprint_sha512(jwk: &Jwk) -> Result<String> {
    let canonical = canonical_thumbprint_json(jwk)?;
    let digest = Sha512::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Generate a JWKS document from a list of JWKs.
pub fn generate_jwks(keys: &[Jwk]) -> Value {
    serde_json::json!({ "keys": keys })
}
