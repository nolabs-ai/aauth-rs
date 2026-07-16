//! Minimal JWS (JWT) encode/decode supporting the algorithms AAuth uses:
//! EdDSA (Ed25519), ES256 (P-256), and ES384 (P-384).

use crate::errors::{AAuthError, Result};
use crate::keys::{jwk_to_public_key, Jwk, PrivateKey, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

/// A parsed (but not necessarily verified) JWT.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    /// `base64url(header) + "." + base64url(payload)` — the signed bytes.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl DecodedJwt {
    /// Header `typ` value.
    pub fn typ(&self) -> Option<&str> {
        self.header.get("typ").and_then(Value::as_str)
    }

    /// Header `alg` value.
    pub fn alg(&self) -> Option<&str> {
        self.header.get("alg").and_then(Value::as_str)
    }

    /// Header `kid` value.
    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    /// Payload claim as `&str`.
    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(Value::as_str)
    }

    /// Payload claim as `i64`.
    pub fn claim_i64(&self, name: &str) -> Option<i64> {
        self.payload.get(name).and_then(Value::as_i64)
    }

    /// The `cnf.jwk` confirmation key, if present.
    pub fn cnf_jwk(&self) -> Option<Jwk> {
        let jwk = self.payload.get("cnf")?.get("jwk")?;
        Jwk::from_value(jwk).ok()
    }

    /// Verify the JWS signature with `public_key`, checking that the header
    /// `alg` is consistent with the key type. Does NOT check exp/aud/etc.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<()> {
        let alg = self
            .alg()
            .ok_or_else(|| AAuthError::signature("JWT header missing 'alg'"))?;
        let compatible = matches!(
            (alg, public_key),
            ("EdDSA", PublicKey::Ed25519(_))
                | ("ES256", PublicKey::P256(_))
                | ("ES384", PublicKey::P384(_))
        );
        if !compatible {
            return Err(AAuthError::signature(format!(
                "JWT alg {alg} does not match key type"
            )));
        }
        public_key
            .verify(&self.signature, self.signing_input.as_bytes())
            .map_err(|_| AAuthError::signature("JWT signature verification failed"))
    }
}

/// Decode a JWT without verifying it (for inspection).
pub fn decode_unverified(token: &str) -> Result<DecodedJwt> {
    let mut parts = token.split('.');
    let (header_b64, payload_b64, signature_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => {
                return Err(AAuthError::signature(
                    "Invalid JWT: expected three dot-separated segments",
                ))
            }
        };

    let decode_json = |segment: &str, what: &str| -> Result<Value> {
        let bytes = URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|e| AAuthError::signature(format!("Invalid JWT {what} encoding: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AAuthError::signature(format!("Invalid JWT {what} JSON: {e}")))
    };

    let header = decode_json(header_b64, "header")?;
    let payload = decode_json(payload_b64, "payload")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| AAuthError::signature(format!("Invalid JWT signature encoding: {e}")))?;

    Ok(DecodedJwt {
        header,
        payload,
        signing_input: format!("{header_b64}.{payload_b64}"),
        signature,
    })
}

/// Encode and sign a JWT. The header must contain `alg` matching the key type
/// (use [`encode_with_key`] to have it filled in automatically).
pub fn encode(header: &Value, payload: &Value, private_key: &PrivateKey) -> Result<String> {
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| AAuthError::signature("JWT header missing 'alg'"))?;
    if alg != private_key.jws_algorithm() {
        return Err(AAuthError::signature(format!(
            "JWT header alg {alg} does not match key algorithm {}",
            private_key.jws_algorithm()
        )));
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    // JWS requires IEEE P1363 (r || s) signatures for ES256/ES384.
    let signature = private_key.sign_p1363(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Encode and sign a JWT, filling in the `alg` header from the key type.
pub fn encode_with_key(
    typ: &str,
    kid: Option<&str>,
    payload: &Value,
    private_key: &PrivateKey,
) -> Result<String> {
    let mut header = serde_json::json!({
        "typ": typ,
        "alg": private_key.jws_algorithm(),
    });
    if let Some(kid) = kid {
        header["kid"] = Value::String(kid.to_string());
    }
    encode(&header, payload, private_key)
}

/// Find the signing key in a JWKS by kid and verify the JWT's signature
/// against it. Returns the resolved [`PublicKey`] on success.
pub fn verify_with_jwks(jwt: &DecodedJwt, jwks: &Value) -> Result<PublicKey> {
    let kid = jwt
        .kid()
        .ok_or_else(|| AAuthError::signature("JWT header missing 'kid'"))?;
    let signing_key = crate::keys::get_key_by_kid(jwks, kid).ok_or_else(|| {
        AAuthError::signature(format!("Signing key with kid={kid} not found in JWKS"))
    })?;
    let jwk = Jwk::from_value(signing_key)?;
    let public_key = jwk_to_public_key(&jwk)?;
    jwt.verify_signature(&public_key)?;
    Ok(public_key)
}
