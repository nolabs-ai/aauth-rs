//! HTTP signature verification per RFC 9421 and
//! draft-hardt-httpbis-signature-key.

use crate::errors::{AAuthError, Result};
use crate::jwt::{decode_unverified, DecodedJwt};
use crate::keys::{
    calculate_jwk_thumbprint, calculate_jwk_thumbprint_sha512, jwk_to_public_key, Jwk,
    JwksResolver, PublicKey,
};
use crate::signing::base::build_signature_base;
use crate::signing::input::parse_signature_input;
use crate::signing::key::parse_signature_key;
use crate::signing::signature::parse_signature;
use crate::util::now_unix;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

/// Options for [`verify_signature`].
pub struct VerifyOptions<'a> {
    /// Known public key (used for the `hwk` scheme instead of the inline JWK).
    pub public_key: Option<&'a PublicKey>,
    /// JWKS resolver for the `jwks_uri` and `jwt` schemes.
    pub jwks_resolver: Option<&'a dyn JwksResolver>,
    /// Max allowed distance of the `created` parameter from now, in seconds
    /// (per AAuth spec — default 60).
    pub created_window: i64,
    /// Override "now" (Unix seconds). Mainly for tests.
    pub now: Option<i64>,
}

impl Default for VerifyOptions<'_> {
    fn default() -> Self {
        VerifyOptions {
            public_key: None,
            jwks_resolver: None,
            created_window: 60,
            now: None,
        }
    }
}

/// Verify an HTTP message signature (RFC 9421).
///
/// Returns `Ok(true)` when the signature is valid, `Ok(false)` when it is
/// well-formed but does not verify (bad signature, stale `created`, label
/// mismatch, unresolvable key), and `Err` when the headers are malformed or
/// the scheme's requirements aren't met
#[allow(clippy::too_many_arguments)]
pub fn verify_signature(
    method: &str,
    target_uri: &str,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    signature_input_header: &str,
    signature_header: &str,
    signature_key_header: &str,
    options: &VerifyOptions<'_>,
) -> Result<bool> {
    let now = options.now.unwrap_or_else(now_unix);

    // Parse Signature-Input
    let input = parse_signature_input(signature_input_header)?;

    // Verify created timestamp. Per spec §12.7.4 step 3 the `created`
    // parameter is REQUIRED and is the primary replay defense for this
    // profile (no nonce) — an absent `created` is a verification failure,
    // not a skip.
    match input.created() {
        Some(created) => {
            if (now - created).abs() > options.created_window {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }

    // Parse Signature-Key
    let parsed_key = parse_signature_key(signature_key_header)?;

    // Verify label consistency across all three headers (SIG-KEY §3.1)
    let sig_label = signature_header
        .split_once('=')
        .map(|(label, _)| label.trim());
    match sig_label {
        Some(sig_label) if sig_label == input.label && sig_label == parsed_key.label => {}
        _ => return Ok(false),
    }

    // --- Resolve the public key based on scheme ---

    let public_key: PublicKey = match parsed_key.scheme.as_str() {
        "hwk" => match options.public_key {
            Some(key) => key.clone(),
            None => {
                // SIG-KEY §3.3: inline JWK parameters
                let jwk = Jwk {
                    kty: parsed_key.param("kty").unwrap_or_default().to_string(),
                    crv: parsed_key.param("crv").map(String::from),
                    x: parsed_key.param("x").map(String::from),
                    y: parsed_key.param("y").map(String::from),
                    n: parsed_key.param("n").map(String::from),
                    e: parsed_key.param("e").map(String::from),
                    ..Default::default()
                };
                jwk_to_public_key(&jwk)?
            }
        },

        "jwks_uri" => {
            // SIG-KEY §3.5: JWKS URI discovery.
            // Parameters: id (REQUIRED), dwk (REQUIRED), kid (REQUIRED).
            let resolver = options
                .jwks_resolver
                .ok_or_else(|| AAuthError::signature("scheme=jwks_uri requires jwks_resolver"))?;
            let id = parsed_key.param("id").ok_or_else(|| {
                AAuthError::signature("scheme=jwks_uri: missing required 'id' parameter")
            })?;
            let dwk = parsed_key.param("dwk").ok_or_else(|| {
                AAuthError::signature("scheme=jwks_uri: missing required 'dwk' parameter")
            })?;
            let kid = parsed_key.param("kid").ok_or_else(|| {
                AAuthError::signature("scheme=jwks_uri: missing required 'kid' parameter")
            })?;

            // The signer identifier drives key discovery — reject anything
            // that is not a well-formed HTTPS server identifier before it is
            // handed to the resolver (spec §12.8 / §5.1).
            if crate::identifiers::validate_server_identifier(id).is_err() {
                return Ok(false);
            }

            let jwks = match resolver.resolve(id, Some(dwk), Some(kid)) {
                Some(jwks) => jwks,
                None => return Ok(false),
            };
            let signing_key = match crate::keys::get_key_by_kid(&jwks, kid) {
                Some(key) => key.clone(),
                None => return Ok(false),
            };
            jwk_to_public_key(&Jwk::from_value(&signing_key)?)?
        }

        "jkt-jwt" => {
            // SIG-KEY §3.4: self-issued key delegation
            match verify_jkt_jwt_scheme(&parsed_key.params, now) {
                Some(key) => key,
                None => return Ok(false),
            }
        }

        "jwt" => {
            // SIG-KEY §3.6: JWT confirmation key. Generic — extracts cnf.jwk
            // from any JWT; AAuth token type validation belongs to the
            // protocol layer (resource verifier).
            let resolver = options
                .jwks_resolver
                .ok_or_else(|| AAuthError::signature("scheme=jwt requires jwks_resolver"))?;
            let jwt_token = match parsed_key.param("jwt") {
                Some(token) => token,
                None => return Ok(false),
            };
            match verify_jwt_scheme(jwt_token, resolver, now) {
                Some(key) => key,
                None => return Ok(false),
            }
        }

        "x509" => {
            return Err(AAuthError::signature("scheme=x509 is not yet implemented"));
        }

        other => {
            return Err(AAuthError::signature(format!(
                "Unknown signature scheme: {other}"
            )));
        }
    };

    // Reconstruct the signature base
    let parsed_uri = Url::parse(target_uri)
        .map_err(|e| AAuthError::signature(format!("Invalid target URI {target_uri}: {e}")))?;
    let authority = match (parsed_uri.host_str(), parsed_uri.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => {
            return Err(AAuthError::signature(format!(
                "Target URI has no host: {target_uri}"
            )))
        }
    };
    let path = if parsed_uri.path().is_empty() {
        "/"
    } else {
        parsed_uri.path()
    };
    let query = parsed_uri.query().filter(|q| !q.is_empty());

    // The part after "{label}=" becomes the @signature-params line
    let prefix = format!("{}=", input.label);
    let signature_params = signature_input_header
        .strip_prefix(&prefix)
        .unwrap_or(signature_input_header);
    if signature_params.is_empty() {
        return Ok(false);
    }

    let signature_base = build_signature_base(
        method,
        &authority,
        path,
        query,
        headers,
        body,
        signature_key_header,
        &input.components,
        signature_params,
    )?;

    let signature_bytes = parse_signature(signature_header, Some(&input.label))?;

    Ok(public_key
        .verify(&signature_bytes, signature_base.as_bytes())
        .is_ok())
}

/// Verify the `jkt-jwt` scheme per SIG-KEY §3.4.
///
/// Returns the ephemeral public key from `cnf.jwk`, or `None` on failure.
fn verify_jkt_jwt_scheme(params: &HashMap<String, String>, now: i64) -> Option<PublicKey> {
    let jwt_token = params.get("jwt")?;

    // Step 1: parse without verifying
    let jwt = decode_unverified(jwt_token).ok()?;

    // Step 2: check typ (jkt-s256+jwt or jkt-s512+jwt)
    let typ = jwt.typ().unwrap_or_default();
    let (hash_name, use_sha512) = match typ {
        "jkt-s256+jwt" => ("sha-256", false),
        "jkt-s512+jwt" => ("sha-512", true),
        _ => return None,
    };

    // Steps 3-4: extract jwk from the JWT header
    let header_jwk_value = jwt.header.get("jwk")?;
    let header_jwk = Jwk::from_value(header_jwk_value).ok()?;

    // Step 5: thumbprint of the header jwk with the determined hash
    let thumbprint = if use_sha512 {
        calculate_jwk_thumbprint_sha512(&header_jwk).ok()?
    } else {
        calculate_jwk_thumbprint(&header_jwk).ok()?
    };

    // Steps 6-7: iss must be urn:jkt:{hash}:{thumbprint}
    let expected_iss = format!("urn:jkt:{hash_name}:{thumbprint}");
    if jwt.claim_str("iss") != Some(expected_iss.as_str()) {
        return None;
    }

    // Step 8: verify the JWT signature with the header jwk
    let enclave_public_key = jwk_to_public_key(&header_jwk).ok()?;
    jwt.verify_signature(&enclave_public_key).ok()?;

    // Step 9: validate exp and iat
    if let Some(exp) = jwt.claim_i64("exp") {
        if now >= exp {
            return None;
        }
    }
    jwt.claim_i64("iat")?;

    // Steps 10-11: extract the ephemeral public key from cnf.jwk
    let cnf_jwk = jwt.cnf_jwk()?;
    jwk_to_public_key(&cnf_jwk).ok()
}

/// Verify the `jwt` scheme per SIG-KEY §3.6.
///
/// Generic JWT verification — extracts `cnf.jwk` from any JWT that carries
/// one. AAuth-specific token type validation is done at the protocol layer.
fn verify_jwt_scheme(jwt_token: &str, resolver: &dyn JwksResolver, now: i64) -> Option<PublicKey> {
    // Step 1: parse
    let jwt: DecodedJwt = decode_unverified(jwt_token).ok()?;

    // Step 2: typ is application-specific; not enforced here.

    // Step 3: validate exp if present
    if let Some(exp) = jwt.claim_i64("exp") {
        if now >= exp {
            return None;
        }
    }

    // Step 4: cnf.jwk must be present
    let cnf_jwk = jwt.cnf_jwk()?;

    // Step 5: discover issuer keys via {iss}/.well-known/{dwk}. The issuer
    // is attacker-supplied and drives the fetch, so reject anything that is
    // not a well-formed HTTPS server identifier before resolving (spec §12.8).
    let iss = jwt.claim_str("iss")?;
    if crate::identifiers::validate_server_identifier(iss).is_err() {
        return None;
    }
    let dwk = jwt.claim_str("dwk");
    let kid = jwt.kid()?;

    let jwks: Value = resolver.resolve(iss, dwk, Some(kid))?;

    let signing_key = crate::keys::get_key_by_kid(&jwks, kid)?;
    let auth_public_key = jwk_to_public_key(&Jwk::from_value(signing_key).ok()?).ok()?;

    // Step 6: verify the JWT signature
    jwt.verify_signature(&auth_public_key).ok()?;

    // Steps 7-8: return cnf.jwk as the request signing key
    jwk_to_public_key(&cnf_jwk).ok()
}
