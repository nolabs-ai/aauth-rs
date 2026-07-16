//! Resource token (`aa-resource+jwt`) creation and validation per AAuth spec
//! Section 8.1 / §Resource Token Verification.

use crate::errors::{AAuthError, Result};
use crate::jwt;
use crate::keys::{JwksResolver, PrivateKey};
use crate::util::now_unix;
use serde_json::{json, Value};

const TOKEN_TYPE: &str = "aa-resource+jwt";

/// Claims for [`create_resource_token`].
#[derive(Debug, Clone)]
pub struct ResourceTokenClaims {
    /// Resource identifier (HTTPS URL).
    pub iss: String,
    /// Auth server (or person server) identifier (HTTPS URL).
    pub aud: String,
    /// Agent identifier.
    pub agent: String,
    /// JWK Thumbprint of the agent's signing key.
    pub agent_jkt: String,
    /// Space-separated scope values.
    pub scope: String,
    /// Expiration timestamp. Defaults to 10 minutes from now.
    pub exp: Option<i64>,
    /// Optional `{"approver": url, "s256": hash}` when mission-aware.
    pub mission: Option<Value>,
}

/// Create a resource token (`aa-resource+jwt`).
pub fn create_resource_token(
    claims: &ResourceTokenClaims,
    private_key: &PrivateKey,
    kid: &str,
) -> Result<String> {
    let now = now_unix();
    // Spec §6.7.1 RECOMMENDS a short lifetime (≤ 5 min); default to that.
    let exp = claims.exp.unwrap_or(now + 300);

    let mut payload = json!({
        "iss": claims.iss,
        "aud": claims.aud,
        "dwk": "aauth-resource.json",
        "jti": uuid::Uuid::new_v4().to_string(),
        "agent": claims.agent,
        "agent_jkt": claims.agent_jkt,
        "scope": claims.scope,
        "iat": now,
        "exp": exp,
    });
    if let Some(mission) = &claims.mission {
        payload["mission"] = mission.clone();
    }

    jwt::encode_with_key(TOKEN_TYPE, Some(kid), &payload, private_key)
}

/// Expectations for [`verify_resource_token`].
#[derive(Debug, Clone, Default)]
pub struct VerifyResourceTokenOptions<'a> {
    /// Expected audience (the recipient's own identifier — PS or AS).
    pub expected_aud: Option<&'a str>,
    /// Expected agent identifier.
    pub expected_agent: Option<&'a str>,
    /// Expected JWK Thumbprint of the agent's signing key.
    pub expected_agent_jkt: Option<&'a str>,
}

fn token_err(message: impl Into<String>) -> AAuthError {
    AAuthError::token(message, TOKEN_TYPE)
}

/// Verify a resource token per SPEC §Resource Token Verification.
pub fn verify_resource_token(
    token: &str,
    resolver: &dyn JwksResolver,
    options: &VerifyResourceTokenOptions<'_>,
) -> Result<Value> {
    let parsed = jwt::decode_unverified(token)
        .map_err(|e| token_err(format!("Failed to parse resource token: {e}")))?;

    // Step 1: verify typ
    let typ = parsed.typ().unwrap_or_default();
    if typ != TOKEN_TYPE {
        return Err(token_err(format!(
            "Invalid token type: expected {TOKEN_TYPE}, got {typ}"
        )));
    }

    // Step 2: verify dwk
    let dwk = parsed.claim_str("dwk").unwrap_or_default();
    if dwk != "aauth-resource.json" {
        return Err(token_err(format!(
            "Invalid dwk: expected aauth-resource.json, got {dwk}"
        )));
    }

    // Step 3: check exp and iat
    let now = now_unix();
    match parsed.claim_i64("exp") {
        Some(exp) => {
            if now >= exp {
                return Err(token_err("Resource token has expired"));
            }
        }
        None => return Err(token_err("Resource token missing 'exp' claim")),
    }
    if let Some(iat) = parsed.claim_i64("iat") {
        if iat > now + 60 {
            return Err(token_err("Resource token iat is in the future"));
        }
    }

    // Step 4: verify aud
    if let Some(expected_aud) = options.expected_aud {
        if parsed.claim_str("aud") != Some(expected_aud) {
            return Err(token_err(format!(
                "Invalid audience: expected {expected_aud}, got {:?}",
                parsed.claim_str("aud")
            )));
        }
    }

    // Step 5: verify agent
    if let Some(expected_agent) = options.expected_agent {
        if parsed.claim_str("agent") != Some(expected_agent) {
            return Err(token_err(format!(
                "Invalid agent: expected {expected_agent}, got {:?}",
                parsed.claim_str("agent")
            )));
        }
    }

    // Step 6: verify agent_jkt
    if let Some(expected_jkt) = options.expected_agent_jkt {
        if parsed.claim_str("agent_jkt") != Some(expected_jkt) {
            return Err(token_err(format!(
                "agent_jkt mismatch: expected {expected_jkt}, got {:?}",
                parsed.claim_str("agent_jkt")
            )));
        }
    }

    // Verify required claims
    for claim in ["jti", "iss", "aud", "agent", "agent_jkt", "scope"] {
        if parsed.payload.get(claim).is_none() {
            return Err(token_err(format!(
                "Resource token missing required '{claim}' claim"
            )));
        }
    }

    // Verify the JWT signature via JWKS discovery
    let kid = parsed
        .kid()
        .ok_or_else(|| token_err("Token header missing 'kid'"))?;
    let iss = parsed.claim_str("iss").unwrap_or_default();
    let jwks = resolver
        .resolve(iss, Some("aauth-resource.json"), Some(kid))
        .ok_or_else(|| token_err(format!("Failed to fetch JWKS from {iss}")))?;
    jwt::verify_with_jwks(&parsed, &jwks)
        .map_err(|e| token_err(format!("Resource token signature verification failed: {e}")))?;

    Ok(parsed.payload)
}
