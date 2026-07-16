//! Agent token (`aa-agent+jwt`) creation and validation per AAuth spec
//! Section 7.1 / 16.2.1.

use crate::errors::{AAuthError, Result};
use crate::jwt;
use crate::keys::{Jwk, JwksResolver, PrivateKey};
use crate::util::now_unix;
use serde_json::{json, Value};

const TOKEN_TYPE: &str = "aa-agent+jwt";

/// Maximum agent-token lifetime in seconds (spec §5.2.2: MUST NOT exceed 24h).
pub const MAX_AGENT_TOKEN_LIFETIME: i64 = 86400;

/// Claims for [`create_agent_token`].
#[derive(Debug, Clone)]
pub struct AgentTokenClaims {
    /// Agent server identifier (HTTPS URL) — also the agent identifier.
    pub iss: String,
    /// Agent delegate identifier (persists across key rotations).
    pub sub: String,
    /// Agent delegate's public signing key.
    pub cnf_jwk: Jwk,
    /// Expiration timestamp. Defaults to one hour from now.
    pub exp: Option<i64>,
    /// Optional audience restriction (single URL string or array).
    pub aud: Option<Value>,
    /// Optional user identifier hint for the auth server in `aud`.
    pub aud_sub: Option<String>,
    /// Optional HTTPS URL of the agent's person server.
    pub ps: Option<String>,
}

impl AgentTokenClaims {
    pub fn new(iss: impl Into<String>, sub: impl Into<String>, cnf_jwk: Jwk) -> Self {
        AgentTokenClaims {
            iss: iss.into(),
            sub: sub.into(),
            cnf_jwk,
            exp: None,
            aud: None,
            aud_sub: None,
            ps: None,
        }
    }
}

/// Create an agent token (`aa-agent+jwt`) signed with the agent server's key.
pub fn create_agent_token(
    claims: &AgentTokenClaims,
    private_key: &PrivateKey,
    kid: &str,
) -> Result<String> {
    let now = now_unix();
    // Clamp to the spec §5.2.2 24h ceiling.
    let exp = claims
        .exp
        .unwrap_or(now + 3600)
        .min(now + MAX_AGENT_TOKEN_LIFETIME);

    let mut payload = json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "dwk": "aauth-agent.json",
        "jti": uuid::Uuid::new_v4().to_string(),
        "cnf": {"jwk": claims.cnf_jwk.to_value()},
        "iat": now,
        "exp": exp,
    });
    if let Some(aud) = &claims.aud {
        payload["aud"] = aud.clone();
    }
    if let Some(aud_sub) = &claims.aud_sub {
        payload["aud_sub"] = Value::String(aud_sub.clone());
    }
    if let Some(ps) = &claims.ps {
        payload["ps"] = Value::String(ps.clone());
    }

    jwt::encode_with_key(TOKEN_TYPE, Some(kid), &payload, private_key)
}

fn token_err(message: impl Into<String>) -> AAuthError {
    AAuthError::token(message, TOKEN_TYPE)
}

/// Verify an agent token per AAuth spec Section 16.2.1.
///
/// The agent server's JWKS is discovered via `resolver` using the token's
/// `iss`. Returns the verified payload claims (including `cnf.jwk`).
pub fn verify_agent_token(
    token: &str,
    resolver: &dyn JwksResolver,
    expected_aud: Option<&str>,
) -> Result<Value> {
    let parsed = jwt::decode_unverified(token)
        .map_err(|e| token_err(format!("Failed to parse agent token: {e}")))?;

    // Check typ
    let typ = parsed.typ().unwrap_or_default();
    if typ != TOKEN_TYPE {
        return Err(token_err(format!(
            "Invalid token type: expected {TOKEN_TYPE}, got {typ}"
        )));
    }

    // Check required claims
    let kid = parsed
        .kid()
        .ok_or_else(|| token_err("Token header missing 'kid'"))?;
    let iss = parsed
        .claim_str("iss")
        .ok_or_else(|| token_err("Token payload missing 'iss'"))?;
    if parsed.payload.get("jti").is_none() {
        return Err(token_err("Token missing required 'jti' claim"));
    }
    if parsed.claim_str("sub").unwrap_or_default().is_empty() {
        return Err(token_err(
            "Token missing 'sub' claim (agent delegate identifier)",
        ));
    }

    // iss MUST be a valid HTTPS server identifier — it doubles as the agent
    // identifier and drives key discovery (spec §5.2.4 / §12.8).
    crate::identifiers::validate_server_identifier(iss)
        .map_err(|e| token_err(format!("Token 'iss' is not a valid server identifier: {e}")))?;

    // dwk MUST be aauth-agent.json (spec §5.2.4).
    let dwk = parsed.claim_str("dwk").unwrap_or_default();
    if dwk != "aauth-agent.json" {
        return Err(token_err(format!(
            "Invalid dwk: expected aauth-agent.json, got {dwk}"
        )));
    }

    // Optional ps / parent_agent, when present, must be valid identifiers.
    if let Some(ps) = parsed.claim_str("ps") {
        crate::identifiers::validate_server_identifier(ps)
            .map_err(|e| token_err(format!("Token 'ps' is not a valid server identifier: {e}")))?;
    }
    if let Some(parent) = parsed.claim_str("parent_agent") {
        crate::identifiers::validate_agent_identifier(parent).map_err(|e| {
            token_err(format!(
                "Token 'parent_agent' is not a valid agent identifier: {e}"
            ))
        })?;
    }

    // Fetch the agent server's JWKS and verify the signature
    let jwks = resolver
        .resolve(iss, Some("aauth-agent.json"), Some(kid))
        .ok_or_else(|| token_err(format!("Failed to fetch JWKS from {iss}")))?;
    jwt::verify_with_jwks(&parsed, &jwks)
        .map_err(|e| token_err(format!("JWT signature verification failed: {e}")))?;

    // Verify exp and iat, and enforce the lifetime ceiling (spec §5.2.2:
    // agent-token lifetime MUST NOT exceed 24 hours).
    let now = now_unix();
    let exp = match parsed.claim_i64("exp") {
        Some(exp) => {
            if now >= exp {
                return Err(token_err("Token has expired"));
            }
            exp
        }
        None => return Err(token_err("Token missing 'exp' claim")),
    };
    if let Some(iat) = parsed.claim_i64("iat") {
        if iat > now + 60 {
            return Err(token_err("Token iat is in the future"));
        }
        if exp - iat > MAX_AGENT_TOKEN_LIFETIME {
            return Err(token_err(format!(
                "Agent token lifetime {}s exceeds the {MAX_AGENT_TOKEN_LIFETIME}s maximum",
                exp - iat
            )));
        }
    }

    // Verify aud if present
    if let (Some(expected), Some(aud)) = (expected_aud, parsed.payload.get("aud")) {
        let matches = match aud {
            Value::Array(list) => list.iter().any(|a| a.as_str() == Some(expected)),
            Value::String(s) => s == expected,
            _ => false,
        };
        if !matches {
            return Err(token_err(format!(
                "Invalid audience: expected {expected}, got {aud}"
            )));
        }
    }

    // Verify cnf.jwk
    if parsed.cnf_jwk().is_none() {
        return Err(token_err("Token missing 'cnf.jwk' claim"));
    }

    Ok(parsed.payload)
}
