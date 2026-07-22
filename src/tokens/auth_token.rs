//! Auth token (`aa-auth+jwt`) creation and validation per AAuth spec
//! Section 9.1 / §Auth Token Verification.

use crate::errors::{AAuthError, Result};
use crate::jwt;
use crate::keys::{Jwk, JwksResolver, PrivateKey};
use crate::util::now_unix;
use serde_json::{json, Value};

const AUTH_TOKEN_TYPE: &str = "aa-auth+jwt";

/// Maximum auth-token lifetime in seconds (spec §9.4.1: MUST NOT exceed 1h).
pub const MAX_AUTH_TOKEN_LIFETIME: i64 = 3600;

/// Claims for [`create_auth_token`].
#[derive(Debug, Clone)]
pub struct AuthTokenClaims {
    /// Auth server identifier (HTTPS URL).
    pub iss: String,
    /// Resource identifier, or agent identifier for self-access.
    pub aud: String,
    /// Agent identifier (`aauth:local@domain`) — REQUIRED.
    pub agent: String,
    /// Agent's public signing key — REQUIRED.
    pub cnf_jwk: Jwk,
    /// Actor claim per RFC 8693 §4.1 — OPTIONAL (spec §9.4.1). Omitted for
    /// direct authorization. For call chaining, set the top-level actor with
    /// `{"agent": <intermediary_id>, "act": <upstream_act>}` (nested via the
    /// inner `act`), keyed on `agent` (spec §9.4.4 / §9.4.5).
    pub act: Option<Value>,
    /// Authorized scopes (at least one of `scope` or `sub` MUST be present).
    pub scope: Option<String>,
    /// User identifier (at least one of `scope` or `sub` MUST be present).
    pub sub: Option<String>,
    /// Expiration timestamp. Defaults to one hour from now.
    pub exp: Option<i64>,
    /// Optional mission object when issued in mission context.
    pub mission: Option<Value>,
    /// Well-known metadata document name for key discovery. Defaults to
    /// `aauth-access.json` (AS-issued); use `aauth-person.json` for
    /// PS-issued tokens.
    pub dwk: Option<String>,
}

/// Create an auth token (`aa-auth+jwt`).
pub fn create_auth_token(
    claims: &AuthTokenClaims,
    private_key: &PrivateKey,
    kid: &str,
) -> Result<String> {
    if claims.agent.is_empty() {
        return Err(AAuthError::token(
            "'agent' claim is required in auth token",
            AUTH_TOKEN_TYPE,
        ));
    }
    if claims.sub.is_none() && claims.scope.is_none() {
        return Err(AAuthError::token(
            "At least one of 'sub' or 'scope' must be present in auth token",
            AUTH_TOKEN_TYPE,
        ));
    }

    let now = now_unix();
    // Spec §9.4.1: auth token lifetime MUST NOT exceed one hour. Clamp on
    // issue.
    let requested_exp = claims.exp.unwrap_or(now + 3600);
    let exp = requested_exp.min(now + MAX_AUTH_TOKEN_LIFETIME);
    let dwk = claims.dwk.as_deref().unwrap_or("aauth-access.json");

    let mut payload = json!({
        "iss": claims.iss,
        "aud": claims.aud,
        "dwk": dwk,
        "jti": uuid::Uuid::new_v4().to_string(),
        "agent": claims.agent,
        "cnf": {"jwk": claims.cnf_jwk.to_value()},
        "iat": now,
        "exp": exp,
    });
    if let Some(act) = &claims.act {
        payload["act"] = act.clone();
    }
    if let Some(sub) = &claims.sub {
        payload["sub"] = Value::String(sub.clone());
    }
    if let Some(scope) = &claims.scope {
        payload["scope"] = Value::String(scope.clone());
    }
    if let Some(mission) = &claims.mission {
        payload["mission"] = mission.clone();
    }

    jwt::encode_with_key(AUTH_TOKEN_TYPE, Some(kid), &payload, private_key)
}

/// A JWT's header and payload, parsed without verification.
#[derive(Debug, Clone)]
pub struct ParsedToken {
    pub header: Value,
    pub payload: Value,
}

/// Parse token claims without verification (for inspection).
pub fn parse_token_claims(token: &str) -> Result<ParsedToken> {
    let parsed = jwt::decode_unverified(token)?;
    Ok(ParsedToken {
        header: parsed.header,
        payload: parsed.payload,
    })
}

/// Expectations for [`verify_token`].
#[derive(Debug, Clone, Default)]
pub struct VerifyTokenOptions<'a> {
    /// Expected `typ` header (e.g. `"aa-auth+jwt"`).
    pub expected_typ: Option<&'a str>,
    /// Expected issuer.
    pub expected_iss: Option<&'a str>,
    /// Expected audience.
    pub expected_aud: Option<&'a str>,
    /// Expected agent identifier (from the request signing context).
    pub expected_agent: Option<&'a str>,
    /// JWK of the key used to sign the HTTP request — verified against
    /// the token's `cnf.jwk`.
    pub request_signing_jwk: Option<&'a Jwk>,
}

/// Verify a JWT token's signature and claims.
///
/// Per SPEC §Auth Token Verification this checks: typ; JWKS discovery + JWT
/// signature; exp and iat; iss; aud; agent; cnf.jwk against the request
/// signing key; the optional `act` claim (when present, `act.agent` must
/// match the agent) for auth tokens; and that auth tokens carry at least one
/// of `sub` or `scope`.
pub fn verify_token(
    token: &str,
    resolver: &dyn JwksResolver,
    options: &VerifyTokenOptions<'_>,
) -> Result<Value> {
    let token_type = options.expected_typ.unwrap_or("jwt").to_string();
    let token_err = |message: String| AAuthError::token(message, token_type.clone());

    let parsed = jwt::decode_unverified(token)
        .map_err(|e| token_err(format!("Failed to parse token: {e}")))?;

    // Step 1: check typ
    if let Some(expected_typ) = options.expected_typ {
        let typ = parsed.typ().unwrap_or_default();
        if typ != expected_typ {
            return Err(token_err(format!(
                "Invalid token type: expected {expected_typ}, got {typ}"
            )));
        }
    }

    let now = now_unix();

    // Step 3: check exp. For auth tokens `exp` is REQUIRED (spec §9.4.1
    // bounds it at ≤ 1h; §9.4.3 verification checks it); an absent claim is a
    // rejection, not a skip, otherwise a token with no `exp` would never
    // expire. For other token types keep the lenient "validate when present"
    // behaviour.
    match parsed.claim_i64("exp") {
        Some(exp) if now >= exp => return Err(token_err("Token has expired".into())),
        Some(_) => {}
        None if options.expected_typ == Some(AUTH_TOKEN_TYPE) => {
            return Err(token_err("Auth token missing required 'exp' claim".into()));
        }
        None => {}
    }

    // Check iat (must not be in the future; 60s clock skew allowed)
    if let Some(iat) = parsed.claim_i64("iat") {
        if iat > now + 60 {
            return Err(token_err("Token iat is in the future".into()));
        }
    }

    // Step 4: check iss
    let iss = parsed.claim_str("iss");
    if let Some(expected_iss) = options.expected_iss {
        if iss != Some(expected_iss) {
            return Err(token_err(format!(
                "Invalid issuer: expected {expected_iss}, got {iss:?}"
            )));
        }
    }

    // Step 5: check aud
    if let Some(expected_aud) = options.expected_aud {
        let matches = match parsed.payload.get("aud") {
            Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(expected_aud)),
            Some(Value::String(s)) => s == expected_aud,
            _ => false,
        };
        if !matches {
            return Err(token_err(format!(
                "Invalid audience: expected {expected_aud}, got {:?}",
                parsed.payload.get("aud")
            )));
        }
    }

    // jti is required for all token types
    if parsed.payload.get("jti").is_none() {
        return Err(token_err("Token missing required 'jti' claim".into()));
    }

    // Step 6: agent must match the request signing context
    if let Some(expected_agent) = options.expected_agent {
        let agent = parsed.claim_str("agent");
        if agent != Some(expected_agent) {
            return Err(token_err(format!(
                "Invalid agent: expected {expected_agent}, got {agent:?}"
            )));
        }
    }

    // Step 7: cnf.jwk must match the key used to sign the HTTP request
    if let Some(request_jwk) = options.request_signing_jwk {
        let cnf_jwk = parsed
            .cnf_jwk()
            .ok_or_else(|| token_err("Token missing 'cnf.jwk' claim".into()))?;
        if !request_jwk.same_key_material(&cnf_jwk) {
            return Err(token_err(
                "cnf.jwk does not match request signing key".into(),
            ));
        }
    }

    // Step 8: the `act` claim is OPTIONAL (spec §9.4.1). When present, the
    // top-level actor is keyed on `act.agent` and must match the agent
    // (spec §9.4.4 / §9.4.5); delegation chains nest via the inner `act`.
    if options.expected_typ == Some(AUTH_TOKEN_TYPE) {
        if let Some(act) = parsed.payload.get("act") {
            if let Some(expected_agent) = options.expected_agent {
                let act_agent = act.get("agent").and_then(Value::as_str);
                if act_agent != Some(expected_agent) {
                    return Err(token_err(format!(
                        "act.agent does not match agent: expected {expected_agent}, got {act_agent:?}"
                    )));
                }
            }
        }

        // Step 9: at least one of sub or scope
        if parsed.claim_str("sub").is_none() && parsed.claim_str("scope").is_none() {
            return Err(token_err(
                "Auth token must contain at least one of 'sub' or 'scope'".into(),
            ));
        }

        // Enforce the lifetime ceiling (spec §9.4.1: MUST NOT exceed 1h).
        if let (Some(iat), Some(exp)) = (parsed.claim_i64("iat"), parsed.claim_i64("exp")) {
            if exp - iat > MAX_AUTH_TOKEN_LIFETIME {
                return Err(token_err(format!(
                    "Auth token lifetime {}s exceeds the {MAX_AUTH_TOKEN_LIFETIME}s maximum",
                    exp - iat
                )));
            }
        }
    }

    // Step 2: discover issuer JWKS via dwk and verify the JWT signature.
    // The issuer drives key discovery, so it MUST be a valid HTTPS server
    // identifier (spec §5.1 / §12.8) before it reaches the resolver.
    let kid = parsed
        .kid()
        .ok_or_else(|| token_err("Token header missing 'kid'".into()))?;
    let iss = iss.unwrap_or_default();
    crate::identifiers::validate_server_identifier(iss)
        .map_err(|e| token_err(format!("Token 'iss' is not a valid server identifier: {e}")))?;
    let dwk = parsed.claim_str("dwk");
    let jwks = resolver
        .resolve(iss, dwk, Some(kid))
        .ok_or_else(|| token_err(format!("Failed to fetch JWKS from {iss}")))?;
    jwt::verify_with_jwks(&parsed, &jwks)
        .map_err(|e| token_err(format!("JWT signature verification failed: {e}")))?;

    Ok(parsed.payload)
}

/// Build the RFC 8693 `act` (actor) claim for a downstream auth token in a
/// delegation chain (spec §10.3).
///
/// `immediate_upstream_agent` is the `aauth:` identifier of the agent one hop
/// upstream of the token's presenter — the intermediary resource in call
/// chaining, or the parent in sub-agent authorization. `upstream_act` is the
/// `act` claim carried by that upstream agent's own auth token, if any; it is
/// nested unchanged so the full chain is preserved. AAuth keys each node on
/// `agent` (not RFC 8693's `sub`); the presenter's own identity lives in the
/// top-level `agent` claim and is never repeated inside `act`.
///
/// ```
/// # use aauth_core::tokens::build_act_claim;
/// # use serde_json::json;
/// // booking was delegated by asst; booking presents downstream at payments.
/// let act = build_act_claim("aauth:asst@agent.example", None);
/// assert_eq!(act, json!({"agent": "aauth:asst@agent.example"}));
///
/// // A sub-agent inside a chain nests the upstream act.
/// let nested = build_act_claim("aauth:booking@booking.example", Some(&act));
/// assert_eq!(nested["act"]["agent"], "aauth:asst@agent.example");
/// ```
pub fn build_act_claim(immediate_upstream_agent: &str, upstream_act: Option<&Value>) -> Value {
    let mut act = json!({ "agent": immediate_upstream_agent });
    if let Some(upstream) = upstream_act {
        act["act"] = upstream.clone();
    }
    act
}

/// Options for [`verify_upstream_token`].
pub struct VerifyUpstreamOptions<'a> {
    /// Issuers the recipient trusts to have brokered — or to be authorized to
    /// extend — an upstream auth token (PS/AS identifiers). The upstream
    /// token's `iss` MUST be one of these. MUST be non-empty.
    pub trusted_issuers: &'a [&'a str],
    /// The `iss` of the intermediary's agent token, taken from the
    /// `Signature-Key` header of the downstream token request. The upstream
    /// token's `aud` MUST equal this — it confirms the upstream token was
    /// issued *to* the resource now making the downstream request
    /// (spec §9.4.5 step 3).
    pub intermediary_agent_iss: &'a str,
}

/// The result of verifying a call-chaining `upstream_token` (spec §9.4.5).
#[derive(Debug, Clone)]
pub struct UpstreamVerification {
    /// The verified claims of the upstream auth token.
    pub upstream_claims: Value,
    /// The `act` claim to place on the downstream auth token, with the
    /// upstream delegation chain preserved (spec §9.4.5 step 4 / §10.3).
    pub downstream_act: Value,
}

/// Verify an `upstream_token` presented in a call-chaining token request and
/// build the downstream `act` claim (spec §9.4.5).
///
/// Steps, per §9.4.5:
/// 1. Full auth-token verification ([`verify_token`]) — typ, signature via
///    JWKS, exp/iat, structure. (The upstream token is a request *parameter*,
///    not the `Signature-Key` credential, so it is bound to the upstream
///    agent's key, not the intermediary's — the request-signing `cnf.jwk`
///    check is intentionally not applied here.)
/// 2. `iss` MUST be a trusted issuer.
/// 3. `aud` MUST equal the intermediary's agent-token `iss`.
/// 4. Construct the downstream `act`: `agent` is the upstream token's own
///    `agent`, nesting the upstream token's `act` (if any) as `act.act`.
///
/// The caller still evaluates its own mission and governance policy on
/// `upstream_claims`; the downstream scope is not required to be a subset of
/// the upstream scope (§10.1.1).
pub fn verify_upstream_token(
    upstream_token: &str,
    resolver: &dyn JwksResolver,
    options: &VerifyUpstreamOptions<'_>,
) -> Result<UpstreamVerification> {
    let token_err = |message: String| AAuthError::token(message, AUTH_TOKEN_TYPE);

    if options.trusted_issuers.is_empty() {
        return Err(token_err(
            "verify_upstream_token requires a non-empty trusted_issuers list".into(),
        ));
    }

    // Step 1 + step 3: full auth-token verification, binding aud to the
    // intermediary's agent-token iss.
    let claims = verify_token(
        upstream_token,
        resolver,
        &VerifyTokenOptions {
            expected_typ: Some(AUTH_TOKEN_TYPE),
            expected_aud: Some(options.intermediary_agent_iss),
            ..Default::default()
        },
    )?;

    // Step 2: iss must be a trusted issuer.
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !options.trusted_issuers.contains(&iss) {
        return Err(token_err(format!(
            "upstream token iss {iss:?} is not among the trusted issuers"
        )));
    }

    // Step 4: the downstream act records the upstream presenter as the
    // immediate upstream agent, nesting the upstream token's own act.
    let upstream_agent = claims.get("agent").and_then(Value::as_str).ok_or_else(|| {
        token_err("upstream token missing 'agent' claim; cannot build delegation chain".into())
    })?;
    let downstream_act = build_act_claim(upstream_agent, claims.get("act"));

    Ok(UpstreamVerification {
        upstream_claims: claims,
        downstream_act,
    })
}
