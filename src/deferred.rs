//! Deferred (202 Accepted) response handling.
//!
//! Per spec Section 10, any endpoint may return `202 Accepted` with a
//! `Location` header to indicate the request is pending. The agent polls the
//! Location URL with GET until a terminal response is received.

use crate::headers::HEADER_AAUTH_REQUIREMENT;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Generate a unique pending-request ID for use in Location URLs
/// (12 hex characters).
pub fn generate_pending_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Minimum interaction-code length in symbols (5 bits each → ≥ 40 bits of
/// entropy). This floor is a hardening choice by this crate; the spec
/// (§12.3.3) defines `code` as a single-use linking string but mandates no
/// encoding or entropy minimum.
pub const MIN_INTERACTION_CODE_SYMBOLS: usize = 8;

/// Crockford base32 alphabet: digits then A–Z with the ambiguous glyphs
/// I, L, O, U removed, so codes survive human transcription and case-folding
/// for out-of-band comparison. Also a crate choice — §12.3.3 gives only
/// illustrative examples, not an alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a single-use interaction code (spec §12.3.3).
///
/// Encoding and entropy are hardening choices (see
/// [`MIN_INTERACTION_CODE_SYMBOLS`]): the Crockford base32 alphabet is used,
/// a clean 5 bits per symbol is drawn from a cryptographically secure RNG so
/// the distribution is uniform (no modulo bias), and `length` is raised to
/// [`MIN_INTERACTION_CODE_SYMBOLS`] if smaller.
pub fn generate_interaction_code(length: usize) -> String {
    use rand_core::RngCore as _;

    let length = length.max(MIN_INTERACTION_CODE_SYMBOLS);

    // One byte per symbol yields 8 bits to draw a 5-bit symbol from — always
    // enough, so a single fill covers the whole code.
    let mut bytes = vec![0u8; length];
    rand_core::OsRng.fill_bytes(&mut bytes);

    // Walk the buffer as a bitstream, taking a clean 5 bits per symbol.
    let mut code = String::with_capacity(length);
    let mut bit_pos = 0usize;
    while code.len() < length {
        let mut value = 0u8;
        for _ in 0..5 {
            let byte = bytes[bit_pos / 8];
            let bit = (byte >> (7 - (bit_pos % 8))) & 1;
            value = (value << 1) | bit;
            bit_pos += 1;
        }
        code.push(CROCKFORD[value as usize] as char);
    }
    code
}

/// Options for [`build_pending_response_body`].
#[derive(Debug, Clone, Default)]
pub struct PendingBody {
    /// The pending URL (echoes the Location header).
    pub location: String,
    /// Requirement level (`interaction`, `approval`, `clarification`, `claims`).
    pub require: Option<String>,
    /// Interaction code (required when `require == "interaction"`).
    pub code: Option<String>,
    /// User's question during clarification chat.
    pub clarification: Option<String>,
    /// Status string: `"pending"` or `"interacting"` (defaults to pending).
    pub status: Option<String>,
    pub required_claims: Option<Vec<String>>,
    pub clarification_timeout: Option<i64>,
    pub clarification_options: Option<Vec<String>>,
}

/// Build the JSON body for a `202 Accepted` pending response.
pub fn build_pending_response_body(options: &PendingBody) -> Value {
    let mut body = Map::new();
    body.insert(
        "status".into(),
        Value::String(options.status.clone().unwrap_or_else(|| "pending".into())),
    );
    body.insert("location".into(), Value::String(options.location.clone()));
    if let Some(require) = &options.require {
        body.insert("requirement".into(), Value::String(require.clone()));
    }
    if let Some(code) = &options.code {
        body.insert("code".into(), Value::String(code.clone()));
    }
    if let Some(clarification) = &options.clarification {
        body.insert("clarification".into(), Value::String(clarification.clone()));
    }
    if let Some(claims) = &options.required_claims {
        body.insert(
            "required_claims".into(),
            Value::Array(claims.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(timeout) = options.clarification_timeout {
        body.insert("timeout".into(), Value::from(timeout));
    }
    if let Some(opts) = &options.clarification_options {
        body.insert(
            "options".into(),
            Value::Array(opts.iter().cloned().map(Value::String).collect()),
        );
    }
    Value::Object(body)
}

/// Options for [`build_pending_response_headers`].
#[derive(Debug, Clone, Default)]
pub struct PendingHeaders {
    /// The pending URL.
    pub location: String,
    /// Seconds before the agent should poll (default 0).
    pub retry_after: i64,
    /// Requirement level for the `AAuth-Requirement` header.
    pub require: Option<String>,
    /// Interaction code.
    pub code: Option<String>,
    /// Interaction URL (REQUIRED when `require == "interaction"` per spec
    /// Section 6.2).
    pub url: Option<String>,
    pub required_claims: Option<Vec<String>>,
}

/// Build the response headers for a `202 Accepted` pending response.
pub fn build_pending_response_headers(options: &PendingHeaders) -> HashMap<String, String> {
    let mut headers = HashMap::from([
        ("Location".to_string(), options.location.clone()),
        ("Retry-After".to_string(), options.retry_after.to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ]);

    let requirement_value = match options.require.as_deref() {
        Some("interaction") => match (&options.code, &options.url) {
            (Some(code), Some(url)) => Some(format!(
                "requirement=interaction; url=\"{url}\"; code=\"{code}\""
            )),
            _ => None,
        },
        Some("approval") => Some("requirement=approval".to_string()),
        // Spec §Clarification Chat: MUST include
        // AAuth-Requirement: requirement=clarification when a 202 carries
        // a clarification question.
        Some("clarification") => Some("requirement=clarification".to_string()),
        Some("claims") => options.required_claims.as_ref().map(|claims| {
            let inner = claims
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(" ");
            format!("requirement=claims; required_claims=({inner})")
        }),
        _ => None,
    };
    if let Some(value) = requirement_value {
        headers.insert(HEADER_AAUTH_REQUIREMENT.to_string(), value);
    }

    headers
}

/// Build the JSON body for a successful token response (200 OK).
pub fn build_success_response(auth_token: &str, expires_in: i64) -> Value {
    serde_json::json!({
        "auth_token": auth_token,
        "expires_in": expires_in,
    })
}

/// Build the error response body for terminal polling responses.
pub fn build_polling_error_body(error: &str, description: Option<&str>) -> Value {
    let mut body = Map::new();
    body.insert("error".into(), Value::String(error.to_string()));
    if let Some(description) = description {
        body.insert(
            "error_description".into(),
            Value::String(description.to_string()),
        );
    }
    Value::Object(body)
}

/// A parsed pending (202) response body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingResponse {
    /// `"pending"` or `"interacting"`; unrecognized values are treated as
    /// pending per spec.
    pub status: String,
    pub location: Option<String>,
    pub requirement: Option<String>,
    pub code: Option<String>,
    pub clarification: Option<String>,
}

/// Parse a pending response body from a server.
pub fn parse_pending_response(body: &Value) -> PendingResponse {
    let raw_status = body
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("pending");
    let status = if raw_status == "pending" || raw_status == "interacting" {
        raw_status
    } else {
        "pending"
    };
    let get = |name: &str| body.get(name).and_then(Value::as_str).map(String::from);
    PendingResponse {
        status: status.to_string(),
        location: get("location"),
        requirement: get("requirement").or_else(|| get("require")),
        code: get("code"),
        clarification: get("clarification"),
    }
}

/// Check whether an HTTP status indicates a pending/deferred state.
pub fn is_pending_response(status_code: u16) -> bool {
    status_code == 202
}

/// Token endpoint request modes (spec Section 11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRequestMode {
    ResourceAccess,
    SelfAccess,
    CallChaining,
    TokenRefresh,
}

impl TokenRequestMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenRequestMode::ResourceAccess => "resource_access",
            TokenRequestMode::SelfAccess => "self_access",
            TokenRequestMode::CallChaining => "call_chaining",
            TokenRequestMode::TokenRefresh => "token_refresh",
        }
    }
}

/// Detect the token endpoint mode from request parameters (spec Section 11.1):
/// `auth_token` → refresh; `resource_token` + `upstream_token` → call
/// chaining; `resource_token` → resource access; `scope` → self access.
pub fn detect_token_request_mode(params: &Value) -> Option<TokenRequestMode> {
    let has = |name: &str| {
        params
            .get(name)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    };
    if has("auth_token") {
        Some(TokenRequestMode::TokenRefresh)
    } else if has("resource_token") && has("upstream_token") {
        Some(TokenRequestMode::CallChaining)
    } else if has("resource_token") {
        Some(TokenRequestMode::ResourceAccess)
    } else if has("scope") {
        Some(TokenRequestMode::SelfAccess)
    } else {
        None
    }
}
