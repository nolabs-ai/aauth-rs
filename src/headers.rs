//! AAuth and Signature-Key HTTP header parsing and building.
//!
//! Per draft-hardt-httpbis-signature-key:
//! - `Accept-Signature` is the response header resources use to declare they
//!   accept HTTP Message Signatures (replaces the old `Signature-Requirement`
//!   header for pseudonym and identity levels).
//! - `Signature-Error` conveys signature validation failures.
//!
//! Per draft-hardt-aauth-protocol:
//! - `AAuth-Requirement` conveys AAuth-specific requirements (auth-token,
//!   interaction, approval, clarification, claims).

use crate::errors::{AAuthError, Result};
use std::collections::HashMap;

// Requirement levels (pseudonym/identity from the Signature-Key spec;
// the rest from the AAuth protocol spec)
pub const REQUIRE_PSEUDONYM: &str = "pseudonym";
pub const REQUIRE_IDENTITY: &str = "identity";
pub const REQUIRE_AUTH_TOKEN: &str = "auth-token";
pub const REQUIRE_INTERACTION: &str = "interaction";
pub const REQUIRE_APPROVAL: &str = "approval";
pub const REQUIRE_CLARIFICATION: &str = "clarification";
pub const REQUIRE_CLAIMS: &str = "claims";

// HTTP header field names
pub const HEADER_ACCEPT_SIGNATURE: &str = "Accept-Signature";
/// Deprecated — use [`HEADER_ACCEPT_SIGNATURE`].
pub const HEADER_SIGNATURE_REQUIREMENT: &str = "Signature-Requirement";
pub const HEADER_AAUTH_REQUIREMENT: &str = "AAuth-Requirement";
pub const HEADER_AAUTH_ACCESS: &str = "AAuth-Access";
pub const HEADER_AAUTH_CAPABILITIES: &str = "AAuth-Capabilities";
pub const HEADER_AAUTH_MISSION: &str = "AAuth-Mission";
pub const HEADER_SIGNATURE_ERROR: &str = "Signature-Error";

// Accept-Signature sigkey types (draft-hardt-httpbis-signature-key §4.1)
/// Pseudonym: inline public key / JWK thumbprint (`hwk`, `jkt-jwt`).
pub const SIGKEY_JKT: &str = "jkt";
/// Identity: URI-identified key (`jwks_uri`, `jwt`).
pub const SIGKEY_URI: &str = "uri";
/// PKI: X.509 certificate chain.
pub const SIGKEY_X509: &str = "x509";

// AAuth-Capabilities values
pub const CAPABILITY_INTERACTION: &str = "interaction";
pub const CAPABILITY_CLARIFICATION: &str = "clarification";
pub const CAPABILITY_PAYMENT: &str = "payment";

const DEFAULT_COMPONENTS: [&str; 3] = ["@method", "@authority", "@path"];

// --- tiny param extraction helpers ---

fn is_boundary(c: Option<char>) -> bool {
    match c {
        None => true,
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_' || c == '-'),
    }
}

/// Find `name="value"` in a header, returning the unquoted value.
fn find_quoted_param(header: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let mut search_from = 0;
    while let Some(pos) = header[search_from..].find(&needle) {
        let abs = search_from + pos;
        let before = header[..abs].chars().next_back();
        if is_boundary(before) {
            let value_start = abs + needle.len();
            let end = header[value_start..].find('"')?;
            return Some(header[value_start..value_start + end].to_string());
        }
        search_from = abs + needle.len();
    }
    None
}

/// Find `name=token` (unquoted `[A-Za-z0-9_-]+` token) in a header.
fn find_token_param(header: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let mut search_from = 0;
    while let Some(pos) = header[search_from..].find(&needle) {
        let abs = search_from + pos;
        let before = header[..abs].chars().next_back();
        let value_start = abs + needle.len();
        let first = header[value_start..].chars().next();
        if is_boundary(before)
            && first.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            let value: String = header[value_start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            return Some(value);
        }
        search_from = abs + needle.len();
    }
    None
}

/// Find `name=("a" "b" ...)` in a header, returning the quoted items.
fn find_list_param(header: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("{name}=(");
    let pos = header.find(&needle)?;
    let inner_start = pos + needle.len();
    let end = header[inner_start..].find(')')?;
    Some(extract_quoted(&header[inner_start..inner_start + end]))
}

/// Extract all `"..."` items from a string.
fn extract_quoted(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                items.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    items
}

fn quoted_list(items: &[impl AsRef<str>]) -> String {
    items
        .iter()
        .map(|c| format!("\"{}\"", c.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

// --- Requirement / challenge headers ---

/// A parsed challenge header (`AAuth-Requirement`, `Accept-Signature`, or
/// legacy `Signature-Requirement` / `require=` formats).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedRequirement {
    /// The requirement level (`pseudonym`, `identity`, `auth-token`,
    /// `interaction`, `approval`, `clarification`, `claims`).
    pub requirement: Option<String>,
    pub resource_token: Option<String>,
    /// Deprecated — the auth server is discovered from the resource token's
    /// `aud` claim.
    pub auth_server: Option<String>,
    /// Interaction URL.
    pub url: Option<String>,
    /// Interaction code.
    pub code: Option<String>,
    pub algorithms: Option<Vec<String>>,
    pub required_input: Option<Vec<String>>,
    /// From `Accept-Signature`: the sigkey type (`jkt`, `uri`, `x509`).
    pub sigkey: Option<String>,
    /// From `Accept-Signature`: covered components.
    pub components: Vec<String>,
    /// From `Accept-Signature`: single acceptable algorithm.
    pub alg: Option<String>,
}

/// Parse a `Signature-Requirement` / `AAuth-Requirement` header value
/// (`requirement=...` format).
pub fn parse_signature_requirement(header_value: &str) -> Result<ParsedRequirement> {
    let requirement = find_token_param(header_value, "requirement").ok_or_else(|| {
        AAuthError::challenge("Signature-Requirement header must include 'requirement' parameter")
    })?;
    Ok(ParsedRequirement {
        requirement: Some(requirement),
        resource_token: find_quoted_param(header_value, "resource-token"),
        auth_server: find_quoted_param(header_value, "auth-server"),
        url: find_quoted_param(header_value, "url"),
        code: find_quoted_param(header_value, "code"),
        algorithms: find_list_param(header_value, "algorithms"),
        required_input: find_list_param(header_value, "required_input"),
        ..Default::default()
    })
}

fn build_level_requirement(
    level: &str,
    algorithms: Option<&[&str]>,
    required_input: Option<&[&str]>,
) -> String {
    let mut parts = vec![format!("requirement={level}")];
    if let Some(algorithms) = algorithms {
        parts.push(format!("algorithms=({})", quoted_list(algorithms)));
    }
    if let Some(required_input) = required_input {
        parts.push(format!("required_input=({})", quoted_list(required_input)));
    }
    parts.join(", ")
}

/// Build a `Signature-Requirement` value requiring a pseudonymous signature.
pub fn build_pseudonym_requirement(
    algorithms: Option<&[&str]>,
    required_input: Option<&[&str]>,
) -> String {
    build_level_requirement(REQUIRE_PSEUDONYM, algorithms, required_input)
}

/// Build a `Signature-Requirement` value requiring verified agent identity.
pub fn build_identity_requirement(
    algorithms: Option<&[&str]>,
    required_input: Option<&[&str]>,
) -> String {
    build_level_requirement(REQUIRE_IDENTITY, algorithms, required_input)
}

/// Build an `AAuth-Requirement` value requiring an auth token.
///
/// Per spec, the auth server is discovered from the resource token's `aud`
/// claim.
pub fn build_auth_token_requirement(resource_token: &str) -> String {
    format!("requirement=auth-token; resource-token=\"{resource_token}\"")
}

/// Build an `AAuth-Requirement` value for user interaction.
pub fn build_interaction_requirement(url: &str, code: &str) -> String {
    format!("requirement=interaction; url=\"{url}\"; code=\"{code}\"")
}

/// Build an `AAuth-Requirement` value for approval pending.
pub fn build_approval_requirement() -> String {
    "requirement=approval".to_string()
}

/// Build an `AAuth-Requirement` value for clarification (question in body).
pub fn build_clarification_requirement() -> String {
    "requirement=clarification".to_string()
}

/// Build an `AAuth-Requirement` value for claims (required_claims in body).
pub fn build_claims_requirement() -> String {
    "requirement=claims".to_string()
}

// --- Accept-Signature ---

/// Build an `Accept-Signature` header value per
/// draft-hardt-httpbis-signature-key, e.g.
/// `sig=("@method" "@authority" "@path");sigkey=uri`.
pub fn build_accept_signature(
    sigkey: &str,
    components: Option<&[&str]>,
    algs: Option<&[&str]>,
) -> String {
    let components: Vec<&str> = components
        .map(|c| c.to_vec())
        .unwrap_or_else(|| DEFAULT_COMPONENTS.to_vec());
    let inner = quoted_list(&components);
    let mut params = format!("sigkey={sigkey}");
    if let Some(algs) = algs {
        if algs.len() == 1 {
            params = format!("alg=\"{}\";{params}", algs[0]);
        }
    }
    format!("sig=({inner});{params}")
}

/// Parse an `Accept-Signature` header value.
///
/// `requirement` is mapped from the sigkey type for challenge-handler
/// compatibility (`jkt` → pseudonym; `uri`/`x509` → identity).
pub fn parse_accept_signature(header_value: &str) -> ParsedRequirement {
    let sigkey = find_token_param(header_value, "sigkey");
    let requirement = match sigkey.as_deref() {
        Some(SIGKEY_JKT) => Some(REQUIRE_PSEUDONYM.to_string()),
        Some(SIGKEY_URI) | Some(SIGKEY_X509) => Some(REQUIRE_IDENTITY.to_string()),
        _ => None,
    };
    let components = find_list_param(header_value, "sig").unwrap_or_default();
    ParsedRequirement {
        requirement,
        sigkey,
        components,
        alg: find_quoted_param(header_value, "alg"),
        ..Default::default()
    }
}

// --- AAuth-Capabilities / AAuth-Access / AAuth-Mission ---

/// Build an `AAuth-Capabilities` request header value: the agent declares
/// which interaction channels it supports.
pub fn build_aauth_capabilities_header(capabilities: &[&str]) -> String {
    capabilities.join(", ")
}

/// Parse an `AAuth-Capabilities` header into capability tokens.
pub fn parse_aauth_capabilities_header(header_value: &str) -> Vec<String> {
    header_value
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(String::from)
        .collect()
}

/// Build an `AAuth-Access` response header value (opaque access token).
///
/// The resource returns this after two-party authorization; the agent echoes
/// it back via `Authorization: AAuth <token>` on subsequent requests.
pub fn build_aauth_access_header(token: &str) -> String {
    token.to_string()
}

/// Extract the opaque token from an `Authorization: AAuth <token>` header.
pub fn parse_authorization_aauth_header(header_value: &str) -> Option<String> {
    if header_value.len() < 6 || !header_value[..6].eq_ignore_ascii_case("aauth ") {
        return None;
    }
    let token = header_value[6..].trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Build an `AAuth-Mission` request header value (spec Section 8.2).
pub fn build_aauth_mission_header(approver: &str, s256: &str) -> String {
    format!("approver=\"{approver}\"; s256=\"{s256}\"")
}

/// Parsed `AAuth-Mission` header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedMission {
    pub approver: Option<String>,
    pub s256: Option<String>,
}

/// Parse an `AAuth-Mission` header into approver URL and s256 hash.
///
/// Supports both `approver=` and the older `manager=` parameter name.
pub fn parse_aauth_mission_header(header_value: &str) -> ParsedMission {
    ParsedMission {
        approver: find_quoted_param(header_value, "approver")
            .or_else(|| find_quoted_param(header_value, "manager")),
        s256: find_quoted_param(header_value, "s256"),
    }
}

// --- header routing ---

/// Requirement levels that MUST use the `AAuth-Requirement` response header.
pub fn aauth_protocol_requirement_levels() -> [&'static str; 5] {
    [
        REQUIRE_AUTH_TOKEN,
        REQUIRE_INTERACTION,
        REQUIRE_APPROVAL,
        REQUIRE_CLARIFICATION,
        REQUIRE_CLAIMS,
    ]
}

/// The correct response header name for a requirement level.
///
/// Pseudonym and identity levels use `Accept-Signature`; all AAuth-specific
/// levels use `AAuth-Requirement`.
pub fn requirement_header_for_level(requirement_level: &str) -> &'static str {
    if requirement_level == REQUIRE_PSEUDONYM || requirement_level == REQUIRE_IDENTITY {
        HEADER_ACCEPT_SIGNATURE
    } else {
        HEADER_AAUTH_REQUIREMENT
    }
}

/// Extract the requirement header value from a map of HTTP response headers.
///
/// Checks `AAuth-Requirement`, `Accept-Signature`, `Signature-Requirement`
/// (deprecated), and legacy `AAuth` / `Agent-Auth`, case-insensitively.
/// Returns an empty string when none is present.
pub fn get_challenge_header_value(headers: &HashMap<String, String>) -> String {
    let lower: HashMap<String, &String> =
        headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();
    for name in [
        "aauth-requirement",
        "accept-signature",
        "signature-requirement",
        "aauth",
        "agent-auth",
    ] {
        if let Some(value) = lower.get(name) {
            if !value.is_empty() {
                return (*value).clone();
            }
        }
    }
    String::new()
}

/// Parse any AAuth challenge header value (handles all formats):
/// `Accept-Signature` (`sig=(...);sigkey=...`), `AAuth-Requirement` /
/// `Signature-Requirement` (`requirement=...`), and the legacy `require=`
/// format.
pub fn parse_aauth_header(header_value: &str) -> Result<ParsedRequirement> {
    // Detect Accept-Signature format (contains "sigkey=" or starts with
    // "sigN=(")
    let trimmed = header_value.trim_start();
    let looks_like_accept_sig = header_value.contains("sigkey=")
        || (trimmed.starts_with("sig") && {
            let after = trimmed[3..].trim_start_matches(|c: char| c.is_ascii_digit());
            after.starts_with("=(")
        });
    if looks_like_accept_sig {
        return Ok(parse_accept_signature(header_value));
    }

    if header_value.contains("requirement=") {
        return parse_signature_requirement(header_value);
    }

    if header_value.contains("require=") {
        return Ok(ParsedRequirement {
            requirement: find_token_param(header_value, "require"),
            resource_token: find_quoted_param(header_value, "resource-token"),
            auth_server: find_quoted_param(header_value, "auth-server"),
            url: find_quoted_param(header_value, "url"),
            code: find_quoted_param(header_value, "code"),
            ..Default::default()
        });
    }

    Err(AAuthError::challenge(
        "Header must include 'requirement', 'require', or 'sigkey' parameter",
    ))
}

// --- Signature-Error header ---

pub use crate::errors::{
    ERROR_EXPIRED_JWT, ERROR_INVALID_INPUT, ERROR_INVALID_JWT, ERROR_INVALID_KEY,
    ERROR_INVALID_REQUEST, ERROR_INVALID_SIGNATURE, ERROR_UNKNOWN_KEY, ERROR_UNSUPPORTED_ALGORITHM,
};

/// Build a `Signature-Error` header value per
/// draft-hardt-httpbis-signature-key.
pub fn build_signature_error(
    error: &str,
    required_input: Option<&[&str]>,
    supported_algorithms: Option<&[&str]>,
) -> String {
    let mut parts = vec![format!("error={error}")];
    if error == ERROR_INVALID_INPUT {
        if let Some(required_input) = required_input {
            parts.push(format!("required_input=({})", quoted_list(required_input)));
        }
    }
    if error == ERROR_UNSUPPORTED_ALGORITHM {
        if let Some(supported) = supported_algorithms {
            parts.push(format!("supported_algorithms=({})", quoted_list(supported)));
        }
    }
    parts.join(", ")
}

/// A parsed `Signature-Error` header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSignatureError {
    pub error: Option<String>,
    pub required_input: Option<Vec<String>>,
    pub supported_algorithms: Option<Vec<String>>,
}

/// Parse a `Signature-Error` header value.
pub fn parse_signature_error(header_value: &str) -> ParsedSignatureError {
    ParsedSignatureError {
        error: find_token_param(header_value, "error"),
        required_input: find_list_param(header_value, "required_input"),
        supported_algorithms: find_list_param(header_value, "supported_algorithms"),
    }
}
