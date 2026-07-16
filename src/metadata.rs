//! Well-known metadata documents for AAuth participants.
//!
//! - Agent servers publish `/.well-known/aauth-agent.json`
//! - Resources publish `/.well-known/aauth-resource.json`
//! - Access servers publish `/.well-known/aauth-access.json`
//! - Person servers publish `/.well-known/aauth-person.json`

use crate::errors::{AAuthError, Result};
use crate::http::HttpClient;
use serde::Serialize;
use serde_json::Value;

fn to_value<T: Serialize>(metadata: &T) -> Value {
    serde_json::to_value(metadata).expect("metadata serialization is infallible")
}

/// Agent server metadata per SPEC §Agent Server Metadata
/// (`/.well-known/aauth-agent.json`).
#[derive(Debug, Clone, Serialize, Default)]
pub struct AgentMetadata {
    /// Agent identifier (HTTPS URL) — REQUIRED.
    pub issuer: String,
    /// URL of the agent's JSON Web Key Set — REQUIRED.
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_dark_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhost_callback_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clarification_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/// Generate agent metadata JSON.
pub fn generate_agent_metadata(metadata: &AgentMetadata) -> Value {
    to_value(metadata)
}

/// Resource metadata per AAuth spec Section 13.3
/// (`/.well-known/aauth-resource.json`).
#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceMetadata {
    /// Resource identifier (HTTPS URL) — REQUIRED.
    pub issuer: String,
    /// URL of the resource's JSON Web Key Set — REQUIRED.
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_dark_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// Legacy URL for proactive resource token requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_endpoint: Option<String>,
    /// Scope name → description map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_descriptions: Option<Value>,
    /// Additional HTTP components agents must cover in signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_signature_components: Option<Vec<String>>,
    /// Signature validity window in seconds for `created`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_window: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

/// Generate resource metadata JSON.
pub fn generate_resource_metadata(metadata: &ResourceMetadata) -> Value {
    to_value(metadata)
}

/// Access server metadata (`/.well-known/aauth-access.json`).
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuthServerMetadata {
    /// Access server identifier (HTTPS URL) — REQUIRED.
    pub issuer: String,
    /// Single endpoint for all agent-to-AS communication — REQUIRED.
    pub token_endpoint: String,
    /// URL where users are sent for authentication and consent — REQUIRED.
    pub interaction_endpoint: String,
    /// URL of the access server's JSON Web Key Set — REQUIRED.
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

/// Generate access server metadata JSON.
pub fn generate_auth_metadata(metadata: &AuthServerMetadata) -> Value {
    to_value(metadata)
}

/// Person server metadata per SPEC §PS Metadata
/// (`/.well-known/aauth-person.json`).
#[derive(Debug, Clone, Serialize, Default)]
pub struct PersonServerMetadata {
    /// PS identifier (HTTPS URL) — REQUIRED.
    pub issuer: String,
    /// URL where agents send token requests — REQUIRED.
    pub token_endpoint: String,
    /// URL of the PS's JSON Web Key Set — REQUIRED.
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_control_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
}

/// Generate person server metadata JSON.
pub fn generate_ps_metadata(metadata: &PersonServerMetadata) -> Value {
    to_value(metadata)
}

/// Fetch a metadata document from a URL via HTTPS.
///
/// HTTP is allowed for localhost development only.
pub fn fetch_metadata(client: &dyn HttpClient, url: &str) -> Result<Value> {
    if !url.starts_with("https://") {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]" | "::1") {
            return Err(AAuthError::metadata(
                format!("Metadata URL must use HTTPS (except localhost): {url}"),
                Some(url.to_string()),
            ));
        }
    }
    client.fetch_json(url).map_err(|e| {
        AAuthError::metadata(
            format!("Failed to fetch metadata from {url}: {e}"),
            Some(url.to_string()),
        )
    })
}

/// Fetch `/.well-known/aauth-person.json` for a person server, trying the
/// `.json` path first and the extension-less path for compatibility.
pub fn fetch_ps_metadata(client: &dyn HttpClient, ps_url: &str) -> Result<Value> {
    let base = ps_url.trim_end_matches('/');
    for path in [
        "/.well-known/aauth-person.json",
        "/.well-known/aauth-person",
    ] {
        let url = format!("{base}{path}");
        if let Ok(value) = client.fetch_json(&url) {
            return Ok(value);
        }
    }
    Err(AAuthError::metadata(
        format!("Could not fetch PS metadata from {ps_url}"),
        Some(ps_url.to_string()),
    ))
}
