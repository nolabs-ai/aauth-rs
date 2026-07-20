//! Errors and protocol error codes for AAuth.

use serde_json::{Map, Value};

// --- Signature-Error header codes (401 responses, per draft-hardt-httpbis-signature-key) ---

pub const ERROR_INVALID_REQUEST: &str = "invalid_request";
pub const ERROR_INVALID_INPUT: &str = "invalid_input";
pub const ERROR_INVALID_SIGNATURE: &str = "invalid_signature";
pub const ERROR_UNSUPPORTED_ALGORITHM: &str = "unsupported_algorithm";
pub const ERROR_INVALID_KEY: &str = "invalid_key";
pub const ERROR_UNKNOWN_KEY: &str = "unknown_key";
pub const ERROR_INVALID_JWT: &str = "invalid_jwt";
pub const ERROR_EXPIRED_JWT: &str = "expired_jwt";

// --- Token endpoint error codes (JSON body, per draft-hardt-aauth-protocol) ---

pub const ERROR_INVALID_AGENT_TOKEN: &str = "invalid_agent_token";
pub const ERROR_EXPIRED_AGENT_TOKEN: &str = "expired_agent_token";
pub const ERROR_INVALID_RESOURCE_TOKEN: &str = "invalid_resource_token";
pub const ERROR_EXPIRED_RESOURCE_TOKEN: &str = "expired_resource_token";
pub const ERROR_INVALID_AUTH_TOKEN: &str = "invalid_auth_token";
pub const ERROR_SERVER_ERROR: &str = "server_error";

// --- Interaction / authorization error codes ---

/// 403: user interaction needed but no interaction channel available.
pub const ERROR_INTERACTION_REQUIRED: &str = "interaction_required";

// --- Mission status error codes ---

pub const ERROR_MISSION_TERMINATED: &str = "mission_terminated";

// --- Polling error codes (JSON body, per draft-hardt-aauth-protocol) ---

pub const ERROR_DENIED: &str = "denied";
pub const ERROR_ABANDONED: &str = "abandoned";
pub const ERROR_EXPIRED: &str = "expired";
pub const ERROR_INVALID_CODE: &str = "invalid_code";
pub const ERROR_SLOW_DOWN: &str = "slow_down";

/// Errors raised by this crate.
#[derive(Debug, thiserror::Error)]
pub enum AAuthError {
    /// HTTP signature validation or creation error.
    #[error("signature error: {message}")]
    Signature {
        message: String,
        /// One of the `ERROR_*` Signature-Error codes.
        error_code: &'static str,
    },

    /// Token validation or creation error.
    #[error("token error ({token_type}): {message}")]
    Token { message: String, token_type: String },

    /// Requirement / challenge parsing or building error.
    #[error("challenge error: {message}")]
    Challenge { message: String },

    /// Metadata discovery or parsing error.
    #[error("metadata error: {message}")]
    Metadata {
        message: String,
        metadata_url: Option<String>,
    },

    /// JWKS fetching or parsing error.
    #[error("JWKS error: {message}")]
    Jwks {
        message: String,
        jwks_uri: Option<String>,
    },

    /// Identifier or URL validation error.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// HTTP transport failure (from an [`crate::http::HttpClient`] implementation).
    #[error("http error: {0}")]
    Http(String),
}

impl AAuthError {
    pub fn signature(message: impl Into<String>) -> Self {
        AAuthError::Signature {
            message: message.into(),
            error_code: ERROR_INVALID_SIGNATURE,
        }
    }

    pub fn signature_with_code(message: impl Into<String>, error_code: &'static str) -> Self {
        AAuthError::Signature {
            message: message.into(),
            error_code,
        }
    }

    pub fn token(message: impl Into<String>, token_type: impl Into<String>) -> Self {
        AAuthError::Token {
            message: message.into(),
            token_type: token_type.into(),
        }
    }

    pub fn challenge(message: impl Into<String>) -> Self {
        AAuthError::Challenge {
            message: message.into(),
        }
    }

    pub fn metadata(message: impl Into<String>, metadata_url: Option<String>) -> Self {
        AAuthError::Metadata {
            message: message.into(),
            metadata_url,
        }
    }

    pub fn jwks(message: impl Into<String>, jwks_uri: Option<String>) -> Self {
        AAuthError::Jwks {
            message: message.into(),
            jwks_uri,
        }
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, AAuthError>;

impl From<httpsig::Error> for AAuthError {
    fn from(error: httpsig::Error) -> Self {
        let error_code = match &error {
            httpsig::Error::InvalidField { .. } | httpsig::Error::InvalidComponent { .. } => {
                ERROR_INVALID_INPUT
            }
            httpsig::Error::InvalidTargetUri(_) => ERROR_INVALID_REQUEST,
            httpsig::Error::InvalidKey(_) => ERROR_INVALID_KEY,
            httpsig::Error::VerificationFailed => ERROR_INVALID_SIGNATURE,
        };
        Self::signature_with_code(error.to_string(), error_code)
    }
}

/// Build a standard AAuth token endpoint error response body (JSON).
///
/// For authentication errors (401), use
/// [`crate::headers::build_signature_error`] to construct the
/// `Signature-Error` header instead.
pub fn build_error_response(
    error: &str,
    description: Option<&str>,
    extras: Option<Map<String, Value>>,
) -> Value {
    let mut body = Map::new();
    body.insert("error".into(), Value::String(error.to_string()));
    if let Some(desc) = description {
        body.insert("error_description".into(), Value::String(desc.to_string()));
    }
    if let Some(extras) = extras {
        for (k, v) in extras {
            body.insert(k, v);
        }
    }
    Value::Object(body)
}
