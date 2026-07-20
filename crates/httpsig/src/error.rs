//! Error types for HTTP signature parsing, creation, and verification.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An HTTP signature field is malformed.
    #[error("invalid {field}: {message}")]
    InvalidField {
        /// Header field name.
        field: &'static str,
        /// Details safe to expose to a caller.
        message: String,
    },

    /// A requested covered component is absent or unsupported.
    #[error("invalid covered component {component}: {message}")]
    InvalidComponent { component: String, message: String },

    /// The target URI cannot be used to construct derived components.
    #[error("invalid target URI: {0}")]
    InvalidTargetUri(String),

    /// Key material is malformed or unsupported.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// The signature is cryptographically invalid.
    #[error("signature verification failed")]
    VerificationFailed,
}

impl Error {
    pub(crate) fn field(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            message: message.into(),
        }
    }

    pub(crate) fn key(message: impl Into<String>) -> Self {
        Self::InvalidKey(message.into())
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
