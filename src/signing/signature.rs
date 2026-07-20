//! `Signature` header parsing and building (RFC 9421 Section 4.2).

use crate::errors::{AAuthError, Result};

/// Build a `Signature` header value.
///
/// Signature bytes are base64url-encoded without padding.
pub fn build_signature_header(signature_bytes: &[u8], label: &str) -> String {
    httpsig::build_signature_header(signature_bytes, label)
}

/// Parse a `Signature` header value, returning the raw signature bytes.
///
/// When `label` is given, the header's label must match.
pub fn parse_signature(header_value: &str, label: Option<&str>) -> Result<Vec<u8>> {
    httpsig::parse_signature(header_value, label).map_err(AAuthError::from)
}
