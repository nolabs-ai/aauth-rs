//! `Signature` header parsing and building (RFC 9421 Section 4.2).

use crate::errors::{AAuthError, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// Build a `Signature` header value.
///
/// Signature bytes are base64url-encoded without padding.
pub fn build_signature_header(signature_bytes: &[u8], label: &str) -> String {
    format!("{label}=:{}:", URL_SAFE_NO_PAD.encode(signature_bytes))
}

/// Decode base64 leniently: standard or url-safe alphabet, padded or not.
fn decode_b64_lenient(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .or_else(|| STANDARD.decode(input).ok())
        .or_else(|| {
            // Standard alphabet without padding
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(trimmed)
                .ok()
        })
}

/// Parse a `Signature` header value, returning the raw signature bytes.
///
/// When `label` is given, the header's label must match.
pub fn parse_signature(header_value: &str, label: Option<&str>) -> Result<Vec<u8>> {
    let invalid = || AAuthError::signature(format!("Invalid Signature format: {header_value}"));

    let value = header_value.trim();
    let eq = value.find('=').ok_or_else(invalid)?;
    let found_label = value[..eq].trim();
    let rest = value[eq + 1..].trim();

    if let Some(expected) = label {
        if found_label != expected {
            return Err(AAuthError::signature(format!(
                "Label mismatch: expected {expected}, got {found_label}"
            )));
        }
    }

    let inner = rest
        .strip_prefix(':')
        .and_then(|r| r.strip_suffix(':'))
        .ok_or_else(invalid)?;

    decode_b64_lenient(inner)
        .ok_or_else(|| AAuthError::signature(format!("Failed to decode signature: {inner}")))
}
