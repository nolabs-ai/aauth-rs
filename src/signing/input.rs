//! `Signature-Input` header parsing and building (RFC 9421 Section 4.1).

use crate::errors::{AAuthError, Result};
use crate::util::now_unix;

/// Parsed `Signature-Input` header: covered components plus parameters.
pub type SignatureInputParams = httpsig::SignatureInput;

/// Build a `Signature-Input` header value.
///
/// `created` defaults to the current time.
pub fn build_signature_input_header(
    covered_components: &[String],
    label: &str,
    created: Option<i64>,
) -> String {
    let created = created.unwrap_or_else(now_unix);
    httpsig::build_signature_input_header(covered_components, label, Some(created))
}

/// Parse a `Signature-Input` header value into components and parameters.
pub fn parse_signature_input(header_value: &str) -> Result<SignatureInputParams> {
    httpsig::parse_signature_input(header_value).map_err(AAuthError::from)
}
