//! Signature base construction per RFC 9421 Section 2.5.

use crate::errors::{AAuthError, Result};
use httpsig::RequestParts;
use std::collections::HashMap;

/// Build the signature base string per RFC 9421 Section 2.5.
///
/// `signature_params` is the `Signature-Input` value after the label (the
/// inner list with its parameters) and becomes the final
/// `"@signature-params"` line.
#[allow(clippy::too_many_arguments)]
pub fn build_signature_base(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
    body: Option<&[u8]>,
    signature_key_header: &str,
    covered_components: &[String],
    signature_params: &str,
) -> Result<String> {
    let mut effective_headers = headers.clone();
    effective_headers.retain(|name, _| !name.eq_ignore_ascii_case("signature-key"));
    effective_headers.insert(
        "Signature-Key".to_string(),
        signature_key_header.to_string(),
    );
    let mut target_uri = format!("https://{authority}{path}");
    if let Some(query) = query {
        target_uri.push('?');
        target_uri.push_str(query);
    }
    httpsig::build_signature_base(
        &RequestParts {
            method,
            target_uri: &target_uri,
            headers: &effective_headers,
            body,
        },
        covered_components,
        signature_params,
    )
    .map_err(AAuthError::from)
}

/// Determine the covered components for a request per AAuth spec Section 15.3.
///
/// MUST cover `@method`, `@authority`, `@path`, and `signature-key`;
/// `@query` when a query string is present. `additional_components` (e.g.
/// `content-type` / `content-digest` from resource metadata) are inserted
/// before `signature-key`. When `include_aauth_mission` is set,
/// `aauth-mission` is appended after `signature-key` (spec §Authorization
/// Endpoint Request).
pub fn determine_covered_components(
    query: Option<&str>,
    additional_components: Option<&[&str]>,
    include_aauth_mission: bool,
) -> Vec<String> {
    let mut components = vec![
        "@method".to_string(),
        "@authority".to_string(),
        "@path".to_string(),
    ];
    if query.is_some_and(|q| !q.is_empty()) {
        components.push("@query".to_string());
    }
    if let Some(additional) = additional_components {
        components.extend(additional.iter().map(|c| c.to_string()));
    }
    components.push("signature-key".to_string());
    if include_aauth_mission {
        components.push("aauth-mission".to_string());
    }
    components
}

/// Build the `Signature-Input` value after the label.
///
/// Per AAuth spec Section 15.4 only `created` is REQUIRED:
/// `("@method" "@authority" ...);created=1234567890`
pub fn build_signature_params(covered_components: &[String], created: i64) -> String {
    let components = covered_components
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!("({components});created={created}")
}

/// Calculate the `Content-Digest` header value per RFC 9530
/// (e.g. `sha-256=:...:`).
pub fn calculate_content_digest(body: &[u8]) -> String {
    httpsig::calculate_content_digest(body)
}
