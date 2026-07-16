//! Signature base construction per RFC 9421 Section 2.5.

use crate::errors::{AAuthError, Result};
use crate::util::get_header;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
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
    if signature_params.is_empty() {
        return Err(AAuthError::signature(
            "signature_params is required for valid signature base",
        ));
    }

    let has_body = body.is_some_and(|b| !b.is_empty());
    let mut lines: Vec<String> = Vec::with_capacity(covered_components.len() + 1);

    for component in covered_components {
        let value: String = match component.as_str() {
            "@method" => method.to_string(),
            "@authority" => authority.to_string(),
            "@path" => path.to_string(),
            "@query" => match query {
                Some(q) if !q.is_empty() => format!("?{q}"),
                _ => {
                    return Err(AAuthError::signature(
                        "@query component specified but no query string present",
                    ))
                }
            },
            "content-type" => {
                if !has_body {
                    return Err(AAuthError::signature(
                        "content-type component specified but no body present",
                    ));
                }
                get_header(headers, "content-type")
                    .ok_or_else(|| {
                        AAuthError::signature("content-type component required but header missing")
                    })?
                    .to_string()
            }
            "content-digest" => {
                if !has_body {
                    return Err(AAuthError::signature(
                        "content-digest component specified but no body present",
                    ));
                }
                get_header(headers, "content-digest")
                    .ok_or_else(|| {
                        AAuthError::signature(
                            "content-digest component required but header missing",
                        )
                    })?
                    .to_string()
            }
            "signature-key" => signature_key_header.to_string(),
            "aauth-mission" => get_header(headers, "aauth-mission")
                .ok_or_else(|| {
                    AAuthError::signature(
                        "aauth-mission in Signature-Input but AAuth-Mission header missing",
                    )
                })?
                .to_string(),
            other => {
                return Err(AAuthError::signature(format!("Unknown component: {other}")));
            }
        };
        lines.push(format!("\"{}\": {value}", component.to_lowercase()));
    }

    lines.push(format!("\"@signature-params\": {signature_params}"));
    Ok(lines.join("\n"))
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
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}
