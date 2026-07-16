//! `Signature-Input` header parsing and building (RFC 9421 Section 4.1).

use crate::errors::{AAuthError, Result};
use crate::util::now_unix;
use std::collections::HashMap;

/// Parsed `Signature-Input` header: covered components plus parameters.
#[derive(Debug, Clone, Default)]
pub struct SignatureInputParams {
    pub label: String,
    pub components: Vec<String>,
    /// Parameters after the component list (e.g. `created`), values with
    /// surrounding quotes stripped.
    pub params: HashMap<String, String>,
}

impl SignatureInputParams {
    /// The `created` parameter as Unix time, if present and numeric.
    pub fn created(&self) -> Option<i64> {
        self.params.get("created")?.parse().ok()
    }
}

/// Build a `Signature-Input` header value.
///
/// `created` defaults to the current time.
pub fn build_signature_input_header(
    covered_components: &[String],
    label: &str,
    created: Option<i64>,
) -> String {
    let created = created.unwrap_or_else(now_unix);
    let components = covered_components
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{label}=({components});created={created}")
}

/// Parse a `Signature-Input` header value into components and parameters.
pub fn parse_signature_input(header_value: &str) -> Result<SignatureInputParams> {
    let invalid =
        || AAuthError::signature(format!("Invalid Signature-Input format: {header_value}"));

    let eq = header_value.find('=').ok_or_else(invalid)?;
    let label = header_value[..eq].trim().to_string();
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(invalid());
    }

    let rest = header_value[eq + 1..].trim_start();
    if !rest.starts_with('(') {
        return Err(invalid());
    }
    let close = rest.find(')').ok_or_else(invalid)?;
    let inner = &rest[1..close];

    let mut components = Vec::new();
    let mut chars = inner.char_indices();
    while let Some((start, c)) = chars.next() {
        if c == '"' {
            let mut end = None;
            for (i, c2) in chars.by_ref() {
                if c2 == '"' {
                    end = Some(i);
                    break;
                }
            }
            let end = end.ok_or_else(invalid)?;
            components.push(inner[start + 1..end].to_string());
        }
    }

    let mut params = HashMap::new();
    let after = &rest[close + 1..];
    for part in after.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').to_string();
            if !key.is_empty() {
                params.insert(key, value);
            }
        }
    }

    Ok(SignatureInputParams {
        label,
        components,
        params,
    })
}
