//! HTTP request signing.

use crate::errors::{AAuthError, Result};
use crate::keys::PrivateKey;
use crate::signing::base::{
    build_signature_base, build_signature_params, calculate_content_digest,
    determine_covered_components,
};
use crate::signing::signature::build_signature_header;
use crate::util::now_unix;
use httpsig::{build_signature_key_header, SigScheme};
use std::collections::HashMap;
use url::Url;

/// The three headers produced by signing a request.
#[derive(Debug, Clone)]
pub struct SignatureHeaders {
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

impl SignatureHeaders {
    /// Iterate as `(header_name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("Signature-Input", self.signature_input.as_str()),
            ("Signature", self.signature.as_str()),
            ("Signature-Key", self.signature_key.as_str()),
        ]
        .into_iter()
    }

    /// Insert the three headers into a header map.
    pub fn apply(&self, headers: &mut HashMap<String, String>) {
        for (name, value) in self.iter() {
            headers.insert(name.to_string(), value.to_string());
        }
    }
}

/// Optional signing parameters.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Signature label (default `"sig"`).
    pub label: Option<String>,
    /// Additional components to cover when a body is present
    /// (`content-type` / `content-digest`, typically from resource metadata's
    /// `additional_signature_components`).
    pub additional_signature_components: Option<Vec<String>>,
    /// Override the `created` timestamp (defaults to now). Mainly for tests.
    pub created: Option<i64>,
}

/// Sign an HTTP request using HTTP Message Signatures (RFC 9421).
///
/// Builds the `Signature-Key` header for `scheme`, determines the covered
/// components from the request shape, signs the base string with
/// `private_key`, and inserts `Signature-Input`, `Signature`, `Signature-Key`
/// (and `Content-Digest` / `Content-Type` when covered) into `headers`.
///
/// When `headers` already carries `AAuth-Mission`, the `aauth-mission`
/// component is covered automatically (spec §Authorization Endpoint Request).
pub fn sign_request(
    method: &str,
    target_uri: &str,
    headers: &mut HashMap<String, String>,
    body: Option<&[u8]>,
    private_key: &PrivateKey,
    scheme: &SigScheme<'_>,
    options: &SignOptions,
) -> Result<SignatureHeaders> {
    let parsed = Url::parse(target_uri)
        .map_err(|e| AAuthError::signature(format!("Invalid target URI {target_uri}: {e}")))?;
    let authority = match (parsed.host_str(), parsed.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => {
            return Err(AAuthError::signature(format!(
                "Target URI has no host: {target_uri}"
            )))
        }
    };
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let query = parsed.query().filter(|q| !q.is_empty());

    let label = options.label.as_deref().unwrap_or("sig");

    // Build Signature-Key header first (needed for the signature-key component)
    let signature_key_header = build_signature_key_header(scheme, Some(private_key), label)?;
    headers.insert("Signature-Key".to_string(), signature_key_header.clone());

    // Determine body components to include (opt-in only)
    let mut body_components: Vec<&str> = Vec::new();
    let has_body = body.is_some_and(|b| !b.is_empty());
    if has_body {
        if let Some(additional) = &options.additional_signature_components {
            for component in additional {
                if component == "content-type" || component == "content-digest" {
                    body_components.push(component.as_str());
                }
            }
            if body_components.contains(&"content-digest")
                && crate::util::get_header(headers, "content-digest").is_none()
            {
                let digest = calculate_content_digest(body.unwrap());
                headers.insert("Content-Digest".to_string(), digest);
            }
            if body_components.contains(&"content-type")
                && crate::util::get_header(headers, "content-type").is_none()
            {
                headers.insert(
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                );
            }
        }
    }

    let include_aauth_mission = headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("aauth-mission"));

    let covered_components = determine_covered_components(
        query,
        if body_components.is_empty() {
            None
        } else {
            Some(&body_components)
        },
        include_aauth_mission,
    );

    // Only `created` is required per spec Section 15.4
    let created = options.created.unwrap_or_else(now_unix);
    let signature_params = build_signature_params(&covered_components, created);
    let signature_input_header = format!("{label}={signature_params}");

    let signature_base = build_signature_base(
        method,
        &authority,
        path,
        query,
        headers,
        body,
        &signature_key_header,
        &covered_components,
        &signature_params,
    )?;

    let signature_bytes = private_key.sign(signature_base.as_bytes());
    let signature_header = build_signature_header(&signature_bytes, label);

    let result = SignatureHeaders {
        signature_input: signature_input_header,
        signature: signature_header,
        signature_key: signature_key_header,
    };
    result.apply(headers);
    Ok(result)
}
