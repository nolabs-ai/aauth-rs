//! Framework-neutral request signing and verification preparation.

use crate::fields::{signature_for_label, signature_input_for_label};
use crate::keys::{PrivateKey, PublicKey};
use crate::{
    build_signature_header, build_signature_input_header, build_signature_key_header,
    parse_signature_input, parse_signature_keys, Error, ParsedSignatureKey, Result, SigScheme,
    SignatureInput, HEADER_SIGNATURE, HEADER_SIGNATURE_INPUT, HEADER_SIGNATURE_KEY,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use url::{Host, Url};

/// The parts of an HTTP request needed to construct a signature base.
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    pub method: &'a str,
    pub target_uri: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub body: Option<&'a [u8]>,
}

impl RequestParts<'_> {
    /// Look up a header field name case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether a header field is present, using case-insensitive matching.
    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

fn authority(url: &Url) -> Result<String> {
    let host = match url.host() {
        Some(Host::Domain(host)) => host.to_string(),
        Some(Host::Ipv4(host)) => host.to_string(),
        Some(Host::Ipv6(host)) => format!("[{host}]"),
        None => {
            return Err(Error::InvalidTargetUri(
                "target URI has no authority".to_string(),
            ))
        }
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn component_value(request: &RequestParts<'_>, component: &str, url: &Url) -> Result<String> {
    match component {
        "@method" => Ok(request.method.to_string()),
        "@authority" => authority(url),
        "@scheme" => Ok(url.scheme().to_string()),
        "@path" => Ok(if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        }),
        "@query" => {
            url.query()
                .map(|query| format!("?{query}"))
                .ok_or_else(|| Error::InvalidComponent {
                    component: component.to_string(),
                    message: "target URI has no query component".to_string(),
                })
        }
        "@target-uri" => Ok(request.target_uri.to_string()),
        component if component.starts_with('@') => Err(Error::InvalidComponent {
            component: component.to_string(),
            message: "unsupported derived component".to_string(),
        }),
        header_name => request
            .header(header_name)
            .map(str::to_owned)
            .ok_or_else(|| Error::InvalidComponent {
                component: header_name.to_string(),
                message: "covered header field is absent".to_string(),
            }),
    }
}

/// Construct an RFC 9421 signature base.
///
/// Header components are resolved case-insensitively. This API intentionally
/// does not choose components for the caller; that decision belongs to the
/// protocol and its verification policy.
pub fn build_signature_base(
    request: &RequestParts<'_>,
    covered_components: &[String],
    signature_params: &str,
) -> Result<String> {
    if signature_params.is_empty() {
        return Err(Error::field(
            "Signature-Input",
            "signature parameters are required",
        ));
    }
    let url = Url::parse(request.target_uri)
        .map_err(|error| Error::InvalidTargetUri(error.to_string()))?;
    let mut lines = Vec::with_capacity(covered_components.len() + 1);
    for original_component in covered_components {
        let component = original_component.to_ascii_lowercase();
        if component.contains(';') || component.contains('"') {
            return Err(Error::InvalidComponent {
                component: original_component.clone(),
                message: "component parameters are not yet supported".to_string(),
            });
        }
        let value = component_value(request, &component, &url)?;
        lines.push(format!("\"{component}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    Ok(lines.join("\n"))
}

/// Calculate an RFC 9530 SHA-256 `Content-Digest` field value.
pub fn calculate_content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// Options controlling signature creation.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Signature dictionary label. Defaults to `sig`.
    pub label: String,
    /// Components to cover, in signature-base order.
    pub covered_components: Vec<String>,
    /// Override the creation time. If absent, the current Unix time is used.
    pub created: Option<i64>,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            label: "sig".to_string(),
            covered_components: vec![
                "@method".to_string(),
                "@authority".to_string(),
                "@path".to_string(),
                "signature-key".to_string(),
            ],
            created: None,
        }
    }
}

/// The three HTTP fields produced by [`sign_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeaders {
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

impl SignatureHeaders {
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            (HEADER_SIGNATURE_INPUT, self.signature_input.as_str()),
            (HEADER_SIGNATURE, self.signature.as_str()),
            (HEADER_SIGNATURE_KEY, self.signature_key.as_str()),
        ]
        .into_iter()
    }

    pub fn apply(&self, headers: &mut HashMap<String, String>) {
        for (name, value) in self.iter() {
            headers.insert(name.to_string(), value.to_string());
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Sign an HTTP request without applying application-specific policy.
pub fn sign_request(
    method: &str,
    target_uri: &str,
    headers: &mut HashMap<String, String>,
    body: Option<&[u8]>,
    private_key: &PrivateKey,
    scheme: &SigScheme<'_>,
    options: &SignOptions,
) -> Result<SignatureHeaders> {
    let signature_key = build_signature_key_header(scheme, Some(private_key), &options.label)?;
    headers.insert(HEADER_SIGNATURE_KEY.to_string(), signature_key.clone());

    let created = options.created.unwrap_or_else(now_unix);
    let signature_input =
        build_signature_input_header(&options.covered_components, &options.label, Some(created));
    let input = parse_signature_input(&signature_input)?;
    let request = RequestParts {
        method,
        target_uri,
        headers,
        body,
    };
    let signature_base = build_signature_base(
        &request,
        &options.covered_components,
        &input.serialized_params,
    )?;
    let signature =
        build_signature_header(&private_key.sign(signature_base.as_bytes()), &options.label);
    let result = SignatureHeaders {
        signature_input,
        signature,
        signature_key,
    };
    result.apply(headers);
    Ok(result)
}

/// A parsed signature whose trust policy and cryptographic verification have
/// not yet been applied.
#[derive(Debug, Clone)]
pub struct UnverifiedSignature {
    pub input: SignatureInput,
    pub signature_key: ParsedSignatureKey,
    pub signature: Vec<u8>,
    pub signature_base: String,
}

impl UnverifiedSignature {
    pub fn label(&self) -> &str {
        &self.input.label
    }

    pub fn components(&self) -> &[String] {
        &self.input.components
    }

    pub fn created(&self) -> Option<i64> {
        self.input.created()
    }

    /// Apply only cryptographic verification with an already trusted key.
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        public_key.verify(&self.signature, self.signature_base.as_bytes())
    }
}

/// Parse and reconstruct a signature before applying policy or resolving
/// external key material.
///
/// If `label` is omitted, `Signature-Input` must contain exactly one member.
pub fn prepare_verification(
    request: &RequestParts<'_>,
    signature_input_header: &str,
    signature_header: &str,
    signature_key_header: &str,
    label: Option<&str>,
) -> Result<UnverifiedSignature> {
    let input = match label {
        Some(label) => signature_input_for_label(signature_input_header, label)?,
        None => parse_signature_input(signature_input_header)?,
    };
    let parsed_keys = parse_signature_keys(signature_key_header)?;
    let signature_key = parsed_keys
        .into_iter()
        .find(|key| key.label == input.label)
        .ok_or_else(|| Error::field("Signature-Key", format!("missing label {:?}", input.label)))?;
    let signature = signature_for_label(signature_header, &input.label)?;
    let signature_base =
        build_signature_base(request, &input.components, &input.serialized_params)?;
    Ok(UnverifiedSignature {
        input,
        signature_key,
        signature,
        signature_base,
    })
}
