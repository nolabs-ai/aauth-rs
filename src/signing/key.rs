//! `Signature-Key` header parsing and building.
//!
//! Supports schemes per draft-hardt-httpbis-signature-key:
//! - `hwk`: hardware/inline public key (pseudonymous)
//! - `jkt-jwt`: self-issued key delegation from a hardware-backed enclave key
//! - `jwks_uri`: reference to a JWKS endpoint (identity)
//! - `jwt`: JWT containing the public key in the `cnf` claim (identity)
//! - `x509`: X.509 certificate reference (build only; verification not implemented)

use crate::errors::{AAuthError, Result};
use crate::keys::{private_key_to_jwk, PrivateKey};
use std::collections::HashMap;

/// The key discovery scheme carried in a `Signature-Key` header.
#[derive(Debug, Clone)]
pub enum SigScheme<'a> {
    /// Inline public key derived from the signing key (pseudonymous).
    Hwk,
    /// Self-issued key-delegation JWT from an enclave key (pseudonymous).
    JktJwt { jwt: &'a str },
    /// JWKS URI discovery: signer identifier, well-known metadata document
    /// name, and key id.
    JwksUri {
        id: &'a str,
        dwk: &'a str,
        kid: &'a str,
    },
    /// JWT with a `cnf.jwk` confirmation key (agent token or auth token).
    Jwt { jwt: &'a str },
    /// X.509 certificate reference (`x5t` is base64, formatted as `:b64:`).
    X509 { x5u: &'a str, x5t: &'a str },
}

impl SigScheme<'_> {
    /// The scheme token as it appears in the header.
    pub fn name(&self) -> &'static str {
        match self {
            SigScheme::Hwk => "hwk",
            SigScheme::JktJwt { .. } => "jkt-jwt",
            SigScheme::JwksUri { .. } => "jwks_uri",
            SigScheme::Jwt { .. } => "jwt",
            SigScheme::X509 { .. } => "x509",
        }
    }
}

/// Escape a value for use inside an RFC 8941 quoted string.
fn escape_sf_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn format_sf_parameters(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_sf_string(v)))
        .collect::<Vec<_>>()
        .join(";")
}

/// Build a `Signature-Key` header value as an RFC 8941 Structured Fields
/// Dictionary member: `label=scheme;param="value";...`.
///
/// For the `hwk` scheme the public key parameters are extracted from
/// `private_key` (required in that case).
///
/// The label must match the label used in the `Signature-Input` and
/// `Signature` headers.
pub fn build_signature_key_header(
    scheme: &SigScheme<'_>,
    private_key: Option<&PrivateKey>,
    label: &str,
) -> Result<String> {
    match scheme {
        SigScheme::Hwk => {
            let private_key = private_key
                .ok_or_else(|| AAuthError::signature("scheme=hwk requires a private key"))?;
            let jwk = private_key_to_jwk(private_key, None);
            let crv = jwk.crv.as_deref().unwrap_or_default().to_string();
            let x = jwk.x.as_deref().unwrap_or_default().to_string();
            let mut pairs: Vec<(&str, &str)> = vec![("kty", &jwk.kty), ("crv", &crv), ("x", &x)];
            let y = jwk.y.clone();
            if let Some(y) = y.as_deref() {
                pairs.push(("y", y));
            }
            Ok(format!("{label}=hwk;{}", format_sf_parameters(&pairs)))
        }
        SigScheme::JktJwt { jwt } => Ok(format!(
            "{label}=jkt-jwt;{}",
            format_sf_parameters(&[("jwt", jwt)])
        )),
        SigScheme::JwksUri { id, dwk, kid } => Ok(format!(
            "{label}=jwks_uri;{}",
            format_sf_parameters(&[("id", id), ("dwk", dwk), ("kid", kid)])
        )),
        SigScheme::Jwt { jwt } => Ok(format!(
            "{label}=jwt;{}",
            format_sf_parameters(&[("jwt", jwt)])
        )),
        SigScheme::X509 { x5u, x5t } => Ok(format!(
            "{label}=x509;x5u=\"{}\";x5t=:{x5t}:",
            escape_sf_string(x5u)
        )),
    }
}

/// A parsed `Signature-Key` header.
#[derive(Debug, Clone, Default)]
pub struct ParsedSignatureKey {
    pub label: String,
    /// The scheme token (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt`, `x509`).
    pub scheme: String,
    pub params: HashMap<String, String>,
}

impl ParsedSignatureKey {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
}

/// Parse RFC 8941 Item parameters after the scheme token.
fn parse_sf_parameters(param_str: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let chars: Vec<char> = param_str.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        while i < n && (chars[i] == ' ' || chars[i] == '\t' || chars[i] == ';') {
            i += 1;
        }
        if i >= n {
            break;
        }
        let key_start = i;
        while i < n && chars[i] != '=' {
            i += 1;
        }
        if i >= n {
            break;
        }
        let key: String = chars[key_start..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();
        i += 1; // skip '='
        if i >= n {
            params.insert(key, String::new());
            break;
        }
        if chars[i] == '"' {
            i += 1;
            let mut buf = String::new();
            while i < n {
                let c = chars[i];
                if c == '\\' && i + 1 < n {
                    buf.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == '"' {
                    i += 1;
                    break;
                }
                buf.push(c);
                i += 1;
            }
            params.insert(key, buf);
        } else {
            let value_start = i;
            while i < n && chars[i] != ';' {
                i += 1;
            }
            let value: String = chars[value_start..i]
                .iter()
                .collect::<String>()
                .trim()
                .to_string();
            params.insert(key, value);
        }
    }
    params
}

/// Parse the legacy inner-list form `label=(scheme=hwk kty="..." ...)`
/// emitted by older library versions.
fn parse_inner_list_legacy(label: &str, inner: &str) -> Result<ParsedSignatureKey> {
    let mut params = HashMap::new();
    let mut scheme = None;

    let bytes: Vec<char> = inner.chars().collect();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        while i < n && bytes[i].is_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }
        let key_start = i;
        while i < n && bytes[i] != '=' && !bytes[i].is_whitespace() {
            i += 1;
        }
        if i >= n || bytes[i] != '=' {
            break;
        }
        let key: String = bytes[key_start..i].iter().collect();
        i += 1;
        let value: String;
        if i < n && bytes[i] == '"' {
            i += 1;
            let value_start = i;
            while i < n && bytes[i] != '"' {
                i += 1;
            }
            value = bytes[value_start..i].iter().collect();
            if i < n {
                i += 1;
            }
        } else {
            let value_start = i;
            while i < n && !bytes[i].is_whitespace() && bytes[i] != ')' {
                i += 1;
            }
            value = bytes[value_start..i].iter().collect();
        }
        if key == "scheme" {
            scheme = Some(value);
        } else {
            params.insert(key, value);
        }
    }

    let scheme = scheme.ok_or_else(|| {
        AAuthError::signature(format!("Missing scheme in Signature-Key: ({inner})"))
    })?;
    Ok(ParsedSignatureKey {
        label: label.to_string(),
        scheme,
        params,
    })
}

/// Parse a `Signature-Key` header value.
///
/// Accepts the spec form `label=scheme;param="value";...` and the legacy
/// inner-list form `label=(scheme=hwk ...)`.
pub fn parse_signature_key(header_value: &str) -> Result<ParsedSignatureKey> {
    let value = header_value.trim();
    let eq = value
        .find('=')
        .ok_or_else(|| AAuthError::signature(format!("Invalid Signature-Key format: {value}")))?;
    let label = value[..eq].trim();
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AAuthError::signature(format!(
            "Invalid Signature-Key format: {value}"
        )));
    }
    let rest = value[eq + 1..].trim();

    if rest.starts_with('(') && rest.ends_with(')') {
        return parse_inner_list_legacy(label, &rest[1..rest.len() - 1]);
    }

    if rest.is_empty() {
        return Err(AAuthError::signature("Missing scheme in Signature-Key"));
    }

    let (scheme, param_str) = match rest.find(';') {
        Some(semicolon) => (rest[..semicolon].trim(), &rest[semicolon + 1..]),
        None => (rest, ""),
    };
    if scheme.is_empty() {
        return Err(AAuthError::signature("Missing scheme in Signature-Key"));
    }

    Ok(ParsedSignatureKey {
        label: label.to_string(),
        scheme: scheme.to_string(),
        params: parse_sf_parameters(param_str),
    })
}
