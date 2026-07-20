//! Parsing and construction for `Signature-Input`, `Signature`, and
//! `Signature-Key`.

use crate::keys::{private_key_to_jwk, Jwk, PrivateKey, PublicKey};
use crate::{Error, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use std::collections::HashMap;

/// A built-in Signature-Key distribution scheme.
#[derive(Debug, Clone)]
pub enum SigScheme<'a> {
    Hwk,
    JktJwt {
        jwt: &'a str,
    },
    JwksUri {
        id: &'a str,
        dwk: &'a str,
        kid: &'a str,
    },
    Jwt {
        jwt: &'a str,
    },
    SelfJwt {
        jwt: &'a str,
    },
    X509 {
        x5u: &'a str,
        /// Base64-encoded certificate thumbprint.
        x5t: &'a str,
    },
}

impl SigScheme<'_> {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hwk => "hwk",
            Self::JktJwt { .. } => "jkt-jwt",
            Self::JwksUri { .. } => "jwks_uri",
            Self::Jwt { .. } => "jwt",
            Self::SelfJwt { .. } => "self-jwt",
            Self::X509 { .. } => "x509",
        }
    }
}

fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

fn escape_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn string_parameter(name: &str, value: &str) -> String {
    format!("{name}=\"{}\"", escape_string(value))
}

/// Build one Signature-Key dictionary member.
pub fn build_signature_key_header(
    scheme: &SigScheme<'_>,
    private_key: Option<&PrivateKey>,
    label: &str,
) -> Result<String> {
    if !valid_key(label) {
        return Err(Error::field("Signature-Key", "invalid signature label"));
    }

    let parameters = match scheme {
        SigScheme::Hwk => {
            let private_key = private_key.ok_or_else(|| {
                Error::field("Signature-Key", "scheme=hwk requires a private key")
            })?;
            let jwk = private_key_to_jwk(private_key, None);
            let mut parameters = vec![
                string_parameter("kty", &jwk.kty),
                string_parameter("crv", jwk.crv.as_deref().unwrap_or_default()),
                string_parameter("x", jwk.x.as_deref().unwrap_or_default()),
            ];
            if let Some(y) = jwk.y.as_deref() {
                parameters.push(string_parameter("y", y));
            }
            parameters
        }
        SigScheme::JktJwt { jwt } | SigScheme::Jwt { jwt } | SigScheme::SelfJwt { jwt } => {
            vec![string_parameter("jwt", jwt)]
        }
        SigScheme::JwksUri { id, dwk, kid } => vec![
            string_parameter("id", id),
            string_parameter("dwk", dwk),
            string_parameter("kid", kid),
        ],
        SigScheme::X509 { x5u, x5t } => {
            vec![string_parameter("x5u", x5u), format!("x5t=:{x5t}:")]
        }
    };

    Ok(format!(
        "{label}={};{}",
        scheme.name(),
        parameters.join(";")
    ))
}

/// Parsed Signature-Key dictionary member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSignatureKey {
    pub label: String,
    pub scheme: String,
    pub params: HashMap<String, String>,
}

impl ParsedSignatureKey {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// Convert an `hwk` member's inline parameters to a JWK.
    pub fn hwk_jwk(&self) -> Result<Jwk> {
        if self.scheme != "hwk" {
            return Err(Error::key(format!(
                "expected Signature-Key scheme hwk, got {}",
                self.scheme
            )));
        }
        Ok(Jwk {
            kty: self.param("kty").unwrap_or_default().to_string(),
            crv: self.param("crv").map(str::to_string),
            x: self.param("x").map(str::to_string),
            y: self.param("y").map(str::to_string),
            n: self.param("n").map(str::to_string),
            e: self.param("e").map(str::to_string),
            kid: self.param("kid").map(str::to_string),
            alg: self.param("alg").map(str::to_string),
            use_: self.param("use").map(str::to_string),
        })
    }

    /// Convert an `hwk` member's inline parameters to a verification key.
    pub fn hwk_public_key(&self) -> Result<PublicKey> {
        self.hwk_jwk()?.to_public_key()
    }
}

fn split_dictionary(value: &str) -> Result<Vec<&str>> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut byte_sequence = false;
    let mut depth = 0usize;

    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if !byte_sequence && character == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted && character == ':' {
            byte_sequence = !byte_sequence;
            continue;
        }
        if quoted || byte_sequence {
            continue;
        }
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| Error::field("Structured Field", "unbalanced inner list"))?;
            }
            ',' if depth == 0 => {
                members.push(value[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }

    if quoted || escaped || byte_sequence || depth != 0 {
        return Err(Error::field(
            "Structured Field",
            "unterminated string, byte sequence, or inner list",
        ));
    }
    members.push(value[start..].trim());
    if members.iter().any(|member| member.is_empty()) {
        return Err(Error::field("Structured Field", "empty dictionary member"));
    }
    Ok(members)
}

fn parse_parameters(value: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b';') {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' && bytes[index] != b';' {
            index += 1;
        }
        if index == bytes.len() || bytes[index] != b'=' {
            return Err(Error::field("Signature-Key", "parameter must have a value"));
        }
        let key = value[key_start..index].trim();
        if !valid_key(key) {
            return Err(Error::field(
                "Signature-Key",
                format!("invalid parameter name {key:?}"),
            ));
        }
        index += 1;
        let parsed = if index < bytes.len() && bytes[index] == b'"' {
            index += 1;
            let mut output = String::new();
            let mut closed = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' if index + 1 < bytes.len() => {
                        output.push(bytes[index + 1] as char);
                        index += 2;
                    }
                    b'"' => {
                        index += 1;
                        closed = true;
                        break;
                    }
                    byte if byte.is_ascii() => {
                        output.push(byte as char);
                        index += 1;
                    }
                    _ => {
                        return Err(Error::field(
                            "Signature-Key",
                            "non-ASCII structured-field string",
                        ))
                    }
                }
            }
            if !closed {
                return Err(Error::field("Signature-Key", "unterminated string"));
            }
            output
        } else if index < bytes.len() && bytes[index] == b':' {
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index] != b':' {
                index += 1;
            }
            if index == bytes.len() {
                return Err(Error::field("Signature-Key", "unterminated byte sequence"));
            }
            let output = value[start..index].to_string();
            index += 1;
            output
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            value[start..index].trim().to_string()
        };
        if params.insert(key.to_string(), parsed).is_some() {
            return Err(Error::field(
                "Signature-Key",
                format!("duplicate parameter {key:?}"),
            ));
        }
    }
    Ok(params)
}

fn parse_signature_key_member(member: &str) -> Result<ParsedSignatureKey> {
    let (label, rest) = member
        .split_once('=')
        .ok_or_else(|| Error::field("Signature-Key", "missing '='"))?;
    let label = label.trim();
    if !valid_key(label) {
        return Err(Error::field("Signature-Key", "invalid signature label"));
    }

    // Compatibility with the pre-dictionary `label=(scheme=hwk ...)` form.
    if let Some(inner) = rest
        .trim()
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    {
        let normalized = inner.replace(' ', ";");
        let params = parse_parameters(&normalized)?;
        let scheme = params
            .get("scheme")
            .cloned()
            .ok_or_else(|| Error::field("Signature-Key", "missing scheme"))?;
        let params = params
            .into_iter()
            .filter(|(name, _)| name != "scheme")
            .collect();
        return Ok(ParsedSignatureKey {
            label: label.to_string(),
            scheme,
            params,
        });
    }

    let (scheme, parameter_text) = rest.trim().split_once(';').unwrap_or((rest.trim(), ""));
    if !valid_key(scheme) {
        return Err(Error::field("Signature-Key", "invalid scheme token"));
    }
    Ok(ParsedSignatureKey {
        label: label.to_string(),
        scheme: scheme.to_string(),
        params: parse_parameters(parameter_text)?,
    })
}

/// Parse the entire Signature-Key Structured Field Dictionary.
pub fn parse_signature_keys(header_value: &str) -> Result<Vec<ParsedSignatureKey>> {
    let members = split_dictionary(header_value)?;
    let mut parsed = Vec::with_capacity(members.len());
    for member in members {
        let key = parse_signature_key_member(member)?;
        if parsed
            .iter()
            .any(|existing: &ParsedSignatureKey| existing.label == key.label)
        {
            return Err(Error::field(
                "Signature-Key",
                format!("duplicate label {:?}", key.label),
            ));
        }
        parsed.push(key);
    }
    Ok(parsed)
}

/// Parse a single Signature-Key member.
///
/// This compatibility helper rejects dictionaries containing multiple keys;
/// use [`parse_signature_keys`] when selecting among multiple signatures.
pub fn parse_signature_key(header_value: &str) -> Result<ParsedSignatureKey> {
    let mut keys = parse_signature_keys(header_value)?;
    if keys.len() != 1 {
        return Err(Error::field(
            "Signature-Key",
            "expected exactly one dictionary member",
        ));
    }
    Ok(keys.remove(0))
}

/// Parsed Signature-Input dictionary member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureInput {
    pub label: String,
    pub components: Vec<String>,
    pub params: HashMap<String, String>,
    /// The inner-list and parameters exactly as serialized, used for
    /// `@signature-params`.
    pub serialized_params: String,
}

impl SignatureInput {
    pub fn created(&self) -> Option<i64> {
        self.params.get("created")?.parse().ok()
    }
}

pub fn build_signature_input_header(
    covered_components: &[String],
    label: &str,
    created: Option<i64>,
) -> String {
    let components = covered_components
        .iter()
        .map(|component| format!("\"{}\"", escape_string(component)))
        .collect::<Vec<_>>()
        .join(" ");
    match created {
        Some(created) => format!("{label}=({components});created={created}"),
        None => format!("{label}=({components})"),
    }
}

fn parse_input_member(member: &str) -> Result<SignatureInput> {
    let (label, serialized_params) = member
        .split_once('=')
        .ok_or_else(|| Error::field("Signature-Input", "missing '='"))?;
    let label = label.trim();
    if !valid_key(label) {
        return Err(Error::field("Signature-Input", "invalid signature label"));
    }
    let serialized_params = serialized_params.trim();
    let close = serialized_params
        .find(')')
        .ok_or_else(|| Error::field("Signature-Input", "unterminated component list"))?;
    let inner = serialized_params
        .strip_prefix('(')
        .ok_or_else(|| Error::field("Signature-Input", "expected inner list"))?;
    let inner = &inner[..close - 1];
    let mut components = Vec::new();
    let mut remaining = inner;
    loop {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        let after_quote = remaining
            .strip_prefix('"')
            .ok_or_else(|| Error::field("Signature-Input", "component must be a string"))?;
        let end = after_quote
            .find('"')
            .ok_or_else(|| Error::field("Signature-Input", "unterminated component string"))?;
        components.push(after_quote[..end].to_string());
        remaining = &after_quote[end + 1..];
    }
    let params =
        parse_parameters(&serialized_params[close + 1..]).map_err(|error| match error {
            Error::InvalidField { message, .. } => Error::field("Signature-Input", message),
            other => other,
        })?;
    Ok(SignatureInput {
        label: label.to_string(),
        components,
        params,
        serialized_params: serialized_params.to_string(),
    })
}

/// Parse one Signature-Input dictionary member.
pub fn parse_signature_input(header_value: &str) -> Result<SignatureInput> {
    let members = split_dictionary(header_value)?;
    if members.len() != 1 {
        return Err(Error::field(
            "Signature-Input",
            "expected exactly one dictionary member",
        ));
    }
    parse_input_member(members[0])
}

pub(crate) fn signature_input_for_label(header_value: &str, label: &str) -> Result<SignatureInput> {
    for member in split_dictionary(header_value)? {
        let input = parse_input_member(member)?;
        if input.label == label {
            return Ok(input);
        }
    }
    Err(Error::field(
        "Signature-Input",
        format!("missing label {label:?}"),
    ))
}

/// Build a Signature dictionary member using RFC 8941 base64.
pub fn build_signature_header(signature_bytes: &[u8], label: &str) -> String {
    format!("{label}=:{}:", STANDARD.encode(signature_bytes))
}

fn decode_signature(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(value.trim_end_matches('=')).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok())
}

pub(crate) fn signature_for_label(header_value: &str, label: &str) -> Result<Vec<u8>> {
    for member in split_dictionary(header_value)? {
        let (member_label, value) = member
            .split_once('=')
            .ok_or_else(|| Error::field("Signature", "missing '='"))?;
        if member_label.trim() != label {
            continue;
        }
        let encoded = value
            .trim()
            .strip_prefix(':')
            .and_then(|value| value.strip_suffix(':'))
            .ok_or_else(|| Error::field("Signature", "expected byte sequence"))?;
        return decode_signature(encoded)
            .ok_or_else(|| Error::field("Signature", "invalid base64"));
    }
    Err(Error::field(
        "Signature",
        format!("missing label {label:?}"),
    ))
}

pub fn parse_signature(header_value: &str, label: Option<&str>) -> Result<Vec<u8>> {
    let members = split_dictionary(header_value)?;
    let label = match label {
        Some(label) => label,
        None if members.len() == 1 => members[0]
            .split_once('=')
            .map(|(label, _)| label.trim())
            .ok_or_else(|| Error::field("Signature", "missing '='"))?,
        None => {
            return Err(Error::field(
                "Signature",
                "label required for multiple signatures",
            ))
        }
    };
    signature_for_label(header_value, label)
}
