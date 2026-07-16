//! Server and agent identifier validation for AAuth.
//!
//! Per spec: server identifiers use HTTPS URLs; agent identifiers use the
//! `aauth:` URI scheme of the form `aauth:local@domain`.

use crate::errors::{AAuthError, Result};
use url::Url;

fn is_valid_local_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '+' | '.')
}

/// Validate a DNS hostname per the server-identifier host rules
/// (spec §5.1 / §12.9.1): lowercase ASCII, dot-separated labels of
/// `[a-z0-9-]`, each 1–63 chars, no leading/trailing hyphen, total ≤ 253.
///
/// Internationalized domains must already be in ACE (punycode) form.
fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host != host.to_ascii_lowercase() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// Validate an agent identifier per AAuth spec (`aauth:local@domain` format).
///
/// Agent identifiers MUST be of the form `aauth:local@domain` where:
/// - The `local` part consists of lowercase ASCII letters (a-z), digits (0-9),
///   hyphen (-), underscore (_), plus (+), and period (.).
/// - The `local` part MUST NOT be empty and MUST NOT exceed 255 characters.
/// - The `domain` part MUST be a valid domain name (no scheme, no port).
pub fn validate_agent_identifier(identifier: &str) -> Result<&str> {
    if identifier.is_empty() {
        return Err(AAuthError::InvalidIdentifier(
            "Agent identifier must not be empty".into(),
        ));
    }

    let rest = identifier.strip_prefix("aauth:").ok_or_else(|| {
        AAuthError::InvalidIdentifier(format!(
            "Agent identifier must use aauth: scheme: {identifier:?}"
        ))
    })?;

    let (local, domain) = rest.split_once('@').ok_or_else(|| {
        AAuthError::InvalidIdentifier(format!(
            "Agent identifier must contain '@' separating local and domain: {identifier:?}"
        ))
    })?;

    if local.is_empty() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier local part must not be empty: {identifier:?}"
        )));
    }
    if local.len() > 255 {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier local part must not exceed 255 characters: {identifier:?}"
        )));
    }
    if !local.chars().all(is_valid_local_char) {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier local part contains invalid characters \
             (only a-z, 0-9, -, _, +, . allowed): {identifier:?}"
        )));
    }
    if domain.is_empty() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier domain part must not be empty: {identifier:?}"
        )));
    }
    if domain.contains("://") {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier domain must not include a scheme: {identifier:?}"
        )));
    }
    // The domain must conform to the server-identifier host rules
    // (spec §5.1 → §12.9.1): a valid, lowercase DNS hostname, no port.
    if domain.contains(':') {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier domain must not include a port: {identifier:?}"
        )));
    }
    if !is_valid_hostname(domain) {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Agent identifier domain is not a valid lowercase hostname: {identifier:?}"
        )));
    }

    Ok(identifier)
}

/// Parse an `aauth:local@domain` identifier into a `(local, domain)` tuple.
pub fn parse_agent_identifier(identifier: &str) -> Result<(&str, &str)> {
    validate_agent_identifier(identifier)?;
    let rest = &identifier["aauth:".len()..];
    Ok(rest.split_once('@').expect("validated above"))
}

/// Derive an `aauth:` identifier from an agent server URL.
///
/// For URLs with a port (e.g. localhost demos), the port is appended to the
/// `local` part so that multiple participants on the same host get distinct
/// identifiers. Production URLs without a port use `local` as-is.
///
/// Examples:
/// - `http://127.0.0.1:8001` → `aauth:agent-8001@127.0.0.1`
/// - `https://agent.example` → `aauth:agent@agent.example`
pub fn agent_identifier_from_server_url(server_url: &str, local: &str) -> String {
    let (host, port) = match Url::parse(server_url) {
        Ok(url) => (
            url.host_str().unwrap_or("localhost").to_string(),
            url.port(),
        ),
        Err(_) => ("localhost".to_string(), None),
    };
    match port {
        Some(port) => format!("aauth:{local}-{port}@{host}"),
        None => format!("aauth:{local}@{host}"),
    }
}

/// Validate a server identifier per AAuth spec Section 5.1.
///
/// Server identifiers (agent, resource, issuer) MUST:
/// - Use the https scheme
/// - Contain only scheme and host (no port, path, query, or fragment)
/// - Not include a trailing slash
/// - Be lowercase
pub fn validate_server_identifier(url: &str) -> Result<&str> {
    if url.is_empty() {
        return Err(AAuthError::InvalidIdentifier(
            "Server identifier must not be empty".into(),
        ));
    }

    let parsed = Url::parse(url).map_err(|e| {
        AAuthError::InvalidIdentifier(format!("Invalid server identifier {url}: {e}"))
    })?;

    if parsed.scheme() != "https" {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must use https scheme: {url}"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must have a hostname: {url}"
        )));
    }
    if parsed.port().is_some() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must not contain a port: {url}"
        )));
    }
    // `Url` normalizes an empty path to "/", so check the original string for
    // any path segment beyond the host.
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must not contain a path: {url}"
        )));
    }
    if parsed.query().is_some() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must not contain a query string: {url}"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must not contain a fragment: {url}"
        )));
    }
    if url.ends_with('/') {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must not include a trailing slash: {url}"
        )));
    }
    if url != url.to_lowercase() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Server identifier must be lowercase: {url}"
        )));
    }

    Ok(url)
}

/// Validate an endpoint URL per AAuth spec Section 5.2.
///
/// Endpoint URLs (token_endpoint, interaction_endpoint, etc.) MUST use the
/// https scheme, and contain no fragment or query string.
pub fn validate_endpoint_url(url: &str) -> Result<&str> {
    if url.is_empty() {
        return Err(AAuthError::InvalidIdentifier(
            "Endpoint URL must not be empty".into(),
        ));
    }
    let parsed = Url::parse(url)
        .map_err(|e| AAuthError::InvalidIdentifier(format!("Invalid endpoint URL {url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Endpoint URL must use https scheme: {url}"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Endpoint URL must not contain a fragment: {url}"
        )));
    }
    if parsed.query().is_some() {
        return Err(AAuthError::InvalidIdentifier(format!(
            "Endpoint URL must not contain a query string: {url}"
        )));
    }
    Ok(url)
}

/// Validate other URLs (jwks_uri, tos_uri, etc.) per AAuth spec Section 5.3.
///
/// These URLs MUST use the https scheme.
pub fn validate_other_url(url: &str) -> Result<&str> {
    if url.is_empty() {
        return Err(AAuthError::InvalidIdentifier(
            "URL must not be empty".into(),
        ));
    }
    let parsed = Url::parse(url)
        .map_err(|e| AAuthError::InvalidIdentifier(format!("Invalid URL {url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(AAuthError::InvalidIdentifier(format!(
            "URL must use https scheme: {url}"
        )));
    }
    Ok(url)
}
