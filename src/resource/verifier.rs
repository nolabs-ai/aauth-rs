//! Request verification for the resource role.

use crate::jwt::decode_unverified;
use crate::keys::JwksResolver;
use crate::signing::{parse_signature_key, verify_signature, VerifyOptions};
use crate::tokens::{verify_agent_token, verify_token, VerifyTokenOptions};
use crate::util::get_header;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

/// The outcome of verifying an inbound request.
#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    pub valid: bool,
    /// Agent identifier, when the scheme conveys identity.
    pub agent_id: Option<String>,
    /// Actor claim (delegation chain) from an auth token.
    pub act: Option<Value>,
    /// User identifier (`sub`) from an auth token.
    pub user_sub: Option<String>,
    /// Authorized scopes from an auth token.
    pub scopes: Option<Vec<String>>,
    pub error: Option<String>,
}

impl VerificationResult {
    fn failure(error: impl Into<String>) -> Self {
        VerificationResult {
            valid: false,
            error: Some(error.into()),
            ..Default::default()
        }
    }
}

/// Verifies incoming requests for resources.
pub struct RequestVerifier<'a> {
    /// Canonical authorities (`host` or `host:port`) per SPEC 10.3.1.
    pub canonical_authorities: Vec<String>,
    /// This resource's own identifier (HTTPS URL). REQUIRED to validate auth
    /// tokens: it is the expected `aud`, without which a token minted for a
    /// different resource would be accepted (spec §9.4.3).
    pub resource_id: Option<String>,
    /// Resolver for `jwks_uri` / `jwt` scheme key discovery.
    pub jwks_resolver: Option<&'a dyn JwksResolver>,
    /// Trusted auth server identifiers (reserved for policy checks).
    pub trusted_auth_servers: Vec<String>,
}

impl<'a> RequestVerifier<'a> {
    pub fn new(canonical_authorities: Vec<String>) -> Self {
        RequestVerifier {
            canonical_authorities,
            resource_id: None,
            jwks_resolver: None,
            trusted_auth_servers: Vec::new(),
        }
    }

    /// Set this resource's own identifier (the expected auth-token `aud`).
    pub fn with_resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    pub fn with_jwks_resolver(mut self, resolver: &'a dyn JwksResolver) -> Self {
        self.jwks_resolver = Some(resolver);
        self
    }

    /// Verify an inbound request: signature headers present, authority
    /// allowed, HTTP signature valid; then extract identity/authorization
    /// info from the Signature-Key scheme.
    pub fn verify_request(
        &self,
        method: &str,
        target_uri: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        require_identity: bool,
        require_auth_token: bool,
    ) -> VerificationResult {
        let signature_input = get_header(headers, "signature-input");
        let signature = get_header(headers, "signature");
        let signature_key = get_header(headers, "signature-key");

        let (signature_input, signature, signature_key) =
            match (signature_input, signature, signature_key) {
                (Some(input), Some(sig), Some(key)) => {
                    (input.to_string(), sig.to_string(), key.to_string())
                }
                _ => return VerificationResult::failure("Missing signature headers"),
            };

        // Parse Signature-Key to determine the scheme
        let parsed_key = match parse_signature_key(&signature_key) {
            Ok(parsed) => parsed,
            Err(e) => return VerificationResult::failure(format!("Invalid Signature-Key: {e}")),
        };

        // Check canonical authority
        let request_authority = match Url::parse(target_uri) {
            Ok(parsed) => match (parsed.host_str(), parsed.port()) {
                (Some(host), Some(port)) => format!("{host}:{port}"),
                (Some(host), None) => host.to_string(),
                _ => return VerificationResult::failure("Target URI has no host"),
            },
            Err(e) => return VerificationResult::failure(format!("Invalid target URI: {e}")),
        };
        if !self.canonical_authorities.contains(&request_authority) {
            return VerificationResult::failure(format!(
                "Request authority {request_authority} not in canonical authorities"
            ));
        }

        // Verify signature
        let options = VerifyOptions {
            jwks_resolver: self.jwks_resolver,
            ..Default::default()
        };
        match verify_signature(
            method,
            target_uri,
            headers,
            body,
            &signature_input,
            &signature,
            &signature_key,
            &options,
        ) {
            Ok(true) => {}
            Ok(false) => return VerificationResult::failure("Signature verification failed"),
            Err(e) => return VerificationResult::failure(e.to_string()),
        }

        // Extract identity / authorization info from the scheme
        let mut result = VerificationResult {
            valid: true,
            ..Default::default()
        };

        match parsed_key.scheme.as_str() {
            "jwks_uri" => {
                // Identity via JWKS URI discovery — agent_id from the 'id' param
                result.agent_id = parsed_key.param("id").map(String::from);
            }
            "jwt" => {
                // Identity/authorization via JWT. The HTTP signature check
                // above already bound cnf.jwk to the signing key; here we
                // MUST also validate the token's own claims (typ, iss, aud,
                // agent) rather than trusting them unverified — otherwise a
                // token minted for another resource is accepted (§9.4.3).
                let Some(jwt_token) = parsed_key.param("jwt") else {
                    return VerificationResult::failure("jwt scheme missing token");
                };
                let Some(resolver) = self.jwks_resolver else {
                    return VerificationResult::failure(
                        "jwks_resolver required to validate token claims",
                    );
                };
                // Peek at the type to pick the right validation path.
                let typ = decode_unverified(jwt_token)
                    .ok()
                    .and_then(|p| p.typ().map(String::from));
                match typ.as_deref() {
                    Some("aa-agent+jwt") => match verify_agent_token(jwt_token, resolver, None) {
                        Ok(claims) => {
                            result.agent_id =
                                claims.get("sub").and_then(Value::as_str).map(String::from);
                        }
                        Err(e) => {
                            return VerificationResult::failure(format!(
                                "agent token validation failed: {e}"
                            ));
                        }
                    },
                    Some("aa-auth+jwt") => {
                        let Some(resource_id) = self.resource_id.as_deref() else {
                            return VerificationResult::failure(
                                "resource_id required to validate auth tokens (expected aud)",
                            );
                        };
                        let options = VerifyTokenOptions {
                            expected_typ: Some("aa-auth+jwt"),
                            expected_aud: Some(resource_id),
                            ..Default::default()
                        };
                        match verify_token(jwt_token, resolver, &options) {
                            Ok(claims) => {
                                result.agent_id = claims
                                    .get("agent")
                                    .and_then(Value::as_str)
                                    .map(String::from);
                                result.user_sub =
                                    claims.get("sub").and_then(Value::as_str).map(String::from);
                                result.act = claims.get("act").cloned();
                                if let Some(scope) = claims.get("scope").and_then(Value::as_str) {
                                    result.scopes =
                                        Some(scope.split_whitespace().map(String::from).collect());
                                }
                            }
                            Err(e) => {
                                return VerificationResult::failure(format!(
                                    "auth token validation failed: {e}"
                                ));
                            }
                        }
                    }
                    _ => {
                        return VerificationResult::failure(
                            "unsupported JWT type in Signature-Key",
                        );
                    }
                }
            }
            // hwk / jkt-jwt are pseudonymous — no identity
            _ => {}
        }

        // Check requirements
        if require_identity && result.agent_id.is_none() {
            return VerificationResult::failure("Agent identity required but not present");
        }
        if require_auth_token && result.scopes.is_none() {
            return VerificationResult::failure("Auth token required but not present");
        }

        result
    }
}
