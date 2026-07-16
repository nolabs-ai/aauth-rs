//! High-level request signing for the agent role.

use crate::errors::{AAuthError, Result};
use crate::keys::PrivateKey;
use crate::signing::{sign_request, SigScheme, SignOptions, SignatureHeaders};
use std::collections::HashMap;

/// High-level request signer for agents.
///
/// Chooses the right `Signature-Key` parameters for each scheme from the
/// agent's configured identity and tokens.
pub struct AgentRequestSigner {
    /// Agent's private signing key.
    pub private_key: PrivateKey,
    /// Agent identifier (HTTPS URL) — required for the `jwks_uri` scheme.
    pub agent_id: Option<String>,
    /// Agent token (`aa-agent+jwt`) — required for the `jwt` scheme.
    pub agent_token: Option<String>,
    /// Key ID for the `jwks_uri` scheme (default `"key-1"`).
    pub kid: String,
    /// Well-known metadata document name for the `jwks_uri` scheme
    /// (default `"aauth-agent.json"`).
    pub dwk: String,
}

impl AgentRequestSigner {
    pub fn new(private_key: PrivateKey) -> Self {
        AgentRequestSigner {
            private_key,
            agent_id: None,
            agent_token: None,
            kid: "key-1".to_string(),
            dwk: "aauth-agent.json".to_string(),
        }
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn with_agent_token(mut self, agent_token: impl Into<String>) -> Self {
        self.agent_token = Some(agent_token.into());
        self
    }

    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = kid.into();
        self
    }

    /// Sign an HTTP request with the named scheme (`"hwk"`, `"jwks_uri"`, or
    /// `"jwt"`). Inserts the signature headers into `headers`.
    ///
    /// For an explicit auth token (rather than the configured agent token),
    /// use [`AgentRequestSigner::sign_request_with_jwt`].
    pub fn sign_request(
        &self,
        method: &str,
        target_uri: &str,
        headers: &mut HashMap<String, String>,
        body: Option<&[u8]>,
        sig_scheme: &str,
    ) -> Result<SignatureHeaders> {
        match sig_scheme {
            "jwks_uri" => {
                let agent_id = self.agent_id.as_deref().ok_or_else(|| {
                    AAuthError::signature("agent_id required for jwks_uri scheme")
                })?;
                self.sign(
                    method,
                    target_uri,
                    headers,
                    body,
                    &SigScheme::JwksUri {
                        id: agent_id,
                        dwk: &self.dwk,
                        kid: &self.kid,
                    },
                )
            }
            "jwt" => {
                let agent_token = self
                    .agent_token
                    .as_deref()
                    .ok_or_else(|| AAuthError::signature("agent_token required for jwt scheme"))?;
                self.sign(
                    method,
                    target_uri,
                    headers,
                    body,
                    &SigScheme::Jwt { jwt: agent_token },
                )
            }
            "hwk" => self.sign(method, target_uri, headers, body, &SigScheme::Hwk),
            other => Err(AAuthError::signature(format!(
                "Unknown signature scheme: {other}"
            ))),
        }
    }

    /// Sign with the `jwt` scheme carrying an explicit JWT (e.g. an auth
    /// token obtained from a token exchange).
    pub fn sign_request_with_jwt(
        &self,
        method: &str,
        target_uri: &str,
        headers: &mut HashMap<String, String>,
        body: Option<&[u8]>,
        jwt: &str,
    ) -> Result<SignatureHeaders> {
        self.sign(method, target_uri, headers, body, &SigScheme::Jwt { jwt })
    }

    fn sign(
        &self,
        method: &str,
        target_uri: &str,
        headers: &mut HashMap<String, String>,
        body: Option<&[u8]>,
        scheme: &SigScheme<'_>,
    ) -> Result<SignatureHeaders> {
        sign_request(
            method,
            target_uri,
            headers,
            body,
            &self.private_key,
            scheme,
            &SignOptions::default(),
        )
    }
}
