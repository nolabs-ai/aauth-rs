//! AAuth challenge building for the resource role.

use crate::errors::{AAuthError, Result};
use crate::headers::{
    build_accept_signature, build_auth_token_requirement, HEADER_AAUTH_REQUIREMENT,
    HEADER_ACCEPT_SIGNATURE, SIGKEY_JKT, SIGKEY_URI,
};
use crate::keys::{calculate_jwk_thumbprint, public_key_to_jwk, PrivateKey, PublicKey};
use crate::tokens::{create_resource_token, ResourceTokenClaims};

/// What the challenge should require of the agent.
#[derive(Debug, Clone, Default)]
pub struct ChallengeRequest<'a> {
    /// Require verified agent identity (`Accept-Signature` with `sigkey=uri`).
    pub require_identity: bool,
    /// Require an auth token (`AAuth-Requirement` carrying a resource token).
    pub require_auth_token: bool,
    /// Agent identifier — required for auth-token challenges.
    pub agent_id: Option<&'a str>,
    /// Agent's public key — required for auth-token challenges.
    pub agent_public_key: Option<&'a PublicKey>,
    /// Required scope — required for auth-token challenges.
    pub scope: Option<&'a str>,
    /// Covered components for `Accept-Signature`.
    pub components: Option<&'a [&'a str]>,
    /// Acceptable algorithms for `Accept-Signature`.
    pub algs: Option<&'a [&'a str]>,
}

/// Builds AAuth challenges for resources.
///
/// Returns `(header_name, header_value)` pairs so callers know which header
/// to set: pseudonym and identity levels use `Accept-Signature` per
/// draft-hardt-httpbis-signature-key; the auth-token level uses
/// `AAuth-Requirement`.
pub struct ChallengeBuilder {
    pub resource_id: String,
    pub resource_private_key: PrivateKey,
    pub resource_kid: String,
    /// Auth server identifier — becomes the resource token's `aud`.
    pub auth_server: String,
}

impl ChallengeBuilder {
    pub fn new(
        resource_id: impl Into<String>,
        resource_private_key: PrivateKey,
        resource_kid: impl Into<String>,
        auth_server: impl Into<String>,
    ) -> Self {
        ChallengeBuilder {
            resource_id: resource_id.into(),
            resource_private_key,
            resource_kid: resource_kid.into(),
            auth_server: auth_server.into(),
        }
    }

    /// Build an AAuth challenge as a `(header_name, header_value)` pair.
    pub fn build_challenge(
        &self,
        request: &ChallengeRequest<'_>,
    ) -> Result<(&'static str, String)> {
        if request.require_auth_token {
            let (agent_id, agent_public_key, scope) =
                match (request.agent_id, request.agent_public_key, request.scope) {
                    (Some(id), Some(key), Some(scope)) => (id, key, scope),
                    _ => return Err(AAuthError::challenge(
                        "agent_id, agent_public_key, and scope required for auth-token challenge",
                    )),
                };

            let agent_jwk = public_key_to_jwk(agent_public_key, None);
            let agent_jkt = calculate_jwk_thumbprint(&agent_jwk)?;

            let resource_token = create_resource_token(
                &ResourceTokenClaims {
                    iss: self.resource_id.clone(),
                    aud: self.auth_server.clone(),
                    agent: agent_id.to_string(),
                    agent_jkt,
                    scope: scope.to_string(),
                    exp: None,
                    mission: None,
                },
                &self.resource_private_key,
                &self.resource_kid,
            )?;

            return Ok((
                HEADER_AAUTH_REQUIREMENT,
                build_auth_token_requirement(&resource_token),
            ));
        }

        let sigkey = if request.require_identity {
            SIGKEY_URI
        } else {
            SIGKEY_JKT
        };
        Ok((
            HEADER_ACCEPT_SIGNATURE,
            build_accept_signature(sigkey, request.components, request.algs),
        ))
    }
}
