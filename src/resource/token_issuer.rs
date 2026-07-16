//! Resource token issuance for the resource role.

use crate::errors::{AAuthError, Result};
use crate::keys::{calculate_jwk_thumbprint, public_key_to_jwk, PrivateKey, PublicKey};
use crate::tokens::{create_resource_token, ResourceTokenClaims};

/// Issues resource tokens for agents.
pub struct ResourceTokenIssuer {
    pub resource_id: String,
    pub resource_private_key: PrivateKey,
    pub resource_kid: String,
    /// Auth server identifier — becomes the resource token's `aud`.
    pub auth_server: String,
}

impl ResourceTokenIssuer {
    pub fn new(
        resource_id: impl Into<String>,
        resource_private_key: PrivateKey,
        resource_kid: impl Into<String>,
        auth_server: impl Into<String>,
    ) -> Self {
        ResourceTokenIssuer {
            resource_id: resource_id.into(),
            resource_private_key,
            resource_kid: resource_kid.into(),
            auth_server: auth_server.into(),
        }
    }

    /// Issue a resource token for `agent_id` bound to `agent_public_key`.
    pub fn issue_token(
        &self,
        agent_id: &str,
        agent_public_key: &PublicKey,
        scope: &str,
        exp: Option<i64>,
    ) -> Result<String> {
        let agent_jwk = public_key_to_jwk(agent_public_key, None);
        let agent_jkt = calculate_jwk_thumbprint(&agent_jwk)?;

        create_resource_token(
            &ResourceTokenClaims {
                iss: self.resource_id.clone(),
                aud: self.auth_server.clone(),
                agent: agent_id.to_string(),
                agent_jkt,
                scope: scope.to_string(),
                exp,
                mission: None,
            },
            &self.resource_private_key,
            &self.resource_kid,
        )
        .map_err(|e| {
            AAuthError::token(
                format!("Failed to issue resource token: {e}"),
                "aa-resource+jwt",
            )
        })
    }
}
