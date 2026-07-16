//! AAuth challenge handling for the agent role.

use crate::errors::{AAuthError, Result};
use crate::headers::{parse_aauth_header, ParsedRequirement, REQUIRE_AUTH_TOKEN, REQUIRE_IDENTITY};

/// Handles AAuth challenges from resources and auth servers.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChallengeHandler;

impl ChallengeHandler {
    pub fn new() -> Self {
        ChallengeHandler
    }

    /// Parse an AAuth challenge header value.
    pub fn parse_challenge(&self, aauth_header: &str) -> Result<ParsedRequirement> {
        parse_aauth_header(aauth_header)
    }

    /// Determine which signature scheme to use in response to a challenge:
    /// `"hwk"`, `"jwks_uri"`, or `"jwt"`.
    pub fn determine_response_scheme(
        &self,
        challenge: &ParsedRequirement,
        has_agent_token: bool,
        has_auth_token: bool,
    ) -> Result<&'static str> {
        match challenge.requirement.as_deref() {
            Some(REQUIRE_AUTH_TOKEN) => {
                if has_auth_token {
                    Ok("jwt")
                } else {
                    Err(AAuthError::challenge(
                        "Challenge requires auth token but agent doesn't have one",
                    ))
                }
            }
            Some(REQUIRE_IDENTITY) => {
                if has_agent_token {
                    Ok("jwt")
                } else {
                    Ok("jwks_uri")
                }
            }
            // Pseudonym or other — just sign with hwk
            _ => Ok("hwk"),
        }
    }
}
