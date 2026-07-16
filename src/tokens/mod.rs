//! AAuth token creation and verification: agent tokens (`aa-agent+jwt`),
//! auth tokens (`aa-auth+jwt`), and resource tokens (`aa-resource+jwt`).

mod agent_token;
mod auth_token;
mod resource_token;

pub use agent_token::{create_agent_token, verify_agent_token, AgentTokenClaims};
pub use auth_token::{
    build_act_claim, create_auth_token, parse_token_claims, verify_token, verify_upstream_token,
    AuthTokenClaims, ParsedToken, UpstreamVerification, VerifyTokenOptions, VerifyUpstreamOptions,
};
pub use resource_token::{
    create_resource_token, verify_resource_token, ResourceTokenClaims, VerifyResourceTokenOptions,
};
