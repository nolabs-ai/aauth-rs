//! Exchange a resource token for an auth token via the person server.
//!
//! This needs the `reqwest-client` feature and a reachable PS, so it only
//! performs the exchange when you supply a resource token from a real 401
//! challenge:
//!
//! ```text
//! AAUTH_RESOURCE_TOKEN=<jwt> cargo run --example exchange_resource_token \
//!     --features reqwest-client
//! ```
//!
//! Without the env var it prints usage and exits, so it is always safe to run.

use aauth_core::agent::{exchange_resource_token, ExchangeOptions};
use aauth_core::http::ReqwestClient;
use aauth_core::keys::{generate_ed25519_keypair, public_key_to_jwk};
use aauth_core::tokens::{create_agent_token, AgentTokenClaims};

fn main() -> aauth_core::Result<()> {
    let Ok(resource_token) = std::env::var("AAUTH_RESOURCE_TOKEN") else {
        eprintln!(
            "set AAUTH_RESOURCE_TOKEN=<jwt> (extracted from a 401 challenge) to run the exchange"
        );
        return Ok(());
    };

    // The agent's request-signing key and an aa-agent+jwt for the
    // Signature-Key header. In practice the agent token comes from the agent
    // server; it is self-issued here only to make the example self-contained.
    let (agent_key, agent_public) = generate_ed25519_keypair();
    let (server_key, _) = generate_ed25519_keypair();
    let agent_jwt = create_agent_token(
        &AgentTokenClaims::new(
            "https://agents.example",
            "delegate-1",
            public_key_to_jwk(&agent_public, None),
        ),
        &server_key,
        "as-key-1",
    )?;

    let client = ReqwestClient::new();
    let auth_token = exchange_resource_token(
        &client,
        &resource_token,
        &agent_key,
        &agent_jwt,
        &ExchangeOptions {
            // Required: pin your own PS and identity. The resource token is
            // verified (iss == the resource you called, agent == you,
            // agent_jkt == your key, exp valid) BEFORE anything is sent, and
            // the request only ever goes to your pinned PS — so a malicious
            // resource cannot redirect it to an attacker-controlled server.
            expected_ps: Some("https://ps.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_resource_iss: Some("https://resource.example"),
            on_interaction: Some(&|url, code| {
                println!("Please visit {url} and enter code {code}");
            }),
            ..Default::default()
        },
    )?;

    println!("got auth token ({} bytes)", auth_token.len());
    // Retry the original request signed with `SigScheme::Jwt { jwt: &auth_token }`.
    Ok(())
}
