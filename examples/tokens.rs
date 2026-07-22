//! Create and verify an agent token (`aa-agent+jwt`).
//!
//! Run: `cargo run --example tokens`

use aauth_core::keys::{generate_ed25519_keypair, public_key_to_jwk};
use aauth_core::tokens::{create_agent_token, verify_agent_token, AgentTokenClaims};
use serde_json::json;

fn main() -> aauth_core::Result<()> {
    let (server_key, server_public) = generate_ed25519_keypair();
    let (_, delegate_public) = generate_ed25519_keypair();

    let token = create_agent_token(
        &AgentTokenClaims::new(
            "https://agents.example",
            "delegate-1",
            public_key_to_jwk(&delegate_public, None),
        ),
        &server_key,
        "as-key-1",
    )?;

    // In-memory resolver standing in for JWKS discovery of the agent server.
    let jwks = json!({ "keys": [public_key_to_jwk(&server_public, Some("as-key-1")).to_value()] });
    let resolver = move |_iss: &str, _dwk: Option<&str>, _kid: Option<&str>| Some(jwks.clone());

    let claims = verify_agent_token(&token, &resolver, None)?;
    println!(
        "verified agent token — iss = {}, sub = {}",
        claims["iss"], claims["sub"]
    );
    Ok(())
}
