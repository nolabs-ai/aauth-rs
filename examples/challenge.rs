//! Build a 401 challenge that requires an auth token. The challenge carries a
//! freshly minted resource token bound to the agent's key.
//!
//! Run: `cargo run --example challenge`

use aauth_core::keys::generate_ed25519_keypair;
use aauth_core::resource::{ChallengeBuilder, ChallengeRequest};

fn main() -> aauth_core::Result<()> {
    let (resource_private_key, _) = generate_ed25519_keypair();
    let (_, agent_public_key) = generate_ed25519_keypair();

    let builder = ChallengeBuilder::new(
        "https://resource.example",
        resource_private_key,
        "res-key-1",
        "https://as.example",
    );

    let (header_name, header_value) = builder.build_challenge(&ChallengeRequest {
        require_auth_token: true,
        agent_id: Some("aauth:alice@agents.example"),
        agent_public_key: Some(&agent_public_key),
        scope: Some("read"),
        ..Default::default()
    })?;

    println!("respond 401 with:\n{header_name}: {header_value}");
    Ok(())
}
