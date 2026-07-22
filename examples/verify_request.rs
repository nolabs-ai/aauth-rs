//! Verify an inbound request on the resource side, including full auth-token
//! claim validation (`typ`, JWKS-discovered signature, `aud`, `agent`).
//!
//! Run: `cargo run --example verify_request`

use aauth_core::keys::{generate_ed25519_keypair, public_key_to_jwk};
use aauth_core::resource::RequestVerifier;
use aauth_core::signing::{sign_request, SigScheme, SignOptions};
use aauth_core::tokens::{create_auth_token, AuthTokenClaims};
use serde_json::json;
use std::collections::HashMap;

fn main() -> aauth_core::Result<()> {
    let agent_id = "aauth:alice@agents.example";

    // The agent's request-signing key, and the AS that issues auth tokens.
    let (agent_key, agent_public) = generate_ed25519_keypair();
    let (as_key, as_public) = generate_ed25519_keypair();

    // The AS mints an auth token bound to the agent's key (cnf.jwk).
    let auth_token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://resource.example".into(),
            agent: agent_id.into(),
            cnf_jwk: public_key_to_jwk(&agent_public, None),
            act: None,
            scope: Some("read".into()),
            sub: Some("user-1".into()),
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )?;

    // The agent signs the request with the jwt scheme carrying that token.
    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &agent_key,
        &SigScheme::Jwt { jwt: &auth_token },
        &SignOptions::default(),
    )?;

    // The resource verifies. The resolver serves the AS's JWKS for signature
    // discovery — an in-memory stand-in for `/.well-known` + JWKS fetching
    // (in production use `JwksFetcher` over an `HttpClient`).
    let as_jwks = json!({ "keys": [public_key_to_jwk(&as_public, Some("as-key-1")).to_value()] });
    let resolver = move |_id: &str, _dwk: Option<&str>, _kid: Option<&str>| Some(as_jwks.clone());

    let verifier = RequestVerifier::new(vec!["resource.example".to_string()])
        .with_resource_id("https://resource.example") // expected auth-token aud
        .with_jwks_resolver(&resolver); // needed for jwks_uri / jwt schemes

    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None, // body
        true, // require_identity
        true, // require_auth_token
    );

    assert!(result.valid, "verification failed: {:?}", result.error);
    println!(
        "valid — agent = {:?}, user = {:?}, scopes = {:?}",
        result.agent_id, result.user_sub, result.scopes
    );
    Ok(())
}
