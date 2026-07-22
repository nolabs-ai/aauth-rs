//! Sign an outbound request three ways: pseudonymous (`hwk`), with agent
//! identity (`jwks_uri`), and with an auth token (`jwt`).
//!
//! Run: `cargo run --example sign_request`

use aauth_core::keys::{generate_ed25519_keypair, public_key_to_jwk};
use aauth_core::signing::{sign_request, SigScheme, SignOptions};
use aauth_core::tokens::{create_auth_token, AuthTokenClaims};
use std::collections::HashMap;

fn main() -> aauth_core::Result<()> {
    let (private_key, _public_key) = generate_ed25519_keypair();

    // Pseudonymous: the public key travels inline in the Signature-Key header.
    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers, // receives Signature-Input, Signature, Signature-Key
        None,         // body
        &private_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )?;
    println!("hwk       Signature-Key: {}", headers["Signature-Key"]);

    // Agent identity: the resource discovers the key via JWKS metadata.
    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &private_key,
        &SigScheme::JwksUri {
            id: "https://agent.example",
            dwk: "aauth-agent.json",
            kid: "key-1",
        },
        &SignOptions::default(),
    )?;
    println!("jwks_uri  Signature-Key: {}", headers["Signature-Key"]);

    // With an auth token (aa-auth+jwt). One is minted here for illustration;
    // in practice it comes from a token exchange with the auth/person server.
    let (as_key, _) = generate_ed25519_keypair();
    let auth_token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://resource.example".into(),
            agent: "aauth:alice@agents.example".into(),
            cnf_jwk: public_key_to_jwk(&private_key.public_key(), None),
            act: None,
            scope: Some("read".into()),
            sub: None,
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )?;
    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Jwt { jwt: &auth_token },
        &SignOptions::default(),
    )?;
    println!("jwt       Signature-Input: {}", headers["Signature-Input"]);

    Ok(())
}
