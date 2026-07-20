//! Sign and cryptographically verify a request using an inline `hwk`.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p aauth-httpsig --example sign_and_verify
//! ```

use httpsig::{
    generate_ed25519_keypair, prepare_verification, sign_request, RequestParts, SigScheme,
    SignOptions,
};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();

    let signed = sign_request(
        "POST",
        "https://service.example/messages",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )?;

    let request = RequestParts {
        method: "POST",
        target_uri: "https://service.example/messages",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )?;

    // An hwk proves possession of the inline key. Deciding whether that proof
    // is acceptable or maps to an identity belongs to application policy.
    let public_key = prepared.signature_key.hwk_public_key()?;
    prepared.verify(&public_key)?;

    println!("Signature-Input: {}", signed.signature_input);
    println!("Signature-Key: {}", signed.signature_key);
    println!("signature is cryptographically valid");
    Ok(())
}
