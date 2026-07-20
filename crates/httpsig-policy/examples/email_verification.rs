//! An Email Verification-shaped HTTP Message Signature policy.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p aauth-httpsig-policy --example email_verification
//! ```

use httpsig::{
    generate_ed25519_keypair, prepare_verification, sign_request, RequestParts, SigScheme,
    SignOptions,
};
use httpsig_policy::{Policy, VerificationPolicy};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::from([(
        "Cookie".to_string(),
        "__Host-email-verification=opaque-value".to_string(),
    )]);

    let signed = sign_request(
        "POST",
        "https://verifier.example/email-verification",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions {
            covered_components: vec![
                "@method".into(),
                "@authority".into(),
                "@path".into(),
                "cookie".into(),
                "signature-key".into(),
            ],
            ..Default::default()
        },
    )?;

    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/email-verification",
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

    // The profile explicitly permits hwk, requires the standard request
    // binding, accepts signatures for 60 seconds, and requires Cookie to be
    // covered whenever the request carries one.
    let policy = Policy::new()
        .allow_scheme("hwk")
        .require_header_when_present("cookie")
        .max_age_seconds(60);

    // Apply policy before key resolution. This ordering is important for
    // schemes whose key resolution could involve network access.
    policy.validate(&request, &prepared, now_unix())?;
    let public_key = prepared.signature_key.hwk_public_key()?;
    prepared.verify(&public_key)?;

    println!("accepted Email Verification-shaped signature");
    println!("covered components: {:?}", prepared.components());
    Ok(())
}
