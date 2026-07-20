use httpsig::{
    generate_ed25519_keypair, prepare_verification, sign_request, RequestParts, SigScheme,
    SignOptions,
};
use httpsig_policy::{
    verify_with_policy, Policy, PolicyError, VerificationError, VerificationPolicy,
};
use std::collections::HashMap;

fn signed_request(
    include_cookie: bool,
    cover_cookie: bool,
    created: i64,
) -> (
    HashMap<String, String>,
    httpsig::SignatureHeaders,
    httpsig::PublicKey,
) {
    let (private_key, public_key) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    if include_cookie {
        headers.insert("Cookie".into(), "email-verification=opaque".into());
    }
    let mut components = vec![
        "@method".into(),
        "@authority".into(),
        "@path".into(),
        "signature-key".into(),
    ];
    if cover_cookie {
        components.push("cookie".into());
    }
    let signed = sign_request(
        "POST",
        "https://verifier.example/verify",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions {
            covered_components: components,
            created: Some(created),
            ..Default::default()
        },
    )
    .unwrap();
    (headers, signed, public_key)
}

#[test]
fn default_policy_fails_closed_on_signature_key_scheme() {
    let now = 1_750_000_000;
    let (headers, signed, _) = signed_request(false, false, now);
    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/verify",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();

    assert_eq!(
        Policy::default().validate(&request, &prepared, now),
        Err(PolicyError::SchemeNotAllowed("hwk".into()))
    );
}

#[test]
fn email_style_policy_requires_cookie_only_when_present() {
    let now = 1_750_000_000;
    let policy = Policy::new()
        .allow_scheme("hwk")
        .require_header_when_present("cookie");
    let (headers, signed, public_key) = signed_request(true, true, now);
    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/verify",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();

    verify_with_policy(&policy, &request, &prepared, &public_key, now).unwrap();

    let (headers, signed, public_key) = signed_request(true, false, now);
    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/verify",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();
    let error = verify_with_policy(&policy, &request, &prepared, &public_key, now).unwrap_err();
    assert!(matches!(
        error,
        VerificationError::Policy(PolicyError::ConditionalComponentMissing { .. })
    ));
}

#[test]
fn rejects_stale_signatures() {
    let now = 1_750_000_100;
    let (headers, signed, _) = signed_request(false, false, now - 61);
    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/verify",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();

    assert_eq!(
        Policy::new()
            .allow_scheme("hwk")
            .validate(&request, &prepared, now),
        Err(PolicyError::Stale)
    );
}

#[test]
fn allowed_scheme_still_requires_request_binding() {
    let now = 1_750_000_000;
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    let signed = sign_request(
        "POST",
        "https://verifier.example/verify",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions {
            covered_components: vec!["signature-key".into()],
            created: Some(now),
            ..Default::default()
        },
    )
    .unwrap();
    let request = RequestParts {
        method: "POST",
        target_uri: "https://verifier.example/verify",
        headers: &headers,
        body: None,
    };
    let prepared = prepare_verification(
        &request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();

    assert_eq!(
        Policy::new()
            .allow_scheme("hwk")
            .validate(&request, &prepared, now),
        Err(PolicyError::MissingRequiredComponent("@authority".into()))
    );
}
