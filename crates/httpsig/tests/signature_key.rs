use httpsig::{
    generate_ed25519_keypair, prepare_verification, sign_request, RequestParts, SigScheme,
    SignOptions,
};
use std::collections::HashMap;

#[test]
fn signs_and_verifies_email_verification_shape() {
    let (private_key, public_key) = generate_ed25519_keypair();
    let mut headers = HashMap::from([(
        "Cookie".to_string(),
        "__Host-email-verification=opaque".to_string(),
    )]);
    let options = SignOptions {
        covered_components: vec![
            "@method".into(),
            "@authority".into(),
            "@path".into(),
            "signature-key".into(),
            "cookie".into(),
        ],
        created: Some(1_750_000_000),
        ..Default::default()
    };

    let signed = sign_request(
        "POST",
        "https://verifier.example/email-verification",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &options,
    )
    .unwrap();
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
    )
    .unwrap();

    assert_eq!(prepared.signature_key.scheme, "hwk");
    assert_eq!(prepared.created(), Some(1_750_000_000));
    prepared.verify(&public_key).unwrap();

    let inline_key = prepared.signature_key.hwk_public_key().unwrap();
    prepared.verify(&inline_key).unwrap();
}

#[test]
fn content_digest_coverage_rejects_a_body_swapped_after_signing() {
    // Regression test: covering `content-digest` signs the header's *text*,
    // not the body itself. If nothing recomputes the digest from the actual
    // received body and compares it, a party that swaps the body while
    // leaving the original (still correctly-signed) Content-Digest header
    // in place would pass verification despite the body no longer matching
    // what was signed.
    let (private_key, public_key) = generate_ed25519_keypair();
    let original_body = br#"{"amount":10}"#;
    let mut headers = HashMap::new();
    let options = SignOptions {
        covered_components: vec![
            "@method".into(),
            "@authority".into(),
            "@path".into(),
            "signature-key".into(),
            "content-digest".into(),
        ],
        created: Some(1_750_000_000),
        ..Default::default()
    };
    headers.insert(
        "content-digest".to_string(),
        httpsig::calculate_content_digest(original_body),
    );

    let signed = sign_request(
        "POST",
        "https://resource.example/pay",
        &mut headers,
        Some(original_body),
        &private_key,
        &SigScheme::Hwk,
        &options,
    )
    .unwrap();

    // Verifying with the real, matching body succeeds.
    let honest_request = RequestParts {
        method: "POST",
        target_uri: "https://resource.example/pay",
        headers: &headers,
        body: Some(original_body),
    };
    let prepared = prepare_verification(
        &honest_request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    )
    .unwrap();
    prepared.verify(&public_key).unwrap();

    // Same headers (same stale Content-Digest, same Signature) but a
    // different body — as if a party between signer and verifier swapped
    // it while forwarding the still-valid headers along. This must be
    // rejected rather than silently accepted.
    let tampered_body = br#"{"amount":999999}"#;
    let tampered_request = RequestParts {
        method: "POST",
        target_uri: "https://resource.example/pay",
        headers: &headers,
        body: Some(tampered_body),
    };
    let result = prepare_verification(
        &tampered_request,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        None,
    );
    assert!(
        result.is_err(),
        "a tampered body under a covered content-digest must be rejected"
    );
}

#[test]
fn selects_matching_key_from_a_dictionary() {
    let header = concat!(
        "first=jwt;jwt=\"one\", ",
        "email=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"abc\""
    );
    let parsed = httpsig::parse_signature_keys(header).unwrap();

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].label, "first");
    assert_eq!(parsed[1].label, "email");
    assert_eq!(parsed[1].scheme, "hwk");
}
