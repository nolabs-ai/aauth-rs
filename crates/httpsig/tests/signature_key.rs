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
