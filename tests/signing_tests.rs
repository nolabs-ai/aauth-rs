//! Tests for the keys and RFC 9421 signing layers.

use aauth::keys::{
    calculate_jwk_thumbprint, generate_ed25519_keypair, generate_p256_keypair,
    generate_p384_keypair, jwk_to_public_key, private_key_to_jwk, public_key_to_jwk, Jwk,
};
use aauth::signing::{
    build_signature_key_header, calculate_content_digest, parse_signature, parse_signature_input,
    parse_signature_key, sign_request, verify_signature, SigScheme, SignOptions, VerifyOptions,
};
use serde_json::json;
use std::collections::HashMap;

// --- keys ---

#[test]
fn ed25519_jwk_round_trip() {
    let (private_key, public_key) = generate_ed25519_keypair();
    let jwk = public_key_to_jwk(&public_key, Some("key-1"));
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
    assert_eq!(jwk.kid.as_deref(), Some("key-1"));

    let recovered = jwk_to_public_key(&jwk).unwrap();
    assert_eq!(recovered, public_key);

    // private_key_to_jwk matches
    let jwk2 = private_key_to_jwk(&private_key, Some("key-1"));
    assert_eq!(jwk, jwk2);
}

#[test]
fn ec_jwk_round_trip() {
    for (private_key, public_key) in [generate_p256_keypair(), generate_p384_keypair()] {
        let jwk = public_key_to_jwk(&public_key, None);
        assert_eq!(jwk.kty, "EC");
        assert!(jwk.y.is_some());
        let recovered = jwk_to_public_key(&jwk).unwrap();
        assert_eq!(recovered, public_key);

        // sign/verify round trip through the key types
        let sig = private_key.sign(b"hello");
        recovered.verify(&sig, b"hello").unwrap();
        assert!(recovered.verify(&sig, b"tampered").is_err());
    }
}

#[test]
fn jwk_thumbprint_rfc8037_vector() {
    // RFC 8037 A.3: Ed25519 JWK thumbprint test vector
    let jwk = Jwk {
        kty: "OKP".into(),
        crv: Some("Ed25519".into()),
        x: Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into()),
        ..Default::default()
    };
    assert_eq!(
        calculate_jwk_thumbprint(&jwk).unwrap(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

#[test]
fn jwk_thumbprint_rfc7638_rsa_vector() {
    // RFC 7638 §3.1 example
    let jwk = Jwk {
        kty: "RSA".into(),
        n: Some(
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into(),
        ),
        e: Some("AQAB".into()),
        ..Default::default()
    };
    assert_eq!(
        calculate_jwk_thumbprint(&jwk).unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

// --- signature base / headers ---

#[test]
fn content_digest_rfc9530_format() {
    let digest = calculate_content_digest(b"{\"hello\": \"world\"}");
    assert!(digest.starts_with("sha-256=:"));
    assert!(digest.ends_with(':'));
}

#[test]
fn signature_input_round_trip() {
    let header = "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=1700000000";
    let parsed = parse_signature_input(header).unwrap();
    assert_eq!(parsed.label, "sig");
    assert_eq!(
        parsed.components,
        vec!["@method", "@authority", "@path", "signature-key"]
    );
    assert_eq!(parsed.created(), Some(1700000000));
}

#[test]
fn signature_key_header_spec_form_round_trip() {
    let (private_key, _) = generate_ed25519_keypair();
    let header = build_signature_key_header(&SigScheme::Hwk, Some(&private_key), "sig").unwrap();
    assert!(header.starts_with("sig=hwk;"));

    let parsed = parse_signature_key(&header).unwrap();
    assert_eq!(parsed.label, "sig");
    assert_eq!(parsed.scheme, "hwk");
    assert_eq!(parsed.param("kty"), Some("OKP"));
    assert_eq!(parsed.param("crv"), Some("Ed25519"));
    assert!(parsed.param("x").is_some());
}

#[test]
fn signature_key_header_jwks_uri_form() {
    let header = build_signature_key_header(
        &SigScheme::JwksUri {
            id: "https://agent.example",
            dwk: "aauth-agent.json",
            kid: "key-1",
        },
        None,
        "sig",
    )
    .unwrap();
    let parsed = parse_signature_key(&header).unwrap();
    assert_eq!(parsed.scheme, "jwks_uri");
    assert_eq!(parsed.param("id"), Some("https://agent.example"));
    assert_eq!(parsed.param("dwk"), Some("aauth-agent.json"));
    assert_eq!(parsed.param("kid"), Some("key-1"));
}

#[test]
fn signature_key_header_legacy_inner_list_form() {
    let header = r#"sig=(scheme=hwk kty="OKP" crv="Ed25519" x="abc123")"#;
    let parsed = parse_signature_key(header).unwrap();
    assert_eq!(parsed.label, "sig");
    assert_eq!(parsed.scheme, "hwk");
    assert_eq!(parsed.param("kty"), Some("OKP"));
    assert_eq!(parsed.param("x"), Some("abc123"));
}

#[test]
fn signature_key_header_escaped_quotes() {
    let parsed = parse_signature_key(r#"sig=jwt;jwt="abc\"def\\ghi""#).unwrap();
    assert_eq!(parsed.param("jwt"), Some(r#"abc"def\ghi"#));
}

// --- sign / verify round trips ---

#[test]
fn hwk_sign_verify_round_trip() {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();

    let signed = sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )
    .unwrap();

    assert!(headers.contains_key("Signature-Input"));
    assert!(headers.contains_key("Signature"));
    assert!(headers.contains_key("Signature-Key"));

    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(valid);

    // Different path fails
    let valid = verify_signature(
        "GET",
        "https://resource.example/api/other",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(!valid);

    // Different method fails
    let valid = verify_signature(
        "POST",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn hwk_sign_verify_p256() {
    let (private_key, _) = generate_p256_keypair();
    let mut headers = HashMap::new();
    let signed = sign_request(
        "GET",
        "https://resource.example/api/data?limit=5",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )
    .unwrap();

    // Query must be covered
    assert!(signed.signature_input.contains("\"@query\""));

    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data?limit=5",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn stale_created_timestamp_rejected() {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let signed = sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions {
            created: Some(now - 120),
            ..Default::default()
        },
    )
    .unwrap();

    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(!valid, "signature older than the 60s window must fail");

    // A wider window accepts it
    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions {
            created_window: 300,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn body_components_covered_when_requested() {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    let body = br#"{"key": "value"}"#;

    let signed = sign_request(
        "POST",
        "https://resource.example/api/data",
        &mut headers,
        Some(body),
        &private_key,
        &SigScheme::Hwk,
        &SignOptions {
            additional_signature_components: Some(vec![
                "content-type".into(),
                "content-digest".into(),
            ]),
            ..Default::default()
        },
    )
    .unwrap();

    assert!(headers.contains_key("Content-Digest"));
    assert!(headers.contains_key("Content-Type"));
    assert!(signed.signature_input.contains("\"content-digest\""));

    let valid = verify_signature(
        "POST",
        "https://resource.example/api/data",
        &headers,
        Some(body),
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn jwks_uri_scheme_sign_verify() {
    let (private_key, public_key) = generate_ed25519_keypair();
    let agent_jwk = public_key_to_jwk(&public_key, Some("key-1"));
    let jwks = json!({"keys": [agent_jwk.to_value()]});

    let mut headers = HashMap::new();
    let signed = sign_request(
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
    )
    .unwrap();

    let resolver = move |id: &str, dwk: Option<&str>, _kid: Option<&str>| {
        assert_eq!(id, "https://agent.example");
        assert_eq!(dwk, Some("aauth-agent.json"));
        Some(jwks.clone())
    };
    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions {
            jwks_resolver: Some(&resolver),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(valid);

    // Wrong key in the JWKS → invalid
    let (_, other_public) = generate_ed25519_keypair();
    let wrong_jwks = json!({"keys": [public_key_to_jwk(&other_public, Some("key-1")).to_value()]});
    let wrong_resolver = move |_: &str, _: Option<&str>, _: Option<&str>| Some(wrong_jwks.clone());
    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions {
            jwks_resolver: Some(&wrong_resolver),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn jkt_jwt_scheme_sign_verify() {
    use aauth::jwt;

    // Enclave (long-lived) key and ephemeral request-signing key
    let (enclave_private, enclave_public) = generate_ed25519_keypair();
    let (ephemeral_private, ephemeral_public) = generate_ed25519_keypair();

    let enclave_jwk = public_key_to_jwk(&enclave_public, None);
    let thumbprint = calculate_jwk_thumbprint(&enclave_jwk).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Self-issued delegation JWT: enclave key signs over the ephemeral key
    let header = json!({
        "typ": "jkt-s256+jwt",
        "alg": "EdDSA",
        "jwk": enclave_jwk.to_value(),
    });
    let payload = json!({
        "iss": format!("urn:jkt:sha-256:{thumbprint}"),
        "iat": now,
        "exp": now + 300,
        "cnf": {"jwk": public_key_to_jwk(&ephemeral_public, None).to_value()},
    });
    let delegation_jwt = jwt::encode(&header, &payload, &enclave_private).unwrap();

    let mut headers = HashMap::new();
    let signed = sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &ephemeral_private,
        &SigScheme::JktJwt {
            jwt: &delegation_jwt,
        },
        &SignOptions::default(),
    )
    .unwrap();

    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn label_mismatch_rejected() {
    let (private_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    let signed = sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &private_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )
    .unwrap();

    // Signature header re-labeled → labels no longer consistent
    let relabeled = signed.signature.replacen("sig=", "other=", 1);
    let valid = verify_signature(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        &signed.signature_input,
        &relabeled,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn parse_signature_accepts_standard_base64() {
    // standard (RFC 4648 §4) base64
    let bytes: Vec<u8> = (0..64).collect();
    let std_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    };
    let parsed = parse_signature(&format!("sig=:{std_b64}:"), Some("sig")).unwrap();
    assert_eq!(parsed, bytes);
}
