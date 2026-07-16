//! Regression tests for the hardening applied after the security review:
//! egress admission, JWKS issuer binding, required `created`, and SSRF
//! rejection of malformed issuers.

use aauth::egress::{EgressPolicy, StandardEgressPolicy};
use aauth::keys::{generate_ed25519_keypair, public_key_to_jwk, JwksFetcher};
use aauth::signing::{sign_request, verify_signature, SigScheme, SignOptions, VerifyOptions};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

// --- egress policy (#3/#6) ---

#[test]
fn default_deny_blocks_private_and_non_https() {
    let policy = StandardEgressPolicy::default_deny();

    // Allowed: public HTTPS host.
    assert!(policy.admit("https://as.example/token").is_ok());

    // Blocked: loopback, link-local metadata, RFC1918, non-https, localhost.
    assert!(policy.admit("https://127.0.0.1/x").is_err());
    assert!(policy.admit("https://169.254.169.254/latest").is_err());
    assert!(policy.admit("https://10.0.0.5/x").is_err());
    assert!(policy.admit("https://192.168.1.1/x").is_err());
    assert!(policy.admit("http://as.example/x").is_err());
    assert!(policy.admit("https://localhost/x").is_err());
    assert!(policy.admit("https://[::1]/x").is_err());
    // IPv4-mapped IPv6 loopback must also be blocked.
    assert!(policy.admit("https://[::ffff:127.0.0.1]/x").is_err());
}

#[test]
fn allow_localhost_policy_permits_dev() {
    let policy = StandardEgressPolicy::allow_localhost();
    assert!(policy.admit("http://127.0.0.1:8080/x").is_ok());
    assert!(policy.admit("http://localhost:9000/x").is_ok());
    // Still blocks other private ranges by default.
    assert!(policy.admit("http://10.0.0.5/x").is_err());
}

#[test]
fn admit_issuer_requires_valid_https_identifier() {
    let policy = StandardEgressPolicy::default_deny();
    assert!(policy.admit_issuer("https://as.example").is_ok());
    assert!(policy.admit_issuer("http://as.example").is_err()); // not https
    assert!(policy.admit_issuer("https://as.example/path").is_err()); // has path
    assert!(policy.admit_issuer("https://169.254.169.254").is_err()); // internal
}

// --- SSRF: malformed / internal iss rejected in signature verification (#3) ---

#[test]
fn jwt_scheme_rejects_non_identifier_iss() {
    use aauth::jwt;

    // An agent token whose `iss` is an internal, non-identifier URL, signed
    // consistently by the issuer key and confirming the request-signing key
    // in cnf.jwk — so the only reason to reject is the bad `iss`.
    let (issuer_key, issuer_public) = generate_ed25519_keypair();
    let (sign_key, sign_public) = generate_ed25519_keypair();
    let header = json!({"typ": "aa-agent+jwt", "alg": "EdDSA", "kid": "k1"});
    let payload = json!({
        "iss": "http://169.254.169.254",
        "sub": "delegate-1",
        "dwk": "aauth-agent.json",
        "jti": "1",
        "cnf": {"jwk": public_key_to_jwk(&sign_public, None).to_value()},
        "iat": 0,
        "exp": 9999999999i64,
    });
    let bad_jwt = jwt::encode(&header, &payload, &issuer_key).unwrap();

    // A resolver that WOULD serve the issuer's key, so failure can only come
    // from the `iss` validation rather than an unresolvable key.
    let jwks = json!({"keys": [public_key_to_jwk(&issuer_public, Some("k1")).to_value()]});
    let resolver = move |_: &str, _: Option<&str>, _: Option<&str>| Some(jwks.clone());

    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api",
        &mut headers,
        None,
        &sign_key,
        &SigScheme::Jwt { jwt: &bad_jwt },
        &SignOptions::default(),
    )
    .unwrap();

    let valid = verify_signature(
        "GET",
        "https://resource.example/api",
        &headers,
        None,
        &headers["Signature-Input"],
        &headers["Signature"],
        &headers["Signature-Key"],
        &VerifyOptions {
            jwks_resolver: Some(&resolver),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!valid, "an internal/non-identifier iss must not verify");
}

// --- required created (#2) ---

#[test]
fn missing_created_fails_verification() {
    let (key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    let signed = sign_request(
        "GET",
        "https://resource.example/api",
        &mut headers,
        None,
        &key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )
    .unwrap();

    // Strip the ;created=... parameter from Signature-Input.
    let stripped = signed
        .signature_input
        .split(';')
        .next()
        .unwrap()
        .to_string();
    headers.insert("Signature-Input".into(), stripped.clone());

    let valid = verify_signature(
        "GET",
        "https://resource.example/api",
        &headers,
        None,
        &stripped,
        &signed.signature,
        &signed.signature_key,
        &VerifyOptions::default(),
    )
    .unwrap();
    assert!(!valid, "absent created must fail (primary replay defense)");
}

// --- JWKS issuer binding (#7) ---

struct StaticClient {
    metadata: serde_json::Value,
    jwks: serde_json::Value,
    calls: Mutex<u32>,
}

impl aauth::http::HttpClient for StaticClient {
    fn execute(
        &self,
        _method: &str,
        url: &str,
        _headers: &HashMap<String, String>,
        _body: Option<&[u8]>,
    ) -> aauth::Result<aauth::http::HttpResponse> {
        *self.calls.lock().unwrap() += 1;
        let body = if url.contains("/.well-known/") {
            &self.metadata
        } else {
            &self.jwks
        };
        Ok(aauth::http::HttpResponse {
            status: 200,
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: serde_json::to_vec(body).unwrap(),
        })
    }
}

#[test]
fn jwks_fetcher_rejects_issuer_mismatch() {
    let (_, public_key) = generate_ed25519_keypair();
    let jwks = json!({"keys": [public_key_to_jwk(&public_key, Some("k1")).to_value()]});

    // Host-poisoned metadata: issuer does not equal the fetched identifier.
    let poisoned = StaticClient {
        metadata: json!({"issuer": "https://attacker.example", "jwks_uri": "https://as.example/jwks.json"}),
        jwks: jwks.clone(),
        calls: Mutex::new(0),
    };
    let fetcher = JwksFetcher::new(poisoned);
    let result = fetcher.fetch("https://as.example", Some("k1"), "aauth-access.json");
    assert!(result.is_err(), "issuer!=fetch URL must be rejected");

    // Matching issuer succeeds.
    let good = StaticClient {
        metadata: json!({"issuer": "https://as.example", "jwks_uri": "https://as.example/jwks.json"}),
        jwks,
        calls: Mutex::new(0),
    };
    let fetcher = JwksFetcher::new(good);
    let result = fetcher.fetch("https://as.example", Some("k1"), "aauth-access.json");
    assert!(result.is_ok(), "matching issuer should succeed: {result:?}");
}

#[test]
fn jwks_fetcher_egress_blocks_internal_issuer() {
    let (_, public_key) = generate_ed25519_keypair();
    let jwks = json!({"keys": [public_key_to_jwk(&public_key, Some("k1")).to_value()]});
    let client = StaticClient {
        metadata: json!({"issuer": "https://as.example", "jwks_uri": "https://as.example/jwks.json"}),
        jwks,
        calls: Mutex::new(0),
    };
    let fetcher = JwksFetcher::new(client);
    // Internal issuer is rejected before any fetch happens.
    let result = fetcher.fetch("https://169.254.169.254", Some("k1"), "aauth-access.json");
    assert!(result.is_err(), "internal issuer must be blocked by egress");
}

// --- auth token exp is required (residual #1) ---

#[test]
fn auth_token_without_exp_is_rejected() {
    use aauth::jwt;
    use aauth::tokens::{verify_token, VerifyTokenOptions};

    // An auth token that is well-formed and correctly signed but carries no
    // `exp` claim — it must be rejected rather than treated as non-expiring.
    let (as_key, as_public) = generate_ed25519_keypair();
    let (_, agent_public) = generate_ed25519_keypair();
    let header = json!({"typ": "aa-auth+jwt", "alg": "EdDSA", "kid": "as-1"});
    let payload = json!({
        "iss": "https://as.example",
        "aud": "https://resource.example",
        "dwk": "aauth-access.json",
        "jti": "j1",
        "agent": "aauth:alice@agents.example",
        "cnf": {"jwk": public_key_to_jwk(&agent_public, None).to_value()},
        "scope": "read",
        "iat": 0,
        // no "exp"
    });
    let token = jwt::encode(&header, &payload, &as_key).unwrap();

    let jwks = json!({"keys": [public_key_to_jwk(&as_public, Some("as-1")).to_value()]});
    let resolver = move |_: &str, _: Option<&str>, _: Option<&str>| Some(jwks.clone());

    let result = verify_token(
        &token,
        &resolver,
        &VerifyTokenOptions {
            expected_typ: Some("aa-auth+jwt"),
            expected_aud: Some("https://resource.example"),
            ..Default::default()
        },
    );
    assert!(result.is_err(), "auth token without exp must be rejected");
}
