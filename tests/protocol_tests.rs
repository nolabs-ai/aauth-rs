//! Tests for the AAuth protocol layer: tokens, headers, identifiers,
//! deferred responses, and the agent/resource roles.

use aauth::agent::{
    exchange_resource_token, extract_resource_token, poll_pending_url, ChallengeHandler,
    ExchangeOptions, PollCallbacks, PollOptions,
};
use aauth::deferred::{
    build_pending_response_body, build_pending_response_headers, detect_token_request_mode,
    generate_interaction_code, parse_pending_response, PendingBody, PendingHeaders,
    TokenRequestMode,
};
use aauth::headers::{
    build_accept_signature, build_auth_token_requirement, build_interaction_requirement,
    build_signature_error, get_challenge_header_value, parse_aauth_header,
    parse_aauth_mission_header, parse_accept_signature, parse_authorization_aauth_header,
    parse_signature_error, requirement_header_for_level, HEADER_AAUTH_REQUIREMENT,
    HEADER_ACCEPT_SIGNATURE, REQUIRE_AUTH_TOKEN, REQUIRE_IDENTITY, REQUIRE_PSEUDONYM, SIGKEY_JKT,
    SIGKEY_URI,
};
use aauth::http::{HttpClient, HttpResponse};
use aauth::identifiers::{
    agent_identifier_from_server_url, parse_agent_identifier, validate_agent_identifier,
    validate_endpoint_url, validate_server_identifier,
};
use aauth::keys::{
    calculate_jwk_thumbprint, generate_ed25519_keypair, public_key_to_jwk, PrivateKey, PublicKey,
};
use aauth::resource::{ChallengeBuilder, ChallengeRequest, RequestVerifier, ResourceTokenIssuer};
use aauth::tokens::{
    build_act_claim, create_agent_token, create_auth_token, create_resource_token,
    parse_token_claims, verify_agent_token, verify_resource_token, verify_token,
    verify_upstream_token, AgentTokenClaims, AuthTokenClaims, ResourceTokenClaims,
    VerifyResourceTokenOptions, VerifyTokenOptions, VerifyUpstreamOptions,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

fn resolver_for(jwks: Value) -> impl Fn(&str, Option<&str>, Option<&str>) -> Option<Value> {
    move |_: &str, _: Option<&str>, _: Option<&str>| Some(jwks.clone())
}

fn keypair_with_jwks(kid: &str) -> (PrivateKey, PublicKey, Value) {
    let (private_key, public_key) = generate_ed25519_keypair();
    let jwks = json!({"keys": [public_key_to_jwk(&public_key, Some(kid)).to_value()]});
    (private_key, public_key, jwks)
}

// --- identifiers ---

#[test]
fn agent_identifier_validation() {
    assert!(validate_agent_identifier("aauth:alice@agents.example").is_ok());
    assert!(validate_agent_identifier("aauth:a-b_c+d.e@example.com").is_ok());
    assert!(validate_agent_identifier("alice@agents.example").is_err()); // no scheme
    assert!(validate_agent_identifier("aauth:alice").is_err()); // no @
    assert!(validate_agent_identifier("aauth:@example.com").is_err()); // empty local
    assert!(validate_agent_identifier("aauth:Alice@example.com").is_err()); // uppercase
    assert!(validate_agent_identifier("aauth:alice@https://x.com").is_err()); // scheme in domain

    let (local, domain) = parse_agent_identifier("aauth:alice@agents.example").unwrap();
    assert_eq!(local, "alice");
    assert_eq!(domain, "agents.example");
}

#[test]
fn agent_identifier_from_url() {
    assert_eq!(
        agent_identifier_from_server_url("http://127.0.0.1:8001", "agent"),
        "aauth:agent-8001@127.0.0.1"
    );
    assert_eq!(
        agent_identifier_from_server_url("https://agent.example", "agent"),
        "aauth:agent@agent.example"
    );
}

#[test]
fn server_identifier_validation() {
    assert!(validate_server_identifier("https://resource.example").is_ok());
    assert!(validate_server_identifier("http://resource.example").is_err()); // not https
    assert!(validate_server_identifier("https://resource.example/").is_err()); // trailing slash
    assert!(validate_server_identifier("https://resource.example/path").is_err()); // path
    assert!(validate_server_identifier("https://resource.example:8443").is_err()); // port
    assert!(validate_server_identifier("https://Resource.example").is_err()); // uppercase

    assert!(validate_endpoint_url("https://as.example/token").is_ok());
    assert!(validate_endpoint_url("https://as.example/token?x=1").is_err());
}

// --- tokens ---

#[test]
fn agent_token_round_trip() {
    let (server_key, _, server_jwks) = keypair_with_jwks("as-key-1");
    let (_, delegate_public) = generate_ed25519_keypair();
    let delegate_jwk = public_key_to_jwk(&delegate_public, None);

    let token = create_agent_token(
        &AgentTokenClaims::new("https://agents.example", "delegate-1", delegate_jwk.clone()),
        &server_key,
        "as-key-1",
    )
    .unwrap();

    let claims = verify_agent_token(&token, &resolver_for(server_jwks.clone()), None).unwrap();
    assert_eq!(claims["iss"], "https://agents.example");
    assert_eq!(claims["sub"], "delegate-1");
    assert_eq!(claims["dwk"], "aauth-agent.json");
    assert_eq!(claims["cnf"]["jwk"]["kty"], "OKP");
    assert!(claims["jti"].is_string());

    // Wrong signing key must fail
    let (_, _, other_jwks) = keypair_with_jwks("as-key-1");
    assert!(verify_agent_token(&token, &resolver_for(other_jwks), None).is_err());

    // Expired token must fail
    let mut expired_claims =
        AgentTokenClaims::new("https://agents.example", "delegate-1", delegate_jwk);
    expired_claims.exp = Some(100);
    let expired = create_agent_token(&expired_claims, &server_key, "as-key-1").unwrap();
    assert!(verify_agent_token(&expired, &resolver_for(server_jwks), None).is_err());
}

#[test]
fn auth_token_round_trip() {
    let (as_key, _, as_jwks) = keypair_with_jwks("as-key-1");
    let (_, agent_public) = generate_ed25519_keypair();
    let agent_jwk = public_key_to_jwk(&agent_public, None);
    let agent_id = "aauth:alice@agents.example";

    let token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://resource.example".into(),
            agent: agent_id.into(),
            cnf_jwk: agent_jwk.clone(),
            act: Some(json!({"agent": agent_id})),
            scope: Some("read write".into()),
            sub: None,
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )
    .unwrap();

    let claims = verify_token(
        &token,
        &resolver_for(as_jwks.clone()),
        &VerifyTokenOptions {
            expected_typ: Some("aa-auth+jwt"),
            expected_iss: Some("https://as.example"),
            expected_aud: Some("https://resource.example"),
            expected_agent: Some(agent_id),
            request_signing_jwk: Some(&agent_jwk),
        },
    )
    .unwrap();
    assert_eq!(claims["scope"], "read write");
    assert_eq!(claims["act"]["agent"], agent_id);

    // Wrong audience fails
    assert!(verify_token(
        &token,
        &resolver_for(as_jwks.clone()),
        &VerifyTokenOptions {
            expected_typ: Some("aa-auth+jwt"),
            expected_aud: Some("https://other.example"),
            ..Default::default()
        },
    )
    .is_err());

    // cnf.jwk mismatch (different request signing key) fails
    let (_, other_public) = generate_ed25519_keypair();
    let other_jwk = public_key_to_jwk(&other_public, None);
    assert!(verify_token(
        &token,
        &resolver_for(as_jwks),
        &VerifyTokenOptions {
            expected_typ: Some("aa-auth+jwt"),
            request_signing_jwk: Some(&other_jwk),
            ..Default::default()
        },
    )
    .is_err());

    // Missing both sub and scope rejected at creation time
    assert!(create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://resource.example".into(),
            agent: agent_id.into(),
            cnf_jwk: agent_jwk,
            act: Some(json!({"agent": agent_id})),
            scope: None,
            sub: None,
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )
    .is_err());
}

#[test]
fn resource_token_round_trip() {
    let (resource_key, _, resource_jwks) = keypair_with_jwks("res-key-1");
    let (_, agent_public) = generate_ed25519_keypair();
    let agent_jkt = calculate_jwk_thumbprint(&public_key_to_jwk(&agent_public, None)).unwrap();

    let token = create_resource_token(
        &ResourceTokenClaims {
            iss: "https://resource.example".into(),
            aud: "https://as.example".into(),
            agent: "aauth:alice@agents.example".into(),
            agent_jkt: agent_jkt.clone(),
            scope: "read".into(),
            exp: None,
            mission: None,
        },
        &resource_key,
        "res-key-1",
    )
    .unwrap();

    let claims = verify_resource_token(
        &token,
        &resolver_for(resource_jwks.clone()),
        &VerifyResourceTokenOptions {
            expected_aud: Some("https://as.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_agent_jkt: Some(&agent_jkt),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(claims["scope"], "read");
    assert_eq!(claims["dwk"], "aauth-resource.json");

    // jkt mismatch fails
    assert!(verify_resource_token(
        &token,
        &resolver_for(resource_jwks),
        &VerifyResourceTokenOptions {
            expected_agent_jkt: Some("wrong-thumbprint"),
            ..Default::default()
        },
    )
    .is_err());

    // parse_token_claims exposes header and payload without verification
    let parsed = parse_token_claims(&token).unwrap();
    assert_eq!(parsed.header["typ"], "aa-resource+jwt");
    assert_eq!(parsed.payload["iss"], "https://resource.example");
}

// --- headers ---

#[test]
fn requirement_headers_round_trip() {
    // auth-token requirement
    let value = build_auth_token_requirement("token123");
    let parsed = parse_aauth_header(&value).unwrap();
    assert_eq!(parsed.requirement.as_deref(), Some(REQUIRE_AUTH_TOKEN));
    assert_eq!(parsed.resource_token.as_deref(), Some("token123"));

    // interaction requirement
    let value = build_interaction_requirement("https://as.example/interact", "ABCD1234");
    let parsed = parse_aauth_header(&value).unwrap();
    assert_eq!(parsed.requirement.as_deref(), Some("interaction"));
    assert_eq!(parsed.url.as_deref(), Some("https://as.example/interact"));
    assert_eq!(parsed.code.as_deref(), Some("ABCD1234"));

    // legacy require= format
    let parsed =
        parse_aauth_header(r#"require=identity; auth-server="https://as.example""#).unwrap();
    assert_eq!(parsed.requirement.as_deref(), Some(REQUIRE_IDENTITY));
    assert_eq!(parsed.auth_server.as_deref(), Some("https://as.example"));
}

#[test]
fn accept_signature_round_trip() {
    let value = build_accept_signature(SIGKEY_URI, None, None);
    assert_eq!(value, r#"sig=("@method" "@authority" "@path");sigkey=uri"#);
    let parsed = parse_accept_signature(&value);
    assert_eq!(parsed.sigkey.as_deref(), Some(SIGKEY_URI));
    assert_eq!(parsed.requirement.as_deref(), Some(REQUIRE_IDENTITY));
    assert_eq!(parsed.components, vec!["@method", "@authority", "@path"]);

    // jkt maps to pseudonym; parse via generic parse_aauth_header too
    let value = build_accept_signature(SIGKEY_JKT, None, Some(&["ed25519"]));
    let parsed = parse_aauth_header(&value).unwrap();
    assert_eq!(parsed.requirement.as_deref(), Some(REQUIRE_PSEUDONYM));
    assert_eq!(parsed.alg.as_deref(), Some("ed25519"));
}

#[test]
fn header_routing() {
    assert_eq!(
        requirement_header_for_level(REQUIRE_PSEUDONYM),
        HEADER_ACCEPT_SIGNATURE
    );
    assert_eq!(
        requirement_header_for_level(REQUIRE_AUTH_TOKEN),
        HEADER_AAUTH_REQUIREMENT
    );

    let headers = HashMap::from([(
        "AAuth-Requirement".to_string(),
        "requirement=approval".to_string(),
    )]);
    assert_eq!(get_challenge_header_value(&headers), "requirement=approval");
}

#[test]
fn signature_error_round_trip() {
    let value = build_signature_error("invalid_input", Some(&["@method", "content-digest"]), None);
    let parsed = parse_signature_error(&value);
    assert_eq!(parsed.error.as_deref(), Some("invalid_input"));
    assert_eq!(
        parsed.required_input,
        Some(vec!["@method".to_string(), "content-digest".to_string()])
    );
}

#[test]
fn misc_headers() {
    let mission = parse_aauth_mission_header(r#"approver="https://ps.example"; s256="abc""#);
    assert_eq!(mission.approver.as_deref(), Some("https://ps.example"));
    assert_eq!(mission.s256.as_deref(), Some("abc"));

    assert_eq!(
        parse_authorization_aauth_header("AAuth mytoken123"),
        Some("mytoken123".to_string())
    );
    assert_eq!(parse_authorization_aauth_header("Bearer x"), None);
}

// --- deferred ---

#[test]
fn deferred_helpers() {
    let code = generate_interaction_code(8);
    assert_eq!(code.len(), 8);
    // Crockford base32: digits + A-Z minus I, L, O, U.
    const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    assert!(code.chars().all(|c| CROCKFORD.contains(c)));
    assert!(!code.contains(['I', 'L', 'O', 'U']));
    // Below the 8-symbol floor is raised to 8 (≥ 40 bits of entropy).
    assert_eq!(generate_interaction_code(4).len(), 8);

    let body = build_pending_response_body(&PendingBody {
        location: "https://as.example/pending/abc".into(),
        require: Some("interaction".into()),
        code: Some("ABCD1234".into()),
        ..Default::default()
    });
    let parsed = parse_pending_response(&body);
    assert_eq!(parsed.status, "pending");
    assert_eq!(parsed.requirement.as_deref(), Some("interaction"));
    assert_eq!(parsed.code.as_deref(), Some("ABCD1234"));

    let headers = build_pending_response_headers(&PendingHeaders {
        location: "https://as.example/pending/abc".into(),
        require: Some("interaction".into()),
        code: Some("ABCD1234".into()),
        url: Some("https://as.example/interact".into()),
        ..Default::default()
    });
    assert!(headers["AAuth-Requirement"].contains("requirement=interaction"));
    assert!(headers["AAuth-Requirement"].contains(r#"code="ABCD1234""#));

    assert_eq!(
        detect_token_request_mode(&json!({"resource_token": "x"})),
        Some(TokenRequestMode::ResourceAccess)
    );
    assert_eq!(
        detect_token_request_mode(&json!({"resource_token": "x", "upstream_token": "y"})),
        Some(TokenRequestMode::CallChaining)
    );
    assert_eq!(
        detect_token_request_mode(&json!({"scope": "read"})),
        Some(TokenRequestMode::SelfAccess)
    );
    assert_eq!(
        detect_token_request_mode(&json!({"auth_token": "z"})),
        Some(TokenRequestMode::TokenRefresh)
    );
    assert_eq!(detect_token_request_mode(&json!({})), None);
}

// --- resource role ---

#[test]
fn resource_verifier_hwk_flow() {
    use aauth::signing::{sign_request, SigScheme, SignOptions};

    let (agent_key, _) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &agent_key,
        &SigScheme::Hwk,
        &SignOptions::default(),
    )
    .unwrap();

    let verifier = RequestVerifier::new(vec!["resource.example".to_string()]);
    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        false,
        false,
    );
    assert!(result.valid, "verification failed: {:?}", result.error);
    assert!(result.agent_id.is_none()); // hwk is pseudonymous

    // Identity required but hwk provided → invalid
    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        true,
        false,
    );
    assert!(!result.valid);

    // Wrong authority → invalid
    let verifier = RequestVerifier::new(vec!["other.example".to_string()]);
    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        false,
        false,
    );
    assert!(!result.valid);
}

#[test]
fn resource_verifier_auth_token_flow() {
    use aauth::signing::{sign_request, SigScheme, SignOptions};

    // Agent key and AS key
    let (agent_key, agent_public) = generate_ed25519_keypair();
    let agent_jwk = public_key_to_jwk(&agent_public, None);
    let (as_key, _, as_jwks) = keypair_with_jwks("as-key-1");
    let agent_id = "aauth:alice@agents.example";

    let auth_token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://resource.example".into(),
            agent: agent_id.into(),
            cnf_jwk: agent_jwk,
            act: Some(json!({"agent": agent_id})),
            scope: Some("read".into()),
            sub: Some("user-1".into()),
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )
    .unwrap();

    let mut headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut headers,
        None,
        &agent_key,
        &SigScheme::Jwt { jwt: &auth_token },
        &SignOptions::default(),
    )
    .unwrap();

    let resolver = resolver_for(as_jwks);
    let verifier = RequestVerifier::new(vec!["resource.example".to_string()])
        .with_resource_id("https://resource.example")
        .with_jwks_resolver(&resolver);
    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &headers,
        None,
        true,
        true,
    );
    assert!(result.valid, "verification failed: {:?}", result.error);
    assert_eq!(result.agent_id.as_deref(), Some(agent_id));
    assert_eq!(result.user_sub.as_deref(), Some("user-1"));
    assert_eq!(result.scopes, Some(vec!["read".to_string()]));
    assert_eq!(result.act.unwrap()["agent"], agent_id);

    // Audience confusion (finding #1): a token minted for a DIFFERENT
    // resource, correctly signed, must be rejected here.
    let wrong_aud_token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://other-resource.example".into(),
            agent: agent_id.into(),
            cnf_jwk: public_key_to_jwk(&agent_public, None),
            act: Some(json!({"agent": agent_id})),
            scope: Some("read".into()),
            sub: Some("user-1".into()),
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )
    .unwrap();
    let mut wrong_headers = HashMap::new();
    sign_request(
        "GET",
        "https://resource.example/api/data",
        &mut wrong_headers,
        None,
        &agent_key,
        &SigScheme::Jwt {
            jwt: &wrong_aud_token,
        },
        &SignOptions::default(),
    )
    .unwrap();
    let result = verifier.verify_request(
        "GET",
        "https://resource.example/api/data",
        &wrong_headers,
        None,
        true,
        true,
    );
    assert!(
        !result.valid,
        "token minted for another resource must be rejected"
    );
}

#[test]
fn challenge_builder_and_token_issuer() {
    let (resource_key, _, resource_jwks) = keypair_with_jwks("res-key-1");
    let (_, agent_public) = generate_ed25519_keypair();

    let builder = ChallengeBuilder::new(
        "https://resource.example",
        resource_key.clone(),
        "res-key-1",
        "https://as.example",
    );

    // Pseudonym challenge
    let (header, value) = builder
        .build_challenge(&ChallengeRequest::default())
        .unwrap();
    assert_eq!(header, HEADER_ACCEPT_SIGNATURE);
    assert!(value.contains("sigkey=jkt"));

    // Identity challenge
    let (header, value) = builder
        .build_challenge(&ChallengeRequest {
            require_identity: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(header, HEADER_ACCEPT_SIGNATURE);
    assert!(value.contains("sigkey=uri"));

    // Auth-token challenge carries a verifiable resource token
    let (header, value) = builder
        .build_challenge(&ChallengeRequest {
            require_auth_token: true,
            agent_id: Some("aauth:alice@agents.example"),
            agent_public_key: Some(&agent_public),
            scope: Some("read"),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(header, HEADER_AAUTH_REQUIREMENT);

    // The agent extracts the resource token from the challenge response
    let response_headers = HashMap::from([(header.to_string(), value)]);
    let resource_token = extract_resource_token(&response_headers).unwrap();

    let claims = verify_resource_token(
        &resource_token,
        &resolver_for(resource_jwks.clone()),
        &VerifyResourceTokenOptions {
            expected_aud: Some("https://as.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(claims["scope"], "read");

    // The standalone issuer produces equivalent tokens
    let issuer = ResourceTokenIssuer::new(
        "https://resource.example",
        resource_key,
        "res-key-1",
        "https://as.example",
    );
    let token = issuer
        .issue_token("aauth:alice@agents.example", &agent_public, "read", None)
        .unwrap();
    verify_resource_token(
        &token,
        &resolver_for(resource_jwks),
        &VerifyResourceTokenOptions::default(),
    )
    .unwrap();
}

// --- agent role ---

#[test]
fn challenge_handler_scheme_selection() {
    let handler = ChallengeHandler::new();

    let pseudonym = handler
        .parse_challenge(&build_accept_signature(SIGKEY_JKT, None, None))
        .unwrap();
    assert_eq!(
        handler
            .determine_response_scheme(&pseudonym, false, false)
            .unwrap(),
        "hwk"
    );

    let identity = handler
        .parse_challenge(&build_accept_signature(SIGKEY_URI, None, None))
        .unwrap();
    assert_eq!(
        handler
            .determine_response_scheme(&identity, false, false)
            .unwrap(),
        "jwks_uri"
    );
    assert_eq!(
        handler
            .determine_response_scheme(&identity, true, false)
            .unwrap(),
        "jwt"
    );

    let auth_token = handler
        .parse_challenge(&build_auth_token_requirement("rt-token"))
        .unwrap();
    assert_eq!(
        handler
            .determine_response_scheme(&auth_token, true, true)
            .unwrap(),
        "jwt"
    );
    assert!(handler
        .determine_response_scheme(&auth_token, true, false)
        .is_err());
}

fn no_sleep(_: std::time::Duration) {}

fn json_response(status: u16, body: Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

#[test]
fn poller_state_machine() {
    // 202 pending twice, then 200 with the auth token
    let responses = Mutex::new(vec![
        json_response(200, json!({"auth_token": "final-token"})),
        json_response(202, json!({"status": "pending", "location": "https://x/p"})),
        json_response(202, json!({"status": "pending", "location": "https://x/p"})),
    ]);
    let get = |_url: &str| Ok(responses.lock().unwrap().pop().unwrap());

    let result = poll_pending_url(
        "https://x/p",
        &get,
        &PollCallbacks::default(),
        &PollOptions {
            max_polls: 10,
            default_wait: 0,
            sleep: no_sleep,
        },
    );
    assert!(result.success);
    assert_eq!(result.auth_token.as_deref(), Some("final-token"));

    // Terminal denial
    let get_denied = |_url: &str| {
        Ok(json_response(
            403,
            json!({"error": "denied", "error_description": "user said no"}),
        ))
    };
    let result = poll_pending_url(
        "https://x/p",
        &get_denied,
        &PollCallbacks::default(),
        &PollOptions {
            max_polls: 10,
            default_wait: 0,
            sleep: no_sleep,
        },
    );
    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("denied"));
    assert_eq!(result.status_code, 403);

    // Interaction callback fires on the first 202
    let interaction_seen = Mutex::new(None::<(String, String)>);
    let on_interaction = |url: &str, code: &str| {
        *interaction_seen.lock().unwrap() = Some((url.to_string(), code.to_string()));
    };
    let responses = Mutex::new(vec![json_response(200, json!({"auth_token": "tok"})), {
        let mut response = json_response(
            202,
            json!({"status": "pending", "requirement": "interaction", "code": "ABCD1234"}),
        );
        response.headers.insert(
            "aauth-requirement".to_string(),
            r#"requirement=interaction; url="https://as.example/interact"; code="ABCD1234""#
                .to_string(),
        );
        response
    }]);
    let get = |_url: &str| Ok(responses.lock().unwrap().pop().unwrap());
    let result = poll_pending_url(
        "https://x/p",
        &get,
        &PollCallbacks {
            on_interaction: Some(&on_interaction),
            ..Default::default()
        },
        &PollOptions {
            max_polls: 10,
            default_wait: 0,
            sleep: no_sleep,
        },
    );
    assert!(result.success);
    let (url, code) = interaction_seen.lock().unwrap().clone().unwrap();
    assert_eq!(url, "https://as.example/interact?code=ABCD1234");
    assert_eq!(code, "ABCD1234");
}

/// Mock HTTP client for the token exchange flow: serves PS metadata and a
/// token endpoint that immediately returns (or defers) an auth token.
struct MockPsClient {
    /// (immediate) 200 on POST, or 202 + Location then 200 on poll.
    deferred: bool,
    posts: Mutex<u32>,
}

impl HttpClient for MockPsClient {
    fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        _body: Option<&[u8]>,
    ) -> aauth::Result<HttpResponse> {
        if url.contains("/.well-known/aauth-person") {
            return Ok(json_response(
                200,
                json!({
                    "issuer": "https://ps.example",
                    "token_endpoint": "https://ps.example/token",
                    "jwks_uri": "https://ps.example/jwks.json",
                }),
            ));
        }
        if url == "https://ps.example/token" && method == "POST" {
            // The exchange must sign its requests
            assert!(headers.contains_key("Signature-Input"));
            assert!(headers.contains_key("Signature-Key"));
            *self.posts.lock().unwrap() += 1;
            if self.deferred {
                let mut response = json_response(
                    202,
                    json!({"status": "pending", "location": "https://ps.example/pending/1"}),
                );
                response.headers.insert(
                    "location".to_string(),
                    "https://ps.example/pending/1".to_string(),
                );
                response
                    .headers
                    .insert("retry-after".to_string(), "0".to_string());
                return Ok(response);
            }
            return Ok(json_response(200, json!({"auth_token": "auth-token-123"})));
        }
        if url == "https://ps.example/pending/1" && method == "GET" {
            assert!(headers.contains_key("Signature-Input"));
            return Ok(json_response(
                200,
                json!({"auth_token": "auth-token-deferred"}),
            ));
        }
        Ok(HttpResponse {
            status: 404,
            headers: HashMap::new(),
            body: Vec::new(),
        })
    }
}

fn make_resource_token(aud: &str) -> (String, PrivateKey, String) {
    let (resource_key, _) = generate_ed25519_keypair();
    let (agent_key, agent_public) = generate_ed25519_keypair();
    let agent_jkt = calculate_jwk_thumbprint(&public_key_to_jwk(&agent_public, None)).unwrap();
    let resource_token = create_resource_token(
        &ResourceTokenClaims {
            iss: "https://resource.example".into(),
            aud: aud.into(),
            agent: "aauth:alice@agents.example".into(),
            agent_jkt,
            scope: "read".into(),
            exp: None,
            mission: None,
        },
        &resource_key,
        "res-key-1",
    )
    .unwrap();

    // A (self-signed, test-only) agent token for the Signature-Key header
    let (server_key, _) = generate_ed25519_keypair();
    let agent_jwt = create_agent_token(
        &AgentTokenClaims::new(
            "https://agents.example",
            "delegate-1",
            public_key_to_jwk(&agent_public, None),
        ),
        &server_key,
        "as-key-1",
    )
    .unwrap();

    (resource_token, agent_key, agent_jwt)
}

#[test]
fn token_exchange_immediate_success() {
    // Three-party: resource token aud is the PS.
    let (resource_token, agent_key, agent_jwt) = make_resource_token("https://ps.example");
    let client = MockPsClient {
        deferred: false,
        posts: Mutex::new(0),
    };

    let auth_token = exchange_resource_token(
        &client,
        &resource_token,
        &agent_key,
        &agent_jwt,
        &ExchangeOptions {
            expected_ps: Some("https://ps.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_resource_iss: Some("https://resource.example"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(auth_token, "auth-token-123");
    assert_eq!(*client.posts.lock().unwrap(), 1);
}

#[test]
fn token_exchange_four_party_aud_is_as() {
    // Four-party: the resource token's aud is the AS, not the PS. The agent
    // still forwards to its own pinned PS, so this must succeed — the aud is
    // not gated against the PS.
    let (resource_token, agent_key, agent_jwt) = make_resource_token("https://as.example");
    let client = MockPsClient {
        deferred: false,
        posts: Mutex::new(0),
    };

    let auth_token = exchange_resource_token(
        &client,
        &resource_token,
        &agent_key,
        &agent_jwt,
        &ExchangeOptions {
            expected_ps: Some("https://ps.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_resource_iss: Some("https://resource.example"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(auth_token, "auth-token-123");
}

#[test]
fn token_exchange_rejects_confused_deputy_issuer() {
    // The resource token was issued by resource.example, but the agent thinks
    // it contacted a different resource — reject before any network call
    // (spec §6.6.3 step 3).
    let (resource_token, agent_key, agent_jwt) = make_resource_token("https://ps.example");
    let client = MockPsClient {
        deferred: false,
        posts: Mutex::new(0),
    };

    let refused = exchange_resource_token(
        &client,
        &resource_token,
        &agent_key,
        &agent_jwt,
        &ExchangeOptions {
            expected_ps: Some("https://ps.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_resource_iss: Some("https://other-resource.example"),
            ..Default::default()
        },
    );
    assert!(refused.is_err(), "issuer mismatch must be refused");
    assert_eq!(
        *client.posts.lock().unwrap(),
        0,
        "must fail before contacting the PS"
    );
}

#[test]
fn token_exchange_deferred_success() {
    let (resource_token, agent_key, agent_jwt) = make_resource_token("https://ps.example");
    let client = MockPsClient {
        deferred: true,
        posts: Mutex::new(0),
    };

    let auth_token = exchange_resource_token(
        &client,
        &resource_token,
        &agent_key,
        &agent_jwt,
        &ExchangeOptions {
            expected_ps: Some("https://ps.example"),
            expected_agent: Some("aauth:alice@agents.example"),
            expected_resource_iss: Some("https://resource.example"),
            poll_options: Some(PollOptions {
                max_polls: 5,
                default_wait: 0,
                sleep: no_sleep,
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(auth_token, "auth-token-deferred");
}

#[test]
fn act_claim_builder_matches_spec_examples() {
    // §10.3.1 "just chaining": booking presents at payments, delegated by asst.
    let asst_hop = build_act_claim("aauth:asst@agent.example", None);
    assert_eq!(asst_hop, json!({"agent": "aauth:asst@agent.example"}));

    // §10.3.1 "sub-agent inside a chain": booking+search1 presents at maps.
    let chained = build_act_claim("aauth:booking@booking.example", Some(&asst_hop));
    assert_eq!(
        chained,
        json!({
            "agent": "aauth:booking@booking.example",
            "act": {"agent": "aauth:asst@agent.example"}
        })
    );
}

#[test]
fn upstream_token_verification_call_chaining() {
    // asst -> booking -> payments. `booking` is a resource acting as an agent
    // (it publishes agent metadata under its own domain), so its agent-token
    // `iss` is https://booking.example — which is also the `aud` of the
    // upstream auth token `asst` presented at booking.
    let (as_key, _, as_jwks) = keypair_with_jwks("as-key-1");
    let (_, asst_public) = generate_ed25519_keypair();
    let asst_jwk = public_key_to_jwk(&asst_public, None);

    let upstream_token = create_auth_token(
        &AuthTokenClaims {
            iss: "https://as.example".into(),
            aud: "https://booking.example".into(), // issued TO booking
            agent: "aauth:asst@agent.example".into(),
            cnf_jwk: asst_jwk,
            act: None, // asst obtained it directly
            scope: Some("book".into()),
            sub: Some("user:alice".into()),
            exp: None,
            mission: None,
            dwk: None,
        },
        &as_key,
        "as-key-1",
    )
    .unwrap();

    let opts = VerifyUpstreamOptions {
        trusted_issuers: &["https://as.example"],
        intermediary_agent_iss: "https://booking.example",
    };
    let result =
        verify_upstream_token(&upstream_token, &resolver_for(as_jwks.clone()), &opts).unwrap();

    // The downstream act records asst as the immediate upstream agent.
    assert_eq!(
        result.downstream_act,
        json!({"agent": "aauth:asst@agent.example"})
    );
    assert_eq!(result.upstream_claims["scope"], "book");

    // Untrusted issuer is rejected.
    let untrusted = VerifyUpstreamOptions {
        trusted_issuers: &["https://other-as.example"],
        intermediary_agent_iss: "https://booking.example",
    };
    assert!(
        verify_upstream_token(&upstream_token, &resolver_for(as_jwks.clone()), &untrusted).is_err()
    );

    // aud that does not match the intermediary's agent-token iss is rejected
    // (the token was issued to booking, not to payments).
    let wrong_binding = VerifyUpstreamOptions {
        trusted_issuers: &["https://as.example"],
        intermediary_agent_iss: "https://payments.example",
    };
    assert!(
        verify_upstream_token(&upstream_token, &resolver_for(as_jwks), &wrong_binding).is_err()
    );
}
