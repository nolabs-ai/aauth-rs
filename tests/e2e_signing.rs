//! End-to-end signing/verification through the public API.
//!
//! These drive the whole `hwk` (pseudonymous, inline-key) path — `sign_request`
//! produces the three headers, `RequestVerifier` consumes them — and then
//! assert the negative cases that verification must reject. `hwk` needs no key
//! discovery, so no network or resolver is involved and the flow is exercised
//! exactly as an application would use it.

use aauth_core::keys::generate_ed25519_keypair;
use aauth_core::resource::RequestVerifier;
use aauth_core::signing::{build_signature_key_header, sign_request, SigScheme, SignOptions};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const METHOD: &str = "GET";
const URI: &str = "https://resource.example/api/data";
const AUTHORITY: &str = "resource.example";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn verifier() -> RequestVerifier<'static> {
    RequestVerifier::new(vec![AUTHORITY.to_string()])
}

/// Sign `uri` with a fresh `hwk` key and return the request headers a client
/// would send.
fn sign_hwk(uri: &str, options: &SignOptions) -> HashMap<String, String> {
    let (key, _public) = generate_ed25519_keypair();
    let mut headers = HashMap::new();
    sign_request(
        METHOD,
        uri,
        &mut headers,
        None,
        &key,
        &SigScheme::Hwk,
        options,
    )
    .expect("signing succeeds");
    headers
}

/// A verify with no identity/auth-token requirement (hwk is pseudonymous).
fn verify(
    method: &str,
    uri: &str,
    headers: &HashMap<String, String>,
) -> aauth_core::resource::VerificationResult {
    verifier().verify_request(method, uri, headers, None, false, false)
}

#[test]
fn hwk_sign_verify_happy_path() {
    let headers = sign_hwk(URI, &SignOptions::default());
    let result = verify(METHOD, URI, &headers);
    assert!(
        result.valid,
        "expected valid, got error: {:?}",
        result.error
    );
    // hwk is pseudonymous: a valid signature but no asserted identity.
    assert_eq!(result.agent_id, None);
}

#[test]
fn rejects_tampered_method() {
    let headers = sign_hwk(URI, &SignOptions::default());
    // Signed as GET, replayed as POST: @method no longer matches the base.
    let result = verify("POST", URI, &headers);
    assert!(!result.valid, "method change must not verify");
}

#[test]
fn rejects_tampered_path() {
    let headers = sign_hwk(URI, &SignOptions::default());
    let result = verify(METHOD, "https://resource.example/api/other", &headers);
    assert!(!result.valid, "path change must not verify");
}

#[test]
fn rejects_stale_created() {
    let options = SignOptions {
        created: Some(now() - 3600),
        ..Default::default()
    };
    let headers = sign_hwk(URI, &options);
    let result = verify(METHOD, URI, &headers);
    assert!(!result.valid, "a signature an hour old must be stale");
}

#[test]
fn rejects_future_created() {
    let options = SignOptions {
        created: Some(now() + 3600),
        ..Default::default()
    };
    let headers = sign_hwk(URI, &options);
    let result = verify(METHOD, URI, &headers);
    assert!(
        !result.valid,
        "a signature from the future must be rejected"
    );
}

#[test]
fn rejects_tampered_signature_bytes() {
    let mut headers = sign_hwk(URI, &SignOptions::default());

    // Flip one base64 character inside the `sig=:...:` byte sequence.
    let signature = headers.get("Signature").expect("signature header").clone();
    let (prefix, rest) = signature.split_once(':').expect("byte-sequence open");
    let encoded = rest.strip_suffix(':').expect("byte-sequence close");
    let mut chars: Vec<char> = encoded.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    headers.insert("Signature".to_string(), format!("{prefix}:{tampered}:"));

    let result = verify(METHOD, URI, &headers);
    assert!(!result.valid, "a corrupted signature must not verify");
}

#[test]
fn rejects_swapped_inline_key() {
    let mut headers = sign_hwk(URI, &SignOptions::default());

    // Replace the inline hwk key with an unrelated key while keeping the
    // original signature: the covered `signature-key` component and the key
    // material no longer match what was signed.
    let (foreign_key, _foreign_public) = generate_ed25519_keypair();
    let foreign_header = build_signature_key_header(&SigScheme::Hwk, Some(&foreign_key), "sig")
        .expect("build foreign signature-key");
    headers.insert("Signature-Key".to_string(), foreign_header);

    let result = verify(METHOD, URI, &headers);
    assert!(!result.valid, "swapping the inline key must not verify");
}

#[test]
fn rejects_query_stripping() {
    // Sign a request whose query is covered (@query is added automatically
    // when a query is present), then replay it with the query removed.
    let signed_uri = "https://resource.example/api/data?account=alice";
    let headers = sign_hwk(signed_uri, &SignOptions::default());

    let result = verify(METHOD, URI, &headers);
    assert!(
        !result.valid,
        "dropping a signed query component must not verify"
    );
}
