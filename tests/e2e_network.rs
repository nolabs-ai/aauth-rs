//! End-to-end tests that cross a real TCP socket.
//!
//! Unlike the protocol tests (which inject mock `HttpClient` implementations),
//! these drive the real [`ReqwestClient`] against a throwaway `tiny_http`
//! server bound to an ephemeral loopback port. They are the first coverage of
//! the actual network transport: HTTP method mapping, request-header and body
//! forwarding, status handling, the non-2xx error path, and response-header
//! normalization — all over a genuine connection.
//!
//! The whole module compiles only with the `reqwest-client` feature, so
//! `cargo test --no-default-features` still builds.
#![cfg(feature = "reqwest-client")]

use aauth_core::egress::{EgressPolicy, StandardEgressPolicy};
use aauth_core::errors::Result;
use aauth_core::http::{HttpClient, ReqwestClient};
use aauth_core::keys::{generate_ed25519_keypair, get_key_by_kid, public_key_to_jwk, JwksFetcher};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tiny_http::{Header, Response, Server};

/// What the test handler sees for one request.
struct Seen {
    method: String,
    path: String,
    body: String,
    headers: HashMap<String, String>,
}

/// A `tiny_http` server on a loopback port that answers via a user handler.
///
/// Requests are counted so tests can assert how many round-trips actually hit
/// the network.
struct TestServer {
    base: String,
    hits: Arc<AtomicUsize>,
    server: Arc<Server>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start(handler: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> Self {
        let server = Arc::new(Server::http("127.0.0.1:0").expect("bind loopback server"));
        let port = server
            .server_addr()
            .to_ip()
            .expect("server bound to an IP address")
            .port();
        let base = format!("http://127.0.0.1:{port}");

        let hits = Arc::new(AtomicUsize::new(0));
        let handle = {
            let server = Arc::clone(&server);
            let hits = Arc::clone(&hits);
            std::thread::spawn(move || {
                let json_header =
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("valid header");
                for mut request in server.incoming_requests() {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let method = request.method().to_string();
                    let url = request.url().to_string();
                    let path = url.split('?').next().unwrap_or("").to_string();
                    let headers = request
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.to_string().to_ascii_lowercase(),
                                h.value.to_string(),
                            )
                        })
                        .collect();
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);

                    let (status, resp_body) = handler(&Seen {
                        method,
                        path,
                        body,
                        headers,
                    });
                    let response = Response::from_string(resp_body)
                        .with_status_code(status)
                        .with_header(json_header.clone());
                    let _ = request.respond(response);
                }
            })
        };

        TestServer {
            base,
            hits,
            server,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Break the blocking `incoming_requests` loop and join the thread.
        self.server.unblock();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A GET over a real socket: the request header is forwarded, the JSON body is
/// parsed, and the response `Content-Type` is exposed lowercased.
#[test]
fn reqwest_get_forwards_headers_and_parses_json() {
    let server = TestServer::start(|seen| match (seen.method.as_str(), seen.path.as_str()) {
        ("GET", "/ok.json") => (
            200,
            json!({ "hello": "world", "saw_header": seen.headers.get("x-test") }).to_string(),
        ),
        _ => (404, "{}".to_string()),
    });

    let client = ReqwestClient::new();
    let mut headers = HashMap::new();
    headers.insert("X-Test".to_string(), "abc".to_string());

    let response = client
        .execute("GET", &server.url("/ok.json"), &headers, None)
        .expect("request over the socket succeeds");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/json"),
        "response headers are exposed lowercased"
    );
    let body = response.json().expect("valid JSON body");
    assert_eq!(body["hello"], "world");
    assert_eq!(
        body["saw_header"], "abc",
        "the X-Test request header crossed the socket"
    );
    assert_eq!(server.hits(), 1);
}

/// A POST over a real socket carries the method and request body to the server.
#[test]
fn reqwest_post_sends_body() {
    let server = TestServer::start(|seen| {
        (
            201,
            json!({ "method": seen.method, "echo": seen.body }).to_string(),
        )
    });

    let client = ReqwestClient::new();
    let response = client
        .execute(
            "POST",
            &server.url("/echo"),
            &HashMap::new(),
            Some(b"payload-bytes"),
        )
        .expect("request over the socket succeeds");

    assert_eq!(response.status, 201);
    let body = response.json().expect("valid JSON body");
    assert_eq!(body["method"], "POST");
    assert_eq!(body["echo"], "payload-bytes");
}

/// `fetch_json` returns the parsed body on 2xx and errors on a non-2xx status.
#[test]
fn reqwest_fetch_json_status_handling() {
    let server = TestServer::start(|seen| match seen.path.as_str() {
        "/data" => (200, json!({ "ok": true }).to_string()),
        _ => (404, json!({ "error": "not found" }).to_string()),
    });

    let client = ReqwestClient::new();

    let value: Value = client
        .fetch_json(&server.url("/data"))
        .expect("2xx JSON is returned");
    assert_eq!(value["ok"], true);

    let error = client
        .fetch_json(&server.url("/missing"))
        .expect_err("non-2xx must be an error");
    assert!(
        error.to_string().contains("404"),
        "error should report the status: {error}"
    );
}

/// Egress policy for the loopback test server: keeps the standard
/// loopback/scheme rules but skips the HTTPS-server-identifier check in
/// `admit_issuer`, so an `http://127.0.0.1:<port>` issuer is accepted. This is
/// the dev seam a deployment uses to point discovery at a local server, and it
/// only works because `Box<dyn EgressPolicy>` now forwards `admit_issuer`.
struct LoopbackEgress;

impl EgressPolicy for LoopbackEgress {
    fn admit(&self, url: &str) -> Result<()> {
        StandardEgressPolicy::allow_localhost().admit(url)
    }

    fn admit_issuer(&self, iss: &str) -> Result<()> {
        self.admit(iss)
    }
}

fn single_key_jwks(kid: &str) -> Value {
    let (_private, public) = generate_ed25519_keypair();
    json!({ "keys": [public_key_to_jwk(&public, Some(kid)).to_value()] })
}

/// Real reqwest client performs two-step JWKS discovery over a socket
/// (metadata document -> `jwks_uri`), and the JWKS response is cached so the
/// second lookup re-reads only the metadata.
#[test]
fn jwks_discovery_over_real_socket_and_caches_jwks() {
    let jwks_body = single_key_jwks("key-1").to_string();
    let server = TestServer::start(move |seen| {
        let host = seen.headers.get("host").cloned().unwrap_or_default();
        match seen.path.as_str() {
            "/.well-known/aauth-agent.json" => (
                200,
                json!({
                    "issuer": format!("http://{host}"),
                    "jwks_uri": format!("http://{host}/jwks.json"),
                })
                .to_string(),
            ),
            "/jwks.json" => (200, jwks_body.clone()),
            _ => (404, "{}".to_string()),
        }
    });

    let fetcher = JwksFetcher::new(ReqwestClient::new()).with_egress(LoopbackEgress);

    let resolved = fetcher
        .fetch(&server.base, Some("key-1"), "aauth-agent.json")
        .expect("discovery succeeds over the socket");
    assert!(
        get_key_by_kid(&resolved, "key-1").is_some(),
        "fetched JWKS contains the requested kid"
    );
    assert_eq!(
        server.hits(),
        2,
        "first lookup fetches metadata and JWKS once each"
    );

    let again = fetcher
        .fetch(&server.base, Some("key-1"), "aauth-agent.json")
        .expect("second discovery succeeds");
    assert!(get_key_by_kid(&again, "key-1").is_some());
    assert_eq!(
        server.hits(),
        3,
        "second lookup re-reads metadata only; JWKS comes from cache"
    );
}

/// Metadata-poisoning defense over a real socket: when the discovered
/// document's `issuer` does not match the identifier it was fetched from, the
/// fetch fails before the (attacker-influenced) `jwks_uri` is ever followed.
#[test]
fn rejects_metadata_issuer_mismatch_over_real_socket() {
    let jwks_body = single_key_jwks("key-1").to_string();
    let server = TestServer::start(move |seen| {
        let host = seen.headers.get("host").cloned().unwrap_or_default();
        match seen.path.as_str() {
            "/.well-known/aauth-agent.json" => (
                200,
                json!({
                    "issuer": "http://attacker.example",
                    "jwks_uri": format!("http://{host}/jwks.json"),
                })
                .to_string(),
            ),
            "/jwks.json" => (200, jwks_body.clone()),
            _ => (404, "{}".to_string()),
        }
    });

    let fetcher = JwksFetcher::new(ReqwestClient::new()).with_egress(LoopbackEgress);
    let error = fetcher
        .fetch(&server.base, Some("key-1"), "aauth-agent.json")
        .expect_err("issuer mismatch must be rejected");
    assert!(
        error.to_string().contains("issuer mismatch"),
        "unexpected error: {error}"
    );
    assert_eq!(
        server.hits(),
        1,
        "only the metadata document is fetched; the poisoned jwks_uri is never followed"
    );
}
