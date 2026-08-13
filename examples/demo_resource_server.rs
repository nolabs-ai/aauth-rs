//! Minimal aauth-verifying "resource server" for the nono demo.
//!
//! Real APIs don't accept aauth signatures yet, so this stands in for one:
//! it binds a loopback HTTP port, verifies every inbound request's
//! `Signature`/`Signature-Input`/`Signature-Key` headers, and responds with
//! the recovered agent identity on success or 401 on a missing/invalid
//! signature.
//!
//! Supports both signing schemes an identity can use:
//! - `hwk` (default): the public key travels inline in the request, no
//!   setup needed here.
//! - `jwks_uri`: pass `--jwks-file <path> --issuer <https-url>`, where
//!   `<path>` is the document `nono aauth show --keyref ... --jwks` prints
//!   and `<https-url>` is the `issuer` configured in the signer's
//!   `aauth_identity.scheme`. This resource then answers as if it had
//!   already discovered and cached that identity's JWKS out of band —
//!   which is realistic (real deployments do cache) and exercises the same
//!   verification code a live HTTPS fetch would, just skipping the
//!   transport; it does not itself perform the `/.well-known` + JWKS fetch.
//!
//! Run: `cargo run --example demo_resource_server -- 8787`
//! Or:  `cargo run --example demo_resource_server -- 8787 --jwks-file jwks.json --issuer https://agent.example`
//!
//! Then point a nono profile's `aauth_identity`-signed route at
//! `http://127.0.0.1:8787` and any request nono forwards through it will
//! show up here as a verified, identified call.

use aauth_core::errors::ERROR_INVALID_SIGNATURE;
use aauth_core::headers::build_signature_error;
use aauth_core::keys::JwksResolver;
use aauth_core::resource::RequestVerifier;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read as _;
use tiny_http::{Header, Response, Server};

/// Body size cap, mirroring nono-proxy's own request-body limit — verifying
/// a signature is cheap; buffering an unbounded body first is not.
const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// Serves a single pre-loaded JWKS for one expected issuer, standing in for
/// "we already fetched and cached this identity's JWKS." Rejects (returns
/// `None`) for any other issuer, per the resolver contract's fail-closed
/// expectation.
struct StaticJwksResolver {
    expected_issuer: String,
    jwks: Value,
}

impl JwksResolver for StaticJwksResolver {
    fn resolve(&self, identifier: &str, _dwk: Option<&str>, _kid: Option<&str>) -> Option<Value> {
        (identifier == self.expected_issuer).then(|| self.jwks.clone())
    }
}

struct Args {
    port: u16,
    jwks_resolver: Option<StaticJwksResolver>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut port = 8787;
    let mut jwks_file: Option<String> = None;
    let mut issuer: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jwks-file" => jwks_file = args.next(),
            "--issuer" => issuer = args.next(),
            other => {
                if let Ok(p) = other.parse::<u16>() {
                    port = p;
                }
            }
        }
    }
    let jwks_resolver = match (jwks_file, issuer) {
        (Some(path), Some(expected_issuer)) => {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("failed to read --jwks-file {path}: {e}");
                std::process::exit(1);
            });
            let jwks = serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("failed to parse --jwks-file {path} as JSON: {e}");
                std::process::exit(1);
            });
            Some(StaticJwksResolver {
                expected_issuer,
                jwks,
            })
        }
        (None, None) => None,
        _ => {
            eprintln!("--jwks-file and --issuer must be given together");
            std::process::exit(1);
        }
    };
    Args {
        port,
        jwks_resolver,
    }
}

fn main() {
    let args = parse_args();
    let addr = format!("127.0.0.1:{}", args.port);
    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });
    println!("aauth demo resource server listening on http://{addr}");
    match &args.jwks_resolver {
        Some(r) => println!(
            "(jwks_uri verification enabled for issuer {})",
            r.expected_issuer
        ),
        None => println!("(hwk verification only — no --jwks-file/--issuer given)"),
    }

    // The server's own bind address is the canonical authority — fixed at
    // startup, not derived from each request's (attacker-controlled) Host
    // header. A real deployment would list its own public hostname(s) here.
    let canonical_authorities = vec![addr.clone()];

    let json_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid header");

    for mut request in server.incoming_requests() {
        let method = request.method().to_string();
        let url = request.url().to_string();
        let headers: HashMap<String, String> = request
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.to_string().to_ascii_lowercase(),
                    h.value.to_string(),
                )
            })
            .collect();

        let mut body = Vec::new();
        let read_result = request
            .as_reader()
            .take(MAX_BODY_BYTES)
            .read_to_end(&mut body);
        if let Err(e) = read_result {
            eprintln!("FAIL {method} {url}  body read error: {e}");
            let _ = request.respond(Response::from_string("body read error").with_status_code(400));
            continue;
        }
        let body_opt = if body.is_empty() {
            None
        } else {
            Some(body.as_slice())
        };

        // Verified against our own fixed bind address, so the client's Host
        // header is irrelevant to the authority check (and can't spoof it).
        let target_uri = format!("http://{addr}{url}");
        let mut verifier = RequestVerifier::new(canonical_authorities.clone());
        if let Some(resolver) = &args.jwks_resolver {
            verifier = verifier.with_jwks_resolver(resolver);
        }
        let result =
            verifier.verify_request(&method, &target_uri, &headers, body_opt, false, false);

        let response = if result.valid {
            println!(
                "OK   {method} {url}  agent_id={:?}",
                result.agent_id.as_deref().unwrap_or("(pseudonymous)")
            );
            let body = serde_json::json!({
                "verified": true,
                "agent_id": result.agent_id,
                "method": method,
                "path": url,
            })
            .to_string();
            Response::from_string(body).with_status_code(200)
        } else {
            println!("FAIL {method} {url}  error={:?}", result.error);
            let body = serde_json::json!({
                "verified": false,
                "error": result.error,
            })
            .to_string();
            Response::from_string(body)
                .with_status_code(401)
                .with_header(
                    Header::from_bytes(
                        &b"Signature-Error"[..],
                        build_signature_error(ERROR_INVALID_SIGNATURE, None, None).as_bytes(),
                    )
                    .expect("valid header"),
                )
        };
        let _ = request.respond(response.with_header(json_header.clone()));
    }
}
