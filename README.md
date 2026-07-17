# aauth-rs

> [!WARNING]
> This is an early-stage and experimental implementation of the AAuth protocol. It has not yet been fully audited by a third party.

Rust implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth) - an authorization protocol for agent-to-resource access built on HTTP Message Signatures (RFC 9421) and JWT-based proof-of-possession tokens.

AAuth defines how an AI agent proves its identity and obtains authorization to call a protected resource. This crate handles both sides of that exchange:

- **Agents** get request signing (RFC 9421 with the `Signature-Key` header extension), 401 challenge handling, resource-token exchange with an authorization / person server, and polling for deferred (202) responses.
- **Resource servers** get primitives to verify inbound agent requests, issue 401 challenges at escalating requirement levels (pseudonym → identity → auth-token), and mint short-lived resource tokens that agents exchange for auth tokens.

This implementation targets conformance to the AAuth draft spec. See
[Security posture](#security-posture).

## Features

- **HTTP Message Signatures (RFC 9421)** with `Signature-Key` schemes per draft-hardt-httpbis-signature-key:
  - `hwk` — inline public key (pseudonymous)
  - `jkt-jwt` — self-issued key delegation from an enclave key (pseudonymous)
  - `jwks_uri` — JWKS discovery via well-known metadata (identity)
  - `jwt` — agent/auth token with `cnf.jwk` confirmation key (identity / authorized)
- **Tokens**: agent tokens (`aa-agent+jwt`), auth tokens (`aa-auth+jwt`), resource tokens (`aa-resource+jwt`) — creation and full verification
- **Keys**: Ed25519 (required by spec), ECDSA P-256 / P-384; JWK conversion; RFC 7638 thumbprints; JWKS fetching with caching, rate limiting, and re-fetch on key rotation
- **Protocol headers**: `Accept-Signature`, `AAuth-Requirement`, `Signature-Error`, `AAuth-Mission`, `AAuth-Capabilities`, `AAuth-Access`
- **Deferred flows**: 202 pending responses, interaction codes, clarification chat, the polling state machine (spec §10.6)
- **Metadata**: well-known documents for agents, resources, access servers, and person servers

Networking is abstracted behind an `HttpClient` trait — the core has no network dependency, allowing you to select your own. Enable the `reqwest-client` feature for a ready-made blocking client:

```toml
[dependencies]
aauth = { version = "0.1", features = ["reqwest-client"] }
```

## Quick start

Each snippet below has a complete, runnable counterpart under
[`examples/`](examples) — run one with `cargo run --example <name>` (e.g.
`sign_request`, `verify_request`, `challenge`, `tokens`,
`exchange_resource_token`), or compile them all with `make examples`.

### Sign a request (agent)

```rust
use aauth::keys::generate_ed25519_keypair;
use aauth::signing::{sign_request, SigScheme, SignOptions};
use std::collections::HashMap;

let (private_key, _public_key) = generate_ed25519_keypair();
let mut headers = HashMap::new();

// Pseudonymous: public key travels inline in the Signature-Key header
sign_request(
    "GET",
    "https://resource.example/api/data",
    &mut headers,                 // receives Signature-Input, Signature, Signature-Key
    None,                         // body
    &private_key,
    &SigScheme::Hwk,
    &SignOptions::default(),
)?;

// With agent identity (JWKS-backed):
sign_request(
    "GET",
    "https://resource.example/api/data",
    &mut headers,
    None,
    &private_key,
    &SigScheme::JwksUri { id: "https://agent.example", dwk: "aauth-agent.json", kid: "key-1" },
    &SignOptions::default(),
)?;

// With an auth token:
sign_request(
    "GET",
    "https://resource.example/api/data",
    &mut headers,
    None,
    &private_key,
    &SigScheme::Jwt { jwt: &auth_token },
    &SignOptions::default(),
)?;
```

### Verify a request (resource server)

```rust
use aauth::resource::RequestVerifier;

let verifier = RequestVerifier::new(vec!["resource.example".to_string()])
    .with_resource_id("https://resource.example") // expected auth-token aud
    .with_jwks_resolver(&resolver);                // needed for jwks_uri / jwt schemes

let result = verifier.verify_request(
    "GET",
    "https://resource.example/api/data",
    &headers,
    None,   // body
    false,  // require_identity
    false,  // require_auth_token
);
if result.valid {
    // result.agent_id / result.user_sub / result.scopes / result.act
}
```

When an auth token is presented, the verifier fully validates its claims
(`typ`, JWKS-discovered signature, `aud` against `resource_id`, `agent`) — not
just the HTTP signature. `resource_id` is therefore required to accept auth
tokens; without it a token minted for another resource would be rejected
rather than silently trusted.

### Challenge an agent (resource server)

```rust
use aauth::resource::{ChallengeBuilder, ChallengeRequest};

let builder = ChallengeBuilder::new(
    "https://resource.example",
    resource_private_key,
    "res-key-1",
    "https://as.example",
);

// 401 challenge requiring an auth token — carries a freshly minted
// resource token bound to the agent's key:
let (header_name, header_value) = builder.build_challenge(&ChallengeRequest {
    require_auth_token: true,
    agent_id: Some("aauth:alice@agents.example"),
    agent_public_key: Some(&agent_public_key),
    scope: Some("read"),
    ..Default::default()
})?;
// respond 401 with `header_name: header_value`
```

### Exchange a resource token for an auth token (agent)

```rust
use aauth::agent::{exchange_resource_token, extract_resource_token, ExchangeOptions};
use aauth::http::ReqwestClient; // feature = "reqwest-client"

// After receiving a 401 challenge:
let resource_token = extract_resource_token(&response_headers).unwrap();

let client = ReqwestClient::new();
let auth_token = exchange_resource_token(
    &client,
    &resource_token,
    &agent_private_key,
    &agent_jwt,                    // aa-agent+jwt for the Signature-Key header
    &ExchangeOptions {
        // Required: pin your own PS and identity. The resource token is
        // verified (iss == the resource you called, agent == you, agent_jkt
        // == your key, exp valid) BEFORE anything is sent, and the request
        // only ever goes to your pinned PS — so a malicious resource can't
        // redirect the exchange to an attacker-controlled server.
        expected_ps: Some("https://ps.example"),
        expected_agent: Some("aauth:alice@agents.example"),
        expected_resource_iss: Some("https://resource.example"),
        on_interaction: Some(&|url, code| {
            println!("Please visit {url} and enter code {code}");
        }),
        ..Default::default()
    },
)?;
// Retry the original request signed with SigScheme::Jwt { jwt: &auth_token }
```

### Tokens

```rust
use aauth::keys::{generate_ed25519_keypair, public_key_to_jwk};
use aauth::tokens::{create_agent_token, verify_agent_token, AgentTokenClaims};

let (server_key, server_public) = generate_ed25519_keypair();
let (_, delegate_public) = generate_ed25519_keypair();

let token = create_agent_token(
    &AgentTokenClaims::new(
        "https://agents.example",
        "delegate-1",
        public_key_to_jwk(&delegate_public, None),
    ),
    &server_key,
    "as-key-1",
)?;

// Verification discovers the issuer's JWKS through the resolver
let claims = verify_agent_token(&token, &resolver, None)?;
```

## Crate layout

| Module | Responsibility |
|---|---|
| `aauth::signing` | RFC 9421 signature base, `Signature-Input` / `Signature` / `Signature-Key` headers, `sign_request`, `verify_signature`. Usable standalone. |
| `aauth::keys` | Key pairs, JWKs, RFC 7638 thumbprints, `JwksFetcher` / `JwksCache` / `JwksResolver` |
| `aauth::jwt` | Minimal JWS (EdDSA, ES256, ES384) used by the token layer |
| `aauth::tokens` | `aa-agent+jwt`, `aa-auth+jwt`, `aa-resource+jwt` create/verify |
| `aauth::headers` | Protocol headers: requirements, `Accept-Signature`, `Signature-Error`, mission, capabilities |
| `aauth::deferred` | 202 pending responses, interaction codes, token endpoint modes |
| `aauth::metadata` | Well-known metadata generation and fetching |
| `aauth::agent` | Agent role: `AgentRequestSigner`, `ChallengeHandler`, `poll_pending_url`, `exchange_resource_token` |
| `aauth::resource` | Resource role: `RequestVerifier`, `ChallengeBuilder`, `ResourceTokenIssuer` |
| `aauth::http` | `HttpClient` trait (+ `ReqwestClient` behind the `reqwest-client` feature) |
| `aauth::identifiers` | `aauth:local@domain` and server identifier validation |
| `aauth::egress` | `EgressPolicy` / `StandardEgressPolicy` — SSRF admission for key discovery and token exchange |

## Security posture

Protocol-level verification is strict and fails closed:

- **Auth-token audience binding.** A resource fully validates an auth token's
  claims (`typ`, signature via JWKS discovery, `aud` == this resource,
  `agent`, `act`, and that `sub`/`scope` is present) — not just the HTTP
  signature — so a token minted for a different resource is rejected at the
  `aud` step (spec §9.4.3).
- **Request freshness.** The RFC 9421 `created` parameter is **required**; a
  signature without it does not verify (spec §12.7.4). This is a bounded
  freshness window (default 60s), not full anti-replay — the profile defines
  no per-request nonce, so replay protection within the window rests on token
  `jti`, not the message signature.
- **SSRF admission (`aauth::egress`) — hardening beyond the spec.** The draft
  has no egress section, but before any issuer-metadata or `jwks_uri` fetch
  (verifier / `JwksFetcher`) or PS token-endpoint dial (agent exchange), the
  target is checked against an `EgressPolicy`. The default
  `StandardEgressPolicy::default_deny()` requires HTTPS and blocks loopback /
  RFC 1918 / link-local / unique-local literal IPs and `localhost`. Use
  `StandardEgressPolicy::allow_localhost()` for local development. Untrusted
  `iss` values must also be well-formed HTTPS server identifiers before they
  drive discovery (this part maps to §12.9.1).
  *Limitation:* the default policy does not resolve DNS, so a public hostname
  that resolves to an internal address is admitted — DNS-rebinding defense
  requires a custom `EgressPolicy` or a connection-level control.
- **Key-discovery integrity.** `JwksFetcher` verifies the discovered metadata
  document's `issuer` equals the identifier it was fetched from before
  trusting its `jwks_uri`. The spec mandates this for the PS and AS documents
  (§12.10.2 / §12.10.3); it is applied uniformly to all four document types
  here (stricter for the agent/resource docs).
- **Resource-token verification before exchange.** The agent verifies the
  resource token before sending it (spec §6.6.3): `iss` matches the resource
  it contacted (confused-deputy defense, when `expected_resource_iss` is
  supplied), `agent` == self, `agent_jkt` == its own key, and `exp` is valid.
  The exchange is always sent to the caller-pinned PS and never to a server
  named by the resource token. The token's `aud` is **not** pinned to the PS:
  it is the PS in three-party mode and the AS in four-party mode, and the PS
  routes on it.
- **Interaction codes — hardening beyond the spec.** §12.3.3 defines `code`
  as a single-use linking string with no mandated encoding or entropy floor.
  This crate uses Crockford base32, drawn with a uniform (bias-free) 5-bit
  extraction from a CSPRNG, with an 8-symbol (≥ 40-bit) floor.
- **Token lifetimes.** Auth tokens are clamped on issue and rejected on verify
  above the 1h ceiling (spec §9.4.1, a **MUST NOT**). Agent tokens are held to
  24h (spec §5.2.2 is a **SHOULD NOT**, so this is stricter than required, and
  can reject a discouraged-but-conformant token). Resource tokens default to
  the recommended ≤ 5 min (§6.6.1). Not enforced: §7.7's rule that an auth
  token's `exp` must not exceed the agent token it derives from — see gaps.

Known coverage gaps (not implemented): missions (§8), AS federation /
`upstream_token` (§9.4.5), the §7.7 auth-token / agent-token lifetime binding,
sub-agent enforcement (§10.2), the PS permission/audit/interaction endpoints,
re-authorization, third-party login, and the `x509` Signature-Key scheme.

## Development

```bash
cargo test --all-features         # unit + integration + security tests
cargo clippy --all-features --all-targets
cargo build --examples --all-features   # compile-check the README examples
make ci                           # the full PR gate (fmt, clippy, test, examples, doc)
```

## License

Apache 2.0, see [LICENSE](LICENSE)
