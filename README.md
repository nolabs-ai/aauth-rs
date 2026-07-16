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
        // verified (agent == you, aud == your PS, agent_jkt == your key,
        // exp valid) BEFORE anything is sent, so a malicious resource can't
        // redirect the exchange to an attacker-controlled server.
        expected_ps: Some("https://ps.example"),
        expected_agent: Some("aauth:alice@agents.example"),
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
  `agent`) — not just the HTTP signature — so a token minted for a different
  resource is rejected (spec §9.4.3.2).
- **Replay defense.** The RFC 9421 `created` parameter is **required**; a
  signature without it does not verify (spec §12.7.4).
- **SSRF admission (`aauth::egress`).** Before any issuer-metadata or
  `jwks_uri` fetch (verifier / `JwksFetcher`) or PS token-endpoint dial
  (agent exchange), the target is checked against an `EgressPolicy`. The
  default `StandardEgressPolicy::default_deny()` requires HTTPS and blocks
  loopback / RFC 1918 / link-local / unique-local literal IPs and
  `localhost`. Use `StandardEgressPolicy::allow_localhost()` for local
  development. Untrusted `iss` values are also required to be well-formed
  HTTPS server identifiers before they drive discovery.
  *Limitation:* the default policy does not resolve DNS, so a public hostname
  that resolves to an internal address is admitted — DNS-rebinding defense
  requires a custom `EgressPolicy` or a connection-level control.
- **Key-discovery integrity.** `JwksFetcher` verifies the discovered metadata
  document's `issuer` equals the identifier it was fetched from before
  trusting its `jwks_uri` (spec §12.10).
- **Resource-token verification before exchange.** The agent verifies the
  resource token (agent == self, `aud` == the caller-pinned PS, `agent_jkt`
  == its own key, `exp`) before sending it, and refuses to contact a PS it
  did not pin.
- **Interaction codes.** Crockford base32, drawn with a uniform (bias-free)
  5-bit extraction from a CSPRNG, with an 8-symbol (≥ 40-bit) floor
  (spec §12.3.3.1).
- **Token lifetimes.** Clamped on issue and rejected on verify above the spec
  ceilings (auth ≤ 1h, agent ≤ 24h).

Known coverage gaps (not implemented): missions (§8), AS federation /
`upstream_token` (§9.4.5), sub-agent enforcement (§10.2), the PS
permission/audit/interaction endpoints, re-authorization, third-party login,
and the `x509` Signature-Key scheme.

## Development

```bash
cargo test --all-features         # unit + integration + security tests
cargo clippy --all-features --all-targets
```

## License

Apache 2.0, see [LICENSE](LICENSE)
