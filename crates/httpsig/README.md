# aauth-httpsig

Framework-independent HTTP Message Signatures (RFC 9421) with
`Signature-Key` support.

The package name is `aauth-httpsig`; its Rust library name is `httpsig`:

```toml
[dependencies]
httpsig = { package = "aauth-httpsig", version = "0.1" }
```

This crate owns mechanism:

- `Signature-Input`, `Signature`, and `Signature-Key` parsing and construction
- signature-base construction for derived components and arbitrary headers
- Ed25519, P-256, and P-384 signing and verification
- JWK conversion and thumbprints
- all currently defined `Signature-Key` scheme representations

It deliberately does not decide which schemes, timestamps, identities, or
covered components an application should trust. Use `aauth-httpsig-policy` or
an application-specific policy for those decisions, and apply policy before
network-backed key discovery.

Run the standalone example from the workspace root:

```text
cargo run -p aauth-httpsig --example sign_and_verify
```

```rust
use httpsig::{
    generate_ed25519_keypair, prepare_verification, sign_request, RequestParts,
    SigScheme, SignOptions,
};
use std::collections::HashMap;

let (private_key, public_key) = generate_ed25519_keypair();
let mut headers = HashMap::new();
let signed = sign_request(
    "POST",
    "https://verifier.example/verify",
    &mut headers,
    None,
    &private_key,
    &SigScheme::Hwk,
    &SignOptions::default(),
)?;
let request = RequestParts {
    method: "POST",
    target_uri: "https://verifier.example/verify",
    headers: &headers,
    body: None,
};
let prepared = prepare_verification(
    &request,
    &signed.signature_input,
    &signed.signature,
    &signed.signature_key,
    None,
)?;

// Apply application policy before this cryptographic check.
prepared.verify(&public_key)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```
