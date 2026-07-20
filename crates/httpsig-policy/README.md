# aauth-httpsig-policy

Independent, fail-closed verification policy for `aauth-httpsig`.

The built-in `Policy` requires `@method`, `@authority`, `@path`,
`signature-key`, and a recent `created` parameter. It permits no
`Signature-Key` schemes until the application explicitly opts into them.

```rust
use httpsig_policy::Policy;

let policy = Policy::new()
    .allow_scheme("hwk")
    .require_header_when_present("cookie")
    .max_age_seconds(60);
```

For a different trust model, implement `VerificationPolicy`. Policy validation
receives the parsed signature and request, and is designed to run before
external key discovery.

The Email Verification-shaped example demonstrates conditional `cookie`
coverage:

```text
cargo run -p aauth-httpsig-policy --example email_verification
```
