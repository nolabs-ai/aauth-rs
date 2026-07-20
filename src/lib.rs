//! Rust implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth)
//! — an authorization protocol for agent-to-resource access built on HTTP
//! Message Signatures (RFC 9421) and JWT-based proof-of-possession tokens.
//!
//! # Layers
//!
//! - [`httpsig`] — the reusable HTTP Message Signatures mechanism crate with
//!   the `Signature-Key` header extension.
//! - [`httpsig_policy`] — independent, overridable verification policy.
//! - [`signing`] — the AAuth signing and verification profile built on those
//!   reusable crates.
//! - [`keys`] — key pairs (Ed25519, P-256, P-384), JWKs, RFC 7638
//!   thumbprints, and JWKS discovery with caching.
//! - [`tokens`] — agent (`aa-agent+jwt`), auth (`aa-auth+jwt`), and resource
//!   (`aa-resource+jwt`) token creation and verification.
//! - [`headers`] — AAuth protocol headers: `Accept-Signature`,
//!   `AAuth-Requirement`, `Signature-Error`, `AAuth-Mission`,
//!   `AAuth-Capabilities`, `AAuth-Access`.
//! - [`metadata`] — well-known metadata documents for agents, resources,
//!   access servers, and person servers.
//! - [`agent`] — the agent role: request signing, challenge handling,
//!   deferred polling, and resource-token exchange.
//! - [`resource`] — the resource role: request verification, challenge
//!   building, and resource token issuance.
//!
//! Networking is abstracted behind [`http::HttpClient`]; enable the
//! `reqwest-client` feature for a ready-made blocking client.
//!
//! # Quick start: sign and verify a request
//!
//! ```
//! use aauth::keys::generate_ed25519_keypair;
//! use aauth::signing::{sign_request, verify_signature, SigScheme, SignOptions, VerifyOptions};
//! use std::collections::HashMap;
//!
//! let (private_key, _public) = generate_ed25519_keypair();
//! let mut headers = HashMap::new();
//!
//! // Pseudonymous signature: public key travels inline in Signature-Key
//! let signed = sign_request(
//!     "GET",
//!     "https://resource.example/api/data",
//!     &mut headers,
//!     None,
//!     &private_key,
//!     &SigScheme::Hwk,
//!     &SignOptions::default(),
//! ).unwrap();
//!
//! let valid = verify_signature(
//!     "GET",
//!     "https://resource.example/api/data",
//!     &headers,
//!     None,
//!     &signed.signature_input,
//!     &signed.signature,
//!     &signed.signature_key,
//!     &VerifyOptions::default(),
//! ).unwrap();
//! assert!(valid);
//! ```

pub mod agent;
pub mod deferred;
pub mod egress;
pub mod errors;
pub mod headers;
pub mod http;
pub mod identifiers;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod resource;
pub mod signing;
pub mod tokens;

mod util;

pub use errors::{AAuthError, Result};
pub use httpsig;
pub use httpsig_policy;
