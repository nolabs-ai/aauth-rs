//! The resource role: verifying inbound agent requests, building 401
//! challenges, and issuing resource tokens.

mod challenge_builder;
mod token_issuer;
mod verifier;

pub use challenge_builder::{ChallengeBuilder, ChallengeRequest};
pub use token_issuer::ResourceTokenIssuer;
pub use verifier::{RequestVerifier, VerificationResult};
