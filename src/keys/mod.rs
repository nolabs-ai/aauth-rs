//! Key management: key pairs, JWK conversion, RFC 7638 thumbprints, JWKS.

mod jwks;

pub use httpsig::keys::{
    calculate_jwk_thumbprint, calculate_jwk_thumbprint_sha512, generate_ed25519_keypair,
    generate_jwks, generate_p256_keypair, generate_p384_keypair, jwk_to_public_key,
    private_key_to_jwk, public_key_to_jwk, Jwk, PrivateKey, PublicKey,
};
pub use jwks::{get_key_by_kid, JwksCache, JwksFetcher, JwksResolver};
