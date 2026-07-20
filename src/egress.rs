//! Egress admission for SSRF defense (spec §12.8).
//!
//! Before a verifier fetches issuer metadata or a `jwks_uri` — or an agent
//! dials a person server's token endpoint — the target URL is derived from
//! attacker-influenced input (a `iss` claim, a resource token's `aud`). An
//! [`EgressPolicy`] gates those fetches so the library cannot be turned into
//! an SSRF probe against internal addresses.
//!
//! The default, [`StandardEgressPolicy::default_deny`], requires HTTPS and
//! rejects literal loopback / private / link-local / unique-local addresses
//! and the `localhost` name. Public hostnames are admitted (full
//! DNS-rebinding protection requires resolving the host and checking the
//! resolved IP at connection time — see the note on [`StandardEgressPolicy`]).

use crate::errors::{AAuthError, Result};
use crate::identifiers::validate_server_identifier;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Decides whether a URL derived from untrusted input may be fetched.
pub trait EgressPolicy {
    /// Admit (or reject) a URL that is about to be fetched (issuer metadata,
    /// `jwks_uri`, PS token endpoint, pending-poll URL).
    fn admit(&self, url: &str) -> Result<()>;

    /// Admit an issuer / server identifier. The default implementation
    /// validates the value is a well-formed HTTPS server identifier
    /// (spec §5.1 / §12.9.1) and then applies [`EgressPolicy::admit`].
    fn admit_issuer(&self, iss: &str) -> Result<()> {
        validate_server_identifier(iss).map_err(|e| {
            AAuthError::signature(format!("issuer is not a valid server identifier: {e}"))
        })?;
        self.admit(iss)
    }
}

impl<T: EgressPolicy + ?Sized> EgressPolicy for &T {
    fn admit(&self, url: &str) -> Result<()> {
        (**self).admit(url)
    }

    // Forward the inner policy's `admit_issuer` rather than inheriting the
    // default, so a custom override is not silently discarded behind a `&T`.
    fn admit_issuer(&self, iss: &str) -> Result<()> {
        (**self).admit_issuer(iss)
    }
}

impl<T: EgressPolicy + ?Sized> EgressPolicy for Box<T> {
    fn admit(&self, url: &str) -> Result<()> {
        (**self).admit(url)
    }

    // Forward the inner policy's `admit_issuer` rather than inheriting the
    // default, so a custom override survives boxing (e.g. via
    // `JwksFetcher::with_egress`).
    fn admit_issuer(&self, iss: &str) -> Result<()> {
        (**self).admit_issuer(iss)
    }
}

/// The default egress policy.
///
/// # SSRF coverage and limits
///
/// This policy blocks **literal** loopback / private / link-local /
/// unique-local IP addresses and the `localhost` name, and (unless
/// [`allow_http`](StandardEgressPolicy::allow_http) is set) requires HTTPS.
/// It does **not** resolve DNS, so a public hostname that resolves to an
/// internal address is admitted here — defense against DNS rebinding must be
/// enforced at connection time (e.g. a custom [`EgressPolicy`] that resolves
/// and pins the address, or a connection-level control in your HTTP client).
/// This limit is intentional and documented rather than silently assumed
/// away.
#[derive(Debug, Clone)]
pub struct StandardEgressPolicy {
    /// Permit loopback addresses and the `localhost` name (dev/test).
    pub allow_localhost: bool,
    /// Permit the `http` scheme (implied for localhost dev).
    pub allow_http: bool,
    /// Permit non-loopback private ranges (RFC 1918, ULA). Off by default.
    pub allow_private: bool,
}

impl StandardEgressPolicy {
    /// Production default: HTTPS only, all non-public destinations blocked.
    pub fn default_deny() -> Self {
        StandardEgressPolicy {
            allow_localhost: false,
            allow_http: false,
            allow_private: false,
        }
    }

    /// Dev/test policy: also permit `http` and loopback / `localhost`.
    pub fn allow_localhost() -> Self {
        StandardEgressPolicy {
            allow_localhost: true,
            allow_http: true,
            allow_private: false,
        }
    }

    fn reject(url: &str, reason: &str) -> AAuthError {
        AAuthError::Http(format!("egress denied for {url}: {reason}"))
    }

    fn ipv4_is_private_range(&self, addr: Ipv4Addr) -> bool {
        // Loopback handled via allow_localhost; here: RFC1918 + CGNAT + others
        addr.is_private()
            || addr.is_link_local()
            || addr.is_broadcast()
            || addr.is_documentation()
            || addr.octets()[0] == 0
            // 100.64.0.0/10 (CGNAT)
            || (addr.octets()[0] == 100 && (64..128).contains(&addr.octets()[1]))
    }

    fn ipv6_is_private_range(addr: Ipv6Addr) -> bool {
        let seg = addr.segments();
        addr.is_unspecified()
            // unique local fc00::/7
            || (addr.octets()[0] & 0xfe) == 0xfc
            // link-local fe80::/10
            || (seg[0] & 0xffc0) == 0xfe80
    }
}

impl Default for StandardEgressPolicy {
    fn default() -> Self {
        StandardEgressPolicy::default_deny()
    }
}

impl EgressPolicy for StandardEgressPolicy {
    fn admit(&self, url: &str) -> Result<()> {
        let parsed =
            Url::parse(url).map_err(|e| Self::reject(url, &format!("invalid URL: {e}")))?;

        match parsed.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            other => return Err(Self::reject(url, &format!("scheme {other} not permitted"))),
        }

        let host = parsed
            .host()
            .ok_or_else(|| Self::reject(url, "URL has no host"))?;

        match host {
            Host::Domain(name) => {
                let lower = name.to_ascii_lowercase();
                let is_localhost = lower == "localhost" || lower.ends_with(".localhost");
                if is_localhost && !self.allow_localhost {
                    return Err(Self::reject(url, "localhost is not permitted"));
                }
                Ok(())
            }
            Host::Ipv4(addr) => {
                if addr.is_loopback() {
                    if self.allow_localhost {
                        return Ok(());
                    }
                    return Err(Self::reject(url, "loopback address not permitted"));
                }
                if self.ipv4_is_private_range(addr) && !self.allow_private {
                    return Err(Self::reject(
                        url,
                        "private/link-local address not permitted",
                    ));
                }
                Ok(())
            }
            Host::Ipv6(addr) => {
                // Unwrap IPv4-mapped addresses (::ffff:a.b.c.d) and check the
                // embedded v4 against the v4 rules.
                if let Some(v4) = ipv4_mapped(addr) {
                    if v4.is_loopback() {
                        return if self.allow_localhost {
                            Ok(())
                        } else {
                            Err(Self::reject(url, "loopback address not permitted"))
                        };
                    }
                    if self.ipv4_is_private_range(v4) && !self.allow_private {
                        return Err(Self::reject(
                            url,
                            "private/link-local address not permitted",
                        ));
                    }
                    return Ok(());
                }
                if addr.is_loopback() {
                    if self.allow_localhost {
                        return Ok(());
                    }
                    return Err(Self::reject(url, "loopback address not permitted"));
                }
                if Self::ipv6_is_private_range(addr) && !self.allow_private {
                    return Err(Self::reject(
                        url,
                        "private/link-local address not permitted",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn ipv4_mapped(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = addr.segments();
    if seg[0..5] == [0, 0, 0, 0, 0] && seg[5] == 0xffff {
        let [a, b] = seg[6].to_be_bytes();
        let [c, d] = seg[7].to_be_bytes();
        Some(Ipv4Addr::new(a, b, c, d))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy that overrides `admit_issuer` to skip the HTTPS check.
    struct AllowAllIssuers;

    impl EgressPolicy for AllowAllIssuers {
        fn admit(&self, _url: &str) -> Result<()> {
            Ok(())
        }

        fn admit_issuer(&self, _iss: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn box_forwards_admit_issuer_override() {
        // A non-HTTPS issuer would be rejected by the default `admit_issuer`
        // (via `validate_server_identifier`); the override must survive boxing.
        let boxed: Box<dyn EgressPolicy + Send + Sync> = Box::new(AllowAllIssuers);
        assert!(boxed.admit_issuer("http://127.0.0.1:8080").is_ok());
    }

    #[test]
    fn ref_forwards_admit_issuer_override() {
        let policy = AllowAllIssuers;
        let by_ref: &dyn EgressPolicy = &policy;
        assert!(by_ref.admit_issuer("http://127.0.0.1:8080").is_ok());
    }

    #[test]
    fn default_admit_issuer_still_requires_https_through_box() {
        // Without an override the default still runs: a non-HTTPS identifier
        // is rejected even when the policy is boxed.
        let boxed: Box<dyn EgressPolicy + Send + Sync> =
            Box::new(StandardEgressPolicy::allow_localhost());
        assert!(boxed.admit_issuer("http://127.0.0.1:8080").is_err());
    }
}
