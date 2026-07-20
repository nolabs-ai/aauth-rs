//! Independent, fail-closed policy for HTTP Message Signatures.
//!
//! The mechanism crate parses and reconstructs signatures. This crate decides
//! whether a syntactically valid signature is acceptable to an application.
//! It does not perform network discovery or decide whether a signer identity
//! should be trusted.

use httpsig::{PublicKey, RequestParts, UnverifiedSignature};
use std::collections::{BTreeMap, BTreeSet};

/// A verification policy rejection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("Signature-Key scheme {0:?} is not allowed")]
    SchemeNotAllowed(String),

    #[error("required covered component {0:?} is missing")]
    MissingRequiredComponent(String),

    #[error("covered component {0:?} occurs more than once")]
    DuplicateComponent(String),

    #[error("the signature has no valid created parameter")]
    MissingCreated,

    #[error("the signature was created too far in the future")]
    CreatedInFuture,

    #[error("the signature is stale")]
    Stale,

    #[error("header {header:?} is present but component {component:?} is not covered")]
    ConditionalComponentMissing { header: String, component: String },
}

/// Interface implemented by built-in and application-defined policies.
///
/// Implementations inspect only parsed, untrusted data. Key discovery should
/// happen after this check so a rejected scheme cannot trigger network access.
pub trait VerificationPolicy {
    fn validate(
        &self,
        request: &RequestParts<'_>,
        signature: &UnverifiedSignature,
        now: i64,
    ) -> Result<(), PolicyError>;
}

/// Configurable policy with secure protocol-neutral defaults.
///
/// The default policy requires the usual request binding components and a
/// recent `created` parameter, but allows no Signature-Key schemes. An
/// application must explicitly opt in to each scheme that its trust model
/// knows how to resolve.
#[derive(Debug, Clone)]
pub struct Policy {
    allowed_schemes: BTreeSet<String>,
    required_components: BTreeSet<String>,
    conditional_components: BTreeMap<String, String>,
    max_age_seconds: i64,
    future_skew_seconds: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_schemes: BTreeSet::new(),
            required_components: ["@method", "@authority", "@path", "signature-key"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            conditional_components: BTreeMap::new(),
            max_age_seconds: 60,
            future_skew_seconds: 5,
        }
    }
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow one Signature-Key scheme, such as `hwk`.
    #[must_use]
    pub fn allow_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.allowed_schemes
            .insert(scheme.into().to_ascii_lowercase());
        self
    }

    /// Require an additional covered component.
    #[must_use]
    pub fn require_component(mut self, component: impl Into<String>) -> Self {
        self.required_components
            .insert(component.into().to_ascii_lowercase());
        self
    }

    /// Require a header to be covered whenever it is present in the request.
    #[must_use]
    pub fn require_header_when_present(self, header: impl Into<String>) -> Self {
        let header = header.into().to_ascii_lowercase();
        self.require_component_when_header_present(header.clone(), header)
    }

    /// Require `component` whenever `header` is present in the request.
    #[must_use]
    pub fn require_component_when_header_present(
        mut self,
        header: impl Into<String>,
        component: impl Into<String>,
    ) -> Self {
        self.conditional_components.insert(
            header.into().to_ascii_lowercase(),
            component.into().to_ascii_lowercase(),
        );
        self
    }

    /// Set the maximum accepted age of a signature.
    ///
    /// Negative values are clamped to zero.
    #[must_use]
    pub fn max_age_seconds(mut self, seconds: i64) -> Self {
        self.max_age_seconds = seconds.max(0);
        self
    }

    /// Set the tolerated clock skew for future creation timestamps.
    ///
    /// Negative values are clamped to zero.
    #[must_use]
    pub fn future_skew_seconds(mut self, seconds: i64) -> Self {
        self.future_skew_seconds = seconds.max(0);
        self
    }
}

impl VerificationPolicy for Policy {
    fn validate(
        &self,
        request: &RequestParts<'_>,
        signature: &UnverifiedSignature,
        now: i64,
    ) -> Result<(), PolicyError> {
        let scheme = signature.signature_key.scheme.to_ascii_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(PolicyError::SchemeNotAllowed(scheme));
        }

        let mut covered = BTreeSet::new();
        for component in signature.components() {
            let component = component.to_ascii_lowercase();
            if !covered.insert(component.clone()) {
                return Err(PolicyError::DuplicateComponent(component));
            }
        }

        for required in &self.required_components {
            if !covered.contains(required) {
                return Err(PolicyError::MissingRequiredComponent(required.clone()));
            }
        }

        for (header, component) in &self.conditional_components {
            if request.has_header(header) && !covered.contains(component) {
                return Err(PolicyError::ConditionalComponentMissing {
                    header: header.clone(),
                    component: component.clone(),
                });
            }
        }

        let created = signature.created().ok_or(PolicyError::MissingCreated)?;
        if created > now.saturating_add(self.future_skew_seconds) {
            return Err(PolicyError::CreatedInFuture);
        }
        if now.saturating_sub(created) > self.max_age_seconds {
            return Err(PolicyError::Stale);
        }
        Ok(())
    }
}

/// Error returned by [`verify_with_policy`].
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Signature(#[from] httpsig::Error),
}

/// Apply policy first, then verify with an already trusted public key.
///
/// Keeping key resolution outside this helper ensures the application can
/// reject unapproved schemes before performing network or trust-store work.
pub fn verify_with_policy(
    policy: &dyn VerificationPolicy,
    request: &RequestParts<'_>,
    signature: &UnverifiedSignature,
    public_key: &PublicKey,
    now: i64,
) -> Result<(), VerificationError> {
    policy.validate(request, signature, now)?;
    signature.verify(public_key)?;
    Ok(())
}
