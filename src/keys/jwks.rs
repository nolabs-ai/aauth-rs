//! JWKS fetching and caching.
//!
//! Implements JWKS Discovery per SPEC §JWKS Discovery:
//! - Cache JWKS responses
//! - Re-fetch on unknown kid (key rotation support)
//! - Rate limit: max once per minute per issuer
//! - Discard cached entries after 24 hours max

use crate::egress::{EgressPolicy, StandardEgressPolicy};
use crate::errors::{AAuthError, Result};
use crate::http::HttpClient;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Resolves an identifier to its JWKS document.
///
/// Used by the signature verifier (for `jwks_uri` / `jwt` schemes) and by
/// token verification. Implemented for closures of the form
/// `Fn(&str, Option<&str>, Option<&str>) -> Option<Value>` taking
/// `(identifier, dwk, kid)`, and for [`JwksFetcher`].
pub trait JwksResolver {
    /// Return the JWKS for `identifier`, or `None` if it cannot be resolved.
    ///
    /// `dwk` is the well-known metadata document name to use for discovery
    /// (e.g. `"aauth-agent.json"`); `kid` is the key the caller is looking
    /// for (a hint to re-fetch on rotation).
    fn resolve(&self, identifier: &str, dwk: Option<&str>, kid: Option<&str>) -> Option<Value>;
}

impl<F> JwksResolver for F
where
    F: Fn(&str, Option<&str>, Option<&str>) -> Option<Value>,
{
    fn resolve(&self, identifier: &str, dwk: Option<&str>, kid: Option<&str>) -> Option<Value> {
        self(identifier, dwk, kid)
    }
}

impl<C: HttpClient> JwksResolver for JwksFetcher<C> {
    fn resolve(&self, identifier: &str, dwk: Option<&str>, kid: Option<&str>) -> Option<Value> {
        self.fetch(identifier, kid, dwk.unwrap_or("aauth-agent.json"))
            .ok()
    }
}

/// Get a key from a JWKS document by `kid`.
pub fn get_key_by_kid<'a>(jwks: &'a Value, kid: &str) -> Option<&'a Value> {
    jwks.get("keys")?
        .as_array()?
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
}

/// In-memory cache for JWKS documents with TTL and max-age enforcement.
///
/// Per SPEC §JWKS Discovery, cached entries SHOULD be discarded after at most
/// 24 hours regardless of cache headers.
pub struct JwksCache {
    entries: Mutex<HashMap<String, (Value, Instant)>>,
    ttl: Duration,
    max_age: Duration,
}

impl JwksCache {
    /// Create a cache with the given TTL and a 24h hard max age.
    pub fn new(ttl: Duration) -> Self {
        JwksCache {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_age: Duration::from_secs(86400),
        }
    }

    pub fn with_max_age(ttl: Duration, max_age: Duration) -> Self {
        JwksCache {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_age,
        }
    }

    /// Get a cached JWKS if still valid.
    pub fn get(&self, url: &str) -> Option<Value> {
        let mut entries = self.entries.lock().unwrap();
        let (jwks, cached_at) = entries.get(url)?;
        let age = cached_at.elapsed();
        if age > self.max_age || age > self.ttl {
            entries.remove(url);
            return None;
        }
        Some(jwks.clone())
    }

    /// Cache a JWKS document.
    pub fn set(&self, url: &str, jwks: Value) {
        self.entries
            .lock()
            .unwrap()
            .insert(url.to_string(), (jwks, Instant::now()));
    }

    /// Invalidate a specific entry (e.g. on unknown kid).
    pub fn invalidate(&self, url: &str) {
        self.entries.lock().unwrap().remove(url);
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        JwksCache::new(Duration::from_secs(3600))
    }
}

/// JWKS fetcher with caching, re-fetch on unknown kid, and rate limiting.
///
/// Performs two-step discovery per SIG-KEY §3.5:
/// 1. Fetch `{identifier}/.well-known/{metadata_path}`
/// 2. Extract `jwks_uri` from the metadata
/// 3. Fetch the JWKS from `jwks_uri`
pub struct JwksFetcher<C: HttpClient> {
    http_client: C,
    cache: JwksCache,
    min_fetch_interval: Duration,
    last_fetch_times: Mutex<HashMap<String, Instant>>,
    egress: Box<dyn EgressPolicy + Send + Sync>,
}

impl<C: HttpClient> JwksFetcher<C> {
    /// Create a fetcher with the safe default egress policy (HTTPS only,
    /// no private/loopback destinations).
    pub fn new(http_client: C) -> Self {
        JwksFetcher {
            http_client,
            cache: JwksCache::default(),
            min_fetch_interval: Duration::from_secs(60),
            last_fetch_times: Mutex::new(HashMap::new()),
            egress: Box::new(StandardEgressPolicy::default_deny()),
        }
    }

    pub fn with_cache(http_client: C, cache: JwksCache, min_fetch_interval: Duration) -> Self {
        JwksFetcher {
            http_client,
            cache,
            min_fetch_interval,
            last_fetch_times: Mutex::new(HashMap::new()),
            egress: Box::new(StandardEgressPolicy::default_deny()),
        }
    }

    /// Replace the egress policy (e.g. to permit localhost in development).
    pub fn with_egress(mut self, egress: impl EgressPolicy + Send + Sync + 'static) -> Self {
        self.egress = Box::new(egress);
        self
    }

    fn can_fetch(&self, identifier: &str) -> bool {
        let times = self.last_fetch_times.lock().unwrap();
        match times.get(identifier) {
            Some(last) => last.elapsed() >= self.min_fetch_interval,
            None => true,
        }
    }

    fn record_fetch(&self, identifier: &str) {
        self.last_fetch_times
            .lock()
            .unwrap()
            .insert(identifier.to_string(), Instant::now());
    }

    /// Fetch the JWKS for `identifier` via two-step metadata discovery.
    ///
    /// `kid` (when given) triggers a re-fetch if the cached JWKS does not
    /// contain the key, subject to rate limiting. `metadata_path` is the
    /// well-known document name (e.g. `"aauth-agent.json"`).
    pub fn fetch(&self, identifier: &str, kid: Option<&str>, metadata_path: &str) -> Result<Value> {
        // Validate the issuer is a well-formed HTTPS server identifier and
        // admit it for egress before any fetch (spec §12.8).
        self.egress.admit_issuer(identifier).map_err(|e| {
            AAuthError::jwks(
                format!("issuer {identifier} rejected by egress policy: {e}"),
                None,
            )
        })?;

        // Step 1: discover jwks_uri from metadata
        let metadata_url = format!("{identifier}/.well-known/{metadata_path}");
        let metadata = self.http_client.fetch_json(&metadata_url).map_err(|e| {
            AAuthError::jwks(
                format!("Failed to fetch metadata from {metadata_url}: {e}"),
                Some(metadata_url.clone()),
            )
        })?;

        // Spec §12.10: the metadata document's `issuer` MUST equal the
        // identifier it was fetched from, or a host-poisoned document could
        // point `jwks_uri` at attacker-controlled keys.
        let doc_issuer = metadata.get("issuer").and_then(Value::as_str);
        if doc_issuer != Some(identifier) {
            return Err(AAuthError::jwks(
                format!(
                    "metadata issuer mismatch: document from {metadata_url} has issuer {doc_issuer:?}, expected {identifier:?}"
                ),
                Some(metadata_url),
            ));
        }

        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AAuthError::jwks(
                    format!("No jwks_uri in metadata from {metadata_url}"),
                    Some(metadata_url.clone()),
                )
            })?
            .to_string();

        // Admit the jwks_uri (attacker-influenced via the metadata document)
        // before following it.
        self.egress.admit(&jwks_uri).map_err(|e| {
            AAuthError::jwks(
                format!("jwks_uri {jwks_uri} rejected by egress policy: {e}"),
                Some(jwks_uri.clone()),
            )
        })?;

        // Step 2: check cache
        if let Some(cached) = self.cache.get(&jwks_uri) {
            match kid {
                Some(kid) => {
                    if get_key_by_kid(&cached, kid).is_some() {
                        return Ok(cached);
                    }
                    // Key not found — re-fetch if rate limit allows, else
                    // return the stale cache.
                    if !self.can_fetch(identifier) {
                        return Ok(cached);
                    }
                    self.cache.invalidate(&jwks_uri);
                }
                None => return Ok(cached),
            }
        }

        // Step 3: rate-limited fresh fetch
        if !self.can_fetch(identifier) {
            return Err(AAuthError::jwks(
                format!(
                    "Rate limited: cannot fetch JWKS for {identifier} more than once per {}s",
                    self.min_fetch_interval.as_secs()
                ),
                Some(jwks_uri),
            ));
        }

        let jwks = self.http_client.fetch_json(&jwks_uri).map_err(|e| {
            AAuthError::jwks(
                format!("Failed to fetch JWKS from {jwks_uri}: {e}"),
                Some(jwks_uri.clone()),
            )
        })?;

        if !jwks.is_object() || jwks.get("keys").is_none() {
            return Err(AAuthError::jwks(
                format!("Invalid JWKS structure from {jwks_uri}"),
                Some(jwks_uri),
            ));
        }

        self.cache.set(&jwks_uri, jwks.clone());
        self.record_fetch(identifier);
        Ok(jwks)
    }
}
