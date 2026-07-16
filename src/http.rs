//! Framework-agnostic HTTP abstractions.
//!
//! The crate never talks to the network directly: components that need HTTP
//! (JWKS discovery, metadata fetching, token exchange, deferred polling) take
//! an implementation of [`HttpClient`]. Enable the `reqwest-client` feature
//! for a ready-made blocking implementation ([`ReqwestClient`]).

use crate::errors::Result;
use serde_json::Value;
use std::collections::HashMap;

/// A minimal HTTP response.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names are lowercased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Get a header value (case-insensitive lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    /// Parse the body as JSON.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Body as UTF-8 text (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A minimal blocking HTTP client interface.
pub trait HttpClient {
    /// Execute a request. `headers` are sent verbatim; `body` is optional.
    fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse>;

    /// Convenience: GET a URL and parse the response body as JSON.
    /// Fails on non-2xx status or invalid JSON.
    fn fetch_json(&self, url: &str) -> Result<Value> {
        let response = self.execute("GET", url, &HashMap::new(), None)?;
        if !(200..300).contains(&response.status) {
            return Err(crate::errors::AAuthError::Http(format!(
                "GET {url} returned HTTP {}",
                response.status
            )));
        }
        response.json().ok_or_else(|| {
            crate::errors::AAuthError::Http(format!("GET {url} returned invalid JSON"))
        })
    }
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        (**self).execute(method, url, headers, body)
    }
}

/// Framework-agnostic HTTP request representation for resource-side
/// verification: the inbound request an AAuth resource wants to verify.
#[derive(Debug, Clone)]
pub struct AAuthRequest {
    /// HTTP method (uppercased).
    pub method: String,
    /// Canonical authority (`host` or `host:port`) per SPEC 10.3.1.
    pub authority: String,
    /// Request path (defaults to "/").
    pub path: String,
    /// Query string without the leading `?`.
    pub query: Option<String>,
    /// Request headers (looked up case-insensitively).
    pub headers: HashMap<String, String>,
    /// Request body bytes, if any.
    pub body: Option<Vec<u8>>,
}

impl AAuthRequest {
    pub fn new(method: &str, authority: &str, path: &str) -> Self {
        AAuthRequest {
            method: method.to_uppercase(),
            authority: authority.to_string(),
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
            query: None,
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Get a header value (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// The full target URI (`https://{authority}{path}?{query}`).
    pub fn target_uri(&self) -> String {
        let mut uri = format!("https://{}{}", self.authority, self.path);
        if let Some(query) = &self.query {
            uri.push('?');
            uri.push_str(query);
        }
        uri
    }
}

#[cfg(feature = "reqwest-client")]
mod reqwest_impl {
    use super::*;
    use crate::errors::AAuthError;
    use std::time::Duration;

    /// Blocking [`HttpClient`] backed by `reqwest` (feature `reqwest-client`).
    pub struct ReqwestClient {
        client: reqwest::blocking::Client,
    }

    impl ReqwestClient {
        pub fn new() -> Self {
            Self::with_timeout(Duration::from_secs(30))
        }

        pub fn with_timeout(timeout: Duration) -> Self {
            ReqwestClient {
                client: reqwest::blocking::Client::builder()
                    .timeout(timeout)
                    .build()
                    .expect("reqwest client construction"),
            }
        }
    }

    impl Default for ReqwestClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HttpClient for ReqwestClient {
        fn execute(
            &self,
            method: &str,
            url: &str,
            headers: &HashMap<String, String>,
            body: Option<&[u8]>,
        ) -> Result<HttpResponse> {
            let method = reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| AAuthError::Http(format!("Invalid HTTP method {method}: {e}")))?;
            let mut request = self.client.request(method, url);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            if let Some(body) = body {
                request = request.body(body.to_vec());
            }
            let response = request
                .send()
                .map_err(|e| AAuthError::Http(format!("Request to {url} failed: {e}")))?;
            let status = response.status().as_u16();
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(value) = value.to_str() {
                    response_headers.insert(name.as_str().to_lowercase(), value.to_string());
                }
            }
            let body = response
                .bytes()
                .map_err(|e| AAuthError::Http(format!("Failed to read response body: {e}")))?
                .to_vec();
            Ok(HttpResponse {
                status,
                headers: response_headers,
                body,
            })
        }
    }
}

#[cfg(feature = "reqwest-client")]
pub use reqwest_impl::ReqwestClient;
