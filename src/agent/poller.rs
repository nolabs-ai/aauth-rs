//! Polling state machine for deferred responses.
//!
//! Per spec Section 10.6, the agent polls the pending URL with GET until a
//! terminal response is received.

use crate::errors::Result;
use crate::headers::parse_aauth_header;
use crate::http::HttpResponse;
use serde_json::Value;
use std::time::Duration;

/// Result of polling a pending URL.
#[derive(Debug, Clone, Default)]
pub struct PollingResult {
    pub success: bool,
    pub auth_token: Option<String>,
    pub response_body: Option<Value>,
    pub status_code: u16,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

impl PollingResult {
    fn failure(error: &str, description: Option<String>) -> Self {
        PollingResult {
            success: false,
            error: Some(error.to_string()),
            error_description: description,
            ..Default::default()
        }
    }

    fn terminal(status_code: u16, body: Option<Value>, default_error: &str) -> Self {
        let error = body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(Value::as_str)
            .unwrap_or(default_error)
            .to_string();
        let error_description = body
            .as_ref()
            .and_then(|b| b.get("error_description"))
            .and_then(Value::as_str)
            .map(String::from);
        PollingResult {
            success: false,
            status_code,
            response_body: body,
            error: Some(error),
            error_description,
            ..Default::default()
        }
    }
}

/// Polling behavior knobs.
pub struct PollOptions {
    /// Maximum poll attempts (default 60).
    pub max_polls: usize,
    /// Default seconds between polls (default 2).
    pub default_wait: u64,
    /// Sleep function — override in tests to avoid real waits.
    pub sleep: fn(Duration),
}

impl Default for PollOptions {
    fn default() -> Self {
        PollOptions {
            max_polls: 60,
            default_wait: 2,
            sleep: std::thread::sleep,
        }
    }
}

/// Callback invoked with `(interaction_url, code)` when user interaction is
/// required.
pub type OnInteraction<'a> = &'a dyn Fn(&str, &str);
/// Callback invoked with `(pending_url, question)`; returns the user's
/// answer, or `None` to skip.
pub type OnClarification<'a> = &'a dyn Fn(&str, &str) -> Option<String>;
/// Signed POST function, called with `(url, json_body)`.
pub type SignedPost<'a> = &'a dyn Fn(&str, &Value) -> Result<HttpResponse>;

/// Callbacks invoked during polling.
#[derive(Default)]
pub struct PollCallbacks<'a> {
    /// Invoked once when `requirement=interaction` is received. The agent
    /// should direct the user to the given URL.
    pub on_interaction: Option<OnInteraction<'a>>,
    /// Invoked when a clarification question is received.
    pub on_clarification: Option<OnClarification<'a>>,
    /// POST function for sending clarification responses.
    pub sign_and_send_post: Option<SignedPost<'a>>,
}

/// Extract the user-facing interaction URL from an `AAuth-Requirement`
/// header, appending the code as a query parameter. Falls back to the
/// pending URL when the header carries no url field.
fn extract_interaction_url(aauth_req_header: &str, code: &str, pending_url: &str) -> String {
    if !aauth_req_header.is_empty() {
        if let Ok(parsed) = parse_aauth_header(aauth_req_header) {
            if let Some(endpoint) = parsed.url {
                let sep = if endpoint.contains('?') { '&' } else { '?' };
                return format!("{endpoint}{sep}code={code}");
            }
        }
    }
    pending_url.to_string()
}

fn retry_after_header(response: &HttpResponse) -> Option<u64> {
    response.header("retry-after")?.trim().parse().ok()
}

/// Poll a pending URL until a terminal response, implementing the agent
/// state machine from spec Section 10.6.
///
/// `sign_and_send_get` sends a signed GET to a URL and returns the response.
pub fn poll_pending_url(
    pending_url: &str,
    sign_and_send_get: &dyn Fn(&str) -> Result<HttpResponse>,
    callbacks: &PollCallbacks<'_>,
    options: &PollOptions,
) -> PollingResult {
    let mut default_wait = options.default_wait;

    for attempt in 0..options.max_polls {
        let response = match sign_and_send_get(pending_url) {
            Ok(response) => response,
            Err(e) => return PollingResult::failure("network_error", Some(e.to_string())),
        };

        match response.status {
            // Terminal: 200 OK — success
            200 => {
                let body = response.json();
                return PollingResult {
                    success: true,
                    auth_token: body
                        .as_ref()
                        .and_then(|b| b.get("auth_token"))
                        .and_then(Value::as_str)
                        .map(String::from),
                    response_body: body,
                    status_code: 200,
                    ..Default::default()
                };
            }

            // Terminal errors
            403 => return PollingResult::terminal(403, response.json(), "denied"),
            408 => return PollingResult::terminal(408, response.json(), "expired"),
            410 => return PollingResult::terminal(410, response.json(), "invalid_code"),
            500 => {
                let body = if response
                    .header("content-type")
                    .is_some_and(|ct| ct.starts_with("application/json"))
                {
                    response.json()
                } else {
                    None
                };
                return PollingResult::terminal(500, body, "server_error");
            }

            // Transient: 429 slow_down — increase interval by 5s per spec
            429 => {
                default_wait += 5;
                let wait = retry_after_header(&response)
                    .map(|r| r.max(default_wait))
                    .unwrap_or(default_wait);
                (options.sleep)(Duration::from_secs(wait));
            }

            // Transient: 202 pending or interacting — continue polling
            202 => {
                let body = response.json().unwrap_or(Value::Null);
                let get = |name: &str| body.get(name).and_then(Value::as_str);

                let aauth_req_header = response.header("aauth-requirement").unwrap_or("");
                let mut require = get("requirement").or_else(|| get("require"));
                if require.is_none() && aauth_req_header.contains("requirement=clarification") {
                    require = Some("clarification");
                }
                let code = get("code");
                let clarification = get("clarification");

                // Handle interaction requirement (first poll only)
                if attempt == 0 && require == Some("interaction") {
                    if let (Some(code), Some(on_interaction)) = (code, callbacks.on_interaction) {
                        let url = extract_interaction_url(aauth_req_header, code, pending_url);
                        on_interaction(&url, code);
                    }
                }

                // Handle clarification question
                if let (Some(question), Some(on_clarification), Some(post)) = (
                    clarification,
                    callbacks.on_clarification,
                    callbacks.sign_and_send_post,
                ) {
                    if let Some(answer) = on_clarification(pending_url, question) {
                        let _ = post(
                            pending_url,
                            &serde_json::json!({ "clarification_response": answer }),
                        );
                    }
                }

                // Respect Retry-After
                let wait = retry_after_header(&response).unwrap_or(default_wait);
                if wait > 0 {
                    (options.sleep)(Duration::from_secs(wait));
                }
            }

            // Transient: 503 temporarily unavailable
            503 => {
                let wait = retry_after_header(&response)
                    .map(|r| r.max(1))
                    .unwrap_or(default_wait * 2);
                (options.sleep)(Duration::from_secs(wait));
            }

            // Unknown status — treat as fatal
            status => {
                return PollingResult {
                    success: false,
                    status_code: status,
                    response_body: response.json(),
                    error: Some("unexpected_status".to_string()),
                    error_description: Some(format!("Unexpected HTTP status {status}")),
                    ..Default::default()
                };
            }
        }
    }

    PollingResult::failure(
        "max_polls_exceeded",
        Some(format!(
            "Exceeded maximum {} poll attempts",
            options.max_polls
        )),
    )
}

/// Send DELETE to a pending URL to cancel the request (spec Section 11.4.3).
///
/// The caller provides `sign_and_send_delete`, which performs a signed
/// DELETE request.
pub fn cancel_pending_request(
    sign_and_send_delete: &dyn Fn(&str) -> Result<HttpResponse>,
    pending_url: &str,
) -> Result<HttpResponse> {
    sign_and_send_delete(pending_url)
}
