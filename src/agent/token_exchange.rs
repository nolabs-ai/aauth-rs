//! Token exchange with a person server (three-party mode, SPEC §4.1.3).

use crate::agent::poller::{poll_pending_url, PollCallbacks, PollOptions};
use crate::egress::EgressPolicy;
use crate::errors::{AAuthError, Result};
use crate::headers::{get_challenge_header_value, parse_aauth_header};
use crate::http::HttpClient;
use crate::jwt::decode_unverified;
use crate::keys::PrivateKey;
use crate::metadata::fetch_ps_metadata;
use crate::signing::{sign_request, SigScheme, SignOptions};
use serde_json::Value;
use std::collections::HashMap;

const AUTH_TOKEN_TYPE: &str = "aa-auth+jwt";

/// Extract the `resource_token` from an AAuth 401 challenge response.
///
/// Parses the challenge header (usually `AAuth-Requirement`) to find the
/// `resource-token` parameter per SPEC §6. Returns `None` when absent.
pub fn extract_resource_token(headers: &HashMap<String, String>) -> Option<String> {
    let raw = get_challenge_header_value(headers);
    if raw.is_empty() {
        return None;
    }
    parse_aauth_header(&raw).ok()?.resource_token
}

/// Options for [`exchange_resource_token`].
///
/// `expected_ps` and `expected_agent` are REQUIRED: the exchange is always
/// sent to the caller-pinned PS, never to a server chosen by the (untrusted)
/// resource token, so a malicious resource cannot redirect the
/// agent-token-signed request elsewhere (spec §6.6.3).
#[derive(Default)]
pub struct ExchangeOptions<'a> {
    /// The agent's own known person server (HTTPS identifier). This is where
    /// the exchange is sent — regardless of the resource token's `aud`, which
    /// is the PS in three-party mode and the AS in four-party mode; the PS
    /// routes on `aud`. REQUIRED.
    pub expected_ps: Option<&'a str>,
    /// The agent's own identifier. The resource token's `agent` MUST match.
    /// REQUIRED.
    pub expected_agent: Option<&'a str>,
    /// Identifier of the resource the agent actually contacted. When set, the
    /// resource token's `iss` MUST match it — the confused-deputy defense of
    /// spec §6.6.3 step 3. Strongly recommended; if omitted, that check is
    /// skipped.
    pub expected_resource_iss: Option<&'a str>,
    /// Resolver for the resource's JWKS. When set, the resource token's
    /// signature is fully verified (spec §6.6.3); when absent, only its
    /// claims (iss, exp, agent, agent_jkt) are checked.
    pub resource_jwks_resolver: Option<&'a dyn crate::keys::JwksResolver>,
    /// Egress policy for the PS token endpoint and pending URLs. Defaults to
    /// [`crate::egress::StandardEgressPolicy::default_deny`].
    pub egress: Option<&'a dyn EgressPolicy>,
    /// Callback invoked when the PS requires human interaction, with
    /// `(interaction_url, code)`. The app should surface these to the user.
    pub on_interaction: Option<crate::agent::poller::OnInteraction<'a>>,
    /// Callback invoked when the PS asks a clarification question, with
    /// `(pending_url, question)`; returns the user's answer or `None`.
    pub on_clarification: Option<crate::agent::poller::OnClarification<'a>>,
    /// Maximum polling attempts before giving up (default 60).
    pub max_polls: Option<usize>,
    /// Polling knobs (sleep override etc.).
    pub poll_options: Option<PollOptions>,
}

fn signed_headers_for(
    method: &str,
    url: &str,
    private_key: &PrivateKey,
    agent_jwt: &str,
    content_type: Option<&str>,
) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    if let Some(content_type) = content_type {
        headers.insert("Content-Type".to_string(), content_type.to_string());
    }
    // Token endpoint requests cover @method/@authority/@path/signature-key
    // only; the body is not part of the signature base here.
    sign_request(
        method,
        url,
        &mut headers,
        None,
        private_key,
        &SigScheme::Jwt { jwt: agent_jwt },
        &SignOptions::default(),
    )?;
    Ok(headers)
}

/// Exchange a `resource_token` for an `auth_token` via the PS (spec §4.1.3).
///
/// Works for both three-party (PS is the token `aud`) and four-party (AS is
/// the `aud`, PS forwards) modes: the request is always sent to the
/// caller-pinned `expected_ps`, and the PS routes on the token's `aud`.
///
/// 1. Verify the resource token before use (spec §6.6.3): `iss` matches the
///    resource contacted (when `expected_resource_iss` is set), `agent` is
///    this agent, `agent_jkt` is this agent's key, and `exp` is valid.
/// 2. Discover the pinned PS's `token_endpoint` via
///    `/.well-known/aauth-person.json` (falls back to `{ps}/token`).
/// 3. POST `{"resource_token": ...}` to the PS, signed with the agent token.
/// 4. On 200, return the `auth_token`; on 202, poll the Location URL until a
///    terminal response (honouring interaction / clarification callbacks).
pub fn exchange_resource_token(
    client: &dyn HttpClient,
    resource_token: &str,
    private_key: &PrivateKey,
    agent_jwt: &str,
    options: &ExchangeOptions<'_>,
) -> Result<String> {
    let token_err = |message: String| AAuthError::token(message, AUTH_TOKEN_TYPE);
    let default_egress = crate::egress::StandardEgressPolicy::default_deny();
    let egress: &dyn EgressPolicy = options.egress.unwrap_or(&default_egress);

    // The PS must be pinned by the caller — never derived solely from the
    // (attacker-influenceable) resource token (spec §6.6.3).
    let expected_ps = options.expected_ps.ok_or_else(|| {
        token_err("expected_ps is required: refusing to send to a PS chosen by the resource".into())
    })?;
    let expected_agent = options.expected_agent.ok_or_else(|| {
        token_err("expected_agent is required to verify the resource token".into())
    })?;

    // Step 1: verify the resource token before using it (spec §6.6.3):
    // iss == the resource we contacted (confused-deputy defense), agent ==
    // self, agent_jkt == our key, exp valid. The token's `aud` is NOT pinned
    // to the PS here — it is the PS in three-party mode and the AS in
    // four-party mode; the PS validates/routes on it. Safety comes from only
    // ever sending to the caller-pinned PS below.
    let agent_jkt = crate::keys::calculate_jwk_thumbprint(&crate::keys::public_key_to_jwk(
        &private_key.public_key(),
        None,
    ))?;
    let verify_opts = crate::tokens::VerifyResourceTokenOptions {
        expected_iss: options.expected_resource_iss,
        expected_aud: None,
        expected_agent: Some(expected_agent),
        expected_agent_jkt: Some(&agent_jkt),
    };
    let _claims = match options.resource_jwks_resolver {
        // Full verification including the resource's signature.
        Some(resolver) => {
            crate::tokens::verify_resource_token(resource_token, resolver, &verify_opts)?
        }
        // No resolver: still enforce claim binding without the signature.
        None => {
            let parsed = decode_unverified(resource_token).map_err(|e| {
                AAuthError::token(
                    format!("Cannot decode resource_token JWT: {e}"),
                    "aa-resource+jwt",
                )
            })?;
            let claim = |name: &str| parsed.claim_str(name);
            if let Some(expected_iss) = options.expected_resource_iss {
                if claim("iss") != Some(expected_iss) {
                    return Err(token_err(format!(
                        "resource_token iss {:?} does not match the contacted resource {expected_iss:?}",
                        claim("iss")
                    )));
                }
            }
            if claim("agent") != Some(expected_agent) {
                return Err(token_err(format!(
                    "resource_token agent {:?} does not match this agent {expected_agent:?}",
                    claim("agent")
                )));
            }
            if claim("agent_jkt") != Some(agent_jkt.as_str()) {
                return Err(token_err(
                    "resource_token agent_jkt does not match this agent's signing key".into(),
                ));
            }
            match parsed.claim_i64("exp") {
                Some(exp) if crate::util::now_unix() < exp => {}
                _ => return Err(token_err("resource_token is expired or missing exp".into())),
            }
            parsed.payload
        }
    };

    // Step 2: discover the PS token_endpoint from the pinned PS's metadata.
    let ps_base = expected_ps.trim_end_matches('/').to_string();
    let token_endpoint = fetch_ps_metadata(client, &ps_base)
        .ok()
        .and_then(|meta| {
            meta.get("token_endpoint")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| format!("{ps_base}/token"));

    // The token endpoint comes from a metadata document — admit it before
    // dialing (spec §12.8). Also enforces HTTPS.
    egress
        .admit(&token_endpoint)
        .map_err(|e| token_err(format!("PS token endpoint rejected by egress policy: {e}")))?;

    // Step 3: sign and POST the resource token to the PS
    let body = serde_json::to_vec(&serde_json::json!({ "resource_token": resource_token }))
        .expect("json serialization");
    let headers = signed_headers_for(
        "POST",
        &token_endpoint,
        private_key,
        agent_jwt,
        Some("application/json"),
    )?;

    let response = client
        .execute("POST", &token_endpoint, &headers, Some(&body))
        .map_err(|e| token_err(format!("PS token_endpoint request failed: {e}")))?;

    // Step 4a: immediate success
    if response.status == 200 {
        let data = response
            .json()
            .ok_or_else(|| token_err("PS response is not valid JSON".into()))?;
        return data
            .get("auth_token")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| token_err("PS response missing 'auth_token'".into()));
    }

    // Step 4b: deferred — poll until terminal
    if response.status == 202 {
        let location = response
            .header("location")
            .map(String::from)
            .ok_or_else(|| {
                token_err("PS returned 202 but no Location header — cannot poll".into())
            })?;

        // The Location is server-supplied — admit it before polling.
        egress
            .admit(&location)
            .map_err(|e| token_err(format!("PS pending URL rejected by egress policy: {e}")))?;

        let signed_get = |url: &str| -> Result<crate::http::HttpResponse> {
            let headers = signed_headers_for("GET", url, private_key, agent_jwt, None)?;
            client.execute("GET", url, &headers, None)
        };
        let signed_post = |url: &str, json_body: &Value| -> Result<crate::http::HttpResponse> {
            let post_body = serde_json::to_vec(json_body).expect("json serialization");
            let headers = signed_headers_for(
                "POST",
                url,
                private_key,
                agent_jwt,
                Some("application/json"),
            )?;
            client.execute("POST", url, &headers, Some(&post_body))
        };

        let mut poll_options = match &options.poll_options {
            Some(opts) => PollOptions {
                max_polls: opts.max_polls,
                default_wait: opts.default_wait,
                sleep: opts.sleep,
            },
            None => PollOptions::default(),
        };
        if let Some(max_polls) = options.max_polls {
            poll_options.max_polls = max_polls;
        }

        let callbacks = PollCallbacks {
            on_interaction: options.on_interaction,
            on_clarification: options.on_clarification,
            sign_and_send_post: if options.on_clarification.is_some() {
                Some(&signed_post)
            } else {
                None
            },
        };

        let result = poll_pending_url(&location, &signed_get, &callbacks, &poll_options);

        if !result.success {
            return Err(token_err(format!(
                "PS deferred exchange failed: {} — {}",
                result.error.unwrap_or_default(),
                result.error_description.unwrap_or_default()
            )));
        }
        return result.auth_token.ok_or_else(|| {
            token_err("PS polling succeeded but response missing 'auth_token'".into())
        });
    }

    Err(token_err(format!(
        "PS token_endpoint returned HTTP {}: {}",
        response.status,
        response.text().chars().take(500).collect::<String>()
    )))
}
