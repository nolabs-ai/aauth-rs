//! The agent role: signing outbound requests, handling 401 challenges,
//! polling deferred (202) responses, and exchanging resource tokens.

mod challenge_handler;
mod poller;
mod signer;
mod token_exchange;

pub use challenge_handler::ChallengeHandler;
pub use poller::{
    cancel_pending_request, poll_pending_url, OnClarification, OnInteraction, PollCallbacks,
    PollOptions, PollingResult, SignedPost,
};
pub use signer::AgentRequestSigner;
pub use token_exchange::{exchange_resource_token, extract_resource_token, ExchangeOptions};
