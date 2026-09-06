//! Signing-host responder half of the host-spec §B pairing protocol.
//!
//! Answers a pairing host's handshake proposal (QR/deeplink) with an
//! encrypted `Success` statement, then serves the encrypted SSO session:
//! acks every inbound request statement, dispatches the batched
//! [`v1::RemoteMessage`] requests onto the local signing authority, and posts
//! the response statements the pairing host is waiting for. Runs until the
//! peer sends `Disconnected`, the local session ends, or the transport fails.
//!
//! Sensitive operations consult [`truapi_platform::UserConfirmation`], the
//! same seam browser hosts use for their confirmation modals; a headless host
//! implements it with its approval policy.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use parity_scale_codec::Encode;
use tracing::{debug, instrument, warn};
use truapi::{CallContext, latest as api, v01};
use truapi_platform::{
    CreateTransactionReview, ResourceAllocationReview, SignPayloadReview, SignRawReview,
    UserConfirmationReview,
};

use super::SigningHost;
use super::allowances::{
    AllowanceAllocationError, allocate_bulletin_allowance, allocate_smart_contract_allowance,
    allocate_statement_store_allowance,
};
use super::sso_replay::{ReplayExecution, SsoReplayScope, execute_once};
use crate::host_logic::entropy::root_entropy_source;
use crate::host_logic::product_account::{
    ProductAccountError, derive_identity_keypair, derive_ring_vrf_domain_entropy,
    derive_root_keypair_from_entropy, product_public_key_to_address,
};
use crate::host_logic::session::SsoSessionInfo;
#[cfg(test)]
use crate::host_logic::sso::messages::OnExistingAllowancePolicy;
use crate::host_logic::sso::messages::{
    self, CreateTransactionPayload, IncomingSsoRequest, RemoteMessage, RemoteMessageData,
    ResourceAllocationResponse, RingVrfAliasResponse, RingVrfError, RingVrfProofResponse,
    RingVrfSignResponse, SignRawLegacyResponse, SignVrfResponse, SigningPayloadResponseData,
    SigningRequest, SigningResponse, SsoAllocatableResource, SsoAllocatedResource,
    SsoAllocationOutcome, SsoResponseCode, build_outgoing_request_statement,
    build_signed_session_response_statement, decode_incoming_sso_request, v1,
};
use crate::host_logic::sso::pairing::{
    ResponderIdentity, VersionedHandshakeProposal, bootstrap_topic, decode_pairing_deeplink,
    derive_identity_chat_private_key, derive_x25519_keypair_from_entropy,
    encrypt_v2_handshake_response, establish_responder_session_info, v2, x25519_public_key,
};
use crate::host_logic::statement_store::{
    build_signed_statement, current_unix_secs as statement_current_unix_secs,
    parse_new_statements_result,
};
use crate::runtime::authority::{
    AccountAliasAuthorityRequest, AuthorityError, CreateProofAuthorityRequest,
    CreateTransactionAuthorityRequest, ListRingVrfKeysAuthorityRequest, ProductAuthority,
    RegisterRingVrfKeyAuthorityRequest, RingVrfSignAuthorityRequest, SignPayloadAuthorityRequest,
    SignRawAuthorityRequest,
};
use crate::runtime::services::RuntimeServices;
use crate::runtime::sso_remote::fresh_statement_expiry;
use crate::runtime::statement_store_rpc;

/// RFC-0022 domain for the responder's persistent SSO X25519 key.
const SSO_ENCRYPTION_DOMAIN: &[u8] = b"sso";
/// Upper bound on undecodable request ids acknowledged within one serve loop.
const MAX_DECODE_FAILURE_REQUEST_IDS: usize = 1024;

fn derive_responder_identity(
    entropy: &[u8],
) -> Result<(ResponderIdentity, [u8; 32]), ProductAccountError> {
    let statement = derive_identity_keypair(entropy)?;
    let (encryption_secret_key, encryption_public_key) =
        derive_x25519_keypair_from_entropy(entropy, SSO_ENCRYPTION_DOMAIN);
    let identity_chat_private_key = derive_identity_chat_private_key(entropy);
    Ok((
        ResponderIdentity {
            statement_secret: statement.secret.to_bytes(),
            statement_public_key: statement.public.to_bytes(),
            encryption_secret_key,
            encryption_public_key,
        },
        identity_chat_private_key,
    ))
}

/// Bounded set of undecodable request ids acknowledged within one serve loop.
struct DecodeFailureRequestIds {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl DecodeFailureRequestIds {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `request_id`, returning `true` if it was not already served.
    /// Evicts the oldest id when the capacity is exceeded.
    fn insert(&mut self, request_id: String) -> bool {
        if !self.seen.insert(request_id.clone()) {
            return false;
        }
        self.order.push_back(request_id);
        if self.order.len() > MAX_DECODE_FAILURE_REQUEST_IDS
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        true
    }
}

/// Terminal outcome of one responder serve loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderExit {
    /// The pairing host announced `Disconnected`; its durable pairing may be removed.
    PeerDisconnected,
    /// The statement subscription ended without a disconnect message; retain the pairing and retry.
    SubscriptionEnded,
}

/// Public key material identifying one pairing host's resumable SSO session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairedSsoPeer {
    /// Pairing host's statement-store account id.
    pub statement_account_id: [u8; 32],
    /// Pairing host's X25519 public key.
    pub encryption_public_key: [u8; 32],
}

struct EstablishedPairing {
    session: SsoSessionInfo,
    replay_scope: SsoReplayScope,
}

impl PairedSsoPeer {
    /// Extract the public peer material carried by a pairing deeplink.
    pub fn from_deeplink(deeplink: &str) -> Result<Self, String> {
        let VersionedHandshakeProposal::V2(proposal) =
            decode_pairing_deeplink(deeplink).map_err(|err| err.to_string())?;
        Ok(Self {
            statement_account_id: proposal.device.statement_account_id,
            encryption_public_key: proposal.device.encryption_public_key,
        })
    }
}

/// Answer `deeplink` and serve the resulting SSO session until it ends.
#[instrument(skip_all, fields(runtime.method = "sso_responder.respond_to_pairing"))]
pub(crate) async fn respond_to_pairing(
    services: Arc<RuntimeServices>,
    signing_host: Arc<SigningHost>,
    deeplink: &str,
) -> Result<ResponderExit, String> {
    let established = establish_pairing_session(&services, &signing_host, deeplink).await?;
    serve_session(
        services,
        signing_host,
        established.session,
        established.replay_scope,
    )
    .await
}

/// Answer a pairing host's handshake without entering its long-lived serve loop.
pub(crate) async fn establish_pairing(
    services: Arc<RuntimeServices>,
    signing_host: Arc<SigningHost>,
    deeplink: &str,
) -> Result<(), String> {
    establish_pairing_session(&services, &signing_host, deeplink).await?;
    Ok(())
}

async fn establish_pairing_session(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    deeplink: &str,
) -> Result<EstablishedPairing, String> {
    let peer = PairedSsoPeer::from_deeplink(deeplink)?;
    let entropy = signing_host
        .root_entropy()
        .map_err(|err| format!("signing host has no active local session: {err}"))?;
    // Product accounts and the SSO statement identity derive from the
    // canonical root key; the identity is the RFC-0022 uid.dot default account.
    let root = derive_root_keypair_from_entropy(&entropy)
        .map_err(|err| format!("root account derivation failed: {err}"))?;
    let (identity, identity_chat_private_key) = derive_responder_identity(&entropy)
        .map_err(|err| format!("responder identity derivation failed: {err}"))?;
    let device_enc_pub_key = x25519_public_key(services.device_encryption_secret().await?);
    let session = responder_session_from_identity(&identity, peer)?;

    let success = v2::EncryptedResponse::Success(Box::new(v2::Success {
        identity_account_id: identity.statement_public_key,
        root_account_id: root.public.to_bytes(),
        identity_chat_private_key,
        sso_enc_pub_key: identity.encryption_public_key,
        device_enc_pub_key,
        root_entropy_source: root_entropy_source(&entropy),
    }));
    let handshake = encrypt_v2_handshake_response(peer.encryption_public_key, &success)?;
    let topic = bootstrap_topic(peer.statement_account_id, peer.encryption_public_key);
    let statement = build_signed_statement(
        &session,
        topic,
        topic,
        handshake.encode(),
        fresh_statement_expiry(),
    )?;
    services
        .statement_store
        .submit(statement, "sso-responder handshake")
        .await?;
    debug!("answered pairing handshake");

    Ok(EstablishedPairing {
        session,
        replay_scope: SsoReplayScope {
            root_public_key: root.public.to_bytes(),
            peer_statement_account_id: peer.statement_account_id,
            peer_encryption_public_key: peer.encryption_public_key,
        },
    })
}

/// Resume a previously paired SSO session from its persisted public peer keys.
pub(crate) async fn resume_pairing(
    services: Arc<RuntimeServices>,
    signing_host: Arc<SigningHost>,
    peer: PairedSsoPeer,
) -> Result<ResponderExit, String> {
    let entropy = signing_host
        .root_entropy()
        .map_err(|err| format!("signing host has no active local session: {err}"))?;
    let root = derive_root_keypair_from_entropy(&entropy)
        .map_err(|err| format!("root account derivation failed: {err}"))?;
    let session = responder_session(&entropy, peer)?;
    serve_session(
        services,
        signing_host,
        session,
        SsoReplayScope {
            root_public_key: root.public.to_bytes(),
            peer_statement_account_id: peer.statement_account_id,
            peer_encryption_public_key: peer.encryption_public_key,
        },
    )
    .await
}

fn responder_session(entropy: &[u8], peer: PairedSsoPeer) -> Result<SsoSessionInfo, String> {
    let (identity, _) = derive_responder_identity(entropy)
        .map_err(|err| format!("responder identity derivation failed: {err}"))?;
    responder_session_from_identity(&identity, peer)
}

fn responder_session_from_identity(
    identity: &ResponderIdentity,
    peer: PairedSsoPeer,
) -> Result<SsoSessionInfo, String> {
    establish_responder_session_info(
        identity,
        peer.statement_account_id,
        peer.encryption_public_key,
    )
}

/// Serve inbound session statements until the session ends.
#[instrument(skip_all, fields(runtime.method = "sso_responder.serve_session"))]
async fn serve_session(
    services: Arc<RuntimeServices>,
    signing_host: Arc<SigningHost>,
    session: SsoSessionInfo,
    replay_scope: SsoReplayScope,
) -> Result<ResponderExit, String> {
    let rpc_client = services
        .statement_store
        .client("sso-responder session")
        .await
        .map_err(|err| err.to_string())?;
    let mut subscription =
        statement_store_rpc::subscribe_match_all(&rpc_client, &[session.session_id_peer])
            .await
            .map_err(|err| format!("sso-responder subscribe failed: {err}"))?;
    let mut decode_failure_request_ids = DecodeFailureRequestIds::new();

    while let Some(item) = subscription.next().await {
        let value = item.map_err(|err| format!("sso-responder subscription failed: {err}"))?;
        let page = parse_new_statements_result("sso-responder".to_string(), &value)
            .map_err(|err| err.to_string())?;
        for statement in page.statements {
            let incoming = match decode_incoming_sso_request(&session, &statement) {
                Ok(Some(incoming)) => incoming,
                Ok(None) => continue,
                Err(error) => {
                    let prefix = hex::encode(&statement[..statement.len().min(16)]);
                    warn!(
                        reason = %error.reason,
                        statement_bytes = statement.len(),
                        statement_prefix = %prefix,
                        "ignoring undecodable SSO session statement"
                    );
                    // Ack a decodable envelope whose messages did not decode
                    // so the peer fails fast instead of waiting out its
                    // response deadline.
                    if let Some(request_id) = error.request_id
                        && decode_failure_request_ids.insert(request_id.clone())
                    {
                        let ack = build_signed_session_response_statement(
                            &session,
                            request_id,
                            SsoResponseCode::DecodingFailed as u8,
                            fresh_statement_expiry(),
                        )?;
                        services
                            .statement_store
                            .submit_sso(ack, "sso-responder decode-failed ack")
                            .await?;
                    }
                    continue;
                }
            };
            for message in &incoming.messages {
                let cli_summary = format!(
                    "Incoming SSO request · {}\nstatement_request_id={}\nremote_message_id={}",
                    message, incoming.request_id, message.message_id
                );
                tracing::event!(
                    target: "truapi_server::sso_transcript",
                    tracing::Level::DEBUG,
                    cli_summary = cli_summary.as_str(),
                    cli_event = "request_received",
                    request = %message,
                    statement_request_id = %incoming.request_id,
                    remote_message_id = %message.message_id,
                );
            }
            let request_id = incoming.request_id.clone();
            let expires_at_unix_secs = incoming.expires_at_unix_secs;
            let duplicate_exit = duplicate_request_exit(&incoming);
            let execution = execute_once(
                services.platform.as_ref(),
                signing_host.sso_replay_locks(),
                replay_scope,
                &request_id,
                expires_at_unix_secs,
                statement_current_unix_secs(),
                || serve_request(&services, &signing_host, &session, incoming),
            )
            .await?;
            let exit = match execution {
                ReplayExecution::Duplicate => {
                    acknowledge_request(&services, &session, &request_id).await?;
                    duplicate_exit
                }
                ReplayExecution::Executed(exit) => exit,
            };
            if let Some(exit) = exit {
                return Ok(exit);
            }
        }
    }
    Ok(ResponderExit::SubscriptionEnded)
}

/// Ack one inbound request statement and answer its batched messages.
async fn serve_request(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    session: &SsoSessionInfo,
    incoming: IncomingSsoRequest,
) -> Result<Option<ResponderExit>, String> {
    acknowledge_request(services, session, &incoming.request_id).await?;

    for message in incoming.messages {
        let RemoteMessageData::V1(request) = message.data;
        if matches!(request, v1::RemoteMessage::Disconnected) {
            debug!("pairing host disconnected the SSO session");
            return Ok(Some(ResponderExit::PeerDisconnected));
        }
        let request_name = request.to_string();
        let responding_to = message.message_id.clone();
        let started = Instant::now();
        let Some(answer) =
            answer_remote_message(services, signing_host, message.message_id, request).await
        else {
            continue;
        };
        let response = answer.response;
        let response_message_id = response.message_id.clone();
        let response_result = answer
            .response_result
            .unwrap_or_else(|| remote_response_result(&response.data));
        let statement_request_id = format!("resp:{}", response.message_id);
        let statement = build_outgoing_request_statement(
            session,
            statement_request_id,
            vec![response],
            fresh_statement_expiry(),
        )?;
        let publish_result = services
            .statement_store
            .submit_sso(statement, "sso-responder response")
            .await;
        let elapsed_ms = started.elapsed().as_millis();
        match publish_result {
            Ok(()) => {
                let cli_summary = response_cli_summary(
                    "SSO response sent",
                    &request_name,
                    &incoming.request_id,
                    &responding_to,
                    &response_message_id,
                    &response_result,
                    elapsed_ms,
                );
                tracing::event!(
                    target: "truapi_server::sso_transcript",
                    tracing::Level::DEBUG,
                    cli_summary = cli_summary.as_str(),
                    cli_event = "response_sent",
                    request = request_name.as_str(),
                    statement_request_id = %incoming.request_id,
                    responding_to = %responding_to,
                    %response_message_id,
                    outcome = response_result.outcome,
                    reason = response_result.reason.as_deref().unwrap_or_default(),
                    elapsed_ms = elapsed_ms as u64,
                );
            }
            Err(reason) => {
                let failure = ResponseResult {
                    outcome: "publish_failed",
                    reason: Some(reason.clone()),
                };
                let cli_summary = response_cli_summary(
                    "SSO response failed",
                    &request_name,
                    &incoming.request_id,
                    &responding_to,
                    &response_message_id,
                    &failure,
                    elapsed_ms,
                );
                tracing::event!(
                    target: "truapi_server::sso_transcript",
                    tracing::Level::WARN,
                    cli_summary = cli_summary.as_str(),
                    cli_event = "response_failed",
                    request = request_name.as_str(),
                    statement_request_id = %incoming.request_id,
                    responding_to = %responding_to,
                    %response_message_id,
                    outcome = failure.outcome,
                    reason = %reason,
                    elapsed_ms = elapsed_ms as u64,
                );
                return Err(reason);
            }
        }
    }
    Ok(None)
}

async fn acknowledge_request(
    services: &Arc<RuntimeServices>,
    session: &SsoSessionInfo,
    request_id: &str,
) -> Result<(), String> {
    let ack = build_signed_session_response_statement(
        session,
        request_id.to_string(),
        SsoResponseCode::Success as u8,
        fresh_statement_expiry(),
    )?;
    services
        .statement_store
        .submit_sso(ack, "sso-responder ack")
        .await
}

fn duplicate_request_exit(incoming: &IncomingSsoRequest) -> Option<ResponderExit> {
    incoming
        .messages
        .iter()
        .any(|message| {
            matches!(
                &message.data,
                RemoteMessageData::V1(v1::RemoteMessage::Disconnected)
            )
        })
        .then_some(ResponderExit::PeerDisconnected)
}

struct ResponseResult {
    outcome: &'static str,
    reason: Option<String>,
}

/// Result of answering one remote message: the response envelope and an
/// optional pre-classified outcome for logging.
pub(crate) struct AnsweredRemoteMessage {
    /// Response to post back over the session transport.
    pub(crate) response: RemoteMessage,
    /// Pre-classified outcome summary for SSO transcript logging (outcome code and error reason).
    response_result: Option<ResponseResult>,
}

struct ResourceAllocationAnswer {
    payload: Result<Vec<SsoAllocationOutcome>, String>,
    item_failures: Vec<String>,
}

fn remote_response_result(message: &RemoteMessageData) -> ResponseResult {
    let RemoteMessageData::V1(message) = message;
    let error = match message {
        v1::RemoteMessage::SignResponse(response) => response.payload.as_ref().err().cloned(),
        v1::RemoteMessage::RingVrfAliasResponse(response) => {
            response.payload.as_ref().err().map(ring_vrf_error_reason)
        }
        v1::RemoteMessage::RingVrfProofResponse(response) => {
            response.payload.as_ref().err().map(ring_vrf_error_reason)
        }
        v1::RemoteMessage::RegisterRingVrfKeyResponse(response) => {
            response.payload.as_ref().err().map(ring_vrf_error_reason)
        }
        v1::RemoteMessage::ListRingVrfKeysResponse(response) => {
            response.payload.as_ref().err().map(ring_vrf_error_reason)
        }
        v1::RemoteMessage::RingVrfSignResponse(response) => {
            response.payload.as_ref().err().map(ring_vrf_error_reason)
        }
        v1::RemoteMessage::ResourceAllocationResponse(response) => {
            return resource_allocation_payload_result(&response.payload, &[]);
        }
        v1::RemoteMessage::CreateTransactionResponse(response) => {
            response.signed_transaction.as_ref().err().cloned()
        }
        v1::RemoteMessage::SignRawLegacyResponse(response) => {
            response.signature.as_ref().err().cloned()
        }
        v1::RemoteMessage::SignVrfResponse(response) => {
            response.payload.as_ref().err().map(sign_vrf_error_reason)
        }
        _ => None,
    };
    ResponseResult {
        outcome: if error.is_some() { "error" } else { "ok" },
        reason: error,
    }
}

fn resource_allocation_payload_result(
    payload: &Result<Vec<SsoAllocationOutcome>, String>,
    item_failures: &[String],
) -> ResponseResult {
    let outcomes = match payload {
        Ok(outcomes) => outcomes,
        Err(reason) => {
            return ResponseResult {
                outcome: "error",
                reason: Some(reason.clone()),
            };
        }
    };
    if outcomes.is_empty() {
        return ResponseResult {
            outcome: "ok",
            reason: None,
        };
    }

    let allocated = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, SsoAllocationOutcome::Allocated(_)))
        .count();
    let rejected = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, SsoAllocationOutcome::Rejected))
        .count();
    let unavailable = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, SsoAllocationOutcome::NotAvailable))
        .count();
    let total = outcomes.len();

    if allocated == total {
        return ResponseResult {
            outcome: "ok",
            reason: None,
        };
    }
    if allocated > 0 {
        let mut reason = format!("{allocated} of {total} requested resources allocated");
        if rejected > 0 {
            reason.push_str(&format!("; {rejected} rejected"));
        }
        if unavailable > 0 {
            reason.push_str(&format!("; {unavailable} unavailable"));
        }
        return allocation_result_with_failures(
            ResponseResult {
                outcome: "partial",
                reason: Some(reason),
            },
            item_failures,
        );
    }
    if rejected > 0 {
        let reason = if rejected == total {
            if total == 1 {
                "Requested resource was rejected".to_string()
            } else {
                format!("All {total} requested resources were rejected")
            }
        } else {
            format!("No resources allocated; {rejected} rejected; {unavailable} unavailable")
        };
        return allocation_result_with_failures(
            ResponseResult {
                outcome: "rejected",
                reason: Some(reason),
            },
            item_failures,
        );
    }

    allocation_result_with_failures(
        ResponseResult {
            outcome: "not_available",
            reason: Some(if total == 1 {
                "Requested resource is not available".to_string()
            } else {
                format!("None of the {total} requested resources are available")
            }),
        },
        item_failures,
    )
}

fn allocation_result_with_failures(
    mut result: ResponseResult,
    item_failures: &[String],
) -> ResponseResult {
    if !item_failures.is_empty() {
        let details = item_failures.join("; ").replace(['\r', '\n'], " ");
        result.reason = Some(match result.reason {
            Some(summary) => format!("{summary}: {details}"),
            None => details,
        });
    }
    result
}

fn ring_vrf_error_reason(error: &RingVrfError) -> String {
    match error {
        RingVrfError::RingNotFound => "RingNotFound".to_string(),
        RingVrfError::NotMember => "NotMember".to_string(),
        RingVrfError::KeyNotRegistered => "KeyNotRegistered".to_string(),
        RingVrfError::KeyNotInRing => "KeyNotInRing".to_string(),
        RingVrfError::NotAllowlisted => "NotAllowlisted".to_string(),
        RingVrfError::Rejected => "Rejected".to_string(),
        RingVrfError::Unknown { reason } => format!("Unknown: {reason}"),
    }
}

fn response_cli_summary(
    heading: &str,
    request_name: &str,
    statement_request_id: &str,
    responding_to: &str,
    response_message_id: &str,
    result: &ResponseResult,
    elapsed_ms: u128,
) -> String {
    let mut summary = format!(
        "{heading} · {request_name} · {}\nstatement_request_id={statement_request_id}\nresponding_to={responding_to}\nresponse_message_id={response_message_id}\nelapsed_ms={elapsed_ms}",
        result.outcome
    );
    if let Some(reason) = &result.reason {
        summary.push_str("\nreason=");
        summary.push_str(&reason.replace(['\r', '\n'], " "));
    }
    summary
}

/// Answer one application-level request message; `None` for message kinds
/// that take no response (responses echoed by the peer, unknown variants).
pub(crate) async fn answer_remote_message(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    message_id: String,
    request: v1::RemoteMessage,
) -> Option<AnsweredRemoteMessage> {
    let response_id = format!("{message_id}:response");
    let mut response_result = None;
    let data = match request {
        v1::RemoteMessage::SignRequest(request) => v1::RemoteMessage::SignResponse(
            sign_response(services, signing_host, &message_id, *request).await,
        ),
        v1::RemoteMessage::RingVrfAliasRequest(request) => {
            let payload = account_alias_response(signing_host, request).await;
            v1::RemoteMessage::RingVrfAliasResponse(RingVrfAliasResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::RingVrfProofRequest(request) => {
            let payload = create_proof_response(signing_host, request).await;
            v1::RemoteMessage::RingVrfProofResponse(RingVrfProofResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::RegisterRingVrfKeyRequest(request) => {
            let payload = register_ring_vrf_key_response(signing_host, request).await;
            v1::RemoteMessage::RegisterRingVrfKeyResponse(messages::RegisterRingVrfKeyResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::ListRingVrfKeysRequest(request) => {
            let payload = list_ring_vrf_keys_response(signing_host, request).await;
            v1::RemoteMessage::ListRingVrfKeysResponse(messages::ListRingVrfKeysResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::RingVrfSignRequest(request) => {
            let payload = ring_vrf_sign_response(signing_host, request).await;
            v1::RemoteMessage::RingVrfSignResponse(RingVrfSignResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::ResourceAllocationRequest(request) => {
            let answer = resource_allocation_response(services, signing_host, request).await;
            if let Err(reason) = &answer.payload {
                warn!(%reason, "resource allocation request failed");
            }
            response_result = Some(resource_allocation_payload_result(
                &answer.payload,
                &answer.item_failures,
            ));
            v1::RemoteMessage::ResourceAllocationResponse(ResourceAllocationResponse {
                responding_to: message_id,
                payload: answer.payload,
            })
        }
        v1::RemoteMessage::CreateTransactionRequest(request) => {
            let CreateTransactionPayload::V1(payload) = request.payload;
            let signed_transaction = create_transaction_response(
                services,
                signing_host,
                CreateTransactionReview::Product(payload.clone()),
                CreateTransactionAuthorityRequest::Product(payload),
            )
            .await;
            v1::RemoteMessage::CreateTransactionResponse(messages::CreateTransactionResponse {
                responding_to: message_id,
                signed_transaction,
            })
        }
        v1::RemoteMessage::CreateTransactionLegacyRequest(request) => {
            let messages::CreateTransactionLegacyPayload::V1(payload) = request.payload;
            let signed_transaction = create_transaction_response(
                services,
                signing_host,
                CreateTransactionReview::LegacyAccount(payload.clone()),
                CreateTransactionAuthorityRequest::IdentityAccount(payload),
            )
            .await;
            v1::RemoteMessage::CreateTransactionResponse(messages::CreateTransactionResponse {
                responding_to: message_id,
                signed_transaction,
            })
        }
        v1::RemoteMessage::SignRawLegacyRequest(request) => {
            let signature = sign_raw_legacy_response(services, signing_host, request).await;
            v1::RemoteMessage::SignRawLegacyResponse(SignRawLegacyResponse {
                responding_to: message_id,
                signature,
            })
        }
        v1::RemoteMessage::SignVrfRequest(request) => {
            let payload = sign_vrf_response(signing_host, message_id.clone(), request).await;
            v1::RemoteMessage::SignVrfResponse(SignVrfResponse {
                responding_to: message_id,
                payload,
            })
        }
        v1::RemoteMessage::ProductSubtreeRequest(request) => {
            let product_public_key = match signing_host.current_session() {
                Some(session) => signing_host
                    .product_subtree_public_key(
                        &CallContext::with_request_id(message_id.clone()),
                        &session,
                        request.product_id,
                    )
                    .await
                    .map_err(|err| err.to_string()),
                None => Err("signing host is disconnected".to_string()),
            };
            v1::RemoteMessage::ProductSubtreeResponse(messages::ProductSubtreeResponse {
                responding_to: message_id,
                product_public_key,
            })
        }
        v1::RemoteMessage::Disconnected
        | v1::RemoteMessage::SignResponse(_)
        | v1::RemoteMessage::RingVrfAliasResponse(_)
        | v1::RemoteMessage::RingVrfProofResponse(_)
        | v1::RemoteMessage::RegisterRingVrfKeyResponse(_)
        | v1::RemoteMessage::ListRingVrfKeysResponse(_)
        | v1::RemoteMessage::RingVrfSignResponse(_)
        | v1::RemoteMessage::ResourceAllocationResponse(_)
        | v1::RemoteMessage::CreateTransactionResponse(_)
        | v1::RemoteMessage::SignRawLegacyResponse(_)
        | v1::RemoteMessage::ProductSubtreeResponse(_)
        | v1::RemoteMessage::SignVrfResponse(_) => return None,
    };
    Some(AnsweredRemoteMessage {
        response: RemoteMessage {
            message_id: response_id,
            data: RemoteMessageData::V1(data),
        },
        response_result,
    })
}

async fn resource_allocation_response(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    request: messages::ResourceAllocationRequest,
) -> ResourceAllocationAnswer {
    let Some(session) = signing_host.current_session() else {
        return ResourceAllocationAnswer {
            payload: Err("signing host session is not active".into()),
            item_failures: Vec::new(),
        };
    };
    let review = UserConfirmationReview::ResourceAllocation(ResourceAllocationReview {
        calling_product_id: request.calling_product_id.clone(),
        resources: request
            .resources
            .iter()
            .map(public_allocatable_resource)
            .collect(),
    });
    match services.platform.confirm_user_action(review).await {
        Ok(true) => {}
        Ok(false) => {
            return ResourceAllocationAnswer {
                payload: Ok(vec![
                    SsoAllocationOutcome::Rejected;
                    request.resources.len()
                ]),
                item_failures: Vec::new(),
            };
        }
        Err(err) => {
            return ResourceAllocationAnswer {
                payload: Err(format!("confirmation failed: {}", err.reason)),
                item_failures: Vec::new(),
            };
        }
    }

    if let Err(error) = signing_host.require_current_session(&session) {
        return ResourceAllocationAnswer {
            payload: Err(error.to_string()),
            item_failures: Vec::new(),
        };
    }
    let mut outcomes = Vec::with_capacity(request.resources.len());
    let mut item_failures = Vec::new();
    for resource in request.resources {
        let outcome = match resource {
            SsoAllocatableResource::StatementStoreAllowance => allocate_statement_store_allowance(
                services,
                signing_host,
                &session,
                &request.calling_product_id,
                request.on_existing,
            )
            .await
            .map(|slot_account_key| {
                SsoAllocationOutcome::Allocated(SsoAllocatedResource::StatementStoreAllowance {
                    slot_account_key,
                })
            }),
            SsoAllocatableResource::BulletinAllowance => allocate_bulletin_allowance(
                services,
                signing_host,
                &session,
                &request.calling_product_id,
                request.on_existing,
            )
            .await
            .map(|slot_account_key| {
                SsoAllocationOutcome::Allocated(SsoAllocatedResource::BulletinAllowance {
                    slot_account_key,
                })
            }),
            SsoAllocatableResource::SmartContractAllowance(index) => {
                allocate_smart_contract_allowance(
                    services,
                    signing_host,
                    &session,
                    &request.calling_product_id,
                    index.clone(),
                    request.on_existing,
                )
                .await
                .map(|()| {
                    SsoAllocationOutcome::Allocated(SsoAllocatedResource::SmartContractAllowance)
                })
            }
            SsoAllocatableResource::AutoSigning => (|| -> Result<_, AllowanceAllocationError> {
                let product_root_private_key = signing_host
                    .product_subtree_secret(&session, &request.calling_product_id)
                    .map_err(AllowanceAllocationError::Authority)?;
                let root_entropy = signing_host.session_entropy(&session)?;
                let ring_vrf_domain_entropy =
                    derive_ring_vrf_domain_entropy(&root_entropy, &request.calling_product_id)
                        .map_err(super::product_authority_error)
                        .map_err(AllowanceAllocationError::Authority)?;
                Ok(SsoAllocationOutcome::Allocated(
                    SsoAllocatedResource::AutoSigning {
                        product_root_private_key,
                        ring_vrf_domain_entropy,
                    },
                ))
            })(),
        };
        match outcome {
            Ok(outcome) => outcomes.push(outcome),
            Err(err) => {
                let reason = err.to_string();
                warn!(%reason, "resource allocation item failed");
                item_failures.push(reason);
                outcomes.push(SsoAllocationOutcome::NotAvailable);
            }
        }
    }
    ResourceAllocationAnswer {
        payload: Ok(outcomes),
        item_failures,
    }
}

fn public_allocatable_resource(resource: &SsoAllocatableResource) -> api::AllocatableResource {
    match resource {
        SsoAllocatableResource::StatementStoreAllowance => {
            api::AllocatableResource::StatementStoreAllowance
        }
        SsoAllocatableResource::BulletinAllowance => api::AllocatableResource::BulletinAllowance,
        SsoAllocatableResource::SmartContractAllowance(index) => {
            api::AllocatableResource::SmartContractAllowance(index.clone())
        }
        SsoAllocatableResource::AutoSigning => api::AllocatableResource::AutoSigning,
    }
}

/// Confirm and serve a payload or raw signing request.
async fn sign_response(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    message_id: &str,
    request: SigningRequest,
) -> SigningResponse {
    let payload = serve_sign_request(services, signing_host, request).await;
    if let Err(reason) = &payload {
        warn!(%reason, "sign request failed");
    }
    SigningResponse {
        responding_to: message_id.to_string(),
        payload,
    }
}

async fn serve_sign_request(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    request: SigningRequest,
) -> Result<SigningPayloadResponseData, String> {
    let session = signing_host
        .current_session()
        .ok_or_else(|| "signing host session is not active".to_string())?;
    let cx = CallContext::default();
    let response = match request {
        SigningRequest::Payload(request) => {
            let request: api::HostSignPayloadRequest = (*request).into();
            confirm(
                services,
                UserConfirmationReview::SignPayload(SignPayloadReview::Product(request.clone())),
            )
            .await?;
            signing_host
                .sign_payload(&cx, &session, SignPayloadAuthorityRequest::Product(request))
                .await
        }
        SigningRequest::Raw(request) => {
            let request: api::HostSignRawRequest = request.into();
            confirm(
                services,
                UserConfirmationReview::SignRaw(SignRawReview::Product(request.clone())),
            )
            .await?;
            signing_host
                .sign_raw(&cx, &session, SignRawAuthorityRequest::Product(request))
                .await
        }
    }
    .map_err(|err| err.to_string())?;
    Ok(SigningPayloadResponseData {
        signature: response.signature,
        signed_transaction: response.signed_transaction,
    })
}

async fn sign_raw_legacy_response(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    request: messages::SignRawLegacyRequest,
) -> Result<Vec<u8>, String> {
    let session = signing_host
        .current_session()
        .ok_or_else(|| "signing host session is not active".to_string())?;
    let public_request = api::HostSignRawWithLegacyAccountRequest {
        signer: product_public_key_to_address(request.account),
        payload: request.data.into(),
    };
    confirm(
        services,
        UserConfirmationReview::SignRaw(SignRawReview::LegacyAccount(public_request.clone())),
    )
    .await?;
    signing_host
        .sign_raw(
            &CallContext::default(),
            &session,
            SignRawAuthorityRequest::LegacyAccount {
                account: request.account,
                request: public_request,
            },
        )
        .await
        .map(|response| response.signature)
        .map_err(|err| err.to_string())
}

fn sign_vrf_error_reason(error: &v01::HostAccountSignVrfError) -> String {
    match error {
        v01::HostAccountSignVrfError::NotConnected => "NotConnected".to_string(),
        v01::HostAccountSignVrfError::Rejected => "Rejected".to_string(),
        v01::HostAccountSignVrfError::Unknown { reason } => reason.clone(),
    }
}

async fn sign_vrf_response(
    signing_host: &Arc<SigningHost>,
    message_id: String,
    request: messages::SignVrfRequest,
) -> Result<v01::VrfSignature, v01::HostAccountSignVrfError> {
    let session = signing_host
        .current_session()
        .ok_or(v01::HostAccountSignVrfError::NotConnected)?;
    signing_host
        .sign_vrf(
            &CallContext::with_request_id(message_id),
            &session,
            request.calling_product_id,
            request.payload,
        )
        .await
        .map_err(|err| match err {
            AuthorityError::Disconnected => v01::HostAccountSignVrfError::NotConnected,
            AuthorityError::Rejected => v01::HostAccountSignVrfError::Rejected,
            AuthorityError::Cancelled(err) => v01::HostAccountSignVrfError::Unknown {
                reason: err.to_string(),
            },
            AuthorityError::Unavailable { reason }
            | AuthorityError::NotSupported { reason }
            | AuthorityError::Unknown { reason } => {
                v01::HostAccountSignVrfError::Unknown { reason }
            }
        })
}

/// Confirm and serve a transaction-creation request.
async fn create_transaction_response(
    services: &Arc<RuntimeServices>,
    signing_host: &Arc<SigningHost>,
    review: CreateTransactionReview,
    request: CreateTransactionAuthorityRequest,
) -> Result<Vec<u8>, String> {
    let session = signing_host
        .current_session()
        .ok_or_else(|| "signing host session is not active".to_string())?;
    confirm(services, UserConfirmationReview::CreateTransaction(review)).await?;
    let cx = CallContext::default();
    signing_host
        .create_transaction(&cx, &session, request)
        .await
        .map(|response| response.transaction)
        .map_err(|err| err.to_string())
}

async fn account_alias_response(
    signing_host: &Arc<SigningHost>,
    request: messages::RingVrfAliasRequest,
) -> Result<api::HostAccountGetAliasResponse, RingVrfError> {
    let session = signing_host
        .current_session()
        .ok_or_else(disconnected_ring_vrf)?;
    let cx = CallContext::default();
    signing_host
        .account_alias(
            &cx,
            &session,
            AccountAliasAuthorityRequest {
                calling_product_id: request.calling_product_id,
                key_handle: request.key_handle,
                context: request.context,
                ring_location: request.ring_location,
            },
        )
        .await
}

async fn create_proof_response(
    signing_host: &Arc<SigningHost>,
    request: messages::RingVrfProofRequest,
) -> Result<api::HostAccountCreateProofResponse, RingVrfError> {
    let session = signing_host
        .current_session()
        .ok_or_else(disconnected_ring_vrf)?;
    let cx = CallContext::default();
    signing_host
        .create_proof(
            &cx,
            &session,
            CreateProofAuthorityRequest {
                calling_product_id: request.calling_product_id,
                key_handle: request.key_handle,
                context: request.context,
                ring_location: request.ring_location,
                message: request.message,
            },
        )
        .await
}

async fn register_ring_vrf_key_response(
    signing_host: &Arc<SigningHost>,
    request: messages::RegisterRingVrfKeyRequest,
) -> Result<api::RingVrfPublicKey, RingVrfError> {
    let session = signing_host
        .current_session()
        .ok_or_else(disconnected_ring_vrf)?;
    signing_host
        .register_ring_vrf_key(
            &CallContext::default(),
            &session,
            RegisterRingVrfKeyAuthorityRequest {
                calling_product_id: request.calling_product_id,
                index: request.index,
                ring: request.ring,
            },
        )
        .await
}

async fn list_ring_vrf_keys_response(
    signing_host: &Arc<SigningHost>,
    request: messages::ListRingVrfKeysRequest,
) -> Result<Vec<api::RegisteredRingVrfKey>, RingVrfError> {
    let session = signing_host
        .current_session()
        .ok_or_else(disconnected_ring_vrf)?;
    signing_host
        .list_ring_vrf_keys(
            &CallContext::default(),
            &session,
            ListRingVrfKeysAuthorityRequest {
                calling_product_id: request.calling_product_id,
                owner: request.owner,
                disclosure: request.disclosure,
            },
        )
        .await
}

async fn ring_vrf_sign_response(
    signing_host: &Arc<SigningHost>,
    request: messages::RingVrfSignRequest,
) -> Result<Vec<u8>, RingVrfError> {
    let session = signing_host
        .current_session()
        .ok_or_else(disconnected_ring_vrf)?;
    signing_host
        .ring_vrf_sign(
            &CallContext::default(),
            &session,
            RingVrfSignAuthorityRequest {
                calling_product_id: request.calling_product_id,
                key_handle: request.key_handle,
                message: request.message,
            },
        )
        .await
}

fn disconnected_ring_vrf() -> RingVrfError {
    RingVrfError::Unknown {
        reason: "signing host session is not active".to_string(),
    }
}

/// Run the platform confirmation seam; rejection and failure both refuse the
/// operation with an opaque reason (host-spec B.7).
async fn confirm(
    services: &Arc<RuntimeServices>,
    review: UserConfirmationReview,
) -> Result<(), String> {
    match services.platform.confirm_user_action(review).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Rejected".to_string()),
        Err(err) => Err(format!("confirmation failed: {}", err.reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::LocalActivation;
    use super::*;
    use crate::host_logic::extrinsic::tests::split_v4;
    use crate::host_logic::statement_store::decode_verified_statement_data;
    use crate::runtime::services::RuntimeServices;
    use crate::test_support::{StubPlatform, test_spawner};
    use std::sync::Arc;
    use truapi_platform::{HostInfo, Platform, PlatformInfo, SigningHostConfig};

    const ENTROPY: [u8; 16] = [0xab; 16];

    fn signing_fixture(platform: Arc<StubPlatform>) -> (Arc<RuntimeServices>, Arc<SigningHost>) {
        let platform: Arc<dyn Platform> = platform;
        let config = SigningHostConfig::new(
            HostInfo {
                name: "Polkadot Mobile".to_string(),
                icon: None,
                version: None,
                platform: truapi::latest::HostPlatform::Unknown,
            },
            PlatformInfo::default(),
            [0; 32],
            [0xbb; 32],
        )
        .expect("signing host config is valid");
        let services = RuntimeServices::new(
            platform.clone(),
            config.host.host_info.clone(),
            config.people_chain_genesis_hash,
            config.bulletin_chain_genesis_hash,
            test_spawner(),
        );
        let signing_host = SigningHost::new(services.clone());
        futures::executor::block_on(signing_host.activate_local_session(ENTROPY.to_vec()))
            .expect("activation succeeds");
        (services, signing_host)
    }

    /// Metadata for the People chain the signing fixture is configured for.
    #[cfg(not(target_arch = "wasm32"))]
    const PEOPLE_METADATA: &[u8] =
        include_bytes!("../../../tests/fixtures/paseo-next-v2-metadata-v16.scale");

    /// An existing statement-store allowance must be served without resolving a
    /// ring or submitting anything. The cache and the scan are covered on their
    /// own; this pins the composition, so removing the early return fails here
    /// rather than passing quietly.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn an_existing_allowance_is_served_without_touching_the_ring() {
        use futures::FutureExt;

        use crate::host_logic::product_account::derive_sr25519_hard_path;

        let product_id = "myapp.dot";
        let allowance =
            derive_sr25519_hard_path(&ENTROPY, &["allowance", "statement-store", product_id])
                .expect("allowance derivation succeeds");
        // The scan reads slot 0 first; answering it with an entry naming the
        // allowance account is the "already allocated" case.
        let slot_entry = (allowance.public.to_bytes(), 0u32, 0u64).encode();

        // Keyed by method, not by request order: this path decodes ~450 KiB of
        // metadata between two requests, which outruns the ordered script's
        // fixed-poll pump on a loaded runner.
        let platform = Arc::new(StubPlatform {
            rpc_method_responses: vec![
                (
                    "state_getRuntimeVersion",
                    r#"{"specVersion":1000000,"transactionVersion":1}"#.to_string(),
                ),
                (
                    "chain_getBlockHash",
                    format!(r#""0x{}""#, hex::encode([0u8; 32])),
                ),
                (
                    "Metadata_metadata_at_version",
                    format!(
                        r#""0x{}""#,
                        hex::encode(Some(PEOPLE_METADATA.to_vec()).encode()),
                    ),
                ),
                // The scan bound, read through the `Resources` view functions.
                (
                    "RuntimeViewFunction_execute_view_function",
                    format!(
                        r#""0x{}""#,
                        hex::encode(Ok::<Vec<u8>, ()>(20u32.encode()).encode()),
                    ),
                ),
                // The network suffix, read once before the scan.
                (
                    "state_getStorage",
                    format!(r#""0x{}""#, hex::encode(b"paseo".to_vec().encode())),
                ),
                (
                    "state_getStorage",
                    format!(r#""0x{}""#, hex::encode(&slot_entry)),
                ),
            ],
            ..Default::default()
        });
        let (services, signing_host) = signing_fixture(platform.clone());

        // Bounded, because the failure mode of losing the early return is a
        // wait on a chain read the stub deliberately does not answer — an
        // unbounded test would hang instead of reporting. The bound is generous
        // because it is catching a hang, not asserting latency.
        let active_session = signing_host.current_session().unwrap();
        let secret = futures::executor::block_on(async {
            futures::select! {
                result = allocate_statement_store_allowance(
                    &services,
                    &signing_host,
                    &active_session,
                    product_id,
                    OnExistingAllowancePolicy::Ignore,
                )
                .fuse() => result,
                _ = futures_timer::Delay::new(std::time::Duration::from_secs(30)).fuse() => {
                    panic!("allocation blocked on a chain read it should not have made")
                }
            }
        })
        .expect("an existing allowance is returned");

        assert_eq!(secret, allowance.secret.to_bytes().to_vec());

        let sent = platform.sent_rpc.lock().expect("rpc list mutex poisoned");
        let methods: Vec<String> = sent
            .iter()
            .filter_map(|request| {
                let value: serde_json::Value = serde_json::from_str(request).ok()?;
                value.get("method")?.as_str().map(ToString::to_string)
            })
            .collect();

        // `find_including_rings` opens with `chain_getFinalizedHead`, so none of
        // these means no ring was resolved.
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "chain_getFinalizedHead")
                .count(),
            0,
            "a ring was resolved for an allowance already in place: {methods:?}"
        );
        assert!(
            !methods
                .iter()
                .any(|method| method.starts_with("author_submit")),
            "an extrinsic was submitted for an allowance already in place: {methods:?}"
        );
        // The suffix and one slot read answered it; the scan stopped at the first match.
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "state_getStorage")
                .count(),
            2,
            "expected one suffix and one slot read: {methods:?}"
        );
    }

    #[test]
    fn responder_advertises_and_signs_with_the_local_uid_identity() {
        let (_services, signing_host) = signing_fixture(Arc::new(StubPlatform::default()));
        let local_identity = signing_host
            .current_session()
            .unwrap()
            .identity_account_id
            .unwrap();
        let (identity, _) = derive_responder_identity(&ENTROPY).unwrap();
        assert_eq!(identity.statement_public_key, local_identity);

        let (_, host_encryption_public_key) =
            derive_x25519_keypair_from_entropy(&[0x42; 16], b"sso");
        let session =
            establish_responder_session_info(&identity, [0x55; 32], host_encryption_public_key)
                .unwrap();
        let statement = build_signed_statement(
            &session,
            [0x66; 32],
            [0x77; 32],
            b"handshake".to_vec(),
            fresh_statement_expiry(),
        )
        .unwrap();
        let verified =
            decode_verified_statement_data(&statement, Some(identity.statement_public_key))
                .unwrap();
        assert_eq!(verified.signer, local_identity);
    }

    #[test]
    fn advertised_device_key_is_independent_of_the_identity() {
        let (services, _signing_host) = signing_fixture(Arc::new(StubPlatform::default()));

        let advertised = x25519_public_key(
            futures::executor::block_on(services.device_encryption_secret()).unwrap(),
        );

        // The regression this guards: advertising the SSO channel key as the
        // device key makes every device sharing an identity indistinguishable.
        let (_, sso_public) = derive_x25519_keypair_from_entropy(&ENTROPY, SSO_ENCRYPTION_DOMAIN);
        assert_ne!(advertised, sso_public);
    }

    #[test]
    fn pairing_deeplink_exposes_the_public_material_needed_to_resume() {
        let proposal = VersionedHandshakeProposal::V2(v2::Proposal {
            device: v2::Device {
                statement_account_id: [0x31; 32],
                encryption_public_key: [0x42; 32],
            },
            metadata: vec![v2::MetadataEntry(
                v2::MetadataKey::HostName,
                "paired host".to_string(),
            )],
        });
        let deeplink = format!(
            "polkadotapp://pair?handshake={}",
            hex::encode(proposal.encode())
        );

        assert_eq!(
            PairedSsoPeer::from_deeplink(&deeplink).unwrap(),
            PairedSsoPeer {
                statement_account_id: [0x31; 32],
                encryption_public_key: [0x42; 32],
            }
        );
    }

    #[test]
    fn persisted_peer_rebuilds_the_original_responder_session() {
        let peer = PairedSsoPeer {
            statement_account_id: [0x53; 32],
            encryption_public_key: x25519_public_key([0x64; 32]),
        };
        let (identity, _) = derive_responder_identity(&ENTROPY).unwrap();
        let mut expected = establish_responder_session_info(
            &identity,
            peer.statement_account_id,
            peer.encryption_public_key,
        )
        .unwrap();
        let resumed = responder_session(&ENTROPY, peer).unwrap();

        assert_eq!(
            crate::host_logic::statement_store::statement_public_key_from_secret(resumed.ss_secret)
                .unwrap(),
            expected.ss_public_key
        );
        expected.ss_secret = resumed.ss_secret;

        assert_eq!(resumed, expected);
    }

    #[test]
    fn replayed_disconnect_still_terminates_the_peer() {
        let disconnect = IncomingSsoRequest {
            request_id: "disconnect-1".to_string(),
            expires_at_unix_secs: Some(200),
            messages: vec![RemoteMessage {
                message_id: "message-1".to_string(),
                data: RemoteMessageData::V1(v1::RemoteMessage::Disconnected),
            }],
        };
        let ordinary = IncomingSsoRequest {
            request_id: "empty-1".to_string(),
            expires_at_unix_secs: Some(200),
            messages: Vec::new(),
        };

        assert_eq!(
            (
                duplicate_request_exit(&disconnect),
                duplicate_request_exit(&ordinary)
            ),
            (Some(ResponderExit::PeerDisconnected), None)
        );
    }

    fn response_payload(answer: AnsweredRemoteMessage) -> v1::RemoteMessage {
        let RemoteMessageData::V1(data) = answer.response.data;
        data
    }

    #[test]
    fn account_alias_requires_confirmation_for_cross_product_request() {
        let (services, signing_host) = signing_fixture(Arc::new(StubPlatform::default()));

        let response = futures::executor::block_on(answer_remote_message(
            &services,
            &signing_host,
            "alias-1".to_string(),
            v1::RemoteMessage::RingVrfAliasRequest(messages::RingVrfAliasRequest {
                calling_product_id: "myapp.dot".to_string(),
                key_handle: api::ProductAccountId {
                    dot_ns_identifier: "peopl.dot".to_string(),
                    derivation_index: api::DerivationIndex::Index(0),
                },
                context: api::ProductProofContext {
                    product_id: "other.dot".to_string(),
                    suffix: api::DerivationIndex::Index(0),
                },
                ring_location: api::RingLocation {
                    chain_id: [0; 32],
                    junctions: vec![],
                },
            }),
        ))
        .expect("response is emitted");

        let v1::RemoteMessage::RingVrfAliasResponse(response) = response_payload(response) else {
            panic!("expected alias response");
        };
        assert_eq!(response.payload.unwrap_err(), RingVrfError::Rejected);
    }

    #[test]
    fn response_summary_reports_protocol_errors_without_multiline_output() {
        let response = RemoteMessageData::V1(v1::RemoteMessage::RingVrfAliasResponse(
            RingVrfAliasResponse {
                responding_to: "alias-1".to_string(),
                payload: Err(RingVrfError::Unknown {
                    reason: "chain RPC\ntimed out".to_string(),
                }),
            },
        ));

        let result = remote_response_result(&response);
        let summary = response_cli_summary(
            "SSO response sent",
            "get_account_alias",
            "statement-1",
            "alias-1",
            "alias-1:response",
            &result,
            42,
        );

        assert_eq!(result.outcome, "error");
        assert_eq!(
            summary,
            "SSO response sent · get_account_alias · error\n\
             statement_request_id=statement-1\n\
             responding_to=alias-1\n\
             response_message_id=alias-1:response\n\
             elapsed_ms=42\n\
            reason=Unknown: chain RPC timed out"
        );
    }

    #[test]
    fn resource_allocation_summary_reflects_per_resource_outcomes() {
        let result =
            resource_allocation_payload_result(&Ok(vec![SsoAllocationOutcome::Rejected]), &[]);
        assert_eq!(result.outcome, "rejected");
        assert_eq!(
            result.reason.as_deref(),
            Some("Requested resource was rejected")
        );

        let result = resource_allocation_payload_result(
            &Ok(vec![
                SsoAllocationOutcome::Allocated(SsoAllocatedResource::BulletinAllowance {
                    slot_account_key: vec![1; 64],
                }),
                SsoAllocationOutcome::Rejected,
                SsoAllocationOutcome::NotAvailable,
            ]),
            &[],
        );
        assert_eq!(result.outcome, "partial");
        assert_eq!(
            result.reason.as_deref(),
            Some("1 of 3 requested resources allocated; 1 rejected; 1 unavailable")
        );

        let result = resource_allocation_payload_result(
            &Ok(vec![SsoAllocationOutcome::NotAvailable]),
            &["timed out waiting for Bulletin authorization".to_string()],
        );
        assert_eq!(result.outcome, "not_available");
        assert_eq!(
            result.reason.as_deref(),
            Some(
                "Requested resource is not available: timed out waiting for Bulletin authorization"
            )
        );
    }

    #[test]
    fn response_summary_classifies_resource_allocation_batches() {
        let response = RemoteMessageData::V1(v1::RemoteMessage::ResourceAllocationResponse(
            ResourceAllocationResponse {
                responding_to: "allocation-1".to_string(),
                payload: Ok(vec![
                    SsoAllocationOutcome::Rejected,
                    SsoAllocationOutcome::NotAvailable,
                ]),
            },
        ));

        let result = remote_response_result(&response);

        assert_eq!(result.outcome, "rejected");
        assert_eq!(
            result.reason.as_deref(),
            Some("No resources allocated; 1 rejected; 1 unavailable")
        );
    }

    #[test]
    fn resource_allocation_requires_confirmation_before_allocation() {
        let platform = Arc::new(StubPlatform::default());
        let (services, signing_host) = signing_fixture(platform.clone());

        let response = futures::executor::block_on(answer_remote_message(
            &services,
            &signing_host,
            "alloc-1".to_string(),
            v1::RemoteMessage::ResourceAllocationRequest(messages::ResourceAllocationRequest {
                calling_product_id: "myapp.dot".to_string(),
                resources: vec![SsoAllocatableResource::StatementStoreAllowance],
                on_existing: messages::OnExistingAllowancePolicy::Ignore,
            }),
        ))
        .expect("response is emitted");

        let v1::RemoteMessage::ResourceAllocationResponse(response) = response_payload(response)
        else {
            panic!("expected resource allocation response");
        };
        assert_eq!(
            response.payload.unwrap(),
            vec![SsoAllocationOutcome::Rejected]
        );

        // The confirmation review names the beneficiary product so the user
        // knows which product receives the delegated allowance key.
        let reviews = platform
            .resource_allocation_reviews
            .lock()
            .expect("resource allocation review list mutex poisoned");
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].calling_product_id, "myapp.dot");
    }

    #[test]
    fn auto_signing_allocation_returns_the_product_subtree_secret() {
        let platform = Arc::new(StubPlatform {
            resource_allocation_confirmed: true,
            ..StubPlatform::default()
        });
        let (services, signing_host) = signing_fixture(platform);
        let expected_secret = signing_host
            .product_subtree_secret(&signing_host.current_session().unwrap(), "myapp.dot")
            .expect("product subtree secret derives");
        let expected_ring_vrf_domain_entropy =
            derive_ring_vrf_domain_entropy(&ENTROPY, "myapp.dot")
                .expect("ring-VRF domain entropy derives");

        let response = futures::executor::block_on(answer_remote_message(
            &services,
            &signing_host,
            "alloc-auto-signing".to_string(),
            v1::RemoteMessage::ResourceAllocationRequest(messages::ResourceAllocationRequest {
                calling_product_id: "myapp.dot".to_string(),
                resources: vec![SsoAllocatableResource::AutoSigning],
                on_existing: messages::OnExistingAllowancePolicy::Ignore,
            }),
        ))
        .expect("response is emitted");

        let v1::RemoteMessage::ResourceAllocationResponse(response) = response_payload(response)
        else {
            panic!("expected resource allocation response");
        };
        assert_eq!(
            response.payload.unwrap(),
            vec![SsoAllocationOutcome::Allocated(
                SsoAllocatedResource::AutoSigning {
                    product_root_private_key: expected_secret,
                    ring_vrf_domain_entropy: expected_ring_vrf_domain_entropy,
                }
            )]
        );
    }

    #[test]
    fn legacy_transaction_request_uses_the_controlled_identity_account() {
        let (services, signing_host) = signing_fixture(Arc::new(StubPlatform {
            create_transaction_confirmed: true,
            ..StubPlatform::default()
        }));
        let identity = derive_identity_keypair(&ENTROPY).unwrap();
        let payload = api::LegacyAccountTxPayload {
            signer: identity.public.to_bytes(),
            genesis_hash: [0xaa; 32],
            call_data: vec![0x00, 0x00],
            extensions: vec![api::TxPayloadExtension {
                id: "CheckNonce".to_string(),
                extra: vec![1],
                additional_signed: vec![2, 3],
            }],
            tx_ext_version: 0,
        };

        let response = futures::executor::block_on(answer_remote_message(
            &services,
            &signing_host,
            "legacy-tx-1".to_string(),
            v1::RemoteMessage::CreateTransactionLegacyRequest(
                messages::CreateTransactionLegacyRequest {
                    payload: messages::CreateTransactionLegacyPayload::V1(payload),
                },
            ),
        ))
        .expect("response is emitted");

        let v1::RemoteMessage::CreateTransactionResponse(response) = response_payload(response)
        else {
            panic!("expected create transaction response");
        };
        let transaction = response
            .signed_transaction
            .expect("identity transaction succeeds");
        let (account, signature, tail) = split_v4(&transaction);
        assert_eq!(account, identity.public.to_bytes());
        assert_eq!(tail, vec![1, 0x00, 0x00]);
        let signature = schnorrkel::Signature::from_bytes(&signature).unwrap();
        assert!(
            identity
                .public
                .verify_simple(b"substrate", &[0x00, 0x00, 1, 2, 3], &signature)
                .is_ok()
        );
    }

    #[test]
    fn product_subtree_request_is_consent_free_and_hard_derived() {
        let (services, signing_host) = signing_fixture(Arc::new(StubPlatform::default()));
        let response = futures::executor::block_on(answer_remote_message(
            &services,
            &signing_host,
            "subtree-1".to_string(),
            v1::RemoteMessage::ProductSubtreeRequest(messages::ProductSubtreeRequest {
                product_id: "browse.dot".to_string(),
            }),
        ))
        .expect("response is emitted");

        let v1::RemoteMessage::ProductSubtreeResponse(response) = response_payload(response) else {
            panic!("expected product subtree response");
        };
        let root =
            derive_root_keypair_from_entropy(&ENTROPY).expect("fixture entropy derives root");
        let expected =
            crate::host_logic::product_account::derive_product_subtree_keypair(&root, "browse.dot")
                .expect("fixture derives subtree")
                .public
                .to_bytes();
        assert_eq!(response.responding_to, "subtree-1");
        assert_eq!(response.product_public_key, Ok(expected));
    }

    #[test]
    fn decode_failure_request_ids_dedup_and_bound() {
        let mut served = DecodeFailureRequestIds::new();

        // First sighting is served; an immediate duplicate is rejected.
        assert!(served.insert("req-a".to_string()));
        assert!(!served.insert("req-a".to_string()));

        // Fill to capacity with distinct ids; the set never exceeds the bound.
        for i in 0..MAX_DECODE_FAILURE_REQUEST_IDS {
            served.insert(format!("fill-{i}"));
        }
        assert_eq!(served.seen.len(), MAX_DECODE_FAILURE_REQUEST_IDS);
        assert_eq!(served.order.len(), MAX_DECODE_FAILURE_REQUEST_IDS);

        // The oldest id ("req-a") has been evicted, so it is accepted again,
        // while a recent id is still deduped — memory stays bounded regardless
        // of how many ids a peer streams.
        assert!(served.insert("req-a".to_string()));
        assert!(!served.insert(format!("fill-{}", MAX_DECODE_FAILURE_REQUEST_IDS - 1)));
        assert_eq!(served.seen.len(), MAX_DECODE_FAILURE_REQUEST_IDS);
    }
}
