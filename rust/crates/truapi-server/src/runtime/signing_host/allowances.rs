//! Session-bound allowance services shared by local and SSO entrypoints.

use super::SigningHost;
use crate::host_logic::sso::messages::OnExistingAllowancePolicy;
use crate::runtime::authority::{AuthorityError, AuthoritySession};
use crate::runtime::services::RuntimeServices;
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    chain_runtime::RuntimeFailure,
    host_logic::product_account::{ProductAccountError, derive_sr25519_hard_path},
    runtime::{
        statement_allowance::StatementAllowanceError,
        statement_store_rpc::StatementStoreRpcClientError,
    },
};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use tracing::{debug, warn};
use truapi::v01;

/// Leave the product runtime one minute to receive and process the SSO response
/// before its 300-second remote-authority deadline expires.
#[cfg(not(target_arch = "wasm32"))]
const BULLETIN_AUTHORIZATION_WAIT: std::time::Duration = std::time::Duration::from_secs(240);

/// Failure while deriving or allocating a Statement Store/Bulletin allowance.
#[derive(Debug, thiserror::Error)]
pub(super) enum AllowanceAllocationError {
    /// Signing host session or authority state was unavailable.
    #[error("{0}")]
    Authority(#[from] AuthorityError),
    /// The host serves no chain for this role, so there is nothing to claim on.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("host serves no {chain} chain")]
    ChainNotServed {
        /// Role that could not be resolved.
        chain: &'static str,
    },
    /// Reading the host's chain set failed.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("supported chains: {0}")]
    SupportedChains(String),
    /// Product-account key derivation failed.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("{0}")]
    ProductAccount(#[from] ProductAccountError),
    /// Chain state, metadata, ring, slot, proof, or extrinsic allocation failed.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("{0}")]
    StatementAllowance(#[from] StatementAllowanceError),
    /// Runtime service could not open the required Statement Store RPC client.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("{0}")]
    StatementStoreRpcClient(#[from] StatementStoreRpcClientError),
    /// Runtime service could not open the required Bulletin RPC client.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("{context}: {source}")]
    ChainRpcClient {
        /// Client context, naming which chain failed.
        context: &'static str,
        /// Chain runtime failure.
        #[source]
        source: RuntimeFailure,
    },
    /// Allocation helper is unavailable for this target.
    #[cfg(target_arch = "wasm32")]
    #[error("signing host: {resource} allowance allocation is native-only")]
    NativeOnly {
        /// Resource name.
        resource: &'static str,
    },
    /// System time cannot be converted into a UNIX timestamp.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("system clock before UNIX epoch")]
    SystemClockBeforeUnixEpoch,
    /// The signing account is not in any personhood ring.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("signing account is not a personhood ring member; cannot grant {resource} allowance")]
    MissingPersonhoodMembership {
        /// Resource name.
        resource: &'static str,
    },
}

impl AllowanceAllocationError {
    pub(super) fn into_authority_error(self) -> AuthorityError {
        match self {
            Self::Authority(err) => err,
            other => AuthorityError::Unavailable {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn allocate_statement_store_allowance(
    services: &Arc<RuntimeServices>,
    signing_host: &SigningHost,
    session: &AuthoritySession,
    product_id: &str,
    policy: OnExistingAllowancePolicy,
) -> Result<Vec<u8>, AllowanceAllocationError> {
    use super::allowance_renewal::{self, StatementRenewalTarget};
    use crate::runtime::statement_allowance::{
        self, PooledRegistrationParams, allocated_in, find_including_rings,
        register_statement_account_pooled, scan_collections,
    };

    let entropy = signing_host.session_entropy(session)?;
    let allowance =
        derive_sr25519_hard_path(&entropy, &["allowance", "statement-store", product_id])?;
    let target = allowance.public.to_bytes();
    let candidates = signing_host.reserved_person_collection_candidates(session)?;
    let client = services
        .statement_store
        .chain_client("statement-store allowance")
        .await?;
    let rpc = client.rpc();
    let chain = services.chain_context.get(&client).await?;
    let network_suffix = statement_allowance::slot::read_network_suffix(rpc).await?;
    let period = statement_allowance::slot::current_period(current_unix_secs()?);
    let reuse_existing = matches!(policy, OnExistingAllowancePolicy::Ignore);

    // Held from the scan through the submission, not just around the submission:
    // the scan is what picks the free slot, so a renewal pass scanning in the gap
    // would choose the same one. Released on the early return below, which
    // submits nothing.
    let _registration = signing_host.renewal.registration_lock().lock().await;

    // One read of the period's slot tables, reused below rather than rescanned:
    // when an allowance is already recorded on chain neither a proof nor a
    // submission is needed, and a ring snapshot pages in every member key.
    let scans = scan_collections(
        rpc,
        &chain.metadata,
        &candidates,
        &network_suffix,
        period,
        &target,
        reuse_existing,
    )
    .await?;
    if let Some((collection, seq)) = allocated_in(&scans) {
        debug!(
            %product_id,
            period,
            seq,
            %collection,
            "statement-store allowance already allocated"
        );
        signing_host.require_current_session(session)?;
        return Ok(allowance.secret.to_bytes().to_vec());
    }

    // Every ring back to index 0, because a membership that stopped being
    // re-included still proves against the ring that holds it.
    let memberships = find_including_rings(rpc, &chain.metadata, &candidates, u32::MAX).await?;
    if memberships.is_empty() {
        return Err(AllowanceAllocationError::MissingPersonhoodMembership {
            resource: "statement-store",
        });
    }
    signing_host.require_current_session(session)?;
    let outcome = register_statement_account_pooled(
        rpc,
        &chain.metadata,
        &chain.state,
        &scans,
        &memberships,
        PooledRegistrationParams {
            target: &target,
            period,
            network_suffix: &network_suffix,
            reuse_existing,
            // Connecting a product must not revoke another product's allowance.
            // A full period is reported as exhaustion; reclaiming space is the
            // renewal pass's job, which only ever replaces for its own ledger.
            allow_eviction: false,
            protected: &[],
        },
    )
    .await?;
    match outcome {
        statement_allowance::RegistrationOutcome::Registered {
            block_hash,
            seq,
            ring_index,
            collection,
        } => {
            debug!(
                %product_id,
                %block_hash,
                seq,
                ring_index,
                %collection,
                "registered statement-store allowance"
            );
        }
        statement_allowance::RegistrationOutcome::AlreadyAllocated { seq, collection } => {
            debug!(
                %product_id,
                seq,
                %collection,
                "statement-store allowance already allocated"
            );
        }
    }
    if let Err(reason) = allowance_renewal::track_for_session(
        signing_host,
        session,
        vec![StatementRenewalTarget::ProductStatementAllowance {
            product_id: product_id.to_string(),
        }],
    )
    .await
    {
        warn!(%product_id, %reason, "failed to record statement-store renewal target");
    }
    signing_host.require_current_session(session)?;
    Ok(allowance.secret.to_bytes().to_vec())
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn allocate_bulletin_allowance(
    services: &Arc<RuntimeServices>,
    signing_host: &SigningHost,
    session: &AuthoritySession,
    product_id: &str,
    policy: OnExistingAllowancePolicy,
) -> Result<Vec<u8>, AllowanceAllocationError> {
    use crate::runtime::statement_allowance::collection::PersonhoodCollection;
    use crate::runtime::statement_allowance::{
        self, claim_long_term_storage, fetch_bulletin_allowance, find_including_rings,
        wait_bulletin_authorization,
    };

    let entropy = signing_host.session_entropy(session)?;
    let allowance = derive_sr25519_hard_path(&entropy, &["allowance", "bulletin", product_id])?;
    let target = allowance.public.to_bytes();

    let bulletin_rpc = statement_allowance::rpc::RpcClient::new(
        services
            .bulletin
            .client("bulletin allowance")
            .await
            .map_err(|source| AllowanceAllocationError::ChainRpcClient {
                context: "bulletin allowance client",
                source,
            })?,
    );
    let current_allowance = fetch_bulletin_allowance(&bulletin_rpc, &target).await?;
    if matches!(policy, OnExistingAllowancePolicy::Ignore)
        && current_allowance.is_some_and(|allowance| allowance.available())
    {
        signing_host.require_current_session(session)?;
        return Ok(allowance.secret.to_bytes().to_vec());
    }

    let people_client = services
        .statement_store
        .chain_client("bulletin allowance claim")
        .await?;
    let people_rpc = people_client.rpc();
    let chain = services.chain_context.get(&people_client).await?;
    let network_suffix = statement_allowance::slot::read_network_suffix(people_rpc).await?;
    let candidates = signing_host.reserved_person_collection_candidates(session)?;
    // Statement-store slots and PGAS claims are each bounded by a per-collection
    // constant, so their budgets are meant to be spent per collection. Long-term
    // storage is bounded by `Resources.LongTermStorageClaimsPerPeriod` alone, with
    // no per-collection variant, so the budget reads as per person. Its spent
    // counters are still keyed by a collection-scoped alias, which means changing
    // collection silently restarts the count at zero. Staying in the light
    // collection keeps one person to one count; full personhood is the fallback
    // for a device without light personhood.
    let memberships =
        find_including_rings(people_rpc, &chain.metadata, &candidates, u32::MAX).await?;
    let membership = memberships
        .iter()
        .find(|membership| membership.collection() == PersonhoodCollection::LitePeople)
        .or_else(|| memberships.first())
        .ok_or(AllowanceAllocationError::MissingPersonhoodMembership {
            resource: "Bulletin",
        })?;
    let period_duration =
        statement_allowance::slot::long_term_storage_period_duration(&chain.metadata)?;
    let period = statement_allowance::slot::current_long_term_storage_period(
        current_unix_secs()?,
        period_duration,
    )?;
    let outcome = claim_long_term_storage(statement_allowance::LongTermStorageClaim {
        rpc: people_rpc,
        metadata: &chain.metadata,
        chain_state: &chain.state,
        entropy: membership.entropy,
        network_suffix: &network_suffix,
        target: &target,
        period,
        ring: &membership.ring,
    })
    .await?;
    let statement_allowance::LongTermStorageOutcome::Claimed {
        block_hash,
        counter,
        ring_index,
    } = outcome;
    debug!(
        %product_id,
        %block_hash,
        counter,
        ring_index,
        "claimed Bulletin long-term storage allowance"
    );

    let authorization = wait_bulletin_authorization(
        &bulletin_rpc,
        &target,
        current_allowance,
        BULLETIN_AUTHORIZATION_WAIT,
    )
    .await?;
    debug!(
        %product_id,
        remained_size = authorization.remained_size,
        remained_transactions = authorization.remained_transactions,
        "Bulletin authorization visible"
    );
    signing_host.require_current_session(session)?;
    Ok(allowance.secret.to_bytes().to_vec())
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn allocate_statement_store_allowance(
    _services: &Arc<RuntimeServices>,
    _signing_host: &SigningHost,
    _session: &AuthoritySession,
    _product_id: &str,
    _policy: OnExistingAllowancePolicy,
) -> Result<Vec<u8>, AllowanceAllocationError> {
    Err(AllowanceAllocationError::NativeOnly {
        resource: "statement-store",
    })
}

/// Claim an Asset Hub PGAS allowance for the product account `derivation_index`
/// selects.
///
/// Unlike the statement-store and Bulletin allowances, this credits the product
/// account itself rather than a dedicated `//allowance//…` account, and returns
/// nothing: PGAS pre-warms a balance on an account the host already controls, so
/// there is no key to hand back.
///
/// Asset Hub is resolved through the host's chain set rather than a configured
/// hash, so a host that does not serve it says so instead of claiming against
/// whatever chain a stale hash happens to reach.
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn allocate_smart_contract_allowance(
    services: &Arc<RuntimeServices>,
    signing_host: &SigningHost,
    session: &AuthoritySession,
    product_id: &str,
    derivation_index: v01::DerivationIndex,
    policy: OnExistingAllowancePolicy,
) -> Result<(), AllowanceAllocationError> {
    use truapi::latest::ChainIdentifier;

    use crate::host_logic::features;
    use crate::runtime::statement_allowance::{self, ChainClient, find_including_rings, pgas};

    // PGAS credits the product account the caller named.
    let target = signing_host
        .product_keypair(
            session,
            &v01::ProductAccountId {
                dot_ns_identifier: product_id.to_string(),
                derivation_index,
            },
        )?
        .public
        .to_bytes();

    let chains = features::supported_chains(services.platform.as_ref())
        .await
        .map_err(|err| AllowanceAllocationError::SupportedChains(err.reason))?;
    let asset_hub_genesis = features::genesis_for(&chains, ChainIdentifier::AssetHub)
        .ok_or(AllowanceAllocationError::ChainNotServed { chain: "Asset Hub" })?;
    let asset_hub_client = ChainClient::new(
        statement_allowance::rpc::RpcClient::new(subxt_rpcs::RpcClient::new(
            services
                .chain
                .rpc_client("PGAS allowance", &asset_hub_genesis)
                .await
                .map_err(|source| AllowanceAllocationError::ChainRpcClient {
                    context: "Asset Hub PGAS client",
                    source,
                })?,
        )),
        asset_hub_genesis,
    );
    let asset_hub = services.chain_context.get(&asset_hub_client).await?;

    // A claim spends one of the day's slots, so honour a caller that asked to leave
    // an existing allowance alone rather than topping up an already-warm account.
    if matches!(policy, OnExistingAllowancePolicy::Ignore)
        && pgas::holds_a_full_claim(asset_hub_client.rpc(), &asset_hub.metadata, &target).await?
    {
        debug!(%product_id, "PGAS allowance already funded; leaving it alone");
        return Ok(());
    }
    let network_suffix =
        statement_allowance::slot::read_network_suffix(asset_hub_client.rpc()).await?;

    let people_client = services
        .statement_store
        .chain_client("PGAS allowance ring")
        .await?;
    let people_rpc = people_client.rpc();
    let people = services.chain_context.get(&people_client).await?;

    let candidates = signing_host.reserved_person_collection_candidates(session)?;
    // A single claim needs one collection, so take the strongest membership the
    // person actually holds rather than assuming light personhood.
    let membership = find_including_rings(people_rpc, &people.metadata, &candidates, u32::MAX)
        .await?
        .into_iter()
        .next()
        .ok_or(AllowanceAllocationError::MissingPersonhoodMembership { resource: "PGAS" })?;

    let outcome = pgas::claim_pgas(pgas::PgasClaim {
        asset_hub_rpc: asset_hub_client.rpc(),
        asset_hub: &asset_hub,
        people_rpc,
        people_metadata: &people.metadata,
        entropy: membership.entropy,
        network_suffix: &network_suffix,
        target: &target,
        ring: &membership.ring,
    })
    .await?;
    debug!(
        %product_id,
        day = outcome.day,
        slot_index = outcome.slot_index,
        ring_index = outcome.ring_index,
        block = %outcome.block_hash,
        "claimed PGAS allowance"
    );
    Ok(())
}

/// PGAS claims need chain access the wasm host does not have.
#[cfg(target_arch = "wasm32")]
pub(super) async fn allocate_smart_contract_allowance(
    _services: &Arc<RuntimeServices>,
    _signing_host: &SigningHost,
    _session: &AuthoritySession,
    _product_id: &str,
    _derivation_index: v01::DerivationIndex,
    _policy: OnExistingAllowancePolicy,
) -> Result<(), AllowanceAllocationError> {
    Err(AllowanceAllocationError::NativeOnly { resource: "PGAS" })
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn allocate_bulletin_allowance(
    _services: &Arc<RuntimeServices>,
    _signing_host: &SigningHost,
    _session: &AuthoritySession,
    _product_id: &str,
    _policy: OnExistingAllowancePolicy,
) -> Result<Vec<u8>, AllowanceAllocationError> {
    Err(AllowanceAllocationError::NativeOnly {
        resource: "Bulletin",
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn current_unix_secs() -> Result<u64, AllowanceAllocationError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AllowanceAllocationError::SystemClockBeforeUnixEpoch)
}
