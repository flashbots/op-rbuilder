use super::{block::PayloadAttributes, service::ServiceContext};
use crate::{builders::fb_next::empty::EmptyBlockPayload, traits::ClientBounds};
use alloy_consensus::{Block, BlockBody, Header};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::{Bytes, B256, B64};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::OpSpecId;
use reth_chainspec::EthereumHardforks;
use reth_evm::{ConfigureEvm, EvmEnv};
use reth_node_api::{Block as _, PayloadBuilderError, PayloadKind};
use reth_optimism_consensus::isthmus;
use reth_optimism_evm::OpNextBlockEnvAttributes;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpBuiltPayload;
use reth_optimism_payload_builder::error::OpPayloadBuilderError;
use reth_optimism_primitives::OpTransactionSigned;
use reth_payload_builder::{EthPayloadBuilderAttributes, KeepPayloadJobAlive, PayloadId};
use reth_primitives::{Recovered, SealedBlock, SealedHeader};
use reth_primitives_traits::WithEncoded;
use reth_provider::{
    HashedPostStateProvider, StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_revm::{database::StateProviderDatabase, db::BundleState, State};
use reth_trie::{updates::TrieUpdates, HashedPostState};
use revm::Database;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Context for a specific job initiated by FCU call into the node.
pub struct JobContext<Client>
where
    Client: ClientBounds,
{
    attribs: PayloadAttributes,
    builder_ctx: Arc<ServiceContext<Client>>,
    cancel: CancellationToken,
}

impl<Client> JobContext<Client>
where
    Client: ClientBounds,
{
    /// Create a new job context for a given payload attributes from FCU call.
    pub fn new(attribs: PayloadAttributes, builder_ctx: Arc<ServiceContext<Client>>) -> Self {
        Self {
            attribs,
            builder_ctx,
            cancel: CancellationToken::new(),
        }
    }

    pub const fn parent(&self) -> B256 {
        self.attributes().parent
    }

    /// Decoded transactions and the original EIP-2718 encoded bytes as received in the payload
    /// attributes.
    pub fn sequencer_transactions(&self) -> &[WithEncoded<OpTransactionSigned>] {
        &self.attribs.transactions
    }

    /// Get the attributes for this job.
    pub const fn attributes(&self) -> &EthPayloadBuilderAttributes {
        &self.attribs.payload_attributes
    }

    pub const fn payload_attributes(&self) -> &PayloadAttributes {
        &self.attribs
    }

    /// Get the builder context.
    pub const fn builder_context(&self) -> &Arc<ServiceContext<Client>> {
        &self.builder_ctx
    }

    /// Gas limit for the block that we're building.
    pub const fn gas_limit(&self) -> Option<u64> {
        self.attribs.gas_limit
    }

    /// Id of the job that we're building for.
    /// This id is assigned by the CL node during the FCU call.
    pub const fn payload_id(&self) -> PayloadId {
        self.attribs.payload_attributes.id
    }

    /// EIP-1559 parameters for the generated payload
    pub const fn eip_1559_params(&self) -> Option<B64> {
        self.attribs.eip_1559_params
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn deposit_nonce(
        &self,
        tx: &Recovered<OpTxEnvelope>,
        db: &mut State<impl Database>,
    ) -> Result<Option<u64>, PayloadBuilderError> {
        // Cache the depositor account prior to the state transition for the deposit nonce.
        //
        // Note that this *only* needs to be done post-regolith hardfork, as deposit nonces
        // were not introduced in Bedrock. In addition, regular transactions don't have deposit
        // nonces, so we don't need to touch the DB for those.
        (self.is_regolith_active() && tx.is_deposit())
            .then(|| {
                db.load_cache_account(tx.signer())
                    .map(|acc| acc.account_info().unwrap_or_default().nonce)
            })
            .transpose()
            .map_err(|_| {
                PayloadBuilderError::other(OpPayloadBuilderError::AccountLoadFailed(tx.signer()))
            })
    }

    pub fn state_root_with_updates<D>(
        &self,
        state: D,
        bundle: &BundleState,
    ) -> Result<(B256, TrieUpdates, HashedPostState), PayloadBuilderError>
    where
        D: StateRootProvider + HashedPostStateProvider,
    {
        let hashed_state = state.hashed_post_state(bundle);
        let (root, updates) = state
            .state_root_with_updates(hashed_state.clone())
            .inspect_err(|err| {
                warn!(parent_header=%self.parent(), %err, "failed to calculate state root for payload");
            }).map_err(PayloadBuilderError::other)?;

        Ok((root, updates, hashed_state))
    }

    pub fn seal_block(
        &self,
        header: Header,
        transactions: Vec<OpTxEnvelope>,
    ) -> SealedBlock<Block<OpTxEnvelope>> {
        let block = Block::<OpTransactionSigned>::new(
            header,
            BlockBody {
                transactions,
                withdrawals: self
                    .is_shanghai_active()
                    .then(|| self.attributes().withdrawals.clone()),
                ommers: vec![],
            },
        );

        block.seal_slow()
    }

    /// withdrawals root field in block header is used for storage root of L2 predeploy
    /// `l2tol1-message-passer`
    pub fn withdrawals_and_requests_root(
        &self,
        bundle_state: &BundleState,
        state: impl StorageRootProvider,
    ) -> Result<(Option<B256>, Option<B256>), PayloadBuilderError> {
        if self.is_isthmus_active() {
            Ok((
                Some(isthmus::withdrawals_root(bundle_state, state)?),
                Some(EMPTY_REQUESTS_HASH),
            ))
        } else {
            Ok((None, None))
        }
    }

    /// OP doesn't support blobs/EIP-4844.
    /// https://specs.optimism.io/protocol/exec-engine.html#ecotone-disable-blob-transactions
    /// Need [Some] or [None] based on hardfork to match block hash.
    pub fn blob_gas_used(&self) -> (Option<u64>, Option<u64>) {
        if self.is_canyon_active() {
            (Some(0), Some(0))
        } else {
            (None, None)
        }
    }

    /// Header of the block that this job is building on top of.
    pub fn parent_header(&self) -> Result<SealedHeader<Header>, PayloadBuilderError> {
        if self.parent().is_zero() {
            self.builder_ctx
                .provider()
                .latest_header()?
                .ok_or_else(|| PayloadBuilderError::MissingParentHeader(self.parent()))
        } else {
            self.builder_ctx
                .provider()
                .sealed_header_by_hash(self.parent())?
                .ok_or_else(|| PayloadBuilderError::MissingParentHeader(self.parent()))
        }
    }

    /// Returns the block building attributes for the next block that this job is building.
    pub fn next_block_env_attributes(&self) -> OpNextBlockEnvAttributes {
        OpNextBlockEnvAttributes {
            timestamp: self.attributes().timestamp,
            suggested_fee_recipient: self.attributes().suggested_fee_recipient,
            prev_randao: self.attributes().prev_randao,
            gas_limit: self
                .gas_limit()
                .unwrap_or(self.parent_header().unwrap().gas_limit),
            parent_beacon_block_root: self.attributes().parent_beacon_block_root,
            extra_data: if self
                .builder_context()
                .chain_spec()
                .is_holocene_active_at_timestamp(self.attributes().timestamp)
            {
                self.attribs
                    .get_holocene_extra_data(
                        self.builder_context()
                            .chain_spec()
                            .base_fee_params_at_timestamp(self.attributes().timestamp),
                    )
                    .unwrap_or_default()
            } else {
                Default::default()
            },
        }
    }

    /// EVM environment for building the next block.
    pub fn next_evm_environment(&self) -> Result<EvmEnv<OpSpecId>, PayloadBuilderError> {
        self.builder_context()
            .evm_config()
            .next_evm_env(
                &self.parent_header()?.header(),
                &self.next_block_env_attributes(),
            )
            .map_err(PayloadBuilderError::other)
    }

    /// State of the blockchain at the parent block that we are building on top of.
    pub fn state_at_parent(
        &self,
    ) -> Result<State<StateProviderDatabase<Box<dyn StateProvider>>>, PayloadBuilderError> {
        Ok(State::builder()
            .with_database(StateProviderDatabase(
                self.builder_context()
                    .provider()
                    .state_by_block_hash(self.parent())?,
            ))
            .with_bundle_update()
            .build())
    }

    pub fn extra_data(&self) -> Bytes {
        if self.is_holocene_active() {
            self.attribs
                .get_holocene_extra_data(
                    self.builder_context()
                        .chain_spec()
                        .base_fee_params_at_timestamp(self.attributes().timestamp),
                )
                .unwrap_or_default()
        } else {
            Bytes::default()
        }
    }
}

impl<Client> JobContext<Client>
where
    Client: ClientBounds,
{
    /// Returns true if the regolith hardfork is active at the job's timestamp.
    pub fn is_regolith_active(&self) -> bool {
        self.builder_context()
            .chain_spec()
            .is_regolith_active_at_timestamp(self.attributes().timestamp)
    }

    /// Returns true if the isthmus hardfork is active at the job's timestamp.
    pub fn is_isthmus_active(&self) -> bool {
        self.builder_context()
            .chain_spec()
            .is_isthmus_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_canyon_active(&self) -> bool {
        self.builder_context()
            .chain_spec()
            .is_canyon_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_holocene_active(&self) -> bool {
        self.builder_context()
            .chain_spec()
            .is_holocene_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_shanghai_active(&self) -> bool {
        self.builder_context()
            .chain_spec()
            .is_shanghai_active_at_timestamp(self.attributes().timestamp)
    }
}

pub struct PayloadJob<Client>
where
    Client: ClientBounds,
{
    job_ctx: JobContext<Client>,
}

impl<Client> PayloadJob<Client>
where
    Client: ClientBounds,
{
    pub fn new(attr: PayloadAttributes, ctx: Arc<ServiceContext<Client>>) -> Self {
        Self {
            job_ctx: JobContext::new(attr, ctx),
        }
    }

    /// Get the attributes for this job.
    pub const fn job_context(&self) -> &JobContext<Client> {
        &self.job_ctx
    }

    /// Get the builder context.
    pub const fn builder_context(&self) -> &Arc<ServiceContext<Client>> {
        self.job_ctx.builder_context()
    }
}

impl<Client> reth_payload_builder::PayloadJob for PayloadJob<Client>
where
    Client: ClientBounds,
{
    type PayloadAttributes = PayloadAttributes;

    type ResolvePayloadFuture = PayloadJobResolveFuture;

    type BuiltPayload = OpBuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        todo!("PayloadJob::best_payload");
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        info!("PayloadJob::payload_attributes");
        Ok(self.job_ctx.attribs.clone())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        info!("PayloadJob::resolve_kind {kind:?}");
        (
            PayloadJobResolveFuture(
                EmptyBlockPayload::new(&self.job_ctx)
                    .expect("EmptyBlockPayload")
                    .into(),
            ),
            KeepPayloadJobAlive::No,
        )
    }
}

pub struct PayloadJobResolveFuture(OpBuiltPayload);

impl<C: ClientBounds> Future for PayloadJob<C> {
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        info!("PayloadJob::poll");
        Poll::Pending
    }
}

impl Future for PayloadJobResolveFuture {
    type Output = Result<OpBuiltPayload, PayloadBuilderError>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        info!("PayloadJobResolveFuture::poll");
        Poll::Ready(Ok(self.0.clone()))
    }
}
