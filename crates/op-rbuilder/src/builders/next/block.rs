//! Block building context
//!
//! This module implements types that carry the context that is used to build payloads on top
//! of a known parent block with access to the state of the chain at that point in time.

use std::sync::Arc;

use super::{payload::PayloadBuilderContext, service::ServiceContext};
use crate::traits::ClientBounds;
use alloy_consensus::Header;
use alloy_op_evm::OpEvm;
use alloy_primitives::{Bytes, B64};
use alloy_rpc_types_eth::Withdrawals;
use op_revm::OpSpecId;
use reth_chainspec::EthereumHardforks;
use reth_evm::{execute::BlockBuilder, precompiles::PrecompilesMap, ConfigureEvm, EvmEnv};
use reth_node_api::PayloadBuilderError;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_payload_builder::{EthPayloadBuilderAttributes, PayloadId};
use reth_primitives::SealedHeader;
use reth_primitives_traits::WithEncoded;
use reth_provider::StateProvider;
use reth_revm::{database::StateProviderDatabase, State};
use revm::inspector::NoOpInspector;

pub type EvmInstance = OpEvm<PayloadState, NoOpInspector, PrecompilesMap>;
pub type PayloadAttributes = OpPayloadBuilderAttributes<OpTransactionSigned>;
pub type PayloadState = State<StateProviderDatabase<Box<dyn StateProvider>>>;

/// Instances of this type are created for each new block building request triggered by an
/// FCU call from the CL node. It contains all the necessary information to spawn individual
/// payload building contexts (`PayloadBuilderContext`) that are used to build versions of
/// payloads that all share the same parent block hash and chain state.
pub struct BlockContext<Client: ClientBounds> {
    /// Access to the node-wide service context that provides access to the chain state,
    /// EVM configuration and other node-wide resources that do not change between blocks.
    service: Arc<ServiceContext<Client>>,

    /// The parent block full header that is all payloads built on top of this block.
    parent: SealedHeader<Header>,

    /// The payload attributes that were sent by the CL through FCU
    attribs: PayloadAttributes,
}

/// Apis used by
impl<Client: ClientBounds> BlockContext<Client> {
    /// Creates a new context for building payloads on top of a specific parent block
    /// as a response to a CL node FCU request.
    ///
    /// The workflow is as follows:
    ///  - `PayloadJobGenerator::new_payload_job` is called with the payload attributes
    ///    by Reth as a response to a CL node FCU request.
    ///  - `PayloadJobGenerator::new_payload_job` creates a new instance of `PayloadJob`
    ///    that is responsible for responding to they FCU payload job request.
    ///  - `PayloadJob` creates one instance of `BlockContext`.
    ///  - `BlockContext` is used to create potentially multiple instances of
    ///    `PayloadBuilderContext` each representing a different attempt to build a
    ///    payload for the same parent block.
    ///  - Some of the `PayloadBuilderContext` instances will result in a valid
    ///    `BuiltPayload`.
    ///  - One of the `BuiltPayload`s will be selected by the `PayloadJob` and returned
    ///    to Reth as a response to the FCU request.
    pub fn new(
        service: Arc<ServiceContext<Client>>,
        attribs: PayloadAttributes,
    ) -> Result<Self, PayloadBuilderError> {
        let header = if attribs.payload_attributes.parent.is_zero() {
            // If the parent is zero, we use the latest block header as the parent.
            service.provider().latest_header()?.ok_or_else(|| {
                PayloadBuilderError::MissingParentBlock(attribs.payload_attributes.parent)
            })?
        } else {
            // Otherwise, we use the parent block header provided in the attributes.
            service
                .provider()
                .sealed_header_by_hash(attribs.payload_attributes.parent)?
                .ok_or_else(|| {
                    PayloadBuilderError::MissingParentBlock(attribs.payload_attributes.parent)
                })?
        };

        Ok(Self {
            service,
            parent: header,
            attribs,
        })
    }

    /// Creates a new payload builder context that can be used to build a new payload
    /// version for the current block. A single block context may create many payload
    /// builder contexts, each representing a different attempt to build a payload
    /// for the same parent block.
    pub fn create_payload_builder(
        self: &Arc<Self>,
    ) -> Result<PayloadBuilderContext<Client>, PayloadBuilderError> {
        PayloadBuilderContext::new(Arc::clone(&self))
    }
}

/// APIs used by payload builder context
impl<Client: ClientBounds> BlockContext<Client> {
    /// Parent block full header
    pub const fn parent(&self) -> &SealedHeader<Header> {
        &self.parent
    }

    /// Get the payload attributes for this job that were sent through FCU.
    pub const fn attributes(&self) -> &EthPayloadBuilderAttributes {
        &self.attribs.payload_attributes
    }

    /// Get the payload attributes for this job that were sent through FCU.
    pub const fn fcu_attributes(&self) -> &PayloadAttributes {
        &self.attribs
    }

    /// Decoded transactions and the original EIP-2718 encoded bytes as received in the payload
    /// attributes.
    pub fn sequencer_transactions(
        &self,
    ) -> impl Iterator<Item = &WithEncoded<OpTransactionSigned>> {
        self.attribs.transactions.iter()
    }

    /// EVM configuration of the node.
    pub fn evm_config(&self) -> &OpEvmConfig {
        self.service.evm_config()
    }

    /// Gas limit for the block that we're building.
    pub const fn gas_limit(&self) -> Option<u64> {
        self.attribs.gas_limit
    }

    /// Returns the withdrawals if shanghai is active.
    pub fn withdrawals(&self) -> Option<&Withdrawals> {
        self.is_shanghai_active()
            .then(|| &self.attributes().withdrawals)
    }

    /// EIP-1559 parameters for the generated payload
    pub const fn eip_1559_params(&self) -> Option<B64> {
        self.attribs.eip_1559_params
    }

    /// Doesn't change between blocks, Its defined at startup time.
    pub fn chain_spec(&self) -> Arc<OpChainSpec> {
        self.service.chain_spec().clone()
    }

    /// Returns the payload id that was assigned by the CL node
    /// during the FCU call.
    pub const fn payload_id(&self) -> PayloadId {
        self.attributes().payload_id()
    }

    /// Returns a new state instance rooted at the parent block that
    /// can be used to accumulate state changes for individual payloads
    /// built on top of this block parent.
    ///
    /// This state comes preinitialized with all required pre-execution changes
    /// such as EIP-4788 (Beacon Chain data), create2deployer and EIP-2935.
    ///
    /// The state produced here is with bundle updates and supports reverts.
    pub fn state(&self) -> Result<PayloadState, PayloadBuilderError> {
        let mut state = State::builder()
            .with_database(StateProviderDatabase(
                self.service
                    .provider()
                    .state_by_block_hash(self.parent().hash())?,
            ))
            .with_bundle_update()
            .build();

        self.evm_config()
            .builder_for_next_block(&mut state, self.parent(), self.next_block_env_attributes())
            .map_err(PayloadBuilderError::other)?
            .apply_pre_execution_changes()?;

        Ok(state)
    }

    /// Returns a new EVM instance that is preconfigured for the current block along
    /// with a state that is rooted at the parent block hash and initialized with all
    /// required pre-execution changes such as EIP-4788 (Beacon Chain data),
    /// create2deployer and EIP-2935.
    pub fn create_evm(&self) -> Result<EvmInstance, PayloadBuilderError> {
        let state = self.state()?;
        Ok(self.evm_config().evm_with_env(state, self.evm_env()?))
    }

    /// Returns the EVM environment metadata for the this block context.
    pub fn evm_env(&self) -> Result<EvmEnv<OpSpecId>, PayloadBuilderError> {
        self.evm_config()
            .next_evm_env(self.parent().header(), &self.next_block_env_attributes())
            .map_err(PayloadBuilderError::other)
    }

    /// Returns parts of the next block header values that can be deduced from the
    /// parent block header without the need to access the chain state or knowing the
    /// transactions that will be included in the next block.
    pub fn next_block_env_attributes(&self) -> OpNextBlockEnvAttributes {
        OpNextBlockEnvAttributes {
            timestamp: self.attributes().timestamp,
            suggested_fee_recipient: self.attributes().suggested_fee_recipient,
            prev_randao: self.attributes().prev_randao,
            gas_limit: self.gas_limit().unwrap_or(self.parent().header().gas_limit),
            parent_beacon_block_root: self.attributes().parent_beacon_block_root,
            extra_data: if self.is_holocene_active() {
                self.attribs
                    .get_holocene_extra_data(
                        self.service
                            .chain_spec()
                            .base_fee_params_at_timestamp(self.attributes().timestamp),
                    )
                    .unwrap_or_default()
            } else {
                Default::default()
            },
        }
    }

    pub fn holocene_extra_data(&self) -> Result<Bytes, PayloadBuilderError> {
        if self.is_holocene_active() {
            self.attribs
                .get_holocene_extra_data(
                    self.service
                        .chain_spec()
                        .base_fee_params_at_timestamp(self.attributes().timestamp),
                )
                .map_err(PayloadBuilderError::other)
        } else {
            Ok(Default::default())
        }
    }
}

/// APIs for hardfork checks
impl<Client> BlockContext<Client>
where
    Client: ClientBounds,
{
    /// Returns true if the regolith hardfork is active at the job's timestamp.
    pub fn is_regolith_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_regolith_active_at_timestamp(self.attributes().timestamp)
    }

    /// Returns true if the isthmus hardfork is active at the job's timestamp.
    pub fn is_isthmus_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_isthmus_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_canyon_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_canyon_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_holocene_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_holocene_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_shanghai_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_shanghai_active_at_timestamp(self.attributes().timestamp)
    }

    pub fn is_ecotone_active(&self) -> bool {
        self.service
            .chain_spec()
            .is_ecotone_active_at_timestamp(self.attributes().timestamp)
    }
}
