use alloy_consensus::Header;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::OpEngineTypes;
use reth_optimism_primitives::OpPrimitives;
use reth_payload_util::PayloadTransactions;
use reth_provider::{BlockReaderIdExt, ChainSpecProvider, StateProviderFactory};
use reth_transaction_pool::TransactionPool;

use crate::tx::FBPooledTransaction;

pub trait NodeBounds:
    FullNodeTypes<
    Types: NodeTypes<Payload = OpEngineTypes, ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
>
{
}

impl<T> NodeBounds for T where
    T: FullNodeTypes<
        Types: NodeTypes<
            Payload = OpEngineTypes,
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
        >,
    >
{
}

pub trait NodeComponents:
    FullNodeComponents<
    Types: NodeTypes<Payload = OpEngineTypes, ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
>
{
}

impl<T> NodeComponents for T where
    T: FullNodeComponents<
        Types: NodeTypes<
            Payload = OpEngineTypes,
            ChainSpec = OpChainSpec,
            Primitives = OpPrimitives,
        >,
    >
{
}

pub trait PoolBounds: TransactionPool<Transaction = FBPooledTransaction> + Unpin + 'static {}

impl<T> PoolBounds for T where
    T: TransactionPool<Transaction = FBPooledTransaction> + Unpin + 'static
{
}

pub trait ClientBounds:
    StateProviderFactory
    + ChainSpecProvider<ChainSpec = OpChainSpec>
    + BlockReaderIdExt<Header = Header>
    + Clone
    + Send
{
}

impl<T> ClientBounds for T where
    T: StateProviderFactory
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt<Header = Header>
        + Clone
        + Send
{
}

pub trait PayloadTxsBounds: PayloadTransactions<Transaction = FBPooledTransaction> {}

impl<T> PayloadTxsBounds for T where T: PayloadTransactions<Transaction = FBPooledTransaction> {}
