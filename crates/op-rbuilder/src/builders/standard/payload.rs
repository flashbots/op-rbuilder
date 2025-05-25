use reth_node_builder::{components::PayloadBuilderBuilder, BuilderContext};
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_payload_builder::config::OpBuilderConfig;

use crate::{builders::BuilderConfig, metrics::OpRBuilderMetrics, traits::{NodeBounds, PoolBounds}, tx_signer::Signer};

pub struct StandardPayloadBuilderBuilder(pub BuilderConfig<()>);

impl<Node, Pool> PayloadBuilderBuilder<Node, Pool, OpEvmConfig> for StandardPayloadBuilderBuilder
where
  Node: NodeBounds,
  Pool: PoolBounds,
{
  type PayloadBuilder = OpPayloadBuilder<Pool, Node::Provider>;

  async fn build_payload_builder(
      self,
      ctx: &BuilderContext<Node>,
      pool: Pool,
      _evm_config: OpEvmConfig,
  ) -> eyre::Result<Self::PayloadBuilder> {
      Ok(StandardOpPayloadBuilder::new(
          OpEvmConfig::optimism(ctx.chain_spec()),
          self.builder_signer,
          pool,
          ctx.provider().clone(),
      ))
  }
}

/// Optimism's payload builder
#[derive(Debug, Clone)]
pub struct StandardOpPayloadBuilder<Pool, Client, Txs = ()> {
  /// The type responsible for creating the evm.
  pub evm_config: OpEvmConfig,
  /// The builder's signer key to use for an end of block tx
  pub builder_signer: Option<Signer>,
  /// The transaction pool
  pub pool: Pool,
  /// Node client
  pub client: Client,
  /// Settings for the builder, e.g. DA settings.
  pub config: OpBuilderConfig,
  /// The type responsible for yielding the best transactions for the payload if mempool
  /// transactions are allowed.
  pub best_transactions: Txs,
  /// The metrics for the builder
  pub metrics: OpRBuilderMetrics,
}