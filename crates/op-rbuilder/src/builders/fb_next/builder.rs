use super::{context::BuilderContext, job::PayloadJob};
use crate::traits::{ClientBounds, PoolBounds};
use reth_node_api::PayloadBuilderError;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use std::sync::Arc;
use tracing::info;

pub struct PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    pool: Pool,
    ctx: Arc<BuilderContext<Client>>,
}

impl<Pool, Client> PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    pub fn new(pool: Pool, client: Client, evm_config: OpEvmConfig) -> Self {
        Self {
            pool,
            ctx: Arc::new(BuilderContext::new(client, evm_config)),
        }
    }
}

impl<Pool, Client> reth_payload_builder::PayloadJobGenerator for PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    type Job = PayloadJob<Client>;

    fn new_payload_job(
        &self,
        attr: OpPayloadBuilderAttributes<OpTransactionSigned>,
    ) -> Result<Self::Job, PayloadBuilderError> {
        info!("PayloadJobGenerator::new_payload_job {attr:#?}");
        Ok(PayloadJob::new(attr, Arc::clone(&self.ctx)))
    }
}
