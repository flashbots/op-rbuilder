use crate::args::OpRbuilderArgs;
use core::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::info;

/// Configuration values that are specific to the flashblocks builder.
#[derive(Debug, Clone)]
pub struct FlashblocksConfig {
    /// The address of the websockets endpoint that listens for subscriptions to
    /// new flashblocks updates.
    pub ws_addr: SocketAddr,

    /// The number of Flashblocks in each block
    pub flashblocks_per_block: u64,

    /// How often a flashblock is produced. This is independent of the block time of the chain.
    /// Each block will contain one or more flashblocks. On average, the number of flashblocks
    /// per block is equal to the block time divided by the flashblock interval.
    pub build_interval: Duration,
}

impl Default for FlashblocksConfig {
    fn default() -> Self {
        Self {
            ws_addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 1111),
            build_interval: Duration::from_millis(225),
            flashblocks_per_block: 10,
        }
    }
}

impl TryFrom<OpRbuilderArgs> for FlashblocksConfig {
    type Error = eyre::Report;

    fn try_from(args: OpRbuilderArgs) -> Result<Self, Self::Error> {
        let ws_addr = SocketAddr::new(
            args.flashblocks.flashblocks_addr.parse()?,
            args.flashblocks.flashblocks_port,
        );

        let build_interval = Duration::from_millis(
            (args.chain_block_time - args.flashblocks.flashblocks_block_overhead)
                / args.flashblocks.flashblocks_per_block,
        );

        info!(
            "Flashblocks parameters builder_interval={}",
            build_interval.as_millis()
        );

        Ok(Self {
            ws_addr,
            build_interval,
            flashblocks_per_block: args.flashblocks.flashblocks_per_block,
        })
    }
}
