use alloy_primitives::Address;

use crate::{args::OpRbuilderArgs, builders::BuilderConfig};
use core::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

/// Configuration values that are specific to the flashblocks builder.
#[derive(Debug, Clone)]
pub struct FlashblocksConfig {
    /// The address of the websockets endpoint that listens for subscriptions to
    /// new flashblocks updates.
    pub ws_addr: SocketAddr,

    /// How often a flashblock is produced. This is independent of the block time of the chain.
    /// Each block will contain one or more flashblocks. On average, the number of flashblocks
    /// per block is equal to the block time divided by the flashblock interval.
    pub interval: Duration,

    /// How much time would be deducted from block build time to account for latencies in
    /// milliseconds.
    ///
    /// If dynamic_adjustment is false this value would be deducted from first flashblock and
    /// it shouldn't be more than interval
    ///
    /// If dynamic_adjustment is true this value would be deducted from first flashblock and
    /// it shouldn't be more than interval
    pub leeway_time: Duration,

    /// Disables dynamic flashblocks number adjustment based on FCU arrival time
    pub fixed: bool,

    /// Should we calculate state root for each flashblock
    pub calculate_state_root: bool,

    /// The address of the flashblocks number contract.
    ///
    /// If set a builder tx will be added to the start of every flashblock instead of the regular builder tx.
    pub flashblocks_number_contract_address: Option<Address>,

    /// Whether to enable the p2p node for flashblocks
    pub p2p_enabled: bool,

    /// Port for the p2p node
    pub p2p_port: u16,

    /// Optional hex-encoded private key file path for the p2p node
    pub p2p_private_key_file: Option<String>,

    /// Comma-separated list of multiaddresses of known peers to connect to
    pub p2p_known_peers: Option<String>,
}

impl Default for FlashblocksConfig {
    fn default() -> Self {
        Self {
            ws_addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 1111),
            interval: Duration::from_millis(250),
            leeway_time: Duration::from_millis(50),
            fixed: false,
            calculate_state_root: true,
            flashblocks_number_contract_address: None,
            p2p_enabled: false,
            p2p_port: 9009,
            p2p_private_key_file: None,
            p2p_known_peers: None,
        }
    }
}

impl TryFrom<OpRbuilderArgs> for FlashblocksConfig {
    type Error = eyre::Report;

    fn try_from(args: OpRbuilderArgs) -> Result<Self, Self::Error> {
        let interval = Duration::from_millis(args.flashblocks.flashblocks_block_time);

        let ws_addr = SocketAddr::new(
            args.flashblocks.flashblocks_addr.parse()?,
            args.flashblocks.flashblocks_port,
        );

        let leeway_time = Duration::from_millis(args.flashblocks.flashblocks_leeway_time);

        let fixed = args.flashblocks.flashblocks_fixed;

        let calculate_state_root = args.flashblocks.flashblocks_calculate_state_root;

        let flashblocks_number_contract_address =
            args.flashblocks.flashblocks_number_contract_address;

        Ok(Self {
            ws_addr,
            interval,
            leeway_time,
            fixed,
            calculate_state_root,
            flashblocks_number_contract_address,
            p2p_enabled: args.flashblocks.p2p.p2p_enabled,
            p2p_port: args.flashblocks.p2p.p2p_port,
            p2p_private_key_file: args.flashblocks.p2p.p2p_private_key_file,
            p2p_known_peers: args.flashblocks.p2p.p2p_known_peers,
        })
    }
}

pub(super) trait FlashBlocksConfigExt {
    fn flashblocks_per_block(&self) -> u64;
}

impl FlashBlocksConfigExt for BuilderConfig<FlashblocksConfig> {
    fn flashblocks_per_block(&self) -> u64 {
        if self.block_time.as_millis() == 0 {
            return 0;
        }
        (self.block_time.as_millis() / self.specific.interval.as_millis()) as u64
    }
}
