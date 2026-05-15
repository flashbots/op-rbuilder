use crate::builder::hooks::post_seal::{PostSealHook, SealedCandidate, SealedCtx};
use reth_optimism_node::OpBuiltPayload;
use tokio::sync::mpsc;
use tracing::warn;

/// Forwards each sealed candidate over a named mpsc channel.
#[derive(Debug)]
pub(in crate::builder) struct ChannelHook {
    name: &'static str,
    sender: mpsc::Sender<OpBuiltPayload>,
}

impl ChannelHook {
    pub(in crate::builder) fn new(
        name: &'static str,
        sender: mpsc::Sender<OpBuiltPayload>,
    ) -> Self {
        Self { name, sender }
    }
}

impl PostSealHook for ChannelHook {
    fn on_sealed(&self, candidate: &SealedCandidate, ctx: &SealedCtx) {
        if let Err(e) = self.sender.try_send(candidate.payload.clone()) {
            warn!(
                target: "payload_builder",
                channel = self.name,
                error = %e,
                flashblock_index = ctx.flashblock_index,
                "Failed to forward sealed payload over channel"
            );
        }
    }
}
