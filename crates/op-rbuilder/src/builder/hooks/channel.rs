use crate::builder::hooks::post_seal::{PostSealHook, SealedCandidate, SlotMeta};
use reth_optimism_node::OpBuiltPayload;
use tokio::sync::mpsc;
use tracing::warn;

/// Forwards each sealed candidate over a named mpsc channel.
#[derive(Debug)]
pub(crate) struct ChannelHook {
    name: &'static str,
    sender: mpsc::Sender<OpBuiltPayload>,
}

impl ChannelHook {
    pub(crate) fn new(name: &'static str, sender: mpsc::Sender<OpBuiltPayload>) -> Self {
        Self { name, sender }
    }
}

impl PostSealHook for ChannelHook {
    fn on_sealed(&self, candidate: &SealedCandidate, _slot: &SlotMeta) {
        if let Err(e) = self.sender.try_send(candidate.payload.clone()) {
            warn!(
                target: "payload_builder",
                channel = self.name,
                error = %e,
                flashblock_index = candidate.fb_payload.index,
                "Failed to forward sealed payload over channel"
            );
        }
    }
}
