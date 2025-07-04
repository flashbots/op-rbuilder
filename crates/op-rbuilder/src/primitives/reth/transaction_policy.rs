use std::collections::HashSet;
use reth::network::NetworkPrimitives;
use reth::network::transactions::{PeerMetadata, TransactionPropagationPolicy};
use reth_network_peers::PeerId;

pub struct RbuilderTransactionPropagation {
    pub peers: HashSet<PeerId>,
}

impl RbuilderTransactionPropagation {
    pub fn new(peers: Vec<PeerId>) -> Self {
        Self {
            peers: HashSet::from_iter(peers),
        }
    }
}
impl TransactionPropagationPolicy for RbuilderTransactionPropagation {
    fn can_propagate<N: NetworkPrimitives>(&self, peer: &mut PeerMetadata<N>) -> bool {
        self.peers.contains(&peer.request_tx().peer_id)
    }

    fn on_session_established<N: NetworkPrimitives>(&mut self, _peer: &mut PeerMetadata<N>) {}

    fn on_session_closed<N: NetworkPrimitives>(&mut self, _peer: &mut PeerMetadata<N>) {}
}