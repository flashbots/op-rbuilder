use futures::stream::FuturesUnordered;
use libp2p::{PeerId, swarm::Stream};
use std::collections::HashMap;
use tracing::warn;

pub(crate) struct Peers {
    peers_to_stream: HashMap<PeerId, Stream>,
}

impl Peers {
    pub(crate) fn new() -> Self {
        Self {
            peers_to_stream: HashMap::new(),
        }
    }

    pub(crate) fn has_peer(&self, peer: &PeerId) -> bool {
        self.peers_to_stream.contains_key(peer)
    }

    pub(crate) fn insert_peer_and_stream(&mut self, peer: PeerId, stream: Stream) {
        self.peers_to_stream.insert(peer, stream);
    }

    pub(crate) fn remove_peer(&mut self, peer: &PeerId) {
        self.peers_to_stream.remove(peer);
    }

    pub(crate) async fn broadcast_payload(&mut self, payload: crate::Message) {
        use futures::{SinkExt as _, StreamExt as _};
        use tokio_util::{
            codec::{FramedWrite, LinesCodec},
            compat::FuturesAsyncReadCompatExt as _,
        };

        // let payload = serde_json::to_string(&payload).expect("can serialize payload");
        let peers = self.peers_to_stream.keys().cloned().collect::<Vec<_>>();
        let mut futures = FuturesUnordered::new();
        for peer in peers {
            let stream = self
                .peers_to_stream
                .remove(&peer)
                .expect("stream must exist for peer");
            let stream = stream.compat();
            let payload = payload.clone();
            let fut = async move {
                let mut writer = FramedWrite::new(stream, LinesCodec::new());
                writer.send(payload).await?;
                Ok::<(PeerId, libp2p::swarm::Stream), eyre::ErrReport>((
                    peer,
                    writer.into_inner().into_inner(),
                ))
            };
            futures.push(fut);
        }
        while let Some(result) = futures.next().await {
            match result {
                Ok((peer, stream)) => {
                    self.peers_to_stream.insert(peer, stream);
                }
                Err(e) => {
                    warn!("failed to send payload to peer: {e:?}");
                }
            }
        }
    }
}
