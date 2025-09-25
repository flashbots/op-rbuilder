use crate::builders::flashblocks::p2p::Message;
use reth_node_builder::Events;
use reth_optimism_node::OpEngineTypes;
use reth_optimism_payload_builder::OpBuiltPayload;
use tokio::sync::mpsc;

pub(crate) struct PayloadHandler {
    // receives new payloads built by us.
    built_rx: mpsc::Receiver<OpBuiltPayload>,
    // receives incoming p2p messages from peers.
    p2p_rx: mpsc::Receiver<Message>,
    // outgoing p2p channel to broadcast new payloads to peers.
    p2p_tx: mpsc::Sender<Message>,
    // sends a `Events::BuiltPayload` to the reth payload builder when a new payload is received.
    payload_events_handle: tokio::sync::broadcast::Sender<Events<OpEngineTypes>>,
}

impl PayloadHandler {
    pub(crate) fn new(
        built_rx: mpsc::Receiver<OpBuiltPayload>,
        p2p_rx: mpsc::Receiver<Message>,
        p2p_tx: mpsc::Sender<Message>,
        payload_events_handle: tokio::sync::broadcast::Sender<Events<OpEngineTypes>>,
    ) -> Self {
        Self {
            built_rx,
            p2p_rx,
            p2p_tx,
            payload_events_handle,
        }
    }

    pub(crate) async fn run(self) {
        let Self {
            mut built_rx,
            mut p2p_rx,
            p2p_tx,
            payload_events_handle,
        } = self;

        tracing::info!("flashblocks payload handler started");

        loop {
            tokio::select! {
                Some(payload) = built_rx.recv() => {
                    let _  = payload_events_handle.send(Events::BuiltPayload(payload.clone()));
                    // TODO: only broadcast if `!no_tx_pool`?
                    let _ = p2p_tx.send(payload.into()).await;
                }
                Some(message) = p2p_rx.recv() => {
                    match message {
                        Message::OpBuiltPayload(payload) => {
                            let payload: OpBuiltPayload = payload.into();
                            let _ = payload_events_handle.send(Events::BuiltPayload(payload));
                            // TODO: what other handling is needed here?
                            // clearing mempool of included txs?
                        }
                    }
                }
            }
        }
    }
}
