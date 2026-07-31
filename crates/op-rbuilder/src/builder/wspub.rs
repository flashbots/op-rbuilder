use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use futures::SinkExt;
use futures_util::StreamExt;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use std::{io, net::TcpListener, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{
        broadcast::{self, Receiver, error::RecvError},
        watch,
    },
};
use tokio_tungstenite::{
    WebSocketStream, accept_async,
    tungstenite::{
        Message, Utf8Bytes,
        protocol::frame::{CloseFrame, coding::CloseCode},
    },
};
use tracing::{debug, info, trace, warn};

use crate::{metrics::OpRBuilderMetrics, tokio_metrics::MonitoredTask};

/// A WebSockets publisher that accepts connections from client websockets and broadcasts to them
/// updates about new flashblocks. It maintains a count of sent messages and active subscriptions.
///
/// This is modelled as a `futures::Sink` that can be used to send `OpFlashblockPayload` messages.
pub(super) struct WebSocketPublisher {
    sent: Arc<AtomicUsize>,
    subs: Arc<AtomicUsize>,
    term: watch::Sender<bool>,
    pipe: broadcast::Sender<Utf8Bytes>,
    subscriber_limit: Option<u16>,
}

impl WebSocketPublisher {
    pub(super) fn new(
        addr: SocketAddr,
        metrics: Arc<OpRBuilderMetrics>,
        task_monitor: &MonitoredTask,
        subscriber_limit: Option<u16>,
    ) -> io::Result<Self> {
        let (pipe, _) = broadcast::channel(100);
        let (term, _) = watch::channel(false);

        let sent = Arc::new(AtomicUsize::new(0));
        let subs = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind(addr)?;

        tokio::spawn(task_monitor.instrument(listener_loop(
            listener,
            metrics,
            pipe.subscribe(),
            term.subscribe(),
            Arc::clone(&sent),
            Arc::clone(&subs),
            subscriber_limit,
        )));

        Ok(Self {
            sent,
            subs,
            term,
            pipe,
            subscriber_limit,
        })
    }

    pub(super) fn publish(&self, payload: &OpFlashblockPayload) -> io::Result<usize> {
        // Serialize the payload to a UTF-8 string
        // serialize only once, then just copy around only a pointer
        // to the serialized data for each subscription.
        debug!(
            target: "payload_builder",
            event = "flashblock_sent",
            message = "Sending flashblock to rollup-boost",
            id = %payload.payload_id,
            index = payload.index,
            block_number = payload.metadata.block_number,
            base = payload.base.is_some(),
        );

        let serialized = serde_json::to_string(payload)?;
        let utf8_bytes = Utf8Bytes::from(serialized);
        let size = utf8_bytes.len();
        // Send the serialized payload to all subscribers
        self.pipe
            .send(utf8_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
        Ok(size)
    }
}

impl Drop for WebSocketPublisher {
    fn drop(&mut self) {
        // Notify the listener loop to terminate
        let _ = self.term.send(true);
        info!(target: "payload_builder", "WebSocketPublisher dropped, terminating listener loop");
    }
}

async fn listener_loop(
    listener: TcpListener,
    metrics: Arc<OpRBuilderMetrics>,
    receiver: Receiver<Utf8Bytes>,
    term: watch::Receiver<bool>,
    sent: Arc<AtomicUsize>,
    subs: Arc<AtomicUsize>,
    subscriber_limit: Option<u16>,
) {
    listener
        .set_nonblocking(true)
        .expect("Failed to set TcpListener socket to non-blocking");

    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("Failed to convert TcpListener to tokio TcpListener");

    let listen_addr = listener
        .local_addr()
        .expect("Failed to get local address of listener");
    info!(
        target: "payload_builder",
        address = %listen_addr,
        "Flashblocks WebSocketPublisher listening"
    );

    let mut term = term;

    loop {
        let subs = Arc::clone(&subs);
        let metrics = Arc::clone(&metrics);

        tokio::select! {
            // drop this connection if the `WebSocketPublisher` is dropped
            _ = term.changed() => {
                if *term.borrow() {
                    return;
                }
            }

            // Accept new connections on the websocket listener
            // when a new connection is established, spawn a dedicated task to handle
            // the connection and broadcast with that connection.
            Ok((connection, peer_addr)) = listener.accept() => {
                let sent = Arc::clone(&sent);
                let term = term.clone();
                let receiver_clone = receiver.resubscribe();

                match accept_async(connection).await {
                    Ok(mut stream) => {
                        tokio::spawn(async move {
                            if let Some(limit) = subscriber_limit && subs.load(Ordering::Relaxed) >= limit as usize {
                                    warn!(
                                        target: "payload_builder",
                                        peer_addr = %peer_addr,
                                        "WebSocket connection rejected: subscriber limit reached"
                                    );
                                    let _ = stream.close(Some(CloseFrame {
                                        code: CloseCode::Again,
                                        reason: "subscriber limit reached, please try again later".into(),
                                    })).await;
                                    return;
                            }
                            subs.fetch_add(1, Ordering::Relaxed);
                            debug!(
                                target: "payload_builder",
                                peer_addr = %peer_addr,
                                "WebSocket connection established"
                            );

                            // Handle the WebSocket connection in a dedicated task
                            broadcast_loop(stream, metrics, term, receiver_clone, sent).await;

                            subs.fetch_sub(1, Ordering::Relaxed);
                            debug!(
                                target: "payload_builder",
                                peer_addr = %peer_addr,
                                "WebSocket connection closed"
                            );
                        });
                    }
                    Err(e) => {
                        warn!(
                            target: "payload_builder",
                            peer_addr = %peer_addr,
                            error = %e,
                            "Failed to accept WebSocket connection"
                        );
                    }
                }
            }
        }
    }
}

/// An instance of this loop is spawned for each connected WebSocket client.
/// It listens for broadcast updates about new flashblocks and sends them to the client.
/// It also handles termination signals to gracefully close the connection.
/// Any connectivity errors will terminate the loop, which will in turn
/// decrement the subscription count in the `WebSocketPublisher`.
async fn broadcast_loop(
    stream: WebSocketStream<TcpStream>,
    metrics: Arc<OpRBuilderMetrics>,
    term: watch::Receiver<bool>,
    blocks: broadcast::Receiver<Utf8Bytes>,
    sent: Arc<AtomicUsize>,
) {
    let mut term = term;
    let mut blocks = blocks;
    let mut stream = stream;
    let Ok(peer_addr) = stream.get_ref().peer_addr() else {
        return;
    };

    loop {
        let metrics = Arc::clone(&metrics);

        tokio::select! {
            // Check if the publisher is terminated
            _ = term.changed() => {
                if *term.borrow() {
                    info!(
                        target: "payload_builder",
                        "WebSocketPublisher is terminating, closing broadcast loop"
                    );
                    return;
                }
            }

            // Receive payloads from the broadcast channel
            payload = blocks.recv() => match payload {
                Ok(payload) => {
                    // Here you would typically send the payload to the WebSocket clients.
                    // For this example, we just increment the sent counter.
                    sent.fetch_add(1, Ordering::Relaxed);
                    metrics.messages_sent_count.increment(1);

                    trace!(target: "payload_builder", payload = ?payload, "Broadcasted payload");
                    if let Err(e) = stream.send(Message::Text(payload)).await {
                        debug!(
                            target: "payload_builder",
                            peer_addr = %peer_addr,
                            error = %e,
                            "Send payload error for flashblocks subscription"
                        );
                        break; // Exit the loop if sending fails
                    }
                }
                Err(RecvError::Closed) => {
                    debug!(
                        target: "payload_builder",
                        "Broadcast channel closed, exiting broadcast loop"
                    );
                    return;
                }
                Err(RecvError::Lagged(_)) => {
                    warn!(
                        target: "payload_builder",
                        "Broadcast channel lagged, some messages were dropped"
                    );
                }
            },

            // Ping-pong handled by tokio_tungstenite when you perform read on the socket
            message = stream.next() => if let Some(message) = message { match message {
                // We handle only close frame to highlight conn closing
                Ok(Message::Close(_)) => {
                    info!(
                        target: "payload_builder",
                        peer_addr = %peer_addr,
                        "Closing frame received, stopping connection"
                    );
                    break;
                }
                Err(e) => {
                    warn!(
                        target: "payload_builder",
                        peer_addr = %peer_addr,
                        error = %e,
                        "Received error. Closing flashblocks subscription"
                    );
                    break;
                }
                _ => (),
            } }
        }
    }
}

impl Debug for WebSocketPublisher {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let subs = self.subs.load(Ordering::Relaxed);
        let sent = self.sent.load(Ordering::Relaxed);
        let subscriber_limit = self.subscriber_limit;

        f.debug_struct("WebSocketPublisher")
            .field("subs", &subs)
            .field("payloads_sent", &sent)
            .field("subscriber_limit", &subscriber_limit)
            .finish()
    }
}

/// Golden-byte pins for the flashblock JSON that [`WebSocketPublisher::publish`] ships to
/// rollup-boost. The payload type lives upstream (op-alloy), so a dependency bump can silently
/// move the wire format under deployed consumers; round-trip tests can't catch that because both
/// sides drift together, so these assert the exact bytes in both directions.
#[cfg(test)]
mod golden_wire {
    use alloy_consensus::{Eip658Value, Receipt};
    use alloy_primitives::{Address, Bloom, Bytes, Log, LogData, U256, address, b256};
    use op_alloy_consensus::{OpDepositReceipt, OpReceipt};
    use op_alloy_rpc_types_engine::{
        OpFlashblockPayload, OpFlashblockPayloadBase, OpFlashblockPayloadDelta,
        OpFlashblockPayloadMetadata,
    };
    use reth_payload_builder::PayloadId;
    use std::collections::BTreeMap;

    fn eip1559_receipt() -> OpReceipt {
        OpReceipt::Eip1559(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 21_000,
            logs: vec![Log {
                address: address!("00000000000000000000000000000000000000aa"),
                data: LogData::new_unchecked(
                    vec![b256!(
                        "00000000000000000000000000000000000000000000000000000000000000a1"
                    )],
                    Bytes::from_static(&[0x01, 0x02]),
                ),
            }],
        })
    }

    fn deposit_receipt() -> OpReceipt {
        OpReceipt::Deposit(OpDepositReceipt {
            inner: Receipt {
                status: Eip658Value::Eip658(true),
                cumulative_gas_used: 50_000,
                logs: vec![],
            },
            deposit_nonce: Some(7),
            deposit_receipt_version: Some(1),
        })
    }

    /// First flashblock of a block: carries `base`, a deposit receipt, and Jovian blob gas.
    fn payload_index0() -> OpFlashblockPayload {
        let mut new_account_balances = BTreeMap::new();
        new_account_balances.insert(
            address!("00000000000000000000000000000000000000bb"),
            U256::from(0x2540be400u64),
        );

        let mut receipts = BTreeMap::new();
        receipts.insert(
            b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            deposit_receipt(),
        );

        OpFlashblockPayload {
            payload_id: PayloadId::new([0x0a; 8]),
            index: 0,
            base: Some(OpFlashblockPayloadBase {
                parent_beacon_block_root: b256!(
                    "2222222222222222222222222222222222222222222222222222222222222222"
                ),
                parent_hash: b256!(
                    "3333333333333333333333333333333333333333333333333333333333333333"
                ),
                fee_recipient: address!("4200000000000000000000000000000000000011"),
                prev_randao: b256!(
                    "4444444444444444444444444444444444444444444444444444444444444444"
                ),
                block_number: 100,
                gas_limit: 30_000_000,
                timestamp: 1_752_000_000,
                extra_data: Bytes::from_static(&[0x00, 0x01, 0x02]),
                base_fee_per_gas: U256::from(1_000_000_000u64),
            }),
            diff: OpFlashblockPayloadDelta {
                state_root: b256!(
                    "5555555555555555555555555555555555555555555555555555555555555555"
                ),
                receipts_root: b256!(
                    "6666666666666666666666666666666666666666666666666666666666666666"
                ),
                logs_bloom: Bloom::ZERO,
                gas_used: 50_000,
                block_hash: b256!(
                    "7777777777777777777777777777777777777777777777777777777777777777"
                ),
                transactions: vec![Bytes::from_static(&[0x7e, 0x01, 0x02, 0x03])],
                withdrawals: vec![],
                withdrawals_root: b256!(
                    "8888888888888888888888888888888888888888888888888888888888888888"
                ),
                blob_gas_used: Some(0),
                post_exec_tx: None,
            },
            metadata: OpFlashblockPayloadMetadata {
                block_number: 100,
                new_account_balances,
                receipts,
            },
        }
    }

    /// Later flashblock: no `base`, a 1559 receipt, pre-Jovian (`blob_gas_used: None` is omitted).
    fn payload_index3() -> OpFlashblockPayload {
        let mut new_account_balances = BTreeMap::new();
        new_account_balances.insert(Address::ZERO, U256::ZERO);

        let mut receipts = BTreeMap::new();
        receipts.insert(
            b256!("9999999999999999999999999999999999999999999999999999999999999999"),
            eip1559_receipt(),
        );

        OpFlashblockPayload {
            payload_id: PayloadId::new([0x0a; 8]),
            index: 3,
            base: None,
            diff: OpFlashblockPayloadDelta {
                state_root: b256!(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                receipts_root: b256!(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                logs_bloom: Bloom::ZERO,
                gas_used: 71_000,
                block_hash: b256!(
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                ),
                transactions: vec![Bytes::from_static(&[0x02, 0xff])],
                withdrawals: vec![],
                withdrawals_root: b256!(
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                ),
                blob_gas_used: None,
                post_exec_tx: None,
            },
            metadata: OpFlashblockPayloadMetadata {
                block_number: 100,
                new_account_balances,
                receipts,
            },
        }
    }

    // Notable encodings these pins guard (all live wire behavior today):
    // - `base.{block_number,gas_limit,timestamp}` are quantity-hex, but
    //   `metadata.block_number` is a plain JSON number — inconsistent by history, now load-bearing.
    // - receipts are internally tagged (`"type":"0x2"/"0x7e"`) with camelCase fields.
    // - `base` and `diff.blob_gas_used` are omitted entirely when `None`.
    const PINNED_INDEX0: &str = r#"{"payload_id":"0x0a0a0a0a0a0a0a0a","index":0,"base":{"parent_beacon_block_root":"0x2222222222222222222222222222222222222222222222222222222222222222","parent_hash":"0x3333333333333333333333333333333333333333333333333333333333333333","fee_recipient":"0x4200000000000000000000000000000000000011","prev_randao":"0x4444444444444444444444444444444444444444444444444444444444444444","block_number":"0x64","gas_limit":"0x1c9c380","timestamp":"0x686d6600","extra_data":"0x000102","base_fee_per_gas":"0x3b9aca00"},"diff":{"state_root":"0x5555555555555555555555555555555555555555555555555555555555555555","receipts_root":"0x6666666666666666666666666666666666666666666666666666666666666666","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","gas_used":"0xc350","block_hash":"0x7777777777777777777777777777777777777777777777777777777777777777","transactions":["0x7e010203"],"withdrawals":[],"withdrawals_root":"0x8888888888888888888888888888888888888888888888888888888888888888","blob_gas_used":"0x0"},"metadata":{"block_number":100,"new_account_balances":{"0x00000000000000000000000000000000000000bb":"0x2540be400"},"receipts":{"0x1111111111111111111111111111111111111111111111111111111111111111":{"type":"0x7e","status":"0x1","cumulativeGasUsed":"0xc350","logs":[],"depositNonce":"0x7","depositReceiptVersion":"0x1"}}}}"#;

    const PINNED_INDEX3: &str = r#"{"payload_id":"0x0a0a0a0a0a0a0a0a","index":3,"diff":{"state_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipts_root":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","gas_used":"0x11558","block_hash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","transactions":["0x02ff"],"withdrawals":[],"withdrawals_root":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"metadata":{"block_number":100,"new_account_balances":{"0x0000000000000000000000000000000000000000":"0x0"},"receipts":{"0x9999999999999999999999999999999999999999999999999999999999999999":{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208","logs":[{"address":"0x00000000000000000000000000000000000000aa","topics":["0x00000000000000000000000000000000000000000000000000000000000000a1"],"data":"0x0102"}]}}}}"#;

    /// Same payload as [`PINNED_INDEX3`] but with the receipt in the legacy externally-tagged
    /// form (`{"Eip1559": {...}}`) that older rollup-boost emitted; the custom deserializer in
    /// op-alloy must keep accepting it.
    const LEGACY_TAGGED_INDEX3: &str = r#"{"payload_id":"0x0a0a0a0a0a0a0a0a","index":3,"diff":{"state_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipts_root":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","logs_bloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","gas_used":"0x11558","block_hash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","transactions":["0x02ff"],"withdrawals":[],"withdrawals_root":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"metadata":{"block_number":100,"new_account_balances":{"0x0000000000000000000000000000000000000000":"0x0"},"receipts":{"0x9999999999999999999999999999999999999999999999999999999999999999":{"Eip1559":{"status":"0x1","cumulativeGasUsed":"0x5208","logs":[{"address":"0x00000000000000000000000000000000000000aa","topics":["0x00000000000000000000000000000000000000000000000000000000000000a1"],"data":"0x0102"}]}}}}}"#;

    #[test]
    fn index0_wire_format_is_pinned() {
        let payload = payload_index0();
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            PINNED_INDEX0,
            "serialized flashblock JSON drifted from the pinned wire format"
        );
        let decoded: OpFlashblockPayload = serde_json::from_str(PINNED_INDEX0).unwrap();
        assert_eq!(
            decoded, payload,
            "pinned wire JSON no longer decodes to the same payload"
        );
    }

    #[test]
    fn index3_wire_format_is_pinned() {
        let payload = payload_index3();
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            PINNED_INDEX3,
            "serialized flashblock JSON drifted from the pinned wire format"
        );
        let decoded: OpFlashblockPayload = serde_json::from_str(PINNED_INDEX3).unwrap();
        assert_eq!(
            decoded, payload,
            "pinned wire JSON no longer decodes to the same payload"
        );
    }

    #[test]
    fn legacy_externally_tagged_receipts_still_deserialize() {
        let decoded: OpFlashblockPayload = serde_json::from_str(LEGACY_TAGGED_INDEX3).unwrap();
        assert_eq!(decoded, payload_index3());
    }
}
