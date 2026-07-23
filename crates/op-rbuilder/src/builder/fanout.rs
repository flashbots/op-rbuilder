use crate::{
    builder::{p2p::Message, timing::compute_slot_offset_ms, wspub::WebSocketPublisher},
    metrics::{OpRBuilderMetrics, record_flashblock_publish_timing},
};
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_node_builder::Events;
use reth_optimism_node::{OpBuiltPayload, OpEngineTypes};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

/// ~6 slots of events at 200ms flashblock
pub(crate) const FLASHBLOCK_BUS_CAPACITY: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct FlashblockEvent {
    /// Wire payload published to websocket subscribers.
    pub fb_payload: Arc<OpFlashblockPayload>,
    /// Built payload forwarded to p2p and engine feedback subscribers.
    pub built: Arc<OpBuiltPayload>,
    /// Payload attributes timestamp used to calculate publication timing.
    pub attributes_timestamp_secs: u64,
    /// Whether this event should be published over websocket.
    pub ws_eligible: bool,
    /// Total transaction count included in tx-trace publication logs.
    pub tx_trace_total_txs: usize,
}

pub(crate) fn channel() -> (
    broadcast::Sender<FlashblockEvent>,
    broadcast::Receiver<FlashblockEvent>,
) {
    broadcast::channel(FLASHBLOCK_BUS_CAPACITY)
}

pub(crate) fn emit(
    sender: &broadcast::Sender<FlashblockEvent>,
    metrics: &OpRBuilderMetrics,
    event: FlashblockEvent,
) -> bool {
    let payload_id = event.fb_payload.payload_id;
    if sender.send(event).is_err() {
        warn!(
            target: "payload_builder",
            id = %payload_id,
            "flashblock fanout bus has no active subscribers; dropping event"
        );
        metrics.fanout_no_subscribers.increment(1);
        false
    } else {
        true
    }
}

async fn recv_event(
    receiver: &mut broadcast::Receiver<FlashblockEvent>,
    mut on_lagged: impl FnMut(u64),
) -> Option<FlashblockEvent> {
    loop {
        match receiver.recv().await {
            Ok(event) => return Some(event),
            Err(broadcast::error::RecvError::Lagged(n)) => on_lagged(n),
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

async fn recv_ws_event(
    receiver: &mut broadcast::Receiver<FlashblockEvent>,
    mut on_lagged: impl FnMut(u64),
) -> Option<FlashblockEvent> {
    loop {
        let event = recv_event(receiver, &mut on_lagged).await?;
        if event.ws_eligible {
            return Some(event);
        }
    }
}

pub(crate) async fn websocket_subscriber(
    receiver: broadcast::Receiver<FlashblockEvent>,
    ws_pub: WebSocketPublisher,
    metrics: Arc<OpRBuilderMetrics>,
    block_time: Duration,
    tx_tracking_logs: bool,
) {
    let lag_metrics = metrics.clone();
    websocket_subscriber_with(
        receiver,
        move |payload| ws_pub.publish(payload),
        move |byte_size| metrics.flashblock_byte_size_histogram.record(byte_size),
        move |n| lag_metrics.ws_publish_lagged.increment(n),
        block_time,
        tx_tracking_logs,
    )
    .await;
}

async fn websocket_subscriber_with(
    mut receiver: broadcast::Receiver<FlashblockEvent>,
    mut publish: impl FnMut(&OpFlashblockPayload) -> io::Result<usize>,
    mut record_byte_size: impl FnMut(f64),
    mut on_lagged: impl FnMut(u64),
    block_time: Duration,
    tx_tracking_logs: bool,
) {
    while let Some(event) = recv_ws_event(&mut receiver, |n| {
        on_lagged(n);
    })
    .await
    {
        // WebSocket failures are isolated from payload construction so a
        // rollup-boost disconnect cannot stop block building.
        let byte_size = match publish(&event.fb_payload) {
            Ok(byte_size) => byte_size,
            Err(error) => {
                warn!(
                    target: "payload_builder",
                    %error,
                    "failed to publish flashblock via websocket"
                );
                continue;
            }
        };
        let slot_offset_ms = compute_slot_offset_ms(event.attributes_timestamp_secs, block_time);
        record_flashblock_publish_timing(event.fb_payload.index, slot_offset_ms);

        if tx_tracking_logs {
            debug!(
                target: "tx_trace",
                payload_id = %event.fb_payload.payload_id,
                block_number = event.fb_payload.metadata.block_number,
                flashblock_index = event.fb_payload.index,
                byte_size,
                total_txs = event.tx_trace_total_txs,
                slot_offset_ms,
                stage = "fb_published"
            );
        }

        record_byte_size(byte_size as f64);
    }
}

pub(crate) async fn p2p_subscriber(
    mut receiver: broadcast::Receiver<FlashblockEvent>,
    p2p_tx: mpsc::Sender<Message>,
    metrics: Arc<OpRBuilderMetrics>,
) {
    while let Some(event) = recv_event(&mut receiver, |n| {
        metrics.p2p_forward_lagged.increment(n);
    })
    .await
    {
        // A closed channel is expected when p2p is disabled.
        let _ = p2p_tx.send((*event.built).clone().into()).await;
    }
}

pub(crate) async fn engine_feedback_subscriber(
    mut receiver: broadcast::Receiver<FlashblockEvent>,
    payload_events_handle: broadcast::Sender<Events<OpEngineTypes>>,
    metrics: Arc<OpRBuilderMetrics>,
) {
    while let Some(event) = recv_event(&mut receiver, |n| {
        metrics.engine_feedback_lagged.increment(n);
    })
    .await
    {
        if let Err(error) = payload_events_handle.send(Events::BuiltPayload((*event.built).clone()))
        {
            warn!(
                target: "payload_builder",
                %error,
                "failed to send BuiltPayload event"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Header};
    use alloy_primitives::{B256, Bloom, U256};
    use op_alloy_rpc_types_engine::{OpFlashblockPayloadDelta, OpFlashblockPayloadMetadata};
    use reth_metrics::metrics::Counter;
    use reth_optimism_primitives::OpBlock;
    use reth_payload_builder::PayloadId;
    use reth_primitives_traits::Block as _;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn event(index: u64, ws_eligible: bool) -> FlashblockEvent {
        let payload_id = PayloadId::new([index as u8; 8]);
        FlashblockEvent {
            fb_payload: Arc::new(OpFlashblockPayload {
                payload_id,
                index,
                base: None,
                diff: OpFlashblockPayloadDelta {
                    state_root: B256::ZERO,
                    receipts_root: B256::ZERO,
                    logs_bloom: Bloom::ZERO,
                    gas_used: 0,
                    block_hash: B256::ZERO,
                    transactions: Vec::new(),
                    withdrawals: Vec::new(),
                    withdrawals_root: B256::ZERO,
                    blob_gas_used: None,
                },
                metadata: OpFlashblockPayloadMetadata {
                    block_number: index,
                    new_account_balances: BTreeMap::new(),
                    receipts: BTreeMap::new(),
                },
            }),
            built: Arc::new(OpBuiltPayload::new(
                payload_id,
                Arc::new(OpBlock::new(Header::default(), BlockBody::default()).seal_slow()),
                U256::ZERO,
                None,
            )),
            attributes_timestamp_secs: 0,
            ws_eligible,
            tx_trace_total_txs: 0,
        }
    }

    #[test]
    fn emit_without_receivers_counts_total_subscriber_loss() {
        let (tx, receiver) = channel();
        drop(receiver);
        let no_subscribers = Arc::new(AtomicU64::new(0));
        let metrics = OpRBuilderMetrics {
            fanout_no_subscribers: Counter::from_arc(no_subscribers.clone()),
            ..Default::default()
        };

        assert!(!emit(&tx, &metrics, event(0, true)));
        assert_eq!(no_subscribers.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fans_out_to_multiple_subscribers_in_order() {
        let (tx, mut first) = channel();
        let mut second = tx.subscribe();
        for index in 0..3 {
            tx.send(event(index, true)).unwrap();
        }
        drop(tx);

        let mut first_indexes = Vec::new();
        let mut second_indexes = Vec::new();
        while let Some(event) = recv_event(&mut first, |_| {}).await {
            first_indexes.push(event.fb_payload.index);
        }
        while let Some(event) = recv_event(&mut second, |_| {}).await {
            second_indexes.push(event.fb_payload.index);
        }

        assert_eq!(first_indexes, [0, 1, 2]);
        assert_eq!(second_indexes, [0, 1, 2]);
    }

    #[tokio::test]
    async fn lagged_receiver_counts_drops_and_continues() {
        let (tx, mut receiver) = broadcast::channel(2);
        for index in 0..4 {
            tx.send(event(index, true)).unwrap();
        }

        let lagged = AtomicU64::new(0);
        let received = recv_event(&mut receiver, |n| {
            lagged.fetch_add(n, Ordering::Relaxed);
        })
        .await
        .unwrap();

        assert_eq!(lagged.load(Ordering::Relaxed), 2);
        assert_eq!(received.fb_payload.index, 2);
    }

    #[tokio::test]
    async fn ineligible_event_skips_websocket_but_reaches_engine_feedback() {
        let (tx, mut ws_receiver) = channel();
        let engine_receiver = tx.subscribe();
        let (payload_events_handle, mut payload_events_receiver) = broadcast::channel(2);
        tokio::spawn(engine_feedback_subscriber(
            engine_receiver,
            payload_events_handle,
            Arc::new(OpRBuilderMetrics::default()),
        ));
        tx.send(event(0, false)).unwrap();
        tx.send(event(1, true)).unwrap();

        let engine_event = payload_events_receiver.recv().await.unwrap();
        let ws_event = recv_ws_event(&mut ws_receiver, |_| {}).await.unwrap();

        let Events::BuiltPayload(engine_payload) = engine_event else {
            panic!("expected built payload event");
        };
        assert_eq!(engine_payload.id(), PayloadId::new([0; 8]));
        assert_eq!(ws_event.fb_payload.index, 1);
    }

    #[tokio::test]
    async fn p2p_subscriber_forwards_events_in_order() {
        let (tx, receiver) = channel();
        let (p2p_tx, mut p2p_rx) = mpsc::channel(3);
        let task = tokio::spawn(p2p_subscriber(
            receiver,
            p2p_tx,
            Arc::new(OpRBuilderMetrics::default()),
        ));

        for index in 0..3 {
            tx.send(event(index, true)).unwrap();
        }
        drop(tx);

        let mut ids = Vec::new();
        while let Some(Message::OpBuiltPayload(payload)) = p2p_rx.recv().await {
            ids.push(payload.id);
        }
        task.await.unwrap();

        assert_eq!(
            ids,
            [
                PayloadId::new([0; 8]),
                PayloadId::new([1; 8]),
                PayloadId::new([2; 8]),
            ]
        );
    }

    #[tokio::test]
    async fn websocket_subscriber_filters_and_records_successful_publications() {
        let (tx, receiver) = channel();
        tx.send(event(0, false)).unwrap();
        tx.send(event(1, true)).unwrap();
        tx.send(event(2, true)).unwrap();
        drop(tx);

        let mut published = Vec::new();
        let mut recorded_sizes = Vec::new();
        websocket_subscriber_with(
            receiver,
            |payload| {
                published.push(payload.index);
                if payload.index == 1 {
                    Err(io::Error::other("test publish failure"))
                } else {
                    Ok(100 + payload.index as usize)
                }
            },
            |byte_size| recorded_sizes.push(byte_size),
            |_| {},
            Duration::from_secs(1),
            false,
        )
        .await;

        assert_eq!(published, [1, 2]);
        assert_eq!(recorded_sizes, [102.0]);
    }
}
