use core::time::Duration;
use std::{
    ops::{Div, Rem},
    sync::mpsc::SyncSender,
};

use tokio_util::sync::CancellationToken;

use crate::builders::flashblocks::config::FlashblocksConfig;

pub(super) struct FlashblockScheduler {
    target_flashblocks: u64,
    first_flashblock_offset: Duration,
    flashblocks_deadline: Duration,

    config: FlashblocksConfig,
}

impl FlashblockScheduler {
    pub(super) fn new(
        config: &FlashblocksConfig,
        block_time: Duration,
        payload_timestamp: u64,
    ) -> Self {
        // Dynamic adjustment disabled
        if config.fixed {
            let target_flashblocks = (block_time.as_millis() / config.interval.as_millis()) as u64;
            let (first_flashblock_offset, flashblocks_deadline) = if config.build_at_interval_end {
                let offset = apply_offset(config.interval, config.send_offset_ms);
                (
                    offset,
                    block_time.saturating_sub(Duration::from_millis(config.end_buffer_ms)),
                )
            } else {
                (config.interval - config.leeway_time, block_time)
            };

            return Self {
                target_flashblocks,
                first_flashblock_offset,
                flashblocks_deadline,
                config: config.clone(),
            };
        }

        // Dynamic adjustment enabled, calculate timing based on payload timestamp and current system time
        let reference_system = std::time::SystemTime::now();
        let target_time = std::time::SystemTime::UNIX_EPOCH
            + Duration::from_secs(payload_timestamp)
            - if !config.build_at_interval_end {
                config.leeway_time
            } else {
                Duration::ZERO
            };

        let remaining_time = target_time
            .duration_since(reference_system)
            .ok()
            .filter(|duration| duration.as_millis() > 0)
            .unwrap_or(block_time)
            .min(block_time);

        let (target_flashblocks, first_flashblock_offset) =
            calculate_first_flashblock_offset(remaining_time, config.interval);

        let (first_flashblock_offset, flashblocks_deadline) = if config.build_at_interval_end {
            let deadline =
                remaining_time.saturating_sub(Duration::from_millis(config.end_buffer_ms));
            let adjusted_offset = apply_offset(first_flashblock_offset, config.send_offset_ms);
            let adjusted_deadline = apply_offset(deadline, config.send_offset_ms);
            (adjusted_offset, adjusted_deadline)
        } else {
            (first_flashblock_offset, block_time)
        };

        Self {
            target_flashblocks,
            first_flashblock_offset,
            flashblocks_deadline,
            config: config.clone(),
        }
    }

    pub(super) async fn run(
        self,
        tx: SyncSender<CancellationToken>,
        block_cancel: CancellationToken,
        mut fb_cancel: CancellationToken,
    ) {
        // If NOT building at interval end, send immediate signal to build first
        // flashblock right away (preserves current default behavior).
        // Otherwise, wait for first_flashblock_offset before first build.
        if !self.config.build_at_interval_end && tx.send(fb_cancel.clone()).is_err() {
            return;
        }

        let mut timer = tokio::time::interval_at(
            tokio::time::Instant::now()
                .checked_add(self.first_flashblock_offset)
                .expect("can add flashblock offset to current time"),
            self.config.interval,
        );

        // Set deadline to ensure the last flashblock will be built before the leeway time
        let deadline_sleep = async {
            tokio::time::sleep(self.flashblocks_deadline).await;
        };
        tokio::pin!(deadline_sleep);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    // cancel current payload building job
                    fb_cancel.cancel();
                    fb_cancel = block_cancel.child_token();
                    // this will tick at first_flashblock_offset,
                    // starting the next flashblock
                    if tx.send(fb_cancel.clone()).is_err() {
                        // receiver channel was dropped, return.
                        // this will only happen if the `build_payload` function returns,
                        // due to payload building error or the main cancellation token being
                        // cancelled.
                        return;
                    }
                }
                _ = &mut deadline_sleep => {
                    // Deadline reached (with leeway applied to end). Cancel current payload building job
                    fb_cancel.cancel();
                    let _ = tx.send(block_cancel.child_token());
                    return;
                }
                _ = block_cancel.cancelled() => {
                    return;
                }
            }
        }
    }

    pub(super) fn target_flashblocks(&self) -> u64 {
        self.target_flashblocks
    }
}

fn apply_offset(duration: Duration, offset_ms: i64) -> Duration {
    let offset_delta = offset_ms.unsigned_abs();
    if offset_ms >= 0 {
        duration.saturating_add(Duration::from_millis(offset_delta))
    } else {
        duration.saturating_sub(Duration::from_millis(offset_delta))
    }
}

fn calculate_first_flashblock_offset(
    remaining_time: Duration,
    interval: Duration,
) -> (u64, Duration) {
    let remaining_time_ms = remaining_time.as_millis() as u64;
    let interval_ms = interval.as_millis() as u64;

    // This is extra check to ensure that we would account at least for block time in case we have any timer discrepancies.
    let first_flashblock_offset_ms = remaining_time_ms.rem(interval_ms);
    if first_flashblock_offset_ms == 0 {
        // We have perfect division, so we use interval as first fb offset
        (
            remaining_time_ms.div(interval_ms),
            Duration::from_millis(interval_ms),
        )
    } else {
        // Non-perfect division, set the first flashblock offset to the remainder of the division
        (
            remaining_time_ms.div(interval_ms) + 1,
            Duration::from_millis(first_flashblock_offset_ms),
        )
    }
}
