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
        if config.build_at_interval_end {
            let timing = calculate_flashblocks_timing(config, block_time, payload_timestamp);
            Self {
                target_flashblocks: timing.flashblocks_per_block,
                first_flashblock_offset: timing.first_flashblock_offset,
                flashblocks_deadline: timing.flashblocks_deadline,
                config: config.clone(),
            }
        } else {
            let (target_flashblocks, first_flashblock_offset) =
                calculate_flashblocks_legacy(config, block_time, payload_timestamp);
            Self {
                target_flashblocks,
                first_flashblock_offset,
                flashblocks_deadline: block_time,
                config: config.clone(),
            }
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

struct FlashblocksTiming {
    /// Number of flashblocks to build in this block
    pub flashblocks_per_block: u64,
    /// Time until the first flashblock should be built
    pub first_flashblock_offset: Duration,
    /// Total time available for flashblock building (deadline)
    pub flashblocks_deadline: Duration,
}

/// Calculate number of flashblocks and time until first flashblock and deadline for building flashblocks
/// If dynamic is enabled this function will take time drift of FCU arrival into the account.
fn calculate_flashblocks_timing(
    config: &FlashblocksConfig,
    block_time: Duration,
    timestamp: u64,
) -> FlashblocksTiming {
    let target_flashblocks = {
        if block_time.as_millis() == 0 {
            0
        } else {
            (block_time.as_millis() / config.interval.as_millis()) as u64
        }
    };

    let offset_delta = config.send_offset_ms.unsigned_abs();
    if config.fixed {
        let offset = if config.send_offset_ms > 0 {
            config
                .interval
                .saturating_add(Duration::from_millis(offset_delta))
        } else {
            config
                .interval
                .saturating_sub(Duration::from_millis(offset_delta))
        };
        return FlashblocksTiming {
            flashblocks_per_block: target_flashblocks,
            first_flashblock_offset: offset,
            flashblocks_deadline: block_time
                .saturating_sub(Duration::from_millis(config.end_buffer_ms)),
        };
    }

    let target_time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
    let now = std::time::SystemTime::now();
    let Some(remaining_time) = target_time
        .duration_since(now)
        .ok()
        .filter(|duration| duration.as_millis() > 0)
    else {
        return FlashblocksTiming {
            flashblocks_per_block: target_flashblocks,
            first_flashblock_offset: config.interval,
            flashblocks_deadline: block_time
                .saturating_sub(Duration::from_millis(config.end_buffer_ms)),
        };
    };

    // This is extra check to ensure that we would account at least for block time in case we have any timer discrepancies.
    let remaining_time = remaining_time.min(block_time).as_millis() as u64;
    let interval = config.interval.as_millis() as u64;
    let first_flashblock_offset = remaining_time.rem(interval);
    let (flashblocks_per_block, offset) = if first_flashblock_offset == 0 {
        // We have perfect division, so we use interval as first fb offset
        (
            remaining_time.div(interval),
            Duration::from_millis(interval),
        )
    } else {
        // Non-perfect division, set the first flashblock offset to the remainder of the division
        (
            remaining_time.div(interval) + 1,
            Duration::from_millis(first_flashblock_offset),
        )
    };
    // Apply send_offset_ms to the timer start time.
    // Positive values = send later, negative values = send earlier.
    let deadline = Duration::from_millis(remaining_time.saturating_sub(config.end_buffer_ms));
    let (adjusted_offset, adjusted_deadline) = if config.send_offset_ms >= 0 {
        (
            offset.saturating_add(Duration::from_millis(offset_delta)),
            deadline.saturating_add(Duration::from_millis(offset_delta)),
        )
    } else {
        (
            offset.saturating_sub(Duration::from_millis(offset_delta)),
            deadline.saturating_sub(Duration::from_millis(offset_delta)),
        )
    };
    FlashblocksTiming {
        flashblocks_per_block,
        first_flashblock_offset: adjusted_offset,
        flashblocks_deadline: adjusted_deadline,
    }
}

/// Calculate number of flashblocks.
/// If dynamic is enabled this function will take time drift into the account.
/// TODO: deprecate this flashblocks timing calculation
fn calculate_flashblocks_legacy(
    config: &FlashblocksConfig,
    block_time: Duration,
    timestamp: u64,
) -> (u64, Duration) {
    let target_flashblocks = {
        if block_time.as_millis() == 0 {
            0
        } else {
            (block_time.as_millis() / config.interval.as_millis()) as u64
        }
    };
    if config.fixed {
        return (
            target_flashblocks,
            // We adjust first FB to ensure that we have at least some time to make all FB in time
            config.interval - config.leeway_time,
        );
    }

    // We use this system time to determine remining time to build a block
    // Things to consider:
    // FCU(a) - FCU with attributes
    // FCU(a) could arrive with `block_time - fb_time < delay`. In this case we could only produce 1 flashblock
    // FCU(a) could arrive with `delay < fb_time` - in this case we will shrink first flashblock
    // FCU(a) could arrive with `fb_time < delay < block_time - fb_time` - in this case we will issue less flashblocks
    let target_time =
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp) - config.leeway_time;
    let now = std::time::SystemTime::now();
    let Some(time_drift) = target_time
        .duration_since(now)
        .ok()
        .filter(|duration| duration.as_millis() > 0)
    else {
        return (target_flashblocks, config.interval);
    };

    // This is extra check to ensure that we would account at least for block time in case we have any timer discrepancies.
    let time_drift = time_drift.min(block_time);
    let interval = config.interval.as_millis() as u64;
    let time_drift = time_drift.as_millis() as u64;
    let first_flashblock_offset = time_drift.rem(interval);
    if first_flashblock_offset == 0 {
        // We have perfect division, so we use interval as first fb offset
        (time_drift.div(interval), Duration::from_millis(interval))
    } else {
        // Non-perfect division, so we account for it.
        (
            time_drift.div(interval) + 1,
            Duration::from_millis(first_flashblock_offset),
        )
    }
}
