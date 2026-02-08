use core::time::Duration;
use std::{ops::Rem, sync::mpsc::SyncSender};

use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::builders::flashblocks::config::FlashblocksConfig;

pub(super) struct FlashblockScheduler {
    send_times: Vec<tokio::time::Instant>,
}

impl FlashblockScheduler {
    pub(super) fn new(
        config: &FlashblocksConfig,
        block_time: Duration,
        payload_timestamp: u64,
    ) -> Self {
        let reference_system = std::time::SystemTime::now();
        let reference_instant = tokio::time::Instant::now();

        // Dynamic adjustment disabled
        if config.fixed {
            let (first_flashblock_offset, flashblocks_deadline) = if config.build_at_interval_end {
                let offset = apply_offset(config.interval, config.send_offset_ms);
                (
                    offset,
                    block_time.saturating_sub(Duration::from_millis(config.end_buffer_ms)),
                )
            } else {
                (config.interval - config.leeway_time, block_time)
            };

            let send_times = compute_send_times(
                reference_instant,
                first_flashblock_offset,
                config.interval,
                flashblocks_deadline,
                config.build_at_interval_end,
            );

            return Self { send_times };
        }

        // Dynamic adjustment enabled, calculate timing based on payload timestamp and current system time
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

        let first_flashblock_offset =
            calculate_first_flashblock_offset(remaining_time, config.interval);

        let (first_flashblock_offset, flashblocks_deadline) = if config.build_at_interval_end {
            let adjusted_offset = apply_offset(first_flashblock_offset, config.send_offset_ms);
            let adjusted_deadline = apply_offset(
                remaining_time.saturating_sub(Duration::from_millis(config.end_buffer_ms)),
                config.send_offset_ms,
            );
            (adjusted_offset, adjusted_deadline)
        } else {
            (first_flashblock_offset, block_time)
        };

        let send_times = compute_send_times(
            reference_instant,
            first_flashblock_offset,
            config.interval,
            flashblocks_deadline,
            config.build_at_interval_end,
        );

        Self { send_times }
    }

    pub(super) async fn run(
        self,
        tx: SyncSender<CancellationToken>,
        block_cancel: CancellationToken,
        mut fb_cancel: CancellationToken,
    ) {
        let start = tokio::time::Instant::now();

        for (i, send_time) in self.send_times.into_iter().enumerate() {
            tokio::select! {
                _ = tokio::time::sleep_until(send_time) => {
                    // Cancel current payload building job
                    fb_cancel.cancel();

                    // Trigger next payload building job
                    fb_cancel = block_cancel.child_token();

                    let elapsed = start.elapsed();
                    debug!(
                        target: "payload_builder",
                        flashblock_index = i + 1,
                        scheduled_time = ?(send_time - start),
                        actual_time = ?elapsed,
                        drift = ?(elapsed - (send_time - start)),
                        "Sending flashblock trigger"
                    );

                    if tx.send(fb_cancel.clone()).is_err() {
                        // receiver channel was dropped, return.
                        // this will only happen if the `build_payload` function returns,
                        // due to payload building error or the main cancellation token being
                        // cancelled.
                        error!(target: "payload_builder", "Failed to send flashblock trigger, receiver channel was dropped");
                        return;
                    }
                }
                _ = block_cancel.cancelled() => return,
            }
        }
    }

    pub(super) fn target_flashblocks(&self) -> u64 {
        self.send_times.len() as u64
    }
}

fn compute_send_times(
    start: tokio::time::Instant,
    first_flashblock_offset: Duration,
    interval: Duration,
    deadline: Duration,
    build_at_interval_end: bool,
) -> Vec<tokio::time::Instant> {
    compute_send_time_intervals(
        first_flashblock_offset,
        interval,
        deadline,
        build_at_interval_end,
    )
    .into_iter()
    .map(|duration| start + duration)
    .collect()
}

fn compute_send_time_intervals(
    first_flashblock_offset: Duration,
    interval: Duration,
    deadline: Duration,
    build_at_interval_end: bool,
) -> Vec<Duration> {
    let mut send_times = vec![];

    if !build_at_interval_end {
        // Immediate send at 0, then timer fires at first_flashblock_offset,
        // then every interval thereafter
        if Duration::ZERO < deadline {
            send_times.push(Duration::ZERO);
        }
    }

    let mut next_time = first_flashblock_offset;
    while next_time < deadline {
        send_times.push(next_time);
        next_time += interval;
    }

    send_times.push(deadline);

    send_times
}

fn apply_offset(duration: Duration, offset_ms: i64) -> Duration {
    let offset_delta = offset_ms.unsigned_abs();
    if offset_ms >= 0 {
        duration.saturating_add(Duration::from_millis(offset_delta))
    } else {
        duration.saturating_sub(Duration::from_millis(offset_delta))
    }
}

fn calculate_first_flashblock_offset(remaining_time: Duration, interval: Duration) -> Duration {
    let remaining_time_ms = remaining_time.as_millis() as u64;
    let interval_ms = interval.as_millis() as u64;

    // The math is equivalent to the modulo operation except we produce a
    // result in the range of [1, interval] instead of [0, interval - 1].
    Duration::from_millis((remaining_time_ms.saturating_sub(1)).rem(interval_ms) + 1)
}

impl std::fmt::Debug for FlashblockScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.send_times.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ComputeSendTimesTestCase {
        first_flashblock_offset_ms: u64,
        deadline_ms: u64,
        expected_send_times_ms: Vec<u64>,
    }

    fn check_compute_send_times(
        test_case: ComputeSendTimesTestCase,
        interval: Duration,
        build_at_interval_end: bool,
    ) {
        let send_times = compute_send_time_intervals(
            Duration::from_millis(test_case.first_flashblock_offset_ms),
            interval,
            Duration::from_millis(test_case.deadline_ms),
            build_at_interval_end,
        );
        let expected_send_times: Vec<Duration> = test_case
            .expected_send_times_ms
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(
            send_times,
            expected_send_times,
            "Failed for test case: first_flashblock_offset_ms: {}, interval: {:?}, deadline_ms: {}, build_at_interval_end: {}",
            test_case.first_flashblock_offset_ms,
            interval,
            test_case.deadline_ms,
            build_at_interval_end
        );
    }

    #[test]
    fn test_compute_send_times_build_at_start() {
        let test_cases = vec![ComputeSendTimesTestCase {
            first_flashblock_offset_ms: 140,
            deadline_ms: 870,
            expected_send_times_ms: vec![0, 140, 340, 540, 740, 870],
        }];

        for test_case in test_cases {
            check_compute_send_times(test_case, Duration::from_millis(200), false);
        }
    }

    #[test]
    fn test_compute_send_times_build_at_end() {
        let test_cases = vec![ComputeSendTimesTestCase {
            first_flashblock_offset_ms: 150,
            deadline_ms: 880,
            expected_send_times_ms: vec![150, 350, 550, 750, 880],
        }];

        for test_case in test_cases {
            check_compute_send_times(test_case, Duration::from_millis(200), true);
        }
    }
}
