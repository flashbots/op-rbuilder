use core::time::Duration;
use std::{ops::Rem, sync::mpsc::SyncSender};

use reth_payload_builder::PayloadId;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::builders::flashblocks::config::FlashblocksConfig;

/// Schedules and triggers flashblock builds at predetermined times during a
/// block slot. This should be created at the start of each payload building
/// job.
pub(super) struct FlashblockScheduler {
    /// Wall clock time when this scheduler was created.
    reference_system: std::time::SystemTime,
    /// Monotonic instant when this scheduler was created.
    reference_instant: tokio::time::Instant,
    /// Absolute times at which to trigger flashblock builds.
    send_times: Vec<tokio::time::Instant>,
}

impl FlashblockScheduler {
    pub(super) fn new(
        config: &FlashblocksConfig,
        block_time: Duration,
        payload_timestamp: u64,
    ) -> Self {
        // Capture current time for calculating relative offsets
        let reference_system = std::time::SystemTime::now();
        let reference_instant = tokio::time::Instant::now();

        let target_flashblocks = (block_time.as_millis() / config.interval.as_millis()) as u64;

        // Calculate how much time remains until the payload deadline
        let remaining_time =
            compute_remaining_time(block_time, payload_timestamp, reference_system);

        // Compute the schedule as relative durations from now
        let intervals = compute_scheduler_intervals(
            config.interval,
            config.send_offset_ms,
            config.end_buffer_ms,
            remaining_time,
            target_flashblocks,
        );

        // Convert relative durations to absolute instants for
        // tokio::time::sleep_until
        let send_times = intervals
            .into_iter()
            .map(|d| reference_instant + d)
            .collect();

        Self {
            reference_system,
            reference_instant,
            send_times,
        }
    }

    /// Runs the scheduler, sending flashblock triggers at the scheduled times.
    pub(super) async fn run(
        self,
        tx: SyncSender<CancellationToken>,
        block_cancel: CancellationToken,
        mut fb_cancel: CancellationToken,
        payload_id: PayloadId,
    ) {
        let start = tokio::time::Instant::now();

        let target_flashblocks = self.send_times.len();
        for (i, send_time) in self.send_times.into_iter().enumerate() {
            tokio::select! {
                _ = tokio::time::sleep_until(send_time) => {
                    // Cancel current flashblock building job
                    fb_cancel.cancel();

                    // Trigger next flashblock building job
                    fb_cancel = block_cancel.child_token();

                    let elapsed = start.elapsed();
                    debug!(
                        target: "payload_builder",
                        id = %payload_id,
                        flashblock_index = i + 1,
                        scheduled_time = ?(send_time - start),
                        actual_time = ?elapsed,
                        drift = ?(elapsed - (send_time - start)),
                        "Sending flashblock trigger"
                    );

                    if tx.send(fb_cancel.clone()).is_err() {
                        // receiver channel was dropped, return. this will only
                        // happen if the `build_payload` function returns, due
                        // to payload building error or the main cancellation
                        // token being cancelled.
                        error!(
                            target: "payload_builder",
                            id = %payload_id,
                            "Failed to send flashblock trigger, receiver channel was dropped"
                        );
                        return;
                    }
                }
                _ = block_cancel.cancelled() => {
                    warn!(
                        target: "payload_builder",
                        id = %payload_id,
                        missed_count = target_flashblocks - i,
                        target_flashblocks = target_flashblocks,
                        "Missing flashblocks because the payload building job was cancelled too early"
                    );
                    return
                },
            }
        }
    }

    /// Returns the total number of flashblocks that will be triggered.
    pub(super) fn target_flashblocks(&self) -> u64 {
        self.send_times.len() as u64
    }
}

/// Computes the remaining time until the payload deadline. Calculates remaining
/// time as `payload_timestamp - now`. The result is capped at `block_time`. If
/// the timestamp is in the past (late FCU), sets remaining time to 0 to try to
/// emit one flashblock.
fn compute_remaining_time(
    block_time: Duration,
    payload_timestamp: u64,
    reference_system: std::time::SystemTime,
) -> Duration {
    let target_time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(payload_timestamp);

    target_time
        .duration_since(reference_system)
        .ok()
        .filter(|duration| duration.as_millis() > 0)
        .map(|d| d.min(block_time))
        .unwrap_or_else(|| {
            // If we're here then the payload timestamp is in the past. This
            // happens when the FCU is really late and it also means we're
            // expecting a getPayload call basically right away, so we don't
            // have any time to build.
            let delay_ms = reference_system
                .duration_since(target_time)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            warn!(
                target: "payload_builder",
                payload_timestamp,
                delay_ms,
                "Late FCU: payload timestamp is in the past"
            );
            Duration::ZERO
        })
}

/// Computes the scheduler send time intervals as durations relative to the
/// start instant.
fn compute_scheduler_intervals(
    flashblock_interval: Duration,
    send_offset_ms: i64,
    end_buffer_ms: u64,
    remaining_time: Duration,
    target_flashblocks: u64,
) -> Vec<Duration> {
    // Align flashblocks to remaining_time
    let first_flashblock_offset =
        calculate_first_flashblock_offset(remaining_time, flashblock_interval);

    let first_flashblock_offset = apply_offset(first_flashblock_offset, send_offset_ms);
    let flashblocks_deadline = apply_offset(
        remaining_time.saturating_sub(Duration::from_millis(end_buffer_ms)),
        send_offset_ms,
    );

    compute_send_time_intervals(
        first_flashblock_offset,
        flashblock_interval,
        flashblocks_deadline,
        target_flashblocks,
    )
}

/// Generates the actual send time intervals given timing parameters.
fn compute_send_time_intervals(
    first_flashblock_offset: Duration,
    interval: Duration,
    deadline: Duration,
    target_flashblocks: u64,
) -> Vec<Duration> {
    let mut send_times = vec![];

    // Add triggers at first_flashblock_offset, then every interval until
    // deadline
    let mut next_time = first_flashblock_offset;
    while next_time < deadline {
        send_times.push(next_time);
        next_time += interval;
    }
    send_times.push(deadline);

    // Clamp the number of triggers. Some of the calculation strategies end up
    // with more triggers concentrated towards the start of the block and so
    // this is needed to preserve backwards compatibility.
    send_times.truncate(target_flashblocks as usize);

    send_times
}

/// Durations cannot be negative values so we need to store the offset value as
/// an int. This is a helper function to apply the signed millisecond offset to
/// a duration.
fn apply_offset(duration: Duration, offset_ms: i64) -> Duration {
    let offset_delta = offset_ms.unsigned_abs();
    if offset_ms >= 0 {
        duration.saturating_add(Duration::from_millis(offset_delta))
    } else {
        duration.saturating_sub(Duration::from_millis(offset_delta))
    }
}

/// Calculates when the first flashblock should be triggered.
fn calculate_first_flashblock_offset(remaining_time: Duration, interval: Duration) -> Duration {
    let remaining_time_ms = remaining_time.as_millis() as u64;
    let interval_ms = interval.as_millis() as u64;

    // The math is equivalent to the modulo operation except we produce a result
    // in the range of [1, interval] instead of [0, interval - 1].
    Duration::from_millis((remaining_time_ms.saturating_sub(1)).rem(interval_ms) + 1)
}

impl std::fmt::Debug for FlashblockScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.send_times.iter().map(|t| {
                let offset = *t - self.reference_instant;
                let wall_time = self.reference_system + offset;
                let duration = wall_time.duration_since(std::time::UNIX_EPOCH).unwrap();
                let total_secs = duration.as_secs();
                let micros = duration.subsec_micros();
                let secs = total_secs % 60;
                let mins = (total_secs / 60) % 60;
                let hours = (total_secs / 3600) % 24;
                format!("{:02}:{:02}:{:02}.{:06}", hours, mins, secs, micros)
            }))
            .finish()
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
        target_flashblocks: u64,
    ) {
        let send_times = compute_send_time_intervals(
            Duration::from_millis(test_case.first_flashblock_offset_ms),
            interval,
            Duration::from_millis(test_case.deadline_ms),
            target_flashblocks,
        );
        let expected_send_times: Vec<Duration> = test_case
            .expected_send_times_ms
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(
            send_times, expected_send_times,
            "Failed for test case: first_flashblock_offset_ms: {}, interval: {:?}, deadline_ms: {}",
            test_case.first_flashblock_offset_ms, interval, test_case.deadline_ms,
        );
    }

    #[test]
    fn test_compute_send_times() {
        let test_cases = vec![ComputeSendTimesTestCase {
            first_flashblock_offset_ms: 150,
            deadline_ms: 880,
            expected_send_times_ms: vec![150, 350, 550, 750, 880],
        }];

        for test_case in test_cases {
            check_compute_send_times(test_case, Duration::from_millis(200), 5);
        }
    }

    #[test]
    fn test_apply_offset() {
        assert_eq!(
            apply_offset(Duration::from_millis(100), 50),
            Duration::from_millis(150)
        );
        assert_eq!(
            apply_offset(Duration::from_millis(100), -30),
            Duration::from_millis(70)
        );
        assert_eq!(
            apply_offset(Duration::from_millis(100), 0),
            Duration::from_millis(100)
        );
        // Should not underflow - saturates at zero
        assert_eq!(
            apply_offset(Duration::from_millis(50), -100),
            Duration::ZERO
        );
    }

    #[test]
    fn test_calculate_first_flashblock_offset() {
        // remaining_time exactly divisible by interval so we get the full
        // interval
        assert_eq!(
            calculate_first_flashblock_offset(
                Duration::from_millis(400),
                Duration::from_millis(200)
            ),
            Duration::from_millis(200)
        );

        // remaining_time with partial interval
        assert_eq!(
            calculate_first_flashblock_offset(
                Duration::from_millis(350),
                Duration::from_millis(200)
            ),
            Duration::from_millis(150)
        );

        // remaining_time less than interval
        assert_eq!(
            calculate_first_flashblock_offset(
                Duration::from_millis(140),
                Duration::from_millis(200)
            ),
            Duration::from_millis(140)
        );

        // remaining_time equals interval
        assert_eq!(
            calculate_first_flashblock_offset(
                Duration::from_millis(200),
                Duration::from_millis(200)
            ),
            Duration::from_millis(200)
        );
    }

    fn durations_ms(ms_values: &[u64]) -> Vec<Duration> {
        ms_values
            .iter()
            .map(|&ms| Duration::from_millis(ms))
            .collect()
    }

    struct SchedulerIntervalsTestCase {
        name: &'static str,
        interval_ms: u64,
        send_offset_ms: i64,
        end_buffer_ms: u64,
        remaining_time_ms: u64,
        target_flashblocks: u64,
        expected_intervals_ms: Vec<u64>,
    }

    fn check_scheduler_intervals(test_case: SchedulerIntervalsTestCase) {
        let intervals = compute_scheduler_intervals(
            Duration::from_millis(test_case.interval_ms),
            test_case.send_offset_ms,
            test_case.end_buffer_ms,
            Duration::from_millis(test_case.remaining_time_ms),
            test_case.target_flashblocks,
        );
        assert_eq!(
            intervals,
            durations_ms(&test_case.expected_intervals_ms),
            "Failed test case '{}': interval={}ms, offset={}ms, buffer={}ms, remaining={}ms",
            test_case.name,
            test_case.interval_ms,
            test_case.send_offset_ms,
            test_case.end_buffer_ms,
            test_case.remaining_time_ms,
        );
    }

    #[test]
    fn test_compute_scheduler_intervals() {
        let test_cases = vec![
            // Basic cases
            SchedulerIntervalsTestCase {
                name: "normal timing",
                interval_ms: 200,
                send_offset_ms: 0,
                end_buffer_ms: 0,
                remaining_time_ms: 880,
                target_flashblocks: 5,
                expected_intervals_ms: vec![80, 280, 480, 680, 880],
            },
            SchedulerIntervalsTestCase {
                name: "with offset and buffer",
                interval_ms: 200,
                send_offset_ms: -20,
                end_buffer_ms: 50,
                remaining_time_ms: 800,
                target_flashblocks: 5,
                expected_intervals_ms: vec![180, 380, 580, 730],
            },
            SchedulerIntervalsTestCase {
                name: "late FCU (300ms remaining)",
                interval_ms: 200,
                send_offset_ms: 0,
                end_buffer_ms: 0,
                remaining_time_ms: 300,
                target_flashblocks: 5,
                expected_intervals_ms: vec![100, 300],
            },
            SchedulerIntervalsTestCase {
                name: "end buffer equals remaining time",
                interval_ms: 200,
                send_offset_ms: 0,
                end_buffer_ms: 200,
                remaining_time_ms: 200,
                target_flashblocks: 5,
                expected_intervals_ms: vec![0],
            },
            SchedulerIntervalsTestCase {
                name: "late FCU with offset and buffer combined",
                interval_ms: 200,
                send_offset_ms: -30,
                end_buffer_ms: 50,
                remaining_time_ms: 400,
                target_flashblocks: 5,
                expected_intervals_ms: vec![170, 320],
            },
            SchedulerIntervalsTestCase {
                name: "no end buffer",
                interval_ms: 200,
                send_offset_ms: 0,
                end_buffer_ms: 0,
                remaining_time_ms: 1000,
                target_flashblocks: 5,
                expected_intervals_ms: vec![200, 400, 600, 800, 1000],
            },
        ];

        for test_case in test_cases {
            check_scheduler_intervals(test_case);
        }
    }

    struct RemainingTimeTestCase {
        name: &'static str,
        block_time_ms: u64,
        reference_ms: u64,
        payload_timestamp: u64,
        expected_remaining_ms: u64,
    }

    fn check_remaining_time(test_case: RemainingTimeTestCase) {
        let block_time = Duration::from_millis(test_case.block_time_ms);
        let reference_system =
            std::time::SystemTime::UNIX_EPOCH + Duration::from_millis(test_case.reference_ms);

        let remaining =
            compute_remaining_time(block_time, test_case.payload_timestamp, reference_system);

        assert_eq!(
            remaining,
            Duration::from_millis(test_case.expected_remaining_ms),
            "Failed test case '{}': block_time={}ms, reference={}ms, timestamp={}",
            test_case.name,
            test_case.block_time_ms,
            test_case.reference_ms,
            test_case.payload_timestamp,
        );
    }

    #[test]
    fn test_compute_remaining_time() {
        let test_cases = vec![
            RemainingTimeTestCase {
                name: "future timestamp within block time",
                block_time_ms: 2000,
                reference_ms: 1_000_000,
                payload_timestamp: 1002,
                expected_remaining_ms: 2000,
            },
            RemainingTimeTestCase {
                name: "remaining exceeds block time (capped)",
                block_time_ms: 1000,
                reference_ms: 1_000_000,
                payload_timestamp: 1005,
                expected_remaining_ms: 1000,
            },
            RemainingTimeTestCase {
                name: "late FCU (844ms past timestamp)",
                block_time_ms: 1000,
                reference_ms: 1_000_844, // 1000.844 seconds
                payload_timestamp: 1000,
                expected_remaining_ms: 0,
            },
            RemainingTimeTestCase {
                name: "late FCU (1ms past timestamp)",
                block_time_ms: 1000,
                reference_ms: 1_000_001, // 1000.001 seconds
                payload_timestamp: 1000,
                expected_remaining_ms: 0,
            },
        ];

        for test_case in test_cases {
            check_remaining_time(test_case);
        }
    }
}
