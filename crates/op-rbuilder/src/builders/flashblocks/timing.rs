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
            compute_remaining_time(config, block_time, payload_timestamp, reference_system);

        // Compute the schedule as relative durations from now
        let intervals =
            compute_scheduler_intervals(config, block_time, remaining_time, target_flashblocks);

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

/// Computes the remaining time until the payload deadline.
/// - **Fixed mode**: Always returns `block_time`, ignoring actual timing.
/// - **Dynamic mode**: Calculates remaining time as `payload_timestamp - now -
///   leeway`. The result is capped at `block_time` and falls back to
///   `block_time` if the timestamp is in the past.
fn compute_remaining_time(
    config: &FlashblocksConfig,
    block_time: Duration,
    payload_timestamp: u64,
    reference_system: std::time::SystemTime,
) -> Duration {
    if config.fixed {
        return block_time;
    }

    // Calculate target time, subtracting leeway when building at interval start
    let target_time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(payload_timestamp)
        - if !config.build_at_interval_end {
            config.leeway_time
        } else {
            Duration::ZERO
        };

    // Calculate remaining time, with fallback to block_time if:
    // - target_time is in the past (duration_since returns Err)
    // - remaining time is 0 or negative
    target_time
        .duration_since(reference_system)
        .ok()
        .filter(|duration| duration.as_millis() > 0)
        .unwrap_or(block_time)
        .min(block_time)
}

/// Computes the scheduler send time intervals as durations relative to the
/// start instant.
fn compute_scheduler_intervals(
    config: &FlashblocksConfig,
    block_time: Duration,
    remaining_time: Duration,
    target_flashblocks: u64,
) -> Vec<Duration> {
    // Fixed mode: calculate timing based on block_time and interval alone
    if config.fixed {
        let (first_flashblock_offset, flashblocks_deadline) = if config.build_at_interval_end {
            // Build at end: first trigger at interval + offset, deadline
            // reduced by end_buffer
            let offset = apply_offset(config.interval, config.send_offset_ms);
            (
                offset,
                block_time.saturating_sub(Duration::from_millis(config.end_buffer_ms)),
            )
        } else {
            // Build at start: first trigger at interval - leeway, deadline is
            // block_time
            (config.interval - config.leeway_time, block_time)
        };

        return compute_send_time_intervals(
            first_flashblock_offset,
            config.interval,
            flashblocks_deadline,
            config.build_at_interval_end,
            target_flashblocks,
        );
    }

    // Dynamic mode: align flashblocks to remaining_time
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
        // Build at start: use calculated offset, deadline is remaining_time to
        // ensure signals fit within the actual time available
        (first_flashblock_offset, remaining_time)
    };

    compute_send_time_intervals(
        first_flashblock_offset,
        config.interval,
        flashblocks_deadline,
        config.build_at_interval_end,
        target_flashblocks,
    )
}

/// Generates the actual send time intervals given timing parameters.
fn compute_send_time_intervals(
    first_flashblock_offset: Duration,
    interval: Duration,
    deadline: Duration,
    build_at_interval_end: bool,
    target_flashblocks: u64,
) -> Vec<Duration> {
    let mut send_times = vec![];

    // When building at interval start, trigger immediately at t=0
    if !build_at_interval_end && Duration::ZERO < deadline {
        send_times.push(Duration::ZERO);
    }

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

/// Calculates when the first flashblock should be triggered in dynamic mode.
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
        build_at_interval_end: bool,
        target_flashblocks: u64,
    ) {
        let send_times = compute_send_time_intervals(
            Duration::from_millis(test_case.first_flashblock_offset_ms),
            interval,
            Duration::from_millis(test_case.deadline_ms),
            build_at_interval_end,
            target_flashblocks,
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
        let test_cases = vec![
            ComputeSendTimesTestCase {
                first_flashblock_offset_ms: 90,
                deadline_ms: 1000,
                expected_send_times_ms: vec![0, 90, 290, 490, 690],
            },
            ComputeSendTimesTestCase {
                first_flashblock_offset_ms: 140,
                deadline_ms: 870,
                expected_send_times_ms: vec![0, 140, 340, 540, 740],
            },
        ];

        for test_case in test_cases {
            check_compute_send_times(test_case, Duration::from_millis(200), false, 5);
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
            check_compute_send_times(test_case, Duration::from_millis(200), true, 5);
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

    fn make_config(
        interval_ms: u64,
        leeway_time_ms: u64,
        fixed: bool,
        build_at_interval_end: bool,
        send_offset_ms: i64,
        end_buffer_ms: u64,
    ) -> FlashblocksConfig {
        FlashblocksConfig {
            interval: Duration::from_millis(interval_ms),
            leeway_time: Duration::from_millis(leeway_time_ms),
            fixed,
            build_at_interval_end,
            send_offset_ms,
            end_buffer_ms,
            ..Default::default()
        }
    }

    fn durations_ms(ms_values: &[u64]) -> Vec<Duration> {
        ms_values
            .iter()
            .map(|&ms| Duration::from_millis(ms))
            .collect()
    }

    #[test]
    fn test_compute_scheduler_intervals_fixed_build_at_start() {
        // Fixed mode, build at start first_offset = interval - leeway = 200 -
        // 60 = 140 deadline = block_time = 1000
        let config = make_config(200, 60, true, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let remaining_time = block_time; // ignored in fixed mode

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 0 (immediate), 140, 340, 540, 740
        assert_eq!(intervals, durations_ms(&[0, 140, 340, 540, 740]));
    }

    #[test]
    fn test_compute_scheduler_intervals_fixed_build_at_end() {
        // Fixed mode, build at start first_offset = apply_offset(interval,
        // send_offset) = 200 + 0 = 200 deadline = block_time - end_buffer =
        // 1000 - 100 = 900
        let config = make_config(200, 0, true, true, 0, 100);
        let block_time = Duration::from_millis(1000);
        let remaining_time = block_time;

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 200, 400, 600, 800, 900 (deadline)
        assert_eq!(intervals, durations_ms(&[200, 400, 600, 800, 900]));
    }

    #[test]
    fn test_compute_scheduler_intervals_fixed_build_at_end_with_offset() {
        // Fixed mode with positive send_offset first_offset = apply_offset(200,
        // 50) = 250 deadline = 1000 - 100 = 900
        let config = make_config(200, 0, true, true, 50, 100);
        let block_time = Duration::from_millis(1000);
        let remaining_time = block_time;

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 250, 450, 650, 850, 900 (deadline)
        assert_eq!(intervals, durations_ms(&[250, 450, 650, 850, 900]));
    }

    #[test]
    fn test_compute_scheduler_intervals_dynamic_build_at_start() {
        // Dynamic mode, build at start remaining_time = 870ms first_offset =
        // calculate_first_flashblock_offset(870, 200) = (870-1) % 200 + 1 = 70
        // deadline = remaining_time = 870 (so signals fit within available time)
        let config = make_config(200, 0, false, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let remaining_time = Duration::from_millis(870);

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 0 (immediate), 70, 270, 470, 670 (all < 870)
        // (deadline=remaining_time ensures signals complete before slot ends)
        assert_eq!(intervals, durations_ms(&[0, 70, 270, 470, 670]));
    }

    #[test]
    fn test_compute_scheduler_intervals_dynamic_build_at_start_late_fcu() {
        // Dynamic mode with late FCU arrival - remaining_time is much less than
        // block_time. This simulates FCU arriving 700ms into a 1000ms slot.
        // The deadline must be remaining_time (not block_time) so signals fit
        // within the actual time available before block_cancel fires.
        let config = make_config(200, 0, false, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let remaining_time = Duration::from_millis(300); // Only 300ms left

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // first_offset = (300-1) % 200 + 1 = 100
        // deadline = remaining_time = 300 (NOT block_time!)
        // Signals: [0, 100] (200 and 300 would be >= deadline)
        // All signals must complete before remaining_time, otherwise they'd be
        // cancelled when block_cancel fires at the slot boundary.
        assert_eq!(intervals, durations_ms(&[0, 100]));
    }

    #[test]
    fn test_compute_scheduler_intervals_dynamic_build_at_end() {
        // Dynamic mode, build at end remaining_time = 880ms first_offset =
        // calculate_first_flashblock_offset(880, 200) = (880-1) % 200 + 1 = 80
        // adjusted_offset = apply_offset(80, 0) = 80 adjusted_deadline =
        // apply_offset(880 - 0, 0) = 880
        let config = make_config(200, 0, false, true, 0, 0);
        let block_time = Duration::from_millis(1000);
        let remaining_time = Duration::from_millis(880);

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 80, 280, 480, 680, 880 (deadline)
        assert_eq!(intervals, durations_ms(&[80, 280, 480, 680, 880]));
    }

    #[test]
    fn test_compute_scheduler_intervals_dynamic_build_at_end_with_offset_and_buffer() {
        // Dynamic mode with send_offset and end_buffer remaining_time = 800ms
        // first_offset = calculate_first_flashblock_offset(800, 200) = (800-1)
        // % 200 + 1 = 200 adjusted_offset = apply_offset(200, -20) = 180
        // adjusted_deadline = apply_offset(800 - 50, -20) = apply_offset(750,
        // -20) = 730
        let config = make_config(200, 0, false, true, -20, 50);
        let block_time = Duration::from_millis(1000);
        let remaining_time = Duration::from_millis(800);

        let intervals = compute_scheduler_intervals(&config, block_time, remaining_time, 5);

        // Expect: 180, 380, 580, 730 (deadline)
        assert_eq!(intervals, durations_ms(&[180, 380, 580, 730]));
    }

    #[test]
    fn test_compute_remaining_time_fixed_mode() {
        // In fixed mode, always returns block_time regardless of other params
        let config = make_config(200, 50, true, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let reference_system = std::time::SystemTime::now();

        let remaining = compute_remaining_time(&config, block_time, 0, reference_system);

        assert_eq!(remaining, block_time);
    }

    #[test]
    fn test_compute_remaining_time_dynamic_future_timestamp() {
        // Dynamic mode with a future timestamp
        let config = make_config(200, 100, false, false, 0, 0);
        let block_time = Duration::from_millis(2000);
        let reference_system = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        // Target = 1000 + 2 - 0.1 (leeway) = 1001.9 Remaining = 1001.9 - 1000 =
        // 1.9s = 1900ms, but capped at block_time
        let payload_timestamp = 1002;

        let remaining =
            compute_remaining_time(&config, block_time, payload_timestamp, reference_system);

        // target_time = EPOCH + 1002s - 100ms = EPOCH + 1001.9s remaining =
        // 1001.9s - 1000s = 1.9s = 1900ms
        assert_eq!(remaining, Duration::from_millis(1900));
    }

    #[test]
    fn test_compute_remaining_time_dynamic_capped_at_block_time() {
        // Dynamic mode where calculated remaining exceeds block_time
        let config = make_config(200, 0, false, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let reference_system = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        // Target = EPOCH + 1005s, Reference = EPOCH + 1000s Remaining would be
        // 5s, but capped at block_time (1s)
        let payload_timestamp = 1005;

        let remaining =
            compute_remaining_time(&config, block_time, payload_timestamp, reference_system);

        assert_eq!(remaining, block_time);
    }

    #[test]
    fn test_compute_remaining_time_dynamic_past_timestamp() {
        // Dynamic mode with a past timestamp (returns block_time as fallback)
        let config = make_config(200, 0, false, false, 0, 0);
        let block_time = Duration::from_millis(1000);
        let reference_system = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        // Target is in the past
        let payload_timestamp = 999;

        let remaining =
            compute_remaining_time(&config, block_time, payload_timestamp, reference_system);

        assert_eq!(remaining, block_time);
    }

    #[test]
    fn test_compute_remaining_time_dynamic_build_at_interval_end_no_leeway() {
        // When build_at_interval_end is true, leeway is not subtracted from
        // target
        let config = make_config(200, 100, false, true, 0, 0);
        let block_time = Duration::from_millis(2000);
        let reference_system = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let payload_timestamp = 1002;

        let remaining =
            compute_remaining_time(&config, block_time, payload_timestamp, reference_system);

        // target_time = EPOCH + 1002s - 0 (no leeway when
        // build_at_interval_end) remaining = 1002s - 1000s = 2s = 2000ms,
        // capped at block_time
        assert_eq!(remaining, Duration::from_millis(2000));
    }
}
