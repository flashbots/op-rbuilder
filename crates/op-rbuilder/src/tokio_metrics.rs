//! Tokio runtime metrics instrumentation using tokio-metrics crate.
//!
//! This module provides task-level metrics for monitoring spawned tokio tasks
//! in the flashblocks builder, including poll times, idle times, and scheduling delays.
//! It also provides global runtime metrics for monitoring the tokio runtime itself.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use std::{fmt, future::Future, sync::Arc, time::Duration};
use tokio_metrics::{RuntimeMetrics, RuntimeMonitor, TaskMetrics, TaskMonitor};

/// Metrics for a single monitored tokio task.
#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.tokio_task")]
pub struct TokioTaskMetricsRecorder {
    /// Total number of times the task has been instrumented (spawned)
    pub instrumented_count: Counter,
    /// Total number of times the task was dropped
    pub dropped_count: Counter,
    /// Number of tasks currently being polled
    pub first_poll_count: Counter,
    /// Total poll count across all intervals
    pub total_poll_count: Counter,
    /// Total time spent polling (seconds)
    pub total_poll_duration_seconds: Histogram,
    /// Mean poll duration per interval (microseconds)
    pub mean_poll_duration_us: Histogram,
    /// Total time spent idle (seconds)
    pub total_idle_duration_seconds: Histogram,
    /// Mean idle duration per interval (microseconds)
    pub mean_idle_duration_us: Histogram,
    /// Total time spent waiting to be scheduled (seconds)
    pub total_scheduled_duration_seconds: Histogram,
    /// Mean scheduled wait duration per interval (microseconds)
    pub mean_scheduled_duration_us: Histogram,
    /// Number of times task exceeded slow poll threshold
    pub slow_poll_count: Counter,
    /// Total duration of slow polls (seconds)
    pub slow_poll_duration_seconds: Histogram,
    /// Number of times task was scheduled for short duration
    pub short_delay_count: Counter,
    /// Number of times task was scheduled for long duration
    pub long_delay_count: Counter,
    /// Total duration of long scheduling delays (seconds)
    pub long_delay_duration_seconds: Histogram,
}

/// Metrics for the global tokio runtime.
///
/// Note: Only stable tokio metrics are exposed here. Additional metrics like
/// steal counts, schedule counts, and overflow counts require the `tokio_unstable` flag.
#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.tokio_runtime")]
pub struct TokioRuntimeMetricsRecorder {
    /// Number of worker threads in the runtime
    pub workers_count: Gauge,
    /// Current number of alive tasks in the runtime
    pub live_tasks_count: Gauge,
    /// Total number of times worker threads parked
    pub total_park_count: Counter,
    /// Max park count across all workers in the interval
    pub max_park_count: Histogram,
    /// Min park count across all workers in the interval
    pub min_park_count: Histogram,
    /// Total time workers spent busy executing tasks (seconds)
    pub total_busy_duration_seconds: Histogram,
    /// Max busy duration across all workers (seconds)
    pub max_busy_duration_seconds: Histogram,
    /// Min busy duration across all workers (seconds)
    pub min_busy_duration_seconds: Histogram,
    /// Depth of the global queue
    pub global_queue_depth: Gauge,
    /// Elapsed time since the runtime started (for rate calculations)
    pub elapsed_seconds: Histogram,
}

impl TokioRuntimeMetricsRecorder {
    /// Record metrics from a RuntimeMetrics snapshot.
    pub fn record(&self, metrics: &RuntimeMetrics) {
        self.workers_count.set(metrics.workers_count as f64);
        self.live_tasks_count.set(metrics.live_tasks_count as f64);
        self.total_park_count.increment(metrics.total_park_count);
        self.max_park_count.record(metrics.max_park_count as f64);
        self.min_park_count.record(metrics.min_park_count as f64);
        self.total_busy_duration_seconds
            .record(metrics.total_busy_duration.as_secs_f64());
        self.max_busy_duration_seconds
            .record(metrics.max_busy_duration.as_secs_f64());
        self.min_busy_duration_seconds
            .record(metrics.min_busy_duration.as_secs_f64());
        self.global_queue_depth
            .set(metrics.global_queue_depth as f64);
        self.elapsed_seconds.record(metrics.elapsed.as_secs_f64());
    }
}

/// A wrapper around tokio_metrics::TaskMonitor that records metrics.
#[derive(Clone)]
pub struct MonitoredTask {
    monitor: TaskMonitor,
    recorder: TokioTaskMetricsRecorder,
    task_name: &'static str,
}

impl MonitoredTask {
    /// Create a new monitored task with the given name.
    pub fn new(task_name: &'static str) -> Self {
        Self {
            monitor: TaskMonitor::new(),
            recorder: TokioTaskMetricsRecorder::new_with_labels(&[("task", task_name)]),
            task_name,
        }
    }

    /// Instrument a future to be monitored by this task monitor.
    pub fn instrument<F: Future>(&self, future: F) -> tokio_metrics::Instrumented<F> {
        self.monitor.instrument(future)
    }

    pub fn monitor(&self) -> &TaskMonitor {
        &self.monitor
    }

    pub fn task_name(&self) -> &'static str {
        self.task_name
    }

    /// Record metrics from a TaskMetrics snapshot.
    pub fn record_metrics(&self, metrics: &TaskMetrics) {
        self.recorder
            .instrumented_count
            .increment(metrics.instrumented_count);
        self.recorder.dropped_count.increment(metrics.dropped_count);
        self.recorder
            .first_poll_count
            .increment(metrics.first_poll_count);
        self.recorder
            .total_poll_count
            .increment(metrics.total_poll_count);

        self.recorder
            .total_poll_duration_seconds
            .record(metrics.total_poll_duration.as_secs_f64());

        if metrics.total_poll_count > 0 {
            let mean_poll_us = metrics.mean_poll_duration().as_micros() as f64;
            self.recorder.mean_poll_duration_us.record(mean_poll_us);
        }

        self.recorder
            .total_idle_duration_seconds
            .record(metrics.total_idle_duration.as_secs_f64());

        if metrics.total_idled_count > 0 {
            let mean_idle_us = metrics.mean_idle_duration().as_micros() as f64;
            self.recorder.mean_idle_duration_us.record(mean_idle_us);
        }

        self.recorder
            .total_scheduled_duration_seconds
            .record(metrics.total_scheduled_duration.as_secs_f64());

        if metrics.total_scheduled_count > 0 {
            let mean_scheduled_us = metrics.mean_scheduled_duration().as_micros() as f64;
            self.recorder
                .mean_scheduled_duration_us
                .record(mean_scheduled_us);
        }

        self.recorder
            .slow_poll_count
            .increment(metrics.total_slow_poll_count);
        self.recorder
            .slow_poll_duration_seconds
            .record(metrics.total_slow_poll_duration.as_secs_f64());

        self.recorder
            .short_delay_count
            .increment(metrics.total_short_delay_count);
        self.recorder
            .long_delay_count
            .increment(metrics.total_long_delay_count);
        self.recorder
            .long_delay_duration_seconds
            .record(metrics.total_long_delay_duration.as_secs_f64());
    }
}

/// Collection of task monitors
#[derive(Clone)]
pub struct FlashblocksTaskMetrics {
    /// Monitor for the flashblock timer task
    pub flashblock_timer: MonitoredTask,
    /// Monitor for the payload builder service
    pub payload_builder_service: MonitoredTask,
    /// Monitor for the payload handler
    pub payload_handler: MonitoredTask,
    /// Monitor for the websocket listener task
    pub websocket_publisher: MonitoredTask,
    /// Global runtime metrics recorder
    runtime_recorder: TokioRuntimeMetricsRecorder,
}

impl Default for FlashblocksTaskMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashblocksTaskMetrics {
    pub fn new() -> Self {
        Self {
            flashblock_timer: MonitoredTask::new("flashblock_timer"),
            payload_builder_service: MonitoredTask::new("payload_builder_service"),
            payload_handler: MonitoredTask::new("payload_handler"),
            websocket_publisher: MonitoredTask::new("websocket_publisher"),
            runtime_recorder: TokioRuntimeMetricsRecorder::default(),
        }
    }

    /// Spawn a background task that periodically records metrics from all monitors.
    ///
    /// This should be called once at startup to begin metric collection.
    pub fn spawn_metrics_collector(self: Arc<Self>, interval: Duration) {
        let metrics = self;
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);

            // Get runtime monitor for the current tokio runtime
            let runtime_monitor = RuntimeMonitor::new(&tokio::runtime::Handle::current());
            let mut runtime_intervals = runtime_monitor.intervals();

            // Get interval iterators for each task monitor
            let mut flashblock_timer_intervals = metrics.flashblock_timer.monitor.intervals();
            let mut payload_builder_intervals = metrics.payload_builder_service.monitor.intervals();
            let mut payload_handler_intervals = metrics.payload_handler.monitor.intervals();
            let mut websocket_publisher_intervals = metrics.websocket_publisher.monitor.intervals();

            loop {
                timer.tick().await;

                // Record global runtime metrics
                if let Some(runtime_metrics) = runtime_intervals.next() {
                    metrics.runtime_recorder.record(&runtime_metrics);
                }

                // Record metrics for each task
                if let Some(task_metrics) = flashblock_timer_intervals.next() {
                    metrics.flashblock_timer.record_metrics(&task_metrics);
                }
                if let Some(task_metrics) = payload_builder_intervals.next() {
                    metrics
                        .payload_builder_service
                        .record_metrics(&task_metrics);
                }
                if let Some(task_metrics) = payload_handler_intervals.next() {
                    metrics.payload_handler.record_metrics(&task_metrics);
                }
                if let Some(task_metrics) = websocket_publisher_intervals.next() {
                    metrics.websocket_publisher.record_metrics(&task_metrics);
                }
            }
        });
    }
}

impl fmt::Debug for FlashblocksTaskMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlashblocksTaskMetrics")
            .field("flashblock_timer", &self.flashblock_timer.task_name())
            .field(
                "payload_builder_service",
                &self.payload_builder_service.task_name(),
            )
            .field("payload_handler", &self.payload_handler.task_name())
            .field("websocket_publisher", &self.websocket_publisher.task_name())
            .field("runtime_monitor", &"enabled")
            .finish()
    }
}
