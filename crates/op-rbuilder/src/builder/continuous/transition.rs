#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopMetricsSource {
    IntervalBase,
    PublishedCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrePublishDecision {
    Publish,
    SuppressBeforePublish {
        count_suppressed: bool,
        metrics_source: StopMetricsSource,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostPublishDecision {
    Continue,
    Stop { metrics_source: StopMetricsSource },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TriggerOutcome {
    /// Publish the candidate and continue to the next flashblock interval.
    PublishAndAdvance,
    /// Publish the candidate and stop (cancelled after publish or last flashblock).
    PublishAndStop,
    /// Suppress before publish; the loop records interval-base stop metrics.
    SuppressAndStop {
        count_suppressed: bool,
        metrics_source: StopMetricsSource,
    },
}

pub(super) fn decide_pre_publish(
    payload_cancelled: bool,
    payload_resolved: bool,
) -> PrePublishDecision {
    if payload_cancelled {
        return PrePublishDecision::SuppressBeforePublish {
            count_suppressed: payload_resolved,
            metrics_source: StopMetricsSource::IntervalBase,
        };
    }

    PrePublishDecision::Publish
}

pub(super) fn decide_after_publish(
    payload_cancelled: bool,
    is_last_flashblock: bool,
) -> PostPublishDecision {
    if payload_cancelled || is_last_flashblock {
        return PostPublishDecision::Stop {
            metrics_source: StopMetricsSource::PublishedCandidate,
        };
    }

    PostPublishDecision::Continue
}

/// Compose pre- and post-publish decisions into a single trigger outcome.
pub(super) fn plan_with_candidate(
    payload_cancelled: bool,
    payload_resolved: bool,
    is_last_flashblock: bool,
) -> TriggerOutcome {
    match decide_pre_publish(payload_cancelled, payload_resolved) {
        PrePublishDecision::Publish => {
            match decide_after_publish(payload_cancelled, is_last_flashblock) {
                PostPublishDecision::Continue => TriggerOutcome::PublishAndAdvance,
                PostPublishDecision::Stop { metrics_source: _ } => TriggerOutcome::PublishAndStop,
            }
        }
        PrePublishDecision::SuppressBeforePublish {
            count_suppressed,
            metrics_source,
        } => TriggerOutcome::SuppressAndStop {
            count_suppressed,
            metrics_source,
        },
    }
}

pub(super) fn fallback_no_candidate_metrics_source() -> StopMetricsSource {
    StopMetricsSource::IntervalBase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncancelled_before_publish_decides_publish() {
        assert_eq!(
            decide_pre_publish(false, false),
            PrePublishDecision::Publish
        );
    }

    #[test]
    fn resolved_before_publish_suppresses_and_counts_suppressed_metric() {
        assert_eq!(
            decide_pre_publish(true, true),
            PrePublishDecision::SuppressBeforePublish {
                count_suppressed: true,
                metrics_source: StopMetricsSource::IntervalBase,
            }
        );
    }

    #[test]
    fn cancelled_unresolved_before_publish_suppresses_without_counting() {
        assert_eq!(
            decide_pre_publish(true, false),
            PrePublishDecision::SuppressBeforePublish {
                count_suppressed: false,
                metrics_source: StopMetricsSource::IntervalBase,
            }
        );
    }

    #[test]
    fn published_candidate_not_cancelled_and_not_last_continues() {
        assert_eq!(
            decide_after_publish(false, false),
            PostPublishDecision::Continue
        );
    }

    #[test]
    fn published_candidate_cancelled_after_publish_stops() {
        assert_eq!(
            decide_after_publish(true, false),
            PostPublishDecision::Stop {
                metrics_source: StopMetricsSource::PublishedCandidate,
            }
        );
    }

    #[test]
    fn published_last_flashblock_stops() {
        assert_eq!(
            decide_after_publish(false, true),
            PostPublishDecision::Stop {
                metrics_source: StopMetricsSource::PublishedCandidate,
            }
        );
    }

    #[test]
    fn plan_publish_and_advance_when_uncancelled_and_not_last() {
        assert_eq!(
            plan_with_candidate(false, false, false),
            TriggerOutcome::PublishAndAdvance
        );
    }

    #[test]
    fn plan_publish_and_stop_on_last_flashblock() {
        assert_eq!(
            plan_with_candidate(false, false, true),
            TriggerOutcome::PublishAndStop
        );
    }

    #[test]
    fn plan_suppress_counts_when_cancelled_and_resolved() {
        assert_eq!(
            plan_with_candidate(true, true, false),
            TriggerOutcome::SuppressAndStop {
                count_suppressed: true,
                metrics_source: StopMetricsSource::IntervalBase,
            }
        );
    }

    #[test]
    fn plan_suppress_does_not_count_when_cancelled_unresolved() {
        assert_eq!(
            plan_with_candidate(true, false, false),
            TriggerOutcome::SuppressAndStop {
                count_suppressed: false,
                metrics_source: StopMetricsSource::IntervalBase,
            }
        );
    }

    #[test]
    fn plan_suppress_takes_precedence_over_last_flashblock() {
        // Cancellation routes through Suppress regardless of last-flashblock state.
        assert_eq!(
            plan_with_candidate(true, true, true),
            TriggerOutcome::SuppressAndStop {
                count_suppressed: true,
                metrics_source: StopMetricsSource::IntervalBase,
            }
        );
    }
}
