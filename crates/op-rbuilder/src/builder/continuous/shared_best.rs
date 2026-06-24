use super::types::BestCandidate;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::warn;

trait CandidateCounters {
    fn set_candidate_counters(&mut self, candidates_evaluated: u64, candidates_improved: u64);
}

impl CandidateCounters for BestCandidate {
    fn set_candidate_counters(&mut self, candidates_evaluated: u64, candidates_improved: u64) {
        self.candidates_evaluated = candidates_evaluated;
        self.candidates_improved = candidates_improved;
    }
}

/// Generic single-slot mailbox: one writer publishes the latest value, one
/// reader takes it on demand.
struct CandidateSlot<T>(Arc<Mutex<Option<T>>>);

impl<T> Clone for CandidateSlot<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> CandidateSlot<T> {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    fn guard(&self) -> MutexGuard<'_, Option<T>> {
        self.0.lock().unwrap_or_else(|poisoned| {
            warn!(
                target: "payload_builder",
                "Continuous candidate slot was poisoned; recovering the last candidate"
            );
            poisoned.into_inner()
        })
    }

    fn take(&self) -> Option<T> {
        self.guard().take()
    }

    fn store(&self, value: T) {
        let _ = self.guard().replace(value);
    }
}

impl<T: CandidateCounters> CandidateSlot<T> {
    fn refresh_metrics(&self, candidates_evaluated: u64, candidates_improved: u64) {
        if let Some(c) = self.guard().as_mut() {
            c.set_candidate_counters(candidates_evaluated, candidates_improved);
        }
    }
}

/// Slot that holds the current highest-fee sealed [`BestCandidate`] from the
/// build task. The build task writes on each improvement; the main loop takes
/// on trigger to publish without awaiting task completion.
#[derive(Clone)]
pub(super) struct SharedBest {
    slot: CandidateSlot<BestCandidate>,
    #[cfg(test)]
    force_take_miss: Arc<AtomicU64>,
}

impl SharedBest {
    pub(super) fn new(#[cfg(test)] force_take_miss: Arc<AtomicU64>) -> Self {
        Self {
            slot: CandidateSlot::new(),
            #[cfg(test)]
            force_take_miss,
        }
    }

    /// Take the current candidate (if any).
    pub(super) fn take(&self) -> Option<BestCandidate> {
        #[cfg(test)]
        if self
            .force_take_miss
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .is_ok()
        {
            return None;
        }
        self.slot.take()
    }

    pub(super) fn store(&self, candidate: BestCandidate) {
        self.slot.store(candidate);
    }

    pub(super) fn refresh_metrics(&self, candidates_evaluated: u64, candidates_improved: u64) {
        self.slot
            .refresh_metrics(candidates_evaluated, candidates_improved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestCandidate {
        id: u64,
        candidates_evaluated: u64,
        candidates_improved: u64,
    }

    impl TestCandidate {
        fn new(id: u64) -> Self {
            Self {
                id,
                candidates_evaluated: 0,
                candidates_improved: 0,
            }
        }
    }

    impl CandidateCounters for TestCandidate {
        fn set_candidate_counters(&mut self, candidates_evaluated: u64, candidates_improved: u64) {
            self.candidates_evaluated = candidates_evaluated;
            self.candidates_improved = candidates_improved;
        }
    }

    #[test]
    fn take_empty_slot_returns_none() {
        let slot = CandidateSlot::<TestCandidate>::new();

        assert_eq!(slot.take(), None);
    }

    #[test]
    fn store_then_take_returns_candidate_and_clears_slot() {
        let slot = CandidateSlot::new();

        slot.store(TestCandidate::new(7));

        assert_eq!(slot.take(), Some(TestCandidate::new(7)));
        assert_eq!(slot.take(), None);
    }

    #[test]
    fn refresh_counters_does_not_replace_candidate() {
        let slot = CandidateSlot::new();

        slot.store(TestCandidate::new(11));
        slot.refresh_metrics(5, 3);

        assert_eq!(
            slot.take(),
            Some(TestCandidate {
                id: 11,
                candidates_evaluated: 5,
                candidates_improved: 3,
            })
        );
    }

    #[test]
    fn refresh_empty_slot_is_noop() {
        let slot = CandidateSlot::<TestCandidate>::new();

        slot.refresh_metrics(5, 3);

        assert_eq!(slot.take(), None);
    }

    #[test]
    fn poisoned_slot_recovers_inner_candidate() {
        let slot = CandidateSlot::new();
        let poisoned_slot = slot.clone();

        let _ = std::thread::spawn(move || {
            let mut guard = poisoned_slot.0.lock().expect("lock is not poisoned yet");
            *guard = Some(TestCandidate::new(13));
            panic!("poison candidate slot");
        })
        .join();

        assert_eq!(slot.take(), Some(TestCandidate::new(13)));
    }
}
