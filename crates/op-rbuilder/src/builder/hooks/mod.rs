//! Lifecycle hooks dispatched from the building loop.
//!
//! [`PostSealHook`] fires after each sealed candidate (fallback or
//! flashblock) and isolates downstream side-effects — WS publication, p2p
//! broadcast, engine propagation, metrics — from the building loop itself.
//! Concrete implementations live alongside this module.

mod channel;
mod metrics;
mod post_seal;
mod ws;

pub(super) use channel::ChannelHook;
pub(super) use metrics::MetricsHook;
pub(super) use post_seal::{PostSealHook, SealedCandidate, SealedCtx};
pub(super) use ws::WsHook;

/// Dispatch a sealed candidate to every hook in `hooks`.
///
/// Hook impls are expected to be cheap; we run them sequentially in the
/// caller's context (sync, including from within `spawn_blocking`).
pub(super) fn dispatch_post_seal(
    hooks: &[Box<dyn PostSealHook>],
    candidate: &SealedCandidate,
    ctx: &SealedCtx,
) {
    for h in hooks {
        h.on_sealed(candidate, ctx);
    }
}
