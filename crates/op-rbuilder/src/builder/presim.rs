//! Top-of-block pre-simulation of pool transactions.
//!
//! Simulates each pending pool transaction against a fresh state at the
//! top of the block and returns any hashes that reverted so the
//! flashblock building loop skips them. A randomized coinbase prevents
//! adversaries from detecting simulation via the `COINBASE` opcode.
//!
//! Only clear reverts are returned — EVM-level errors (wrong nonce,
//! insufficient balance, etc.) are kept, since they may become valid
//! after other transactions execute.
//!
//! ## Known limitations
//!
//! - **Reverting txs forfeit gas revenue.** Excluded txs are never
//!   included in the block, so the builder does not collect their gas
//!   fees. This is an explicit tradeoff: faster flashblock production
//!   at the cost of lost revert-gas revenue. The flag defaults to off
//!   so operators opt in knowingly.
//!
//! - **Top-of-block only.** Presim runs once before the flashblock
//!   loop. Txs arriving mid-block are not pre-simulated, but the
//!   existing `exclude_reverts_between_flashblocks` mechanism catches
//!   those during building (defense in depth).
//!
//! - **Parent state, not post-sequencer state.** Presim runs against
//!   the parent block's state, not the post-deposit state. A pool tx
//!   that depends on state written by a deposit in the current block
//!   will be falsely excluded. In practice this is rare.
//!
//! - **Independent simulation.** Each tx is simulated against the same
//!   top-of-block state without committing prior results. Multi-tx
//!   flows from one sender (approve → transferFrom) may be falsely
//!   excluded if the second tx depends on the first's state changes.
//!
//! - **Coinbase balance detection.** An adversary can check
//!   `block.coinbase.balance` to distinguish presim (random address,
//!   zero balance) from real execution. Mitigation: seed the random
//!   address with the real builder's balance. Left for a follow-up.

use alloy_primitives::{Address, B256};
use reth_evm::{ConfigureEvm, Evm, EvmEnvFor};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_util::{BestPayloadTransactions, PayloadTransactions};
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction, TransactionPool};
use std::time::{Duration, Instant};
use tracing::{debug, info};

use crate::{metrics::OpRBuilderMetrics, tx::FBPooledTransaction};

/// Maximum number of transactions to pre-simulate per block.
const MAX_PRESIM_TXS: u64 = 4096;

/// Maximum wall-clock time for the presim pass. Prevents adversarial
/// txs that maximize EVM compute from turning presim into a
/// self-inflicted DoS on the first flashblock.
const PRESIM_DEADLINE: Duration = Duration::from_millis(500);

/// Outcome of a top-of-block pre-simulation pass.
#[derive(Debug, Default)]
pub(super) struct PresimResult {
    /// Transaction hashes that reverted and should be skipped.
    pub excluded: Vec<B256>,
}

/// Pre-simulate pending pool transactions against the top of the block
/// with an optionally randomized coinbase.
///
/// Each transaction is simulated independently against a fresh copy of
/// the parent state — no side effects are committed. This means a tx
/// with a future nonce will surface as an EVM error and be kept; only
/// txs that execute and revert are returned in the exclusion list.
///
/// Bounded by both [`MAX_PRESIM_TXS`] and [`PRESIM_DEADLINE`] to
/// limit time on the critical path before the first flashblock.
///
/// This function is synchronous and EVM-bound; callers should run it
/// inside a blocking task.
pub(super) fn presimulate_pool_txs<Pool, Sp>(
    pool: &Pool,
    state_provider: Sp,
    evm_config: &OpEvmConfig,
    evm_env: &EvmEnvFor<OpEvmConfig>,
    best_tx_attrs: BestTransactionsAttributes,
    random_coinbase: bool,
    metrics: &OpRBuilderMetrics,
) -> PresimResult
where
    Pool: TransactionPool<Transaction = FBPooledTransaction>,
    Sp: StateProvider,
{
    let started = Instant::now();
    let deadline = started + PRESIM_DEADLINE;
    let mut result = PresimResult::default();
    let mut simulated: u64 = 0;
    let mut gas_saved: u64 = 0;

    let mut env = evm_env.clone();
    if random_coinbase {
        env.block_env.beneficiary = Address::random();
    }

    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(&state_provider))
        .with_bundle_update()
        .build();

    let best = pool.best_transactions_with_attributes(best_tx_attrs);
    let mut best_txs = BestPayloadTransactions::new(best);

    while let Some(tx) = best_txs.next(()) {
        if simulated >= MAX_PRESIM_TXS {
            debug!(target: "payload_builder", limit = MAX_PRESIM_TXS, "presim: tx limit reached");
            break;
        }
        if Instant::now() >= deadline {
            debug!(target: "payload_builder", budget_ms = PRESIM_DEADLINE.as_millis(), "presim: time budget exceeded");
            break;
        }

        let tx_hash = *tx.hash();
        let recovered = tx.into_consensus();
        simulated += 1;

        let sim = evm_config
            .evm_with_env(&mut state, env.clone())
            .transact(&recovered);

        match sim {
            Ok(exec) if !exec.result.is_success() => {
                let gas = exec.result.gas_used();
                debug!(
                    target: "payload_builder",
                    %tx_hash,
                    gas_used = gas,
                    "presim: excluding reverting transaction"
                );
                result.excluded.push(tx_hash);
                gas_saved = gas_saved.saturating_add(gas);
            }
            Ok(exec) => {
                debug!(
                    target: "payload_builder",
                    %tx_hash,
                    gas_used = exec.result.gas_used(),
                    "presim: transaction succeeded, keeping"
                );
            }
            Err(ref err) => {
                debug!(
                    target: "payload_builder",
                    %tx_hash,
                    error = %err,
                    "presim: EVM error, keeping transaction"
                );
            }
        }
    }

    let elapsed = started.elapsed();
    metrics.presim_pass_duration.record(elapsed);
    metrics.presim_txs_simulated.record(simulated as f64);
    metrics
        .presim_txs_excluded
        .record(result.excluded.len() as f64);
    metrics.presim_gas_saved.increment(gas_saved);

    info!(
        target: "payload_builder",
        simulated,
        excluded = result.excluded.len(),
        gas_saved,
        elapsed_ms = elapsed.as_millis(),
        random_coinbase,
        "presim: top-of-block simulation complete"
    );

    result
}
