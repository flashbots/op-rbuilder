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

use alloy_primitives::{Address, B256};
use reth_evm::{ConfigureEvm, Evm};
use reth_payload_util::{BestPayloadTransactions, PayloadTransactions};
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction, TransactionPool};
use std::time::Instant;
use tracing::debug;

use crate::{evm::OpBlockEvmFactory, metrics::OpRBuilderMetrics, tx::FBPooledTransaction};

/// Outcome of a top-of-block pre-simulation pass.
#[derive(Debug, Default)]
pub(super) struct PresimResult {
    /// Transaction hashes that reverted and should be skipped by the
    /// flashblock building loop.
    pub excluded: Vec<B256>,
}

/// Pre-simulate all pending pool transactions against the top of the
/// block with an optionally randomized coinbase.
///
/// Each transaction is simulated independently against a fresh copy of
/// the parent state — no side effects are committed. This means a tx
/// with a future nonce will surface as an EVM error and be kept; only
/// txs that execute and revert are returned in the exclusion list.
///
/// This function is synchronous and EVM-bound; callers should run it
/// inside a blocking task.
pub(super) fn presimulate_pool_txs<Pool, Sp>(
    pool: &Pool,
    state_provider: Sp,
    evm_factory: &OpBlockEvmFactory,
    best_tx_attrs: BestTransactionsAttributes,
    random_coinbase: bool,
    metrics: &OpRBuilderMetrics,
) -> PresimResult
where
    Pool: TransactionPool<Transaction = FBPooledTransaction>,
    Sp: StateProvider,
{
    let started = Instant::now();
    let mut result = PresimResult::default();
    let mut simulated: u64 = 0;
    let mut gas_saved: u64 = 0;

    // Build an EVM env with an optionally-randomized coinbase. Adversaries
    // cannot detect the simulation by checking `COINBASE` when this is set,
    // since each block uses a fresh random address instead of the known
    // builder address.
    let mut env = evm_factory.evm_env().clone();
    if random_coinbase {
        env.block_env.beneficiary = Address::random();
    }

    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(&state_provider))
        .with_bundle_update()
        .build();

    let evm_config = evm_factory.evm_config();

    // Iterate pending txs with the same attributes the flashblock loop
    // will use, so we're simulating the same candidate set.
    let best = pool.best_transactions_with_attributes(best_tx_attrs);
    let mut best_txs = BestPayloadTransactions::new(best);

    while let Some(tx) = best_txs.next(()) {
        let tx_hash = *tx.hash();
        let recovered = tx.into_consensus();

        simulated = simulated.saturating_add(1);

        // Note: we never commit state, so each tx is simulated against
        // the top-of-block state independently.
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
            Err(_) => {
                // EVM error (nonce too low/high, insufficient balance, etc.).
                // Keep — may become valid after earlier txs execute.
            }
            Ok(_) => {
                // Success — keep.
            }
        }
    }

    let elapsed = started.elapsed();
    metrics.presim_duration.record(elapsed);
    metrics.presim_txs_simulated.record(simulated as f64);
    metrics
        .presim_txs_excluded
        .increment(result.excluded.len() as u64);
    metrics.presim_gas_saved.increment(gas_saved);

    debug!(
        target: "payload_builder",
        simulated,
        excluded = result.excluded.len(),
        gas_saved,
        elapsed_ms = elapsed.as_millis(),
        random_coinbase,
        "presim: top-of-block pre-simulation complete"
    );

    result
}
