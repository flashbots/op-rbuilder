use std::{num::NonZeroUsize, sync::Arc, time::Instant};

use alloy_consensus::{BlockHeader, Header};
use alloy_evm::{Evm, InvalidTxError};
use alloy_op_evm::OpTx;
use alloy_primitives::{Address, B256, Bytes};
use eyre::Context;
use futures_util::{Stream, StreamExt};
use parking_lot::RwLock;
use reth_chain_state::CanonStateNotification;
use reth_evm::{EvmError, IntoTxEnv};
use reth_optimism_chainspec::{OpChainSpec, OpHardforks};
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{Block, NodePrimitives, Recovered, RecoveredBlock};
use reth_provider::{BlockReaderIdExt, ChainSpecProvider, StateProvider, StateProviderFactory};
use reth_revm::{State, database::StateProviderDatabase};
use reth_transaction_pool::{FullTransactionEvent, PoolTransaction, TransactionPool};
use revm::{context::result::ResultAndState, context_interface::result::InvalidTransaction};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, warn};

use crate::{
    evm::OpBlockEvmFactory, metrics::GaugeExt, pool::metrics::PoolMetrics, tx::FBPooledTransaction,
};

/// Pre-simulates transactions against the current head state to filter out
/// reverting transactions before they enter the pool.
pub(crate) struct TopOfBlockSimulator {
    tip_state: RwLock<Arc<Option<TipState>>>,
    permits: Option<Arc<Semaphore>>,
    metrics: Arc<PoolMetrics>,
}

/// Holds a concurrency permit when presim limiting is enabled.
#[derive(derive_more::IsVariant)]
enum PresimPermit {
    Limited { _permit: OwnedSemaphorePermit },
    Unlimited,
}

impl std::fmt::Debug for TopOfBlockSimulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopOfBlockSimulator")
            .finish_non_exhaustive()
    }
}

pub(crate) struct TipState {
    evm_factory: OpBlockEvmFactory,
    state_provider: Box<dyn StateProvider + Send + Sync>,
}

impl TopOfBlockSimulator {
    pub(crate) fn new(max_concurrent: Option<NonZeroUsize>, metrics: Arc<PoolMetrics>) -> Self {
        let permits = max_concurrent.map(|limit| {
            metrics.presim_concurrency_limit.set(limit.get() as f64);
            Arc::new(Semaphore::new(limit.get()))
        });

        Self {
            tip_state: RwLock::new(Arc::new(None)),
            permits,
            metrics,
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        Self {
            tip_state: RwLock::new(Arc::new(None)),
            permits: None,
            metrics: Arc::new(PoolMetrics::default()),
        }
    }

    pub(crate) async fn simulate_tx(
        self: Arc<Self>,
        tx: Recovered<OpTransactionSigned>,
    ) -> eyre::Result<bool> {
        let permit = self.acquire_permit().await?;

        let in_flight = self.metrics.presim_in_flight.increment_guard();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _in_flight = in_flight;
            self.simulate_tx_sync(tx)
        })
        .await
        .wrap_err("simulate tx task panicked")
    }

    async fn acquire_permit(&self) -> eyre::Result<PresimPermit> {
        let Some(permits) = self.permits.clone() else {
            return Ok(PresimPermit::Unlimited);
        };

        let wait_start = Instant::now();
        let _waiting = self.metrics.presim_waiting.increment_guard();

        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .wrap_err("presim semaphore closed")?;

        self.metrics
            .presim_wait_duration
            .record(wait_start.elapsed());

        Ok(PresimPermit::Limited { _permit: permit })
    }

    pub(crate) fn simulate_tx_sync(&self, tx: impl IntoTxEnv<OpTx>) -> bool {
        let tip_state = {
            let tip_state = self.tip_state.read();
            tip_state.clone()
        };

        let Some(ref tip_state) = *tip_state else {
            warn!("tip state for top of block simulator not initialized yet");
            return true;
        };

        tip_state.run_simulation(tx)
    }

    pub(crate) fn update_tip(&self, tip_state: TipState) {
        *self.tip_state.write() = Arc::new(Some(tip_state));
    }
}

impl TipState {
    fn create<B: Block<Header = alloy_consensus::Header>>(
        provider: impl StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec>,
        evm_config: OpEvmConfig,
        block_time_secs: u64,
        tip: &RecoveredBlock<B>,
    ) -> eyre::Result<Self> {
        let chain_spec = provider.chain_spec();
        let timestamp = tip.timestamp() + block_time_secs;
        let extra_data = if chain_spec.is_holocene_active_at_timestamp(timestamp) {
            tip.extra_data().clone()
        } else {
            Bytes::default()
        };

        let block_env_attributes = OpNextBlockEnvAttributes {
            timestamp,
            // Use a random coinbase so attackers can't craft txs that behave
            // differently during simulation vs block building
            suggested_fee_recipient: Address::random(),
            prev_randao: B256::ZERO,
            gas_limit: tip.gas_limit(),
            parent_beacon_block_root: tip.parent_beacon_block_root(),
            extra_data,
        };

        let evm_factory =
            OpBlockEvmFactory::for_next_block(evm_config, tip.header(), &block_env_attributes)?;
        let state_provider = provider.state_by_block_hash(tip.hash_slow())?;

        // SAFETY: reth's concrete StateProvider implementations are Send + Sync.
        // StateProviderBox omits these bounds but the underlying types satisfy them.
        let state_provider: Box<dyn StateProvider + Send + Sync> =
            unsafe { std::mem::transmute::<Box<dyn StateProvider + Send>, _>(state_provider) };
        // Compile-time assertion
        const _: () = assert!(
            std::mem::size_of::<Box<dyn StateProvider + Send>>()
                == std::mem::size_of::<Box<dyn StateProvider + Send + Sync>>()
                && std::mem::align_of::<Box<dyn StateProvider + Send>>()
                    == std::mem::align_of::<Box<dyn StateProvider + Send + Sync>>()
        );

        Ok(Self {
            evm_factory,
            state_provider,
        })
    }

    fn run_simulation(&self, tx: impl IntoTxEnv<OpTx>) -> bool {
        let db = StateProviderDatabase::new(&*self.state_provider);
        let mut state = State::builder().with_database(db).build();
        let mut evm = self.evm_factory.evm(&mut state);

        match evm.transact(tx) {
            // The EVM executed the transaction: keep it only if it didn't revert.
            Ok(ResultAndState { result, .. }) => result.is_success(),
            Err(err) => {
                if !err.is_invalid_tx_err() {
                    // The simulation failed for a reason unrelated to the
                    // transaction itself (e.g. a state-provider/database read
                    // error). Make the failure visible; the tx is kept rather
                    // than evicted (see `keep_tx_on_simulation_error`).
                    warn!(error = %err, "pre-simulation failed with a non-transaction error; keeping tx");
                }
                keep_tx_on_simulation_error(&err)
            }
        }
    }
}

/// Decide whether a transaction whose pre-simulation returned an error should
/// remain in the pool.
///
/// `Evm::transact` returns an error either because the transaction is invalid
/// (`EvmError::InvalidTransaction`) or because of an infrastructure failure such
/// as a state-provider/database read error. Only the former says anything about
/// the transaction, so we evict *only* on a genuine validity error and otherwise
/// keep the tx (fail open). A transient state-read failure (e.g. the pinned tip
/// state being reorged out or pruned) must never silently drop a transaction the
/// user paid to revert-protect.
fn keep_tx_on_simulation_error<E: EvmError>(err: &E) -> bool {
    let Some(invalid_tx) = err.as_invalid_tx_err() else {
        // Not a transaction-validity error: keep the tx.
        return true;
    };
    // A nonce gap usually means the tx depends on not-yet-applied pending state,
    // so let the pool resolve ordering. Any other validity error means the tx
    // can never be included, so drop it.
    matches!(
        invalid_tx.as_invalid_tx_err(),
        Some(InvalidTransaction::NonceTooLow { .. } | InvalidTransaction::NonceTooHigh { .. })
    )
}

pub(crate) async fn maintain_tip_state<N, St, Provider>(
    simulator: Arc<TopOfBlockSimulator>,
    provider: Provider,
    evm_config: OpEvmConfig,
    block_time_secs: u64,
    metrics: Arc<PoolMetrics>,
    mut events: St,
) where
    N: NodePrimitives<Block: Block<Header = Header>>,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt<Header = Header>
        + Clone
        + Send
        + Sync
        + 'static,
{
    loop {
        let Some(event) = events.next().await else {
            break;
        };

        match TipState::create(&provider, evm_config.clone(), block_time_secs, event.tip()) {
            Ok(tip_state) => {
                simulator.update_tip(tip_state);
                metrics.presim_tip_state_updates.increment(1);
            }
            Err(e) => {
                warn!(error = %e, "failed to create tip state for pre-simulation");
            }
        }
    }
}

pub(crate) async fn maintain_pending_simulations<Pool, St>(
    simulator: Arc<TopOfBlockSimulator>,
    pool: Pool,
    metrics: Arc<PoolMetrics>,
    mut events: St,
) where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + 'static,
    St: Stream<Item = FullTransactionEvent<FBPooledTransaction>> + Send + Unpin + 'static,
{
    while let Some(event) = events.next().await {
        let FullTransactionEvent::Pending(tx_hash) = event else {
            continue;
        };

        // Fetch full tx from pool — may already be gone
        let Some(tx) = pool.get(&tx_hash) else {
            continue;
        };

        // Only simulate txs that enable revert protection since if they don't
        // then the sender will just pay gas fees
        if !tx.transaction.revert_protected() {
            continue;
        }

        let simulator = simulator.clone();
        let pool = pool.clone();
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let consensus_tx = tx.transaction.clone_into_consensus();
            match simulator.simulate_tx(consensus_tx).await {
                Ok(false) => {
                    debug!(tx_hash = %tx_hash, "evicting reverting tx from pool");
                    pool.remove_transactions(vec![tx_hash]);
                    metrics.presim_pending_evictions.increment(1);
                }
                Ok(true) => {}
                Err(e) => {
                    error!(tx_hash = %tx_hash, error = %e, "background simulation failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_evm::EvmEnv;
    use alloy_network::TxSignerSync;
    use alloy_primitives::{Address, TxKind, U256, hex, map::HashMap};
    use alloy_signer_local::PrivateKeySigner;
    use op_alloy_consensus::OpTxEnvelope;
    use op_revm::OpSpecId;
    use reth_optimism_chainspec::BASE_MAINNET;
    use reth_optimism_evm::OpEvmConfig;
    use reth_primitives_traits::Account;
    use reth_revm::test_utils::StateProviderTest;
    use revm::context::CfgEnv;

    const ONE_ETH: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);
    const CHAIN_ID: u64 = 8453; // Base mainnet

    fn test_evm_config() -> OpEvmConfig {
        OpEvmConfig::optimism(BASE_MAINNET.clone())
    }

    /// Create a TipState with a properly configured EVM env and the given state provider.
    fn tip_state_with_provider(state_provider: StateProviderTest) -> TipState {
        let evm_config = test_evm_config();
        let cfg = CfgEnv::new_with_spec(OpSpecId::ECOTONE).with_chain_id(CHAIN_ID);
        let evm_env = EvmEnv {
            cfg_env: cfg,
            ..Default::default()
        };
        let evm_factory = OpBlockEvmFactory::new(evm_config, evm_env);
        TipState {
            evm_factory,
            state_provider: Box::new(state_provider),
        }
    }

    fn sign_test_tx(signer: &PrivateKeySigner, tx: TxEip1559) -> Recovered<OpTransactionSigned> {
        let mut tx = tx;
        let signature = signer.sign_transaction_sync(&mut tx).unwrap();
        let envelope = OpTxEnvelope::Eip1559(tx.into_signed(signature));
        Recovered::new_unchecked(OpTransactionSigned::from(envelope), signer.address())
    }

    fn simple_transfer(signer: &PrivateKeySigner, nonce: u64) -> Recovered<OpTransactionSigned> {
        sign_test_tx(
            signer,
            TxEip1559 {
                chain_id: BASE_MAINNET.chain().id(),
                nonce,
                gas_limit: 21_000,
                max_fee_per_gas: 20_000_000_000,
                to: TxKind::Call(Address::random()),
                ..Default::default()
            },
        )
    }

    fn reverting_create(signer: &PrivateKeySigner, nonce: u64) -> Recovered<OpTransactionSigned> {
        sign_test_tx(
            signer,
            TxEip1559 {
                chain_id: BASE_MAINNET.chain().id(),
                nonce,
                gas_limit: 100_000,
                max_fee_per_gas: 20_000_000_000,
                to: TxKind::Create,
                // PUSH1 0x00 PUSH1 0x00 REVERT
                input: hex!("60006000fd").into(),
                ..Default::default()
            },
        )
    }

    fn funded_provider(address: Address) -> StateProviderTest {
        let mut provider = StateProviderTest::default();
        provider.insert_account(
            address,
            Account {
                nonce: 0,
                balance: ONE_ETH,
                bytecode_hash: None,
            },
            None,
            HashMap::default(),
        );
        provider
    }

    #[test]
    fn successful_transfer_returns_true() {
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());
        let tip_state = tip_state_with_provider(provider);

        let tx = simple_transfer(&signer, 0);
        assert!(tip_state.run_simulation(tx));
    }

    #[test]
    fn reverting_tx_returns_false() {
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());
        let tip_state = tip_state_with_provider(provider);

        let tx = reverting_create(&signer, 0);
        assert!(!tip_state.run_simulation(tx));
    }

    #[test]
    fn nonce_too_high_passes_through() {
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());
        let tip_state = tip_state_with_provider(provider);

        // Account has nonce 0, tx uses nonce 5 — should pass (let pool handle it)
        let tx = simple_transfer(&signer, 5);
        assert!(tip_state.run_simulation(tx));
    }

    #[test]
    fn insufficient_balance_returns_false() {
        let signer = PrivateKeySigner::random();
        // Account with zero balance
        let mut provider = StateProviderTest::default();
        provider.insert_account(
            signer.address(),
            Account {
                nonce: 0,
                balance: U256::ZERO,
                bytecode_hash: None,
            },
            None,
            HashMap::default(),
        );
        let tip_state = tip_state_with_provider(provider);

        let tx = simple_transfer(&signer, 0);
        assert!(!tip_state.run_simulation(tx));
    }

    #[test]
    fn unknown_sender_returns_false() {
        let signer = PrivateKeySigner::random();
        // Empty state — sender doesn't exist
        let provider = StateProviderTest::default();
        let tip_state = tip_state_with_provider(provider);

        let tx = simple_transfer(&signer, 0);
        assert!(!tip_state.run_simulation(tx));
    }

    #[test]
    fn no_tip_state_passes_through() {
        let simulator = TopOfBlockSimulator::new_for_test();
        let signer = PrivateKeySigner::random();
        let tx = simple_transfer(&signer, 0);

        assert!(simulator.simulate_tx_sync(tx));
    }

    #[test]
    fn update_tip_makes_simulation_available() {
        let simulator = TopOfBlockSimulator::new_for_test();
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());

        // Before update — passes through
        assert!(simulator.simulate_tx_sync(reverting_create(&signer, 0)));

        // After update — successfully rejected
        simulator.update_tip(tip_state_with_provider(provider));
        assert!(!simulator.simulate_tx_sync(reverting_create(&signer, 0)));
    }

    #[test]
    fn simulations_are_isolated() {
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());
        let tip_state = tip_state_with_provider(provider);

        // Run a transfer that mutates state (nonce advances)
        assert!(tip_state.run_simulation(simple_transfer(&signer, 0)));

        // Same nonce=0 tx should still succeed — state wasn't persisted
        assert!(tip_state.run_simulation(simple_transfer(&signer, 0)));
    }

    #[tokio::test]
    async fn presim_limits_concurrent_tasks() {
        let simulator = Arc::new(TopOfBlockSimulator::new(
            NonZeroUsize::new(2),
            Arc::new(PoolMetrics::default()),
        ));

        let first = simulator.acquire_permit().await.unwrap();
        let _second = simulator.acquire_permit().await.unwrap();

        let blocked = tokio::spawn({
            let simulator = simulator.clone();
            async move { simulator.acquire_permit().await.unwrap() }
        });

        tokio::task::yield_now().await;
        assert!(
            !blocked.is_finished(),
            "third task incorrectly acquired a permit"
        );

        drop(first);

        let third = tokio::time::timeout(Duration::from_millis(100), blocked)
            .await
            .unwrap()
            .unwrap();
        assert!(third.is_limited())
    }

    #[tokio::test]
    async fn presim_unlimited_concurrency() {
        let simulator = TopOfBlockSimulator::new_for_test();

        assert!(simulator.acquire_permit().await.unwrap().is_unlimited());
    }

    #[test]
    fn non_transaction_errors_keep_tx() {
        use revm::context_interface::result::EVMError;

        // A state-provider/database read failure during simulation says nothing
        // about the transaction's validity, so the tx must be kept, not evicted.
        // Regression: previously every non-nonce error (infrastructure errors
        // included) was treated as a revert and evicted the tx.
        let db_err = EVMError::<std::io::Error, InvalidTransaction>::Database(
            std::io::Error::other("simulated state read failure"),
        );
        assert!(keep_tx_on_simulation_error(&db_err));

        let custom_err =
            EVMError::<std::io::Error, InvalidTransaction>::Custom("evm misconfiguration".into());
        assert!(keep_tx_on_simulation_error(&custom_err));
    }

    #[test]
    fn nonce_gaps_kept_other_validity_errors_evicted() {
        use revm::context_interface::result::EVMError;

        // Nonce gaps are kept — the pool resolves ordering against pending state.
        let too_low = EVMError::<std::io::Error, InvalidTransaction>::Transaction(
            InvalidTransaction::NonceTooLow { tx: 1, state: 5 },
        );
        let too_high = EVMError::<std::io::Error, InvalidTransaction>::Transaction(
            InvalidTransaction::NonceTooHigh { tx: 9, state: 5 },
        );
        assert!(keep_tx_on_simulation_error(&too_low));
        assert!(keep_tx_on_simulation_error(&too_high));

        // A genuine validity error (can never be included) is evicted.
        let no_funds = EVMError::<std::io::Error, InvalidTransaction>::Transaction(
            InvalidTransaction::LackOfFundForMaxFee {
                fee: Box::new(U256::from(1u64)),
                balance: Box::new(U256::ZERO),
            },
        );
        assert!(!keep_tx_on_simulation_error(&no_funds));
    }
}
