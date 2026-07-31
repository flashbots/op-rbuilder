//! Criterion bench for flashblock candidate build path.
//!
//! One-shot, prints times for every case
//! `cargo bench -p op-rbuilder --features bench-internals --bench bench_build_candidate`
//!
//! Baseline comparison:
//! `cargo bench -p op-rbuilder --features bench-internals --bench bench_build_candidate -- --save-baseline pre-swap`
//! then:
//! `cargo bench -p op-rbuilder --features bench-internals --bench bench_build_candidate -- --baseline pre-swap`
//!
//! Benched paths:
//! - `execute_best_transactions`, cold (empty prestate, flashblock 0) and warm (prestate carried
//!   from a 10-flashblock prefix, i.e. mid-block).
//! - `assemble`, sealing the 10 recorded prefix flashblocks back to back.
//!
//! Candidates are synthetic but repeat a fixed disposition mix (see `TransactionDisposition`), so
//! every prefix length hits commits, dropped reverts, sender cascades and nonce collisions.
use std::{collections::HashSet, sync::Arc};

use alloy_consensus::{Header, Transaction, TxEip1559};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B64, B256, Bytes, TxHash, TxKind, U256, address, keccak256};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use op_alloy_consensus::OpTypedTransaction;
use op_rbuilder::{
    builder::{StateRootCalculator, bench::CandidateBenchContext},
    primitives::reth::ExecutionInfo,
    traits::PayloadTxsBounds,
    tx::{FBPooledTransaction, WithFlashbotsMetadata},
    tx_signer::Signer,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use reth_basic_payload_builder::PayloadConfig;
use reth_chainspec::{EthChainSpec, MAINNET};
use reth_db::{tables, transaction::DbTxMut};
use reth_optimism_chainspec::OpChainSpecBuilder;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_optimism_txpool::OpPooledTransaction;
use reth_payload_builder::PayloadId;
use reth_payload_util::PayloadTransactions;
use reth_primitives_traits::{Account, Bytecode, SealedHeader};
use reth_provider::{
    DatabaseProviderFactory, HashingWriter, LatestStateProvider,
    providers::ProviderFactory,
    test_utils::{MockNodeTypesWithDB, create_test_provider_factory_with_chain_spec},
};
use reth_revm::{
    State,
    database::StateProviderDatabase,
    db::{CacheState, TransitionState},
};
use reth_transaction_pool::PoolTransaction;
use reth_trie::HashedPostState;

const SEED: u64 = 0x5eed_f1a5_b10c;
const BASE_FEE: u64 = 1_000_000_000;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;
const MAX_TXS: usize = 200;
/// Dispositions repeat every window, so any prefix length keeps the same commit/revert/cascade mix.
const TX_SCENARIO_LEN: usize = 20;
/// Prefix replayed to produce warm mid-block state: 10 flashblocks of 5 txs.
const ASSEMBLY_TXS: usize = 50;
const ASSEMBLY_FLASHBLOCKS: usize = 10;
const TXS_PER_FLASHBLOCK: usize = ASSEMBLY_TXS / ASSEMBLY_FLASHBLOCKS;
const FUNDED_BALANCE: u128 = 100_000_000_000_000_000_000;
// Helper contracts: one dirties a storage slot from calldata, the other always reverts.
const STORAGE_WRITER: Address = address!("0x1000000000000000000000000000000000000001");
const REVERTER: Address = address!("0x1000000000000000000000000000000000000002");
const STORAGE_WRITER_CODE: &[u8] = &[
    0x60, 0x00, // PUSH1 0
    0x35, // CALLDATALOAD
    0x60, 0x00, // PUSH1 0
    0x55, // SSTORE
    0x00, // STOP
];
const REVERTER_CODE: &[u8] = &[
    0x60, 0x00, // PUSH1 0
    0x60, 0x00, // PUSH1 0
    0xfd, // REVERT
];

type TestProviderFactory = ProviderFactory<MockNodeTypesWithDB>;

/// State captured after each prefix flashblock, replayed as the prestate for the `assemble` bench
/// and for the warm execution bench.
struct AssemblySnapshot {
    cache: CacheState,
    transition: Option<TransitionState>,
    info: ExecutionInfo,
    /// Txs committed before this flashblock; `assemble` seals only the ones after it.
    previous_transaction_count: usize,
}

struct BenchFixture {
    provider_factory: TestProviderFactory,
    chain_spec: Arc<reth_optimism_chainspec::OpChainSpec>,
    payload_config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    /// Candidates for the cold benches; the first `ASSEMBLY_TXS` also build the prefix.
    transactions: Vec<FBPooledTransaction>,
    /// Same scenario mix from a second seed, so the warm benches never reuse a prefix sender.
    warm_transactions: Vec<FBPooledTransaction>,
    assembly_snapshots: Vec<AssemblySnapshot>,
}

impl BenchFixture {
    fn new() -> Self {
        let chain_spec = Arc::new(
            OpChainSpecBuilder::optimism_mainnet()
                .jovian_activated()
                .build(),
        );
        let chain_id = chain_spec.chain_id();
        let (mut signers, mut transactions) = generate_transactions(SEED, chain_id);
        let (warm_signers, mut warm_transactions) =
            generate_transactions(SEED ^ 0xa11c_e5e5_cac4_ebad, chain_id);
        signers.extend(warm_signers);
        // Priority fee descends with generation index, so pool ordering preserves the scenario
        // layout that the disposition/nonce assertions below rely on.
        transactions.sort_by(|left, right| {
            right
                .max_priority_fee_per_gas()
                .cmp(&left.max_priority_fee_per_gas())
                .then_with(|| left.hash().cmp(right.hash()))
        });
        warm_transactions.sort_by(|left, right| {
            right
                .max_priority_fee_per_gas()
                .cmp(&left.max_priority_fee_per_gas())
                .then_with(|| left.hash().cmp(right.hash()))
        });
        let prefix_senders = transactions[..ASSEMBLY_TXS]
            .iter()
            .map(|tx| *tx.sender_ref())
            .collect::<HashSet<_>>();
        assert!(
            warm_transactions
                .iter()
                .all(|tx| !prefix_senders.contains(tx.sender_ref())),
            "warm batches must use senders distinct from the carried prefix"
        );

        let provider_factory = setup_provider(&signers);
        let parent_state_root = {
            let provider = provider_factory.database_provider_ro().unwrap();
            let latest = LatestStateProvider::new(provider);
            StateRootCalculator::new(true, false)
                .compute_from_hashed(&latest, HashedPostState::default())
                .unwrap()
                .state_root
        };
        let parent = SealedHeader::seal_slow(Header {
            state_root: parent_state_root,
            gas_limit: BLOCK_GAS_LIMIT,
            base_fee_per_gas: Some(BASE_FEE),
            number: 0,
            timestamp: 0,
            ..Default::default()
        });
        let attributes = OpPayloadBuilderAttributes {
            id: PayloadId::new([0x42; 8]),
            parent: parent.hash(),
            timestamp: 1,
            suggested_fee_recipient: Address::repeat_byte(0x42),
            prev_randao: B256::repeat_byte(0x24),
            parent_beacon_block_root: Some(B256::repeat_byte(0x11)),
            gas_limit: Some(BLOCK_GAS_LIMIT),
            eip_1559_params: Some(B64::ZERO),
            min_base_fee: Some(1),
            ..Default::default()
        };
        let payload_id = attributes.id;
        let payload_config = PayloadConfig::new(Arc::new(parent), attributes, payload_id);
        let context =
            CandidateBenchContext::new(Arc::clone(&chain_spec), payload_config.clone()).unwrap();

        let provider = provider_factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        let mut state = State::builder()
            .with_database(StateProviderDatabase::new(latest))
            .with_bundle_update()
            .build();
        // Replay the prefix one flashblock at a time, snapshotting state after each.
        let mut info = execution_info(ASSEMBLY_TXS);
        let mut assembly_snapshots = Vec::with_capacity(ASSEMBLY_FLASHBLOCKS);
        let mut previous_transaction_count = 0;
        let mut protected_reverts = 0;
        let mut cascaded_descendants = 0;
        for flashblock_index in 0..ASSEMBLY_FLASHBLOCKS {
            let start = flashblock_index * TXS_PER_FLASHBLOCK;
            let end = start + TXS_PER_FLASHBLOCK;
            let mut cursor = SyntheticCursor::new(transactions[start..end].to_vec());
            let cancelled = context
                .execute_best_transactions(
                    &mut info,
                    &mut state,
                    &mut cursor,
                    BLOCK_GAS_LIMIT,
                    None,
                    None,
                    None,
                    flashblock_index as u64,
                )
                .unwrap();
            assert!(cancelled.is_none());
            protected_reverts += cursor.excluded.len();
            cascaded_descendants += cursor.invalid_descendants_skipped;
            assembly_snapshots.push(AssemblySnapshot {
                cache: state.cache.clone(),
                transition: state.transition_state.clone(),
                info: info.clone(),
                previous_transaction_count,
            });
            previous_transaction_count = info.executed_transactions.len();
        }
        // Tripwire: the prefix must exercise the whole mix, not degenerate into all-commit.
        assert_eq!(protected_reverts, protected_revert_count(ASSEMBLY_TXS));
        assert_eq!(
            cascaded_descendants,
            cascaded_descendant_count(ASSEMBLY_TXS)
        );
        assert_eq!(
            info.executed_transactions.len(),
            expected_committed_count(ASSEMBLY_TXS)
        );
        assert_eq!(info.receipts.len(), expected_committed_count(ASSEMBLY_TXS));
        assert!(info.cumulative_gas_used > 0);

        Self {
            provider_factory,
            chain_spec,
            payload_config,
            transactions,
            warm_transactions,
            assembly_snapshots,
        }
    }

    fn context(&self) -> CandidateBenchContext {
        CandidateBenchContext::new(Arc::clone(&self.chain_spec), self.payload_config.clone())
            .unwrap()
    }

    /// Runs a benched configuration once outside timing: if the scenario stops producing the
    /// expected mix, the numbers stop being comparable, so fail loudly instead.
    fn assert_execution_tripwire(
        &self,
        transactions: &[FBPooledTransaction],
        tx_count: usize,
        cached_prestate: Option<&AssemblySnapshot>,
        flashblock_index: u64,
    ) {
        let provider = self.provider_factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        let state_builder = State::builder().with_database(StateProviderDatabase::new(latest));
        let mut state = if let Some(snapshot) = cached_prestate {
            let mut state = state_builder
                .with_cached_prestate(snapshot.cache.clone())
                .with_bundle_update()
                .build();
            state.transition_state = snapshot.transition.clone();
            state
        } else {
            state_builder.with_bundle_update().build()
        };
        let mut info = execution_info(tx_count);
        let mut cursor = SyntheticCursor::new(transactions[..tx_count].to_vec());
        let cancelled = self
            .context()
            .execute_best_transactions(
                &mut info,
                &mut state,
                &mut cursor,
                BLOCK_GAS_LIMIT,
                None,
                None,
                None,
                flashblock_index,
            )
            .unwrap();

        assert!(cancelled.is_none());
        assert_eq!(
            cursor.excluded.len(),
            protected_revert_count(tx_count),
            "protected-revert coverage changed for {tx_count} candidates"
        );
        assert_eq!(
            cursor.invalid_descendants_skipped,
            cascaded_descendant_count(tx_count),
            "mark_invalid cascade coverage changed for {tx_count} candidates"
        );
        assert_eq!(
            info.executed_transactions.len(),
            expected_committed_count(tx_count),
            "committed transaction count changed for {tx_count} candidates"
        );
        assert_eq!(
            info.receipts.len(),
            expected_committed_count(tx_count),
            "receipt count changed for {tx_count} candidates"
        );
        assert!(
            info.cumulative_gas_used > 0,
            "execution used no gas for {tx_count} candidates"
        );
    }
}

/// Stand-in for the pool's best-tx iterator: replays a fixed list, honours the builder's
/// `mark_invalid`/`mark_excluded` feedback, and records how often each fired.
#[derive(Clone)]
struct SyntheticCursor {
    transactions: Vec<FBPooledTransaction>,
    index: usize,
    invalid_senders: HashSet<Address>,
    excluded: HashSet<TxHash>,
    invalid_descendants_skipped: usize,
}

impl SyntheticCursor {
    fn new(transactions: Vec<FBPooledTransaction>) -> Self {
        Self {
            transactions,
            index: 0,
            invalid_senders: HashSet::new(),
            excluded: HashSet::new(),
            invalid_descendants_skipped: 0,
        }
    }
}

impl PayloadTransactions for SyntheticCursor {
    type Transaction = FBPooledTransaction;

    fn next(&mut self, _ctx: ()) -> Option<Self::Transaction> {
        while let Some(tx) = self.transactions.get(self.index).cloned() {
            self.index += 1;
            if self.invalid_senders.contains(tx.sender_ref()) {
                self.invalid_descendants_skipped += 1;
                continue;
            }
            if self.excluded.contains(tx.hash()) {
                continue;
            }
            return Some(tx);
        }
        None
    }

    fn mark_invalid(&mut self, sender: Address, _nonce: u64) {
        self.invalid_senders.insert(sender);
    }
}

impl PayloadTxsBounds for SyntheticCursor {
    fn mark_excluded(&mut self, hash: TxHash) {
        self.excluded.insert(hash);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionDisposition {
    /// Lands in the block. Index 10 of each window reverts but allows it, so it commits too.
    Commit,
    /// Reverts with an empty allow-list: the builder drops it and invalidates the sender.
    ProtectedRevert,
    /// Next nonce of the sender invalidated just above, so the cursor never yields it.
    CascadedDescendant,
    /// Reuses a nonce already committed in the same window.
    NonceTooLowDuplicate,
}

fn transaction_disposition(index: usize) -> TransactionDisposition {
    match index % TX_SCENARIO_LEN {
        1 => TransactionDisposition::ProtectedRevert,
        2 => TransactionDisposition::CascadedDescendant,
        4 => TransactionDisposition::NonceTooLowDuplicate,
        _ => TransactionDisposition::Commit,
    }
}

fn generate_transactions(seed: u64, chain_id: u64) -> (Vec<Signer>, Vec<FBPooledTransaction>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut signers = Vec::with_capacity(MAX_TXS);
    let mut signer_nonces = Vec::with_capacity(MAX_TXS);
    let mut transactions = Vec::with_capacity(MAX_TXS);

    // Signer/nonce layout inside a window is what produces the dispositions:
    //   0,1,2 -> one signer, nonces 0,1,2 (1 is a protected revert, so 2 cascades)
    //   3,4   -> one signer, both nonce 0 (4 is nonce-too-low)
    //   5,6   -> one signer, nonces 0,1 (sequential, both commit)
    //   7..   -> a fresh signer per tx, nonce 0
    for scenario_start in (0..MAX_TXS).step_by(TX_SCENARIO_LEN) {
        let cascading_signer = deterministic_signer(&mut rng);
        let duplicate_nonce_signer = deterministic_signer(&mut rng);
        let sequential_signer = deterministic_signer(&mut rng);
        signers.extend([cascading_signer, duplicate_nonce_signer, sequential_signer]);

        let scenario_end = (scenario_start + TX_SCENARIO_LEN).min(MAX_TXS);
        for index in scenario_start..scenario_end {
            let (signer, nonce) = match index - scenario_start {
                0 => (cascading_signer, 0),
                1 => (cascading_signer, 1),
                2 => (cascading_signer, 2),
                3 | 4 => (duplicate_nonce_signer, 0),
                5 => (sequential_signer, 0),
                6 => (sequential_signer, 1),
                _ => {
                    let signer = deterministic_signer(&mut rng);
                    signers.push(signer);
                    (signer, 0)
                }
            };
            signer_nonces.push((signer, nonce));
        }
    }

    // Tx shapes: reverting call, bare transfer (cheap, no state) or storage write (100k gas, dirty
    // slot). Index 10 of each window reverts without the empty allow-list, so it commits reverted.
    for (index, (signer, nonce)) in signer_nonces.into_iter().enumerate() {
        let priority_fee = 1_000_000u128 + (MAX_TXS - index) as u128;
        let (to, value, input, gas_limit) = if transaction_disposition(index)
            == TransactionDisposition::ProtectedRevert
            || index % TX_SCENARIO_LEN == 10
        {
            (TxKind::Call(REVERTER), U256::ZERO, Bytes::new(), 100_000)
        } else if index.is_multiple_of(2) {
            (
                TxKind::Call(random_address(&mut rng)),
                U256::from(index as u64 + 1),
                Bytes::new(),
                21_000,
            )
        } else {
            let mut value = [0u8; 32];
            rng.fill(&mut value);
            (
                TxKind::Call(STORAGE_WRITER),
                U256::ZERO,
                Bytes::copy_from_slice(&value),
                100_000,
            )
        };
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: BASE_FEE as u128 + priority_fee,
            max_priority_fee_per_gas: priority_fee,
            to,
            value,
            input,
            ..Default::default()
        };
        let signed = signer
            .sign_tx(OpTypedTransaction::Eip1559(tx))
            .expect("deterministic key must sign");
        let encoded_len = signed.inner().encode_2718_len();
        let pooled = OpPooledTransaction::new(signed, encoded_len);
        let pooled = if transaction_disposition(index) == TransactionDisposition::ProtectedRevert {
            WithFlashbotsMetadata::new(pooled).with_allowed_revert_hashes(Vec::new())
        } else {
            WithFlashbotsMetadata::new(pooled)
        };

        transactions.push(pooled);
    }

    (signers, transactions)
}

fn deterministic_signer(rng: &mut StdRng) -> Signer {
    loop {
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        if let Ok(signer) = Signer::try_from_secret(B256::from(secret)) {
            return signer;
        }
    }
}

fn random_address(rng: &mut StdRng) -> Address {
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    Address::from(bytes)
}

/// Funds every signer and writes the two helper contracts straight into plain state.
fn setup_provider(signers: &[Signer]) -> TestProviderFactory {
    let provider_factory = create_test_provider_factory_with_chain_spec(MAINNET.clone());
    let provider = provider_factory.provider_rw().unwrap();
    let writer_hash = keccak256(STORAGE_WRITER_CODE);
    let reverter_hash = keccak256(REVERTER_CODE);
    let mut accounts = signers
        .iter()
        .map(|signer| {
            (
                signer.address,
                Account {
                    nonce: 0,
                    balance: U256::from(FUNDED_BALANCE),
                    bytecode_hash: None,
                },
            )
        })
        .collect::<Vec<_>>();
    accounts.extend([
        (
            STORAGE_WRITER,
            Account {
                nonce: 1,
                balance: U256::ZERO,
                bytecode_hash: Some(writer_hash),
            },
        ),
        (
            REVERTER,
            Account {
                nonce: 1,
                balance: U256::ZERO,
                bytecode_hash: Some(reverter_hash),
            },
        ),
    ]);

    for (address, account) in &accounts {
        provider
            .tx_ref()
            .put::<tables::PlainAccountState>(*address, *account)
            .unwrap();
    }
    provider
        .tx_ref()
        .put::<tables::Bytecodes>(
            writer_hash,
            Bytecode::new_raw(Bytes::from_static(STORAGE_WRITER_CODE)),
        )
        .unwrap();
    provider
        .tx_ref()
        .put::<tables::Bytecodes>(
            reverter_hash,
            Bytecode::new_raw(Bytes::from_static(REVERTER_CODE)),
        )
        .unwrap();
    provider
        .insert_account_for_hashing(
            accounts
                .into_iter()
                .map(|(address, account)| (address, Some(account))),
        )
        .unwrap();
    provider.commit().unwrap();

    provider_factory
}

fn execution_info(capacity: usize) -> ExecutionInfo {
    let mut info = ExecutionInfo::with_capacity(capacity);
    // Keeps the DA footprint accounting on the benched path, as in production.
    info.da_footprint_scalar = Some(1);
    info
}

fn protected_revert_count(tx_count: usize) -> usize {
    (0..tx_count)
        .filter(|index| transaction_disposition(*index) == TransactionDisposition::ProtectedRevert)
        .count()
}

fn cascaded_descendant_count(tx_count: usize) -> usize {
    (0..tx_count)
        .filter(|index| {
            transaction_disposition(*index) == TransactionDisposition::CascadedDescendant
        })
        .count()
}

fn nonce_too_low_duplicate_count(tx_count: usize) -> usize {
    (0..tx_count)
        .filter(|index| {
            transaction_disposition(*index) == TransactionDisposition::NonceTooLowDuplicate
        })
        .count()
}

fn expected_committed_count(tx_count: usize) -> usize {
    tx_count
        - protected_revert_count(tx_count)
        - cascaded_descendant_count(tx_count)
        - nonce_too_low_duplicate_count(tx_count)
}

/// Bench IDs count candidates loaded into the synthetic cursor ("txs considered"), including
/// descendants later removed by production-style sender invalidation.
fn bench_execute_best_transactions(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let mut group = c.benchmark_group("execute_best_transactions");

    // Cold: empty prestate at flashblock 0, so every account and slot is a fresh database read.
    for tx_count in [10, 50, 200] {
        let transactions = fixture.transactions[..tx_count].to_vec();
        fixture.assert_execution_tripwire(&transactions, tx_count, None, 0);
        group.bench_function(format!("{tx_count}txs"), |b| {
            b.iter_batched(
                || {
                    let provider = fixture.provider_factory.database_provider_ro().unwrap();
                    let latest = LatestStateProvider::new(provider);
                    let state = State::builder()
                        .with_database(StateProviderDatabase::new(latest))
                        .with_bundle_update()
                        .build();
                    (
                        fixture.context(),
                        state,
                        execution_info(tx_count),
                        SyntheticCursor::new(transactions.clone()),
                    )
                },
                |(context, mut state, mut info, mut cursor)| {
                    context
                        .execute_best_transactions(
                            &mut info,
                            &mut state,
                            &mut cursor,
                            BLOCK_GAS_LIMIT,
                            None,
                            None,
                            None,
                            0,
                        )
                        .unwrap();
                    black_box((context, state, info, cursor))
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Warm: prestate carried from the full 50-tx prefix, so caches are populated and the bundle is
    // non-empty. Senders are disjoint from the prefix, so nothing collides on nonces.
    let warm_snapshot = fixture
        .assembly_snapshots
        .last()
        .expect("fixture always contains assembly snapshots");
    for tx_count in [50, 200] {
        let transactions = fixture.warm_transactions[..tx_count].to_vec();
        fixture.assert_execution_tripwire(
            &transactions,
            tx_count,
            Some(warm_snapshot),
            ASSEMBLY_FLASHBLOCKS as u64,
        );
        group.bench_function(format!("{tx_count}txs_warm"), |b| {
            b.iter_batched(
                || {
                    let provider = fixture.provider_factory.database_provider_ro().unwrap();
                    let latest = LatestStateProvider::new(provider);
                    let mut state = State::builder()
                        .with_database(StateProviderDatabase::new(latest))
                        .with_cached_prestate(warm_snapshot.cache.clone())
                        .with_bundle_update()
                        .build();
                    state.transition_state = warm_snapshot.transition.clone();
                    (
                        fixture.context(),
                        state,
                        execution_info(tx_count),
                        SyntheticCursor::new(transactions.clone()),
                    )
                },
                |(context, mut state, mut info, mut cursor)| {
                    context
                        .execute_best_transactions(
                            &mut info,
                            &mut state,
                            &mut cursor,
                            BLOCK_GAS_LIMIT,
                            None,
                            None,
                            None,
                            ASSEMBLY_FLASHBLOCKS as u64,
                        )
                        .unwrap();
                    black_box((context, state, info, cursor))
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Seals the 10 recorded prefix flashblocks back to back, each from its own snapshot, to cover a
/// whole block's worth of assembly including the growing state-root work.
fn bench_assemble(c: &mut Criterion) {
    let fixture = BenchFixture::new();
    let mut group = c.benchmark_group("assemble");

    group.bench_function("10fb", |b| {
        b.iter_batched(
            || {
                (
                    fixture.context(),
                    std::array::from_fn::<_, ASSEMBLY_FLASHBLOCKS, _>(|index| {
                        let snapshot = &fixture.assembly_snapshots[index];
                        let provider = fixture.provider_factory.database_provider_ro().unwrap();
                        let latest = LatestStateProvider::new(provider);
                        let mut state = State::builder()
                            .with_database(StateProviderDatabase::new(latest))
                            .with_cached_prestate(snapshot.cache.clone())
                            .with_bundle_update()
                            .build();
                        state.transition_state = snapshot.transition.clone();
                        (
                            state,
                            snapshot.info.clone(),
                            // These 10 calculators are independent. Flipping `incremental` to true
                            // would not model cumulative incremental caching across flashblocks.
                            StateRootCalculator::new(true, false),
                            snapshot.previous_transaction_count,
                        )
                    }),
                )
            },
            |(context, candidates)| {
                let mut flashblock_index = 0;
                let outputs = candidates.map(
                    |(mut state, mut info, mut state_root_calc, previous_transaction_count)| {
                        let output = context
                            .assemble(
                                &mut state,
                                &mut info,
                                &mut state_root_calc,
                                flashblock_index,
                                previous_transaction_count,
                            )
                            .unwrap();
                        flashblock_index += 1;
                        output
                    },
                );
                black_box((context, outputs))
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_execute_best_transactions, bench_assemble);
criterion_main!(benches);
