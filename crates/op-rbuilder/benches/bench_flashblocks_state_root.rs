//! Benchmark comparing flashblocks state root calculation with and without incremental trie caching.
//!
//! This benchmark simulates building 10 sequential flashblocks, measuring the total time
//! spent in state root calculation. It uses `StateRootCalculator` — the same
//! code path as the production payload builder — so results reflect real-world
//! performance.
//!
//! It compares:
//! - Without cache: Full state root calculation each time
//! - With cache: Incremental using `IncrementalStateRootCalculator`
//!
//! Run with:
//! ```
//! cargo bench -p op-rbuilder --bench bench_flashblocks_state_root
//! ```

use alloy_primitives::{Address, B256, U256, keccak256};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use op_rbuilder::builder::state_root::StateRootCalculator;
use rand::{Rng, SeedableRng, rngs::StdRng};
use reth_chainspec::MAINNET;
use reth_primitives_traits::Account;
use reth_provider::{
    DatabaseProviderFactory, HashingWriter, LatestStateProvider,
    test_utils::create_test_provider_factory_with_chain_spec,
};
use reth_trie::{HashedPostState, HashedStorage};
use std::{collections::HashMap, time::Instant};

const SEED: u64 = 42;

type AccountList = Vec<(Address, Account)>;
type StorageMap = HashMap<Address, Vec<(B256, U256)>>;

/// Generate random accounts and storage for initial database state
fn generate_test_data(
    num_accounts: usize,
    storage_per_account: usize,
    seed: u64,
) -> (AccountList, StorageMap) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut accounts = Vec::with_capacity(num_accounts);
    let mut storage = HashMap::new();

    for _ in 0..num_accounts {
        let mut addr_bytes = [0u8; 20];
        rng.fill(&mut addr_bytes);
        let address = Address::from_slice(&addr_bytes);

        let account = Account {
            nonce: rng.random_range(0..1000),
            balance: U256::from(rng.random_range(0u64..1_000_000)),
            bytecode_hash: if rng.random_bool(0.3) {
                let mut hash = [0u8; 32];
                rng.fill(&mut hash);
                Some(B256::from(hash))
            } else {
                None
            },
        };
        accounts.push((address, account));

        if storage_per_account > 0 && rng.random_bool(0.5) {
            let mut slots = Vec::with_capacity(storage_per_account);
            for _ in 0..storage_per_account {
                let mut key = [0u8; 32];
                rng.fill(&mut key);
                let value = U256::from(rng.random_range(1u64..1_000_000));
                slots.push((B256::from(key), value));
            }
            storage.insert(address, slots);
        }
    }

    (accounts, storage)
}

/// Setup test database with initial state
fn setup_database(
    accounts: &[(Address, Account)],
    storage: &HashMap<Address, Vec<(B256, U256)>>,
) -> reth_provider::providers::ProviderFactory<reth_provider::test_utils::MockNodeTypesWithDB> {
    let provider_factory = create_test_provider_factory_with_chain_spec(MAINNET.clone());

    {
        let provider_rw = provider_factory.provider_rw().unwrap();

        let accounts_iter = accounts.iter().map(|(addr, acc)| (*addr, Some(*acc)));
        provider_rw
            .insert_account_for_hashing(accounts_iter)
            .unwrap();

        let storage_entries: Vec<_> = storage
            .iter()
            .map(|(addr, slots)| {
                let entries: Vec<_> = slots
                    .iter()
                    .map(|(key, value)| reth_primitives_traits::StorageEntry {
                        key: *key,
                        value: *value,
                    })
                    .collect();
                (*addr, entries)
            })
            .collect();
        provider_rw
            .insert_storage_for_hashing(storage_entries)
            .unwrap();

        provider_rw.commit().unwrap();
    }

    provider_factory
}

/// Generate a flashblock's worth of state changes
fn generate_flashblock_changes(
    base_accounts: &[(Address, Account)],
    change_size: usize,
    seed: u64,
) -> (AccountList, StorageMap) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut accounts = Vec::with_capacity(change_size);
    let mut storage = HashMap::new();

    for i in 0..change_size {
        let address = if i < base_accounts.len() && rng.random_bool(0.7) {
            base_accounts[rng.random_range(0..base_accounts.len())].0
        } else {
            let mut addr_bytes = [0u8; 20];
            rng.fill(&mut addr_bytes);
            Address::from_slice(&addr_bytes)
        };

        let account = Account {
            nonce: rng.random_range(1000..2000),
            balance: U256::from(rng.random_range(1_000_000u64..2_000_000)),
            bytecode_hash: None,
        };
        accounts.push((address, account));

        if rng.random_bool(0.3) {
            let mut slots = Vec::new();
            for _ in 0..rng.random_range(1..10) {
                let mut key = [0u8; 32];
                rng.fill(&mut key);
                let value = U256::from(rng.random_range(1u64..1_000_000));
                slots.push((B256::from(key), value));
            }
            storage.insert(address, slots);
        }
    }

    (accounts, storage)
}

/// Convert to HashedPostState for state root calculation
fn to_hashed_post_state(
    accounts: &[(Address, Account)],
    storage: &HashMap<Address, Vec<(B256, U256)>>,
) -> HashedPostState {
    let hashed_accounts: Vec<_> = accounts
        .iter()
        .map(|(addr, acc)| (keccak256(addr), Some(*acc)))
        .collect();

    let mut hashed_storages = alloy_primitives::map::HashMap::default();
    for (addr, slots) in storage {
        let hashed_addr = keccak256(addr);
        let hashed_storage = HashedStorage::from_iter(
            false,
            slots.iter().map(|(key, value)| (keccak256(key), *value)),
        );
        hashed_storages.insert(hashed_addr, hashed_storage);
    }

    HashedPostState {
        accounts: hashed_accounts.into_iter().collect(),
        storages: hashed_storages,
    }
}

/// Benchmark without incremental trie cache (baseline — fresh calculator each flashblock)
fn bench_without_cache(
    provider_factory: &reth_provider::providers::ProviderFactory<
        reth_provider::test_utils::MockNodeTypesWithDB,
    >,
    flashblock_changes: &[HashedPostState],
) -> (u128, Vec<u128>) {
    let mut individual_times = Vec::new();
    let total_start = Instant::now();

    for hashed_state in flashblock_changes {
        let fb_start = Instant::now();
        let provider = provider_factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        let output = StateRootCalculator::new(false)
            .compute(&latest, hashed_state.clone())
            .unwrap();
        individual_times.push(fb_start.elapsed().as_micros());
        black_box(output.state_root);
    }

    (total_start.elapsed().as_micros(), individual_times)
}

/// Benchmark with incremental trie cache (single calculator across all flashblocks)
fn bench_with_cache(
    provider_factory: &reth_provider::providers::ProviderFactory<
        reth_provider::test_utils::MockNodeTypesWithDB,
    >,
    flashblock_changes: &[HashedPostState],
) -> (u128, Vec<u128>) {
    let mut individual_times = Vec::new();
    let mut calc = StateRootCalculator::new(true);
    let total_start = Instant::now();

    for hashed_state in flashblock_changes {
        let fb_start = Instant::now();
        let provider = provider_factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);

        let output = calc.compute(&latest, hashed_state.clone()).unwrap();

        individual_times.push(fb_start.elapsed().as_micros());
        black_box(output.state_root);
    }

    (total_start.elapsed().as_micros(), individual_times)
}

fn bench_flashblocks_state_root(c: &mut Criterion) {
    // Setup: Create a large database with 50k accounts, 10 storage slots each
    eprintln!("\n=== Setting up database with 50,000 accounts...");
    let (base_accounts, base_storage) = generate_test_data(50_000, 10, SEED);
    let provider_factory = setup_database(&base_accounts, &base_storage);
    eprintln!("Database setup complete\n");

    // Test different flashblock sizes (transactions per flashblock)
    for txs_per_flashblock in [50, 100, 200] {
        let mut group = c.benchmark_group(format!("flashblocks_{}_txs", txs_per_flashblock));
        group.sample_size(10);

        eprintln!(
            "--- Testing with {} transactions per flashblock ---",
            txs_per_flashblock
        );

        // Generate 10 flashblocks worth of changes
        let mut flashblock_changes = Vec::new();
        for i in 0..10 {
            let (accounts, storage) =
                generate_flashblock_changes(&base_accounts, txs_per_flashblock, SEED + i + 1);
            let hashed_state = to_hashed_post_state(&accounts, &storage);
            flashblock_changes.push(hashed_state);
        }

        // Benchmark without cache (baseline)
        group.bench_function(BenchmarkId::new("without_cache", "10_flashblocks"), |b| {
            b.iter(|| bench_without_cache(&provider_factory, &flashblock_changes))
        });

        // Benchmark with incremental cache
        group.bench_function(BenchmarkId::new("with_cache", "10_flashblocks"), |b| {
            b.iter(|| bench_with_cache(&provider_factory, &flashblock_changes))
        });

        // Manual comparison run for detailed output
        eprintln!("\nManual timing comparison:");
        let (total_without, times_without) =
            bench_without_cache(&provider_factory, &flashblock_changes);
        eprintln!("  WITHOUT cache: {} us total", total_without);
        eprintln!("    Per-flashblock: {:?} us", times_without);

        let (total_with, times_with) = bench_with_cache(&provider_factory, &flashblock_changes);
        eprintln!("  WITH cache: {} us total", total_with);
        eprintln!("    Per-flashblock: {:?} us", times_with);

        let speedup = total_without as f64 / total_with as f64;
        let improvement = ((total_without - total_with) as f64 / total_without as f64) * 100.0;
        eprintln!(
            "  Cache speedup: {:.2}x ({:.1}% faster)",
            speedup, improvement
        );
        eprintln!();

        group.finish();
    }

    eprintln!("\n=== Benchmark complete! ===");
    eprintln!("Results saved to target/criterion/");
}

criterion_group!(benches, bench_flashblocks_state_root);
criterion_main!(benches);
