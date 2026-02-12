use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use dashmap::DashMap;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::SignedTransaction;
use revm::state::AccountInfo;
use std::{cmp::Ordering, collections::HashSet, sync::Arc};

#[derive(Debug, Clone)]
pub struct BackrunBundle {
    /// Hash of the target tx; we assume it's in the txpool.
    pub target_tx_hash: B256,
    pub backrun_tx: OpTransactionSigned,
    pub block_number_min: u64,
    pub block_number_max: u64,
    pub flashblock_number_min: Option<u64>,
    pub flashblock_number_max: Option<u64>,
}

impl BackrunBundle {
    pub fn is_valid(&self, block_number: u64, flashblock_number: Option<u64>) -> bool {
        if block_number < self.block_number_min || block_number > self.block_number_max {
            return false;
        }

        if let Some(fb) = flashblock_number {
            if self.flashblock_number_min.is_some_and(|min| fb < min) {
                return false;
            }
            if self.flashblock_number_max.is_some_and(|max| fb > max) {
                return false;
            }
        }

        true
    }
}

/// Ord impl: highest `max_priority_fee_per_gas` first, backrun tx hash as tiebreaker.
#[derive(Debug, Clone)]
pub struct OrderedBackrunBundle(pub BackrunBundle);

impl OrderedBackrunBundle {
    fn priority_fee(&self) -> u128 {
        self.0.backrun_tx.max_priority_fee_per_gas().unwrap_or(0)
    }

    fn backrun_tx_hash(&self) -> B256 {
        B256::from(*self.0.backrun_tx.tx_hash())
    }
}

impl PartialEq for OrderedBackrunBundle {
    fn eq(&self, other: &Self) -> bool {
        self.backrun_tx_hash() == other.backrun_tx_hash()
    }
}

impl Eq for OrderedBackrunBundle {}

impl PartialOrd for OrderedBackrunBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedBackrunBundle {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .priority_fee()
            .cmp(&self.priority_fee())
            .then_with(|| self.backrun_tx_hash().cmp(&other.backrun_tx_hash()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct TxBackruns {
    pub bundles: std::collections::BTreeSet<OrderedBackrunBundle>,
}

impl TxBackruns {
    pub fn iter(&self) -> impl Iterator<Item = &OrderedBackrunBundle> {
        self.bundles.iter()
    }
}

#[derive(Debug, Clone)]
pub struct BackrunBundlePayloadPool {
    inner: Arc<DashMap<B256, TxBackruns>>,
}

impl BackrunBundlePayloadPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn add_bundle(&self, bundle: BackrunBundle) {
        self.inner
            .entry(bundle.target_tx_hash)
            .or_default()
            .bundles
            .insert(OrderedBackrunBundle(bundle));
    }

    pub fn get_backruns(
        &self,
        target_tx_hash: &B256,
        mut account_info: impl FnMut(Address) -> Option<AccountInfo>,
        base_fee: u64,
        max_count: usize,
    ) -> Vec<BackrunBundle> {
        let Some(tx_backruns) = self.inner.get(target_tx_hash) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        let mut seen = HashSet::<(Address, u64)>::new();
        let base_fee = base_fee as u128;

        for ordered in tx_backruns.bundles.iter() {
            if result.len() >= max_count {
                break;
            }

            let bundle = &ordered.0;
            let backrun_tx = &bundle.backrun_tx;

            // Base fee check
            if backrun_tx.max_fee_per_gas() < base_fee {
                continue;
            }

            // Recover signer
            let Ok(recovered) = backrun_tx.clone().try_into_recovered() else {
                continue;
            };
            let sender = recovered.signer();
            let nonce = backrun_tx.nonce();

            // Dedup by (address, nonce) — first seen wins (highest priority fee)
            if !seen.insert((sender, nonce)) {
                continue;
            }

            // Account state checks
            let Some(account) = account_info(sender) else {
                continue;
            };

            // Nonce check
            if account.nonce != nonce {
                continue;
            }

            // Balance check: max_fee_per_gas * gas_limit + value
            let max_cost = U256::from(backrun_tx.max_fee_per_gas())
                * U256::from(backrun_tx.gas_limit())
                + U256::from(backrun_tx.value());
            if account.balance < max_cost {
                continue;
            }

            result.push(bundle.clone());
        }

        result
    }
}

impl Default for BackrunBundlePayloadPool {
    fn default() -> Self {
        Self::new()
    }
}
