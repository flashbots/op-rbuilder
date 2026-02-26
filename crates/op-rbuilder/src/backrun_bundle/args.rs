//! # Enabling backruns
//!
//! Backrun processing is **off by default**. Pass `--backruns.enabled` to turn it on.
//! Additional CLI flags control how many backruns the builder will evaluate and
//! include per block and per transaction:
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `--backruns.enabled` | `false` | Master switch |
//! | `--backruns.max_considered_backruns_per_block` | `100` | Candidates evaluated per block |
//! | `--backruns.max_landed_backruns_per_block` | `100` | Included backruns per block |
//! | `--backruns.max_considered_backruns_per_transaction` | `10` | Candidates evaluated per tx |
//! | `--backruns.max_landed_backruns_per_transaction` | `1` | Included backruns per tx |
//! | `--backruns.enforce_strict_priority_fee_ordering` | `false` | Require backrun and tx priority fee to match and order backruns by coinbase profit |

use clap::Args;

const DEFAULT_BACKRUNS_ENABLED: bool = false;
const DEFAULT_MAX_CONSIDERED_PER_BLOCK: usize = 100;
const DEFAULT_MAX_LANDED_PER_BLOCK: usize = 100;
const DEFAULT_MAX_CONSIDERED_PER_TRANSACTION: usize = 10;
const DEFAULT_MAX_LANDED_PER_TRANSACTION: usize = 1;
const DEFAULT_ENFORCE_STRICT_PRIORITY_FEE_ORDERING: bool = false;

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct BackrunBundleArgs {
    #[arg(long = "backruns.enabled", default_value_t = DEFAULT_BACKRUNS_ENABLED)]
    pub backruns_enabled: bool,
    #[arg(
        long = "backruns.max_considered_backruns_per_block",
        default_value_t = DEFAULT_MAX_CONSIDERED_PER_BLOCK
    )]
    pub max_considered_backruns_per_block: usize,
    #[arg(long = "backruns.max_landed_backruns_per_block", default_value_t = DEFAULT_MAX_LANDED_PER_BLOCK)]
    pub max_landed_backruns_per_block: usize,
    #[arg(
        long = "backruns.max_considered_backruns_per_transaction",
        default_value_t = DEFAULT_MAX_CONSIDERED_PER_TRANSACTION
    )]
    pub max_considered_backruns_per_transaction: usize,
    #[arg(
        long = "backruns.max_landed_backruns_per_transaction",
        default_value_t = DEFAULT_MAX_LANDED_PER_TRANSACTION
    )]
    pub max_landed_backruns_per_transaction: usize,
    #[arg(
        long = "backruns.enforce_strict_priority_fee_ordering",
        default_value_t = DEFAULT_ENFORCE_STRICT_PRIORITY_FEE_ORDERING
    )]
    pub enforce_strict_priority_fee_ordering: bool,
}

impl BackrunBundleArgs {
    pub fn is_limit_reached(
        &self,
        block_backruns_considered: usize,
        block_backruns_landed: usize,
        tx_backruns_considered: usize,
        tx_backruns_landed: usize,
    ) -> bool {
        tx_backruns_considered >= self.max_considered_backruns_per_transaction
            || tx_backruns_landed >= self.max_landed_backruns_per_transaction
            || block_backruns_considered >= self.max_considered_backruns_per_block
            || block_backruns_landed >= self.max_landed_backruns_per_block
    }
}

impl Default for BackrunBundleArgs {
    fn default() -> Self {
        Self {
            backruns_enabled: DEFAULT_BACKRUNS_ENABLED,
            max_considered_backruns_per_block: DEFAULT_MAX_CONSIDERED_PER_BLOCK,
            max_landed_backruns_per_block: DEFAULT_MAX_LANDED_PER_BLOCK,
            max_considered_backruns_per_transaction: DEFAULT_MAX_CONSIDERED_PER_TRANSACTION,
            max_landed_backruns_per_transaction: DEFAULT_MAX_LANDED_PER_TRANSACTION,
            enforce_strict_priority_fee_ordering: DEFAULT_ENFORCE_STRICT_PRIORITY_FEE_ORDERING,
        }
    }
}
