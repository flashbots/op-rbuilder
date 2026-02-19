use clap::Args;

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct BackrunBundleArgs {
    #[arg(long = "backruns.enabled", default_value = "false")]
    pub backruns_enabled: bool,
    #[arg(
        long = "backruns.max_considered_backruns_per_block",
        default_value = "100"
    )]
    pub max_considered_backruns_per_block: usize,
    #[arg(long = "backruns.max_landed_backruns_per_block", default_value = "100")]
    pub max_landed_backruns_per_block: usize,
    #[arg(
        long = "backruns.max_considered_backruns_per_transaction",
        default_value = "10"
    )]
    pub max_considered_backruns_per_transaction: usize,
    #[arg(
        long = "backruns.max_landed_backruns_per_transaction",
        default_value = "1"
    )]
    pub max_landed_backruns_per_transaction: usize,
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
            backruns_enabled: false,
            max_considered_backruns_per_block: 100,
            max_landed_backruns_per_block: 100,
            max_considered_backruns_per_transaction: 10,
            max_landed_backruns_per_transaction: 1,
        }
    }
}
