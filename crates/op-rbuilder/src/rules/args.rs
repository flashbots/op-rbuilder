use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct RulesArgs {
    /// Path to the txpool policy configuration file.
    ///
    /// This file controls ingress filtering and ordering regimes.
    #[arg(long = "rules.config-path", env = "RULES_CONFIG_PATH")]
    pub config_path: Option<PathBuf>,
}
