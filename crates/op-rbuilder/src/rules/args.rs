use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct RulesArgs {
    /// Enable the rules system for transaction filtering and scoring
    #[arg(
        id = "rules_enabled",
        long = "rules.enabled",
        default_value = "false",
        env = "RULES_ENABLED"
    )]
    pub rules_enabled: bool,

    /// Path to the rules registry configuration file
    #[arg(long = "rules.config-path", env = "RULES_CONFIG_PATH")]
    pub config_path: Option<PathBuf>,
}
