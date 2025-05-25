mod flashblocks;
mod standard;

/// Defines the payload building mode for the OP builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuilderMode {
    /// Uses the plain OP payload builder that produces blocks every chain blocktime.
    #[default]
    Standard,
    /// Uses the flashblocks payload builder that progressively builds chunks of a
    /// block every short interval and makes it available through a websocket update
    /// then merges them into a full block every chain block time.
    Flashblocks,
}
