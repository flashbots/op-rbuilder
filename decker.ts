// decker (https://github.com/flashbots/decker) manifest for op-rbuilder's local
// devnet — the primary local dev flow; see local-testing/README.md for
// prerequisites/quickstart. builder-playground (local-testing/playground.yaml)
// is kept as a deprecated fallback for the duration of the migration.
//
// Requires three decker opstack options not yet on `main` as of 2026-07-20:
//   - builderBinary (jules/opstack-builder-process): run op-rbuilder as a host process
//   - flashblocks   (jules/opstack-flashblocks):     op-rbuilder's flashblocks ws stream
//   - chainMonitor  (jules/opstack-chain-monitor):   chain-monitor sidecar
// Until they land on flashbots/decker main, point `source` below at a local
// checkout of their tip instead, e.g.:
//   source: "file:///path/to/decker-chain-monitor", ref: "HEAD",

// A post-up hook. Author each in its own module typed against decker's real
// `Script`/`Recipe` (from your clone); here the array just needs to accept them,
// so the parameter is left open.
type Script = (recipe: never) => void | Promise<void>;

// A Recipe value, or a Prototype value keyed by name in `prototypes`. Build
// these in their own modules typed against decker's real `Recipe`/`Prototype`
// (from your clone); here they're left open so this file stays self-contained.
type Recipe = Record<string, unknown>;
type Prototype = Record<string, unknown>;

type DeckerProject = {
  decker: {
    source: string;
    ref: string;
    into?: string;
  };
  recipe: string | Recipe;
  options?: Record<string, unknown>;
  prototypes?: {
    pods?: Record<string, Prototype>;
    processes?: Record<string, Prototype>;
  };
  scripts?: Script[];
  target?: {
    pods?: string;
    processes?: string;
  };
};

export const project: DeckerProject = {
  decker: {
    source: "https://github.com/flashbots/decker.git",
    ref: "main",
    into: ".decker",
  },
  recipe: "opstack",
  options: {
    // Run a real op-rbuilder behind rollup-boost instead of the sequencer EL
    // building its own blocks.
    externalBuilder: "op-rbuilder",
    // Host process instead of the pinned container, so this devnet always runs
    // your local op-rbuilder checkout. `just devnet` builds this exact binary
    // (`make op-rbuilder-profiling`) before starting decker, and `just` always
    // runs recipes from this justfile's directory, so the relative path below
    // resolves correctly through `just devnet`. It does NOT resolve relative to
    // this file — a bare `decker start`/`up` run from elsewhere would resolve it
    // against that shell's cwd instead (decker never chdirs; see the
    // builderBinary option doc in the opstack recipe). cd here first if you
    // invoke decker directly instead of through `just devnet`.
    builderBinary: "./target/profiling/op-rbuilder",
    // Karst (the default l2Fork) needs 1s+ blocks to be useful for local iteration.
    l2BlockTime: 1,
    // builder-playground's tuned cadence — these numbers are also flashblocks'
    // own defaults; spelled out here for discoverability. ws stream on :1111.
    flashblocks: { blockTimeMs: 200, endBufferMs: 75, sendOffsetMs: -30, continuousBuild: true },
    // Sidecar watching L1 + L2 for stalled/missed blocks + the builder's wallet.
    chainMonitor: true,
  },
  // Note on the builder's RPC port: decker's op-rbuilder container/process
  // prototype hardcodes rpc=9645 (authrpc=9651, metrics=6062) with no options
  // surface (recipe or prototype-override) to repin it to builder-playground's
  // old :2222 without risking a mismatch between the port it actually binds and
  // what other services resolve by name (see local-testing/README.md's service
  // table) — so :9645 is the port to use everywhere for this devnet.
  //
  // Docker instead of podman (no rootless podman socket available):
  // target: { pods: "docker-compose" },
};
