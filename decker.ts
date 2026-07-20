// decker (https://github.com/flashbots/decker) manifest for op-rbuilder's local
// devnet. See local-testing/README.md for quickstart.

import { recipe as opstackRecipe, type OpstackOptions } from "./.decker/recipes/opstack.ts";
import type { DeckerProject } from "./.decker/utils/manifest.ts";
import type { Recipe } from "./.decker/utils/types.ts";
import { obsPods } from "./local-testing/decker/obs.ts";

const options: OpstackOptions = {
  // Run op-rbuilder behind rollup-boost
  externalBuilder: "op-rbuilder",
  // Host process instead of pinned op-rbuilder container
  // Use `just devnet` or `make op-rbuilder-profiling` to compile binary.
  builderBinary: "./target/profiling/op-rbuilder",
  // Karst needs 1s+ blocks for local iteration.
  l2BlockTime: 1,
  flashblocks: { blockTimeMs: 200, endBufferMs: 75, sendOffsetMs: -30, continuousBuild: true },
  chainMonitor: true,
};

// Builder's RPC port: decker's op-rbuilder container/process
// prototype hardcodes rpc=9645 (authrpc=9651, metrics=6062) with no options
// surface (recipe or prototype-override) to repin it to builder-playground's
// old :2222 without risking a mismatch between the port it actually binds and
// what other services resolve by name so :9645 is the port to use everywhere
// for this devnet.
const opstack = opstackRecipe(options);

// Prometheus + Grafana appended on top of the opstack recipe's own pods
// (see local-testing/decker/obs.ts).
const recipe: Recipe = { ...opstack, pods: [...opstack.pods, ...obsPods(opstack)] };

export const project: DeckerProject = {
  decker: {
    source: "https://github.com/flashbots/decker.git",
    ref: "main",
    into: ".decker",
  },
  recipe,
  // Docker instead of podman (no rootless podman socket available):
  // target: { pods: "docker-compose" },
};
