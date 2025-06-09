use op_rbuilder::{
    args::{Cli, CliExt},
    launcher::launch,
};

// Prefer jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> eyre::Result<()> {
    let cli = Cli::parsed();
    launch(cli)
}
