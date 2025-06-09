use op_rbuilder::launcher::launch;

fn main() -> eyre::Result<()> {
    // Prefer jemalloc for performance reasons.
    #[cfg(all(feature = "jemalloc", unix))]
    #[global_allocator]
    static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

    launch()
}
