fn main() {
    // Run registered benchmarks.
    divan::main();
}

// Register a `fibonacci` function and benchmark it over multiple cases.
#[divan::bench(args = [1, 2, 4, 8, 16, 32])]
fn test_bench(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        test_bench(n - 2) + test_bench(n - 1)
    }
}
