fn main() {
    // Tell the compiler that `cfg(kani)` is an expected condition so
    // `cargo clippy -- -D warnings` does not flag the proof-harness gates.
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
