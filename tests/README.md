# tests/ — lit-style runner

`run_tests.py` is the LLVM-`lit`-inspired driver for the full suite:

```sh
python3 tests/run_tests.py                # discover + run everything in parallel
python3 tests/run_tests.py --list-only    # inventory
python3 tests/run_tests.py --suite t1_     # filter by regex
python3 tests/run_tests.py -j 2           # bound parallelism
```

Outcomes: `PASS`, `FAIL`, `TIMEOUT`, `UNSUPPORTED` (root-only hardware
suites that self-skipped; not a failure). Exit code is non-zero iff any
suite failed or timed out.

The actual test files live inside each crate (`crates/*/tests/`, plus
`#[cfg(test)]` units); this directory contains only the runner. See
`docs/TESTING.md` for the architecture.
