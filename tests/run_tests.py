#!/usr/bin/env python3
"""
lit-style test runner for discCleaner (LLVM-test-style harness).

Inspired by LLVM's `lit` harness: discovers test suites by pattern, executes
them in parallel, reports PASS/FAIL/UNSUPPORTED per test with a summary and
a non-zero exit on any failure.

Usage:
    python3 tests/run_tests.py [--suite REGEX] [-j JOBS] [--list-only]

Test inventory (discovered dynamically):
    * `cargo test --lib -p <crate>`          unit tests per crate
    * `cargo test --test <integration>`      integration suites in dc-cli/dc-testkit

Root-privileged hardware suites (loop devices, real ioctls) self-skip inside
the tests when EUID != 0; the runner reflects that as UNSUPPORTED, which does
not fail the run.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class TestResult:
    name: str
    outcome: str  # PASS | FAIL | UNSUPPORTED | TIMEOUT
    duration_s: float
    log: str = field(default="")
    detail: str = field(default="")


def crate_name_of(manifest_path: Path) -> str | None:
    """Parse the [package].name from a Cargo.toml."""
    name = None
    in_package = False
    for line in manifest_path.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_package = False
            continue
        if in_package and stripped.startswith("name"):
            _, _, v = stripped.partition("=")
            name = v.strip().strip('"')
            break
    return name


def has_lib_target(manifest_path: Path) -> bool:
    text = manifest_path.read_text()
    return bool(re.search(r"^\s*\[\s*lib\s*\]", text, re.M))


def discover_suites() -> list[tuple[str, list[str]]]:
    """Discover every cargo test target in the workspace."""
    suites: list[tuple[str, list[str]]] = []

    for cargo in sorted(REPO_ROOT.rglob("Cargo.toml")):
        rel = cargo.parent.relative_to(REPO_ROOT)
        if "target" in rel.parts:
            continue
        if rel.as_posix() == ".":
            continue  # virtual workspace manifest
        crate = crate_name_of(cargo)
        if crate and has_lib_target(cargo):
            suites.append((f"unit/{rel.as_posix()}", ["cargo", "test", "--lib", "-p", crate]))

        tests_dir = cargo.parent / "tests"
        if tests_dir.is_dir():
            for f in sorted(tests_dir.glob("*.rs")):
                if crate:
                    suites.append(
                        (
                            f"integration/{rel.as_posix()}/{f.stem}",
                            ["cargo", "test", "-p", crate, "--test", f.stem],
                        )
                    )
    return suites


def is_root() -> bool:
    return os.geteuid() == 0


HARDWARE_SUITES = re.compile(
    r"(t1_zero_trust|t2_fault_injection|t3_crash_recovery|t4_guardian_matrix|"
    r"t5_lvm_matrix|t6_tamper_matrix|t10_hardware_matrix|t11_interrupt_matrix|"
    r"t17_purge_verify_matrix|g7_operator|t9_cert|t7_identity|"
    r"t8_prng|t12_truncation|t13_|t14_|t15_|t16_|t18_|t19_|t20_|t21_|t22_|t23_|"
    r"m1_|m2_)"
)


def run_one(entry: tuple[str, list[str]]) -> TestResult:
    name, argv = entry
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=45 * 60,
        )
    except subprocess.TimeoutExpired:
        return TestResult(name, "TIMEOUT", time.monotonic() - start, "", "exceeded 45m budget")
    dur = time.monotonic() - start
    log = proc.stdout + proc.stderr

    if proc.returncode == 0:
        skipped = "[SKIP]" in log
        if skipped and not is_root() and HARDWARE_SUITES.search(name):
            return TestResult(name, "UNSUPPORTED", dur, log, "requires root (self-skipped)")
        return TestResult(name, "PASS", dur, log)

    return TestResult(name, "FAIL", dur, log, f"exit code {proc.returncode}")


def main() -> int:
    ap = argparse.ArgumentParser(description="lit-style runner for discCleaner")
    ap.add_argument("--suite", default=None, help="regex filter on suite names")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()

    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.is_dir() and str(cargo_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{cargo_bin}:{os.environ['PATH']}"

    suites = discover_suites()
    if args.suite:
        rx = re.compile(args.suite)
        suites = [s for s in suites if rx.search(s[0])]

    if args.list_only:
        for name, _ in suites:
            print(name)
        return 0

    print(f"-- discCleaner lit-runner: {len(suites)} suites, {args.jobs} jobs")
    results: list[TestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = [pool.submit(run_one, s) for s in suites]
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            marker = {"PASS": "PASS", "FAIL": "FAIL", "UNSUPPORTED": "UNSUP", "TIMEOUT": "TMOUT"}[r.outcome]
            print(f"[{i:>3}/{len(suites)}] {marker:<5} {r.name} ({r.duration_s:.1f}s)")

    order = {"FAIL": 0, "TIMEOUT": 1, "PASS": 2, "UNSUPPORTED": 3}
    results.sort(key=lambda r: (order[r.outcome], r.name))

    counts = {k: sum(1 for r in results if r.outcome == k) for k in ("PASS", "FAIL", "UNSUPPORTED", "TIMEOUT")}
    print("\n" + "=" * 72)
    for r in results:
        if r.outcome in ("FAIL", "TIMEOUT"):
            print(f"{r.outcome}: {r.name} ({r.detail})")
    print("=" * 72)
    print(
        f"Total: {len(results)} | PASS {counts['PASS']} | FAIL {counts['FAIL']} | "
        f"UNSUPPORTED {counts['UNSUPPORTED']} | TIMEOUT {counts['TIMEOUT']}"
    )
    if not is_root():
        print("note: not running as root; hardware-dependent suites self-skip (UNSUPPORTED)")
    return 1 if (counts["FAIL"] or counts["TIMEOUT"]) else 0


if __name__ == "__main__":
    sys.exit(main())
