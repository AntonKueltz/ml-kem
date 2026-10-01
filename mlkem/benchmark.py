"""Benchmark ML-KEM operations: ops/sec for each parameter set.

Operations: keygen, encaps, decaps.

Usage:
    python benchmark.py
    python benchmark.py --ops encaps --duration 5 --repeats 7 --json results.json

Replace the import below with wherever ML_KEM and ParameterSet live.
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import statistics
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

from mlkem import ML_KEM, ParameterSet

SHARED_SECRET_LEN = 32


@dataclass(frozen=True)
class Case:
    """One parameter set to benchmark.

    ParameterSet is a PyO3 enum: it can't be iterated, has no .name, and may not
    be hashable, so the benchmark lists the sets explicitly and carries its own
    labels. `sizes` are FIPS 203 sizes in bytes: (ek, dk, ciphertext).
    """

    name: str
    ps: ParameterSet
    sizes: tuple[int, int, int]


CASES = [
    Case("ML_KEM_512", ParameterSet.ML_KEM_512, (800, 1632, 768)),
    Case("ML_KEM_768", ParameterSet.ML_KEM_768, (1184, 2400, 1088)),
    Case("ML_KEM_1024", ParameterSet.ML_KEM_1024, (1568, 3168, 1568)),
]


@dataclass
class Result:
    operation: str
    parameter_set: str
    ops_per_sec_median: float
    ops_per_sec_mean: float
    ops_per_sec_min: float
    ops_per_sec_max: float
    ops_per_sec_stdev: float
    us_per_op_median: float
    iterations_per_round: int
    rounds: int


def calibrate(fn: Callable[[], object], target_seconds: float) -> int:
    """Find an iteration count whose runtime is roughly target_seconds."""
    n = 1
    while True:
        start = time.perf_counter()
        for _ in range(n):
            fn()
        elapsed = time.perf_counter() - start
        if elapsed >= 0.05:  # long enough to be measurable
            return max(1, int(n * target_seconds / elapsed))
        n *= 2


def bench(
    op: str,
    name: str,
    fn: Callable[[], object],
    duration: float,
    repeats: int,
    warmup: float,
) -> Result:
    # Warm-up: caches, branch predictors, CPU frequency ramp.
    end = time.perf_counter() + warmup
    while time.perf_counter() < end:
        fn()

    iters = calibrate(fn, duration / repeats)

    rates: list[float] = []
    gc.collect()
    gc.disable()  # keep GC pauses out of the measurement
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            for _ in range(iters):
                fn()
            elapsed = time.perf_counter() - start
            rates.append(iters / elapsed)
    finally:
        gc.enable()

    median = statistics.median(rates)
    return Result(
        operation=op,
        parameter_set=name,
        ops_per_sec_median=median,
        ops_per_sec_mean=statistics.fmean(rates),
        ops_per_sec_min=min(rates),
        ops_per_sec_max=max(rates),
        ops_per_sec_stdev=statistics.stdev(rates) if len(rates) > 1 else 0.0,
        us_per_op_median=1e6 / median,
        iterations_per_round=iters,
        rounds=repeats,
    )


def make_keygen(case: Case) -> Callable[[], object]:
    ek_len, dk_len, _ = case.sizes
    kem = ML_KEM(case.ps)
    a, b = kem.key_gen()
    if sorted((len(a), len(b))) != sorted((ek_len, dk_len)):
        raise AssertionError(
            f"{case.name} keygen: sizes {(len(a), len(b))}, expected {(ek_len, dk_len)}"
        )
    return kem.key_gen


def make_encaps(case: Case) -> Callable[[], object]:
    ek_len, _, ct_len = case.sizes
    kem = ML_KEM(case.ps)
    keys = kem.key_gen()
    # Don't assume return order: pick the key whose length matches ek.
    ek = next((k for k in keys if len(k) == ek_len), None)
    if ek is None:
        raise AssertionError(f"{case.name}: no key of length {ek_len} in keygen output")

    out = kem.encaps(ek)
    if sorted(len(x) for x in out) != sorted((ct_len, SHARED_SECRET_LEN)):
        raise AssertionError(
            f"{case.name} encaps: sizes {tuple(len(x) for x in out)}, "
            f"expected ct={ct_len}, ss={SHARED_SECRET_LEN}"
        )
    # Fixed ek, keygen excluded from the timed region. Encaps is randomized,
    # so each call still does fresh work.
    return lambda: kem.encaps(ek)


def make_decaps(case: Case) -> Callable[[], object]:
    ek_len, dk_len, ct_len = case.sizes
    kem = ML_KEM(case.ps)
    keys = kem.key_gen()
    ek = next((k for k in keys if len(k) == ek_len), None)
    dk = next((k for k in keys if len(k) == dk_len), None)
    if ek is None or dk is None:
        raise AssertionError(
            f"{case.name}: keygen output lacks ek ({ek_len}) or dk ({dk_len})"
        )

    parts = kem.encaps(ek)
    ct = next((x for x in parts if len(x) == ct_len), None)
    ss = next((x for x in parts if len(x) == SHARED_SECRET_LEN), None)
    if ct is None or ss is None:
        raise AssertionError(
            f"{case.name} encaps: sizes {tuple(len(x) for x in parts)}, "
            f"expected ct={ct_len}, ss={SHARED_SECRET_LEN}"
        )

    # Round-trip check: decaps must recover the encapsulated shared secret.
    if kem.decaps(dk, ct) != ss:
        raise AssertionError(f"{case.name}: decaps(dk, ct) != encaps shared secret")
    # Fixed (dk, ct); keygen and encaps are outside the timed region.
    return lambda: kem.decaps(dk, ct)


OPS: dict[str, Callable[[Case], Callable[[], object]]] = {
    "keygen": make_keygen,
    "encaps": make_encaps,
    "decaps": make_decaps,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ops",
        nargs="+",
        choices=[*OPS, "all"],
        default=["all"],
        help="operations to benchmark (default: all)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=3.0,
        help="total measured seconds per op/parameter set (default: 3)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="rounds per op/parameter set; stats are over rounds (default: 5)",
    )
    parser.add_argument(
        "--warmup",
        type=float,
        default=0.5,
        help="warm-up seconds per op/parameter set (default: 0.5)",
    )
    parser.add_argument("--json", metavar="PATH", help="also write results as JSON")
    args = parser.parse_args()

    selected = list(OPS) if "all" in args.ops else args.ops

    print(
        f"Python {platform.python_version()} on {platform.platform()} ({platform.machine()})"
    )
    print(
        f"ops={selected} duration={args.duration}s repeats={args.repeats} "
        f"warmup={args.warmup}s\n"
    )

    results: list[Result] = []
    for op in selected:
        for case in CASES:
            fn = OPS[op](case)  # includes sanity check
            results.append(
                bench(op, case.name, fn, args.duration, args.repeats, args.warmup)
            )

    header = (
        f"{'op':<8}{'param set':<12}{'ops/sec (med)':>16}{'µs/op':>10}"
        f"{'min':>14}{'max':>14}{'stdev':>12}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.operation:<8}{r.parameter_set:<12}{r.ops_per_sec_median:>16,.0f}"
            f"{r.us_per_op_median:>10.1f}{r.ops_per_sec_min:>14,.0f}"
            f"{r.ops_per_sec_max:>14,.0f}{r.ops_per_sec_stdev:>12,.0f}"
        )

    if args.json:
        payload = {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "results": [asdict(r) for r in results],
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\nWrote {args.json}")


if __name__ == "__main__":
    main()
