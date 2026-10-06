"""Benchmark ML-KEM operations: ops/sec for each parameter set.

Operations: keygen, encaps, decaps, plus key (de)serialization.

Usage:
    python benchmark.py
    python benchmark.py --ops encaps decaps --duration 5 --repeats 7 --json results.json
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

from mlkem import ML_KEM, DecapsKey, EncapsKey, ParameterSet

SHARED_SECRET_LEN = 32


@dataclass(frozen=True)
class Case:
    """One parameter set to benchmark.

    ParameterSet is a PyO3 enum: it can't be iterated and has no .name, so the
    benchmark lists the sets explicitly and carries its own labels. `sizes` are
    FIPS 203 sizes in bytes: (ek, dk, ciphertext).
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


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _keys(case: Case) -> tuple[ML_KEM, EncapsKey, DecapsKey]:
    """Fresh keypair with size and parameter-set sanity checks."""
    ek_len, dk_len, _ = case.sizes
    kem = ML_KEM(case.ps)
    ek, dk = kem.key_gen()
    _check(
        len(ek.to_bytes()) == ek_len,
        f"{case.name}: ek is {len(ek.to_bytes())} bytes, expected {ek_len}",
    )
    _check(
        len(dk.to_bytes()) == dk_len,
        f"{case.name}: dk is {len(dk.to_bytes())} bytes, expected {dk_len}",
    )
    _check(ek.parameter_set == case.ps, f"{case.name}: ek parameter_set mismatch")
    _check(dk.parameter_set == case.ps, f"{case.name}: dk parameter_set mismatch")
    return kem, ek, dk


def make_keygen(case: Case) -> Callable[[], object]:
    kem, _, _ = _keys(case)  # sanity check only; timed region is key_gen itself
    return kem.key_gen


def make_encaps(case: Case) -> Callable[[], object]:
    _, _, ct_len = case.sizes
    kem, ek, _ = _keys(case)

    ss, ct = kem.encaps(ek)
    _check(
        len(ss) == SHARED_SECRET_LEN, f"{case.name}: shared secret is {len(ss)} bytes"
    )
    _check(
        len(ct) == ct_len,
        f"{case.name}: ciphertext is {len(ct)} bytes, expected {ct_len}",
    )
    # Fixed ek, keygen excluded. Encaps is randomized, so each call does fresh work.
    return lambda: kem.encaps(ek)


def make_decaps(case: Case) -> Callable[[], object]:
    kem, ek, dk = _keys(case)
    ss, ct = kem.encaps(ek)

    # Round-trip check: decaps must recover the encapsulated shared secret.
    _check(
        kem.decaps(dk, ct) == ss, f"{case.name}: decaps(dk, ct) != encaps shared secret"
    )
    # Fixed (dk, ct); keygen and encaps are outside the timed region.
    return lambda: kem.decaps(dk, ct)


def make_ek_to_bytes(case: Case) -> Callable[[], object]:
    _, ek, _ = _keys(case)
    return ek.to_bytes


def make_ek_from_bytes(case: Case) -> Callable[[], object]:
    # Note: deserialization re-expands the matrix A from rho (K^2 sample_ntt
    # calls), so this is expected to be much slower than to_bytes.
    _, ek, _ = _keys(case)
    data = ek.to_bytes()
    _check(
        EncapsKey.from_bytes(data).to_bytes() == data,
        f"{case.name}: ek serialization round trip failed",
    )
    return lambda: EncapsKey.from_bytes(data)


def make_dk_to_bytes(case: Case) -> Callable[[], object]:
    _, _, dk = _keys(case)
    return dk.to_bytes


def make_dk_from_bytes(case: Case) -> Callable[[], object]:
    # Includes the nested ek deserialization (and its matrix expansion).
    kem, ek, dk = _keys(case)
    data = dk.to_bytes()
    dk2 = DecapsKey.from_bytes(data)
    _check(dk2.to_bytes() == data, f"{case.name}: dk serialization round trip failed")
    # A deserialized dk must still decapsulate correctly.
    ss, ct = kem.encaps(ek)
    _check(
        kem.decaps(dk2, ct) == ss, f"{case.name}: decaps with deserialized dk failed"
    )
    return lambda: DecapsKey.from_bytes(data)


OPS: dict[str, Callable[[Case], Callable[[], object]]] = {
    "keygen": make_keygen,
    "encaps": make_encaps,
    "decaps": make_decaps,
    "ek_to_bytes": make_ek_to_bytes,
    "ek_from_bytes": make_ek_from_bytes,
    "dk_to_bytes": make_dk_to_bytes,
    "dk_from_bytes": make_dk_from_bytes,
}

CORE_OPS = ["keygen", "encaps", "decaps"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ops",
        nargs="+",
        choices=[*OPS, "core", "all"],
        default=["core"],
        help="operations to benchmark; 'core' = keygen/encaps/decaps, "
        "'all' adds serialization (default: core)",
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

    if "all" in args.ops:
        selected = list(OPS)
    elif "core" in args.ops:
        selected = CORE_OPS + [o for o in args.ops if o not in ("core", *CORE_OPS)]
    else:
        selected = args.ops

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
        f"{'op':<15}{'param set':<12}{'ops/sec (med)':>16}{'µs/op':>10}"
        f"{'min':>14}{'max':>14}{'stdev':>12}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.operation:<15}{r.parameter_set:<12}{r.ops_per_sec_median:>16,.0f}"
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
