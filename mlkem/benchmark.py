import timeit

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_512, ML_KEM_768, ML_KEM_1024, ParameterSet


def f(params: ParameterSet, fast: bool) -> None:
    ml_kem = ML_KEM(params, fast)
    ek, dk = ml_kem.key_gen()
    k, c = ml_kem.encaps(ek)
    k_ = ml_kem.decaps(dk, c)
    assert k == k_


def run() -> None:
    for fast in (True, False):
        print("===== C Extensions =====" if fast else "===== Pure Python =====")
        for params, name in [
            (ML_KEM_512, "ML_KEM_512"),
            (ML_KEM_768, "ML_KEM_768"),
            (ML_KEM_1024, "ML_KEM_1024"),
        ]:
            time = timeit.timeit(stmt=lambda: f(params, fast), number=1000)
            print(
                f"1000 KeyGen, Encaps and Decaps operations with parameter set {name} took {time:.3f} seconds"
            )


if __name__ == "__main__":
    run()
