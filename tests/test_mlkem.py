from unittest import TestCase

from mlkem import ML_KEM, ParameterSet

ROUNDS = 1000


class TestML_KEM(TestCase):
    def test_512_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_512)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)

    def test_768_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_768)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)

    def test_1024_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_1024)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)
