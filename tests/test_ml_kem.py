from unittest import TestCase

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_512


class TestML_KEM(TestCase):
    def test_full(self) -> None:
        ml_kem = ML_KEM(ML_KEM_512)

        ek, dk = ml_kem.key_gen()
        k, c = ml_kem.encaps(ek)
        k_ = ml_kem.decaps(dk, c)

        self.assertEqual(k, k_)
