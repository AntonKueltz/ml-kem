from unittest import TestCase

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_512, ML_KEM_768, ML_KEM_1024, ParameterSet

from parameterized import parameterized  # type: ignore


class TestML_KEM(TestCase):
    @parameterized.expand([ML_KEM_512, ML_KEM_768, ML_KEM_1024])
    def test_full(self, params: ParameterSet) -> None:
        ml_kem = ML_KEM(params)

        ek, dk = ml_kem.key_gen()
        k, c = ml_kem.encaps(ek)
        k_ = ml_kem.decaps(dk, c)

        self.assertEqual(k, k_)
