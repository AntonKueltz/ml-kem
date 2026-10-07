from unittest import TestCase

from mlkem import ML_KEM, DecapsKey, EncapsKey, ParameterSet

ROUNDS = 1000


class TestML_KEM(TestCase):
    def test_512_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_512)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            ek_bytes, dk_bytes = bytes(ek), bytes(dk)
            ek, dk = EncapsKey.from_bytes(ek_bytes), DecapsKey.from_bytes(dk_bytes)

            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)

    def test_768_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_768)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            ek_bytes, dk_bytes = bytes(ek), bytes(dk)
            ek, dk = EncapsKey.from_bytes(ek_bytes), DecapsKey.from_bytes(dk_bytes)

            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)

    def test_1024_params_full(self) -> None:
        kem = ML_KEM(ParameterSet.ML_KEM_1024)
        for _ in range(ROUNDS):
            ek, dk = kem.key_gen()
            ek_bytes, dk_bytes = bytes(ek), bytes(dk)
            ek, dk = EncapsKey.from_bytes(ek_bytes), DecapsKey.from_bytes(dk_bytes)

            k, c = kem.encaps(ek)
            k_ = kem.decaps(dk, c)
            self.assertEqual(k, k_)
