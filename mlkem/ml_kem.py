from os import urandom

from mlkem.auxiliary.crypto import h
from mlkem.k_pke import K_PKE
from mlkem.parameter_set import ParameterSet


class ML_KEM:
    def __init__(self, parameters: ParameterSet):
        self.k_pke = K_PKE(parameters)

    def key_gen(self) -> tuple[bytes, bytes]:
        d = urandom(32)
        z = urandom(32)

        return self._key_gen(d, z)

    def _key_gen(self, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        ek, dk_pke = self.k_pke.key_gen(d)
        dk = dk_pke + ek + h(ek) + z
        return ek, dk
