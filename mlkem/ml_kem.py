from os import urandom

from mlkem.auxiliary.crypto import g, h
from mlkem.auxiliary.general import byte_decode, byte_encode
from mlkem.k_pke import K_PKE
from mlkem.parameter_set import ParameterSet


class ML_KEM:
    def __init__(self, parameters: ParameterSet):
        self.parameters = parameters
        self.k_pke = K_PKE(parameters)

    def key_gen(self) -> tuple[bytes, bytes]:
        d = urandom(32)
        z = urandom(32)

        return self._key_gen(d, z)

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        if not self._check_ek(ek):
            raise ValueError("Encapsulation key is not valid.")

        m = urandom(32)
        return self._encaps(m, ek)

    def _key_gen(self, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        ek, dk_pke = self.k_pke.key_gen(d)
        dk = dk_pke + ek + h(ek) + z
        return ek, dk

    def _encaps(self, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
        k, r = g(m + h(ek))
        c = self.k_pke.encrypt(ek, m, r)
        return k, c

    def _check_ek(self, ek: bytes) -> bool:
        k = self.parameters.k

        if len(ek) != 384 * k + 32:
            return False

        expected = ek[: 384 * k]
        test = byte_encode(12, byte_decode(12, expected))
        if expected != test:
            return False

        return True
