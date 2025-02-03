from os import urandom

from mlkem.auxiliary.crypto import g, h, j
from mlkem.auxiliary.general import byte_decode, byte_encode
from mlkem.fast_k_pke import Fast_K_PKE
from mlkem.fastmath import byte_decode_matrix, byte_encode_matrix  # type: ignore
from mlkem.k_pke import K_PKE
from mlkem.parameter_set import ParameterSet


class ML_KEM:
    def __init__(self, parameters: ParameterSet, fast: bool = True):
        self.parameters = parameters
        self.fast = fast
        self.k_pke = Fast_K_PKE(parameters) if fast else K_PKE(parameters)

    def key_gen(self) -> tuple[bytes, bytes]:
        d = urandom(32)
        z = urandom(32)

        return self._key_gen(d, z)

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        self._check_ek(ek)
        m = urandom(32)
        return self._encaps(ek, m)

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        return self._decaps(dk, c)

    def _key_gen(self, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        ek, dk_pke = self.k_pke.key_gen(d)
        dk = dk_pke + ek + h(ek) + z
        return ek, dk

    def _encaps(self, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
        k, r = g(m + h(ek))
        c = self.k_pke.encrypt(ek, m, r)
        return k, c

    def _decaps(self, dk: bytes, c: bytes) -> bytes:
        k = self.parameters.k
        # extract encryption and decryption keys, hash of encryption key, and rejection value
        dk_pke = dk[: 384 * k]
        ek_pke = dk[384 * k : 768 * k + 32]
        h_ = dk[768 * k + 32 : 768 * k + 64]
        z = dk[768 * k + 64 : 768 * k + 96]

        # decrypt ciphertext
        m_prime = self.k_pke.decrypt(dk_pke, c)
        k_prime, r_prime = g(m_prime + h_)
        k_bar = j(z + c)

        # re-encrypt using the derived randomness r_prime
        c_prime = self.k_pke.encrypt(ek_pke, m_prime, r_prime)
        if c != c_prime:
            # if ciphertexts do not match, then implicitly reject
            k_prime = k_bar

        return k_prime

    def _check_ek(self, ek: bytes) -> None:
        k = self.parameters.k

        if len(ek) != 384 * k + 32:
            raise ValueError(f"Expected key of size {384 * k + 32}, got {len(ek)}.")

        if self.fast:
            expected = ek[: 384 * k]
            test = byte_encode_matrix(byte_decode_matrix(ek, 12, k), 12)
            if expected != test:
                raise ValueError(
                    "Encapsulation key contains bytes greater than or equal to q."
                )
        else:
            for i in range(k):
                expected = ek[i * 384 : i * 384 + 384]
                test = byte_encode(12, byte_decode(12, expected))
                if expected != test:
                    raise ValueError(
                        "Encapsulation key contains bytes greater than or equal to q."
                    )
