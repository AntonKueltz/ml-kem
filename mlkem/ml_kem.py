from os import urandom
from typing import Callable

from mlkem.auxiliary.crypto import g, h, j
from mlkem.auxiliary.general import byte_decode, byte_encode
from mlkem.fast_k_pke import Fast_K_PKE
from mlkem.fastmath import byte_decode_matrix, byte_encode_matrix  # type: ignore
from mlkem.k_pke import K_PKE, PKE_Interface
from mlkem.parameter_set import ML_KEM_768, ParameterSet


class ML_KEM:
    """A CCA-secure module-lattice-based key encapsulation mechanism (KEM)."""

    parameter_set: ParameterSet
    randomness: Callable[[int], bytes]
    fast: bool
    k_pke: PKE_Interface

    def __init__(
        self,
        parameters: ParameterSet = ML_KEM_768,
        randomness: Callable[[int], bytes] = urandom,
        fast: bool = True,
    ):
        self.parameters = parameters
        self.randomness = randomness
        self.fast = fast
        self.k_pke = Fast_K_PKE(parameters) if fast else K_PKE(parameters)

    def key_gen(self) -> tuple[bytes, bytes]:
        r"""Generate a keypair (ek, dk) for use in the ML-KEM system.

        The key generation algorithm accepts no input, generates randomness internally, and produces an encapsulation
        key and a decapsulation key. While the encapsulation key can be made public, the decapsulation key shall
        remain private.

        Returns:
            :type:`tuple[bytes, bytes]`: The (encapsulation key, decapulation key) pair.
        """
        d = self.randomness(32)
        z = self.randomness(32)

        return self._key_gen(d, z)

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        r"""Take an encapsulation key and produce a shared key and ciphertext.

        The shared key can be used as e.g. input to a KDF or as a key for a symmetric cipher between two parties.
        The ciphertext should be sent to the party in possession of the decapsulation key (the ciphertext is an
        encapsulation of the shared key).

        Args:
            | ek (:type:`bytes`): The encapsulation key.

        Returns:
            :type:`tuple[bytes, bytes]`: The (shared key, ciphertext) pair.
        """
        self._check_encaps_input(ek)
        m = self.randomness(32)
        return self._encaps(ek, m)

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        r"""Takes a decapsulation key and ciphertext as input, does not use any randomness, and outputs a shared
        secret.

        The ciphertext should be produced by :func:`encaps` using the encapsulation key corresponding to the
        decapsulation key that was passed to this method. The result is the shared key, the same as the first value
        in the tuple output by :func:`encaps`.

        Args:
            | dk (:type:`bytes`): The decapsulation key.
            | c (:type:`bytes`): The ciphertext.

        Returns:
            :type:`bytes`: The shared key.
        """
        self._check_decaps_input(dk, c)
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

    def _check_encaps_input(self, ek: bytes) -> None:
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

    def _check_decaps_input(self, dk: bytes, c: bytes) -> None:
        k = self.parameters.k

        expected_ciphertext_size = 32 * (self.parameters.du * k + self.parameters.dv)
        if len(c) != expected_ciphertext_size:
            raise ValueError(
                f"Expected ciphertext of size {expected_ciphertext_size}, got {len(c)}."
            )

        expected_key_size = 768 * k + 96
        if len(dk) != expected_key_size:
            raise ValueError(
                f"Expected ciphertext of size {expected_key_size}, got {len(dk)}."
            )

        expected_hash = dk[768 * k + 32 : 768 * k + 64]
        if h(dk[384 * k : 768 * k + 32]) != expected_hash:
            raise ValueError("Encapsulation key hash did not match expected hash.")
