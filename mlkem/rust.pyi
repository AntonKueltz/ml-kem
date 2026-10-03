from enum import Enum

class ParameterSet(Enum):
    ML_KEM_512 = 512
    ML_KEM_768 = 768
    ML_KEM_1024 = 1024

class ML_KEM:
    """A CCA-secure module-lattice-based key encapsulation mechanism (KEM)."""

    def __init__(self, parameter_set: ParameterSet): ...
    def key_gen(self) -> tuple[bytes, bytes]:
        r"""Generate a keypair (ek, dk) for use in the ML-KEM system.

        The key generation algorithm accepts no input, generates randomness internally, and produces an encapsulation
        key and a decapsulation key. While the encapsulation key can be made public, the decapsulation key shall
        remain private.

        Returns:
            :type:`tuple[bytes, bytes]`: The (encapsulation key, decapulation key) pair.
        """

    def encaps(self, ek: bytes, check_key: bool = True) -> tuple[bytes, bytes]:
        r"""Take an encapsulation key and produce a shared key and ciphertext.

        The shared key can be used as e.g. input to a KDF or as a key for a symmetric cipher between two parties.
        The ciphertext should be sent to the party in possession of the decapsulation key (the ciphertext is an
        encapsulation of the shared key).

        Checking of the encapsulation key is performed by default, but can be disabled by setting the parameter
        :code:`check_key = False`. The spec states "Instead, assurance that these checks have been performed can be
        acquired through other means (see
        `SP 800-227 [1] <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf>`_)".

        Args:
            | ek (:type:`bytes`): The encapsulation key.
            | check_key: (:type:`bool`): Whether or not to check the encapsulation key.

        Returns:
            :type:`tuple[bytes, bytes]`: The (shared key, ciphertext) pair.
        """

    def decaps(self, dk: bytes, c: bytes, check_key: bool = True) -> bytes:
        r"""Takes a decapsulation key and ciphertext as input, does not use any randomness, and outputs a shared
        secret.

        The ciphertext should be produced by :func:`encaps` using the encapsulation key corresponding to the
        decapsulation key that was passed to this method. The result is the shared key, the same as the first value
        in the tuple output by :func:`encaps`.

        Checking of the decapsulation key is performed by default, but can be disabled by setting the parameter
        :code:`check_key = False`. The spec states "Instead, assurance that this check has been performed can be
        acquired through other means (see
        `SP 800-227 [1] <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf>`_)".
        Ciphertext checks are always performed.

        Args:
            | dk (:type:`bytes`): The decapsulation key.
            | c (:type:`bytes`): The ciphertext.
            | check_key: (:type:`bool`): Whether or not to check the decapsulation key.

        Returns:
            :type:`bytes`: The shared key.
        """
