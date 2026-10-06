from enum import Enum

class ParameterSet(Enum):
    ML_KEM_512 = 512
    ML_KEM_768 = 768
    ML_KEM_1024 = 1024

class EncapsKey:
    def __bytes__(self) -> bytes: ...
    def to_bytes(self) -> bytes: ...
    @property
    def parameter_set(self) -> ParameterSet: ...
    @staticmethod
    def from_bytes(serialized: bytes) -> EncapsKey: ...

class DecapsKey:
    def __bytes__(self) -> bytes: ...
    def to_bytes(self) -> bytes: ...
    @property
    def parameter_set(self) -> ParameterSet: ...
    @staticmethod
    def from_bytes(serialized: bytes) -> DecapsKey: ...

class ML_KEM:
    """A CCA-secure module-lattice-based key encapsulation mechanism (KEM)."""

    def __init__(self, parameter_set: ParameterSet): ...
    def key_gen(self) -> tuple[EncapsKey, DecapsKey]:
        r"""Generate a keypair (ek, dk) for use in the ML-KEM system.

        The key generation algorithm accepts no input, generates randomness internally, and produces an encapsulation
        key and a decapsulation key. While the encapsulation key can be made public, the decapsulation key shall
        remain private.

        Returns:
            :type:`tuple[EncapsKey, DecapsKey]`: The (encapsulation key, decapulation key) pair.
        """

    def encaps(self, ek: EncapsKey) -> tuple[bytes, bytes]:
        r"""Take an encapsulation key and produce a shared key and ciphertext.

        The shared key can be used as e.g. input to a KDF or as a key for a symmetric cipher between two parties.
        The ciphertext should be sent to the party in possession of the decapsulation key (the ciphertext is an
        encapsulation of the shared key).

        Args:
            | ek (:type:`EncapsKey`): The encapsulation key.

        Returns:
            :type:`tuple[bytes, bytes]`: The (shared key, ciphertext) pair.
        """

    def decaps(self, dk: DecapsKey, c: bytes) -> bytes:
        r"""Takes a decapsulation key and ciphertext as input, does not use any randomness, and outputs a shared
        secret.

        The ciphertext should be produced by :func:`encaps` using the encapsulation key corresponding to the
        decapsulation key that was passed to this method. The result is the shared key, the same as the first value
        in the tuple output by :func:`encaps`.

        Args:
            | dk (:type:`DecapsKey`): The decapsulation key.
            | c (:type:`bytes`): The ciphertext.

        Returns:
            :type:`bytes`: The shared key.
        """
