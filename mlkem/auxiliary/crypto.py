from hashlib import sha3_256, sha3_512, shake_128, shake_256


def prf(eta: int, s: bytes, b: bytes) -> bytes:
    r"""A pseudorandom function based on SHAKE-256.

    Args:
        | eta (:type:`int`): A parameter of the ML-KEM instance.
        | s (:type:`bytes`): A seed of 32 bytes.
        | b (:type:`bytes`): The byte encoding of a counter.

    Returns:
        :type:`bytes`: :code:`64 * eta` pseudorandom bytes.
    """

    if eta not in {2, 3}:
        raise ValueError(f"eta must be 2 or 3 (got {eta})")
    if len(s) != 32:
        raise ValueError(f"len(s) must be 32 (got {len(s)})")
    if len(b) != 1:
        raise ValueError(f"len(b) must be 1 (got {len(b)})")

    # length passed to digest is byte length, so omit factor of 8 from spec (which uses bit length)
    return shake_256(s + b).digest(64 * eta)


def h(s: bytes) -> bytes:
    r"""An alias for the SHA3-256 hash function.

    Args:
        | s (:type:`bytes`): The input to be hashed.

    Returns:
        :type:`bytes`: The digest of the input.
    """
    return sha3_256(s).digest()


def j(s: bytes) -> bytes:
    r"""An alias for the SHAKE-256 hash function.

    Args:
        | s (:type:`bytes`): The input to be hashed.

    Returns:
        :type:`bytes`: A 32 byte digest of the input.
    """
    # length passed to digest is byte length, so omit factor of 8 from spec (which uses bit length)
    return shake_256(s).digest(32)


def g(c: bytes) -> tuple[bytes, bytes]:
    r"""An alias for the SHA3-512 hash function.

    The resulting 64 byte output is split into two 32 bytes values.

    Args:
        | s (:type:`bytes`): The input to be hashed.

    Returns:
        :type:`tuple[bytes, bytes]`: The digest of the input, split into two equal-sized values.
    """
    ab = sha3_512(c).digest()
    return ab[:32], ab[32:]


class XOF:
    r"""An eXtendable-Output Function that provides an incremental API for SHAKE-128."""

    def __init__(self) -> None:
        r"""Initialize an instance of the function.

        We use a chunk size of 840 as python's implementation of SHAKE-128 does not allow
        convenient reading of the output of SHAKE-128.
        See https://cryptojedi.org/papers/terminate-20230516.pdf for why this size was chosen.
        """
        #
        self.chunk_size = 840
        self.shake = shake_128()
        self.data = b""
        self.idx = 0

    def absorb(self, string: bytes) -> None:
        r"""Inject data into SHAKE-128 and update the context.

        Args:
            | string (:type:`bytes`): The data being injected.
        """
        self.shake.update(string)
        self.data += self.shake.digest(self.chunk_size)

    def squeeze(self, length: int) -> bytes:
        r"""Extract output bytes from SHAKE-128 and update the context.

        Args:
            | length (:type:`int`): The number of bytes to extract.

        returns:
            :type:`bytes`:n The extracted bytes.
        """
        while self.idx + length > len(self.data):
            self.data += self.shake.digest(self.chunk_size)

        result = self.data[self.idx : self.idx + length]
        self.idx += length
        return result
