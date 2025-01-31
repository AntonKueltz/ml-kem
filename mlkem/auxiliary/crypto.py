from hashlib import sha3_256, sha3_512, shake_128, shake_256


def prf(eta: int, s: bytes, b: bytes) -> bytes:
    if eta not in {2, 3}:
        raise ValueError(f"eta must be 2 or 3 (got {eta})")
    if len(s) != 32:
        raise ValueError(f"len(s) must be 32 (got {len(s)})")
    if len(b) != 1:
        raise ValueError(f"len(b) must be 1 (got {len(b)})")

    # length passed to digest is byte length, so omit factor of 8 from spec (which uses bit length)
    return shake_256(s + b).digest(64 * eta)


def h(s: bytes) -> bytes:
    return sha3_256(s).digest()


def j(s: bytes) -> bytes:
    # length passed to digest is byte length, so omit factor of 8 from spec (which uses bit length)
    return shake_256(s).digest(32)


def g(c: bytes) -> tuple[bytes, bytes]:
    ab = sha3_512(c).digest()
    return ab[:32], ab[32:]


class XOF:
    def __init__(self) -> None:
        # https://cryptojedi.org/papers/terminate-20230516.pdf
        self.chunk_size = 840
        self.shake = shake_128()
        self.data = b""
        self.idx = 0

    def absorb(self, string: bytes) -> None:
        self.shake.update(string)
        self.data += self.shake.digest(self.chunk_size)

    def squeeze(self, length: int) -> bytes:
        while self.idx + length > len(self.data):
            self.data += self.shake.digest(self.chunk_size)

        result = self.data[self.idx : self.idx + length]
        self.idx += length
        return result
