from mlkem.math.constants import n, q
from mlkem.math.field import Zm

BITS_IN_BYTE = 8
MAX_D = q.bit_length()


def bits_to_bytes(bits: list[int]) -> list[int]:
    """Converts a bit array (of a length that is a multiple of 8) into an array of bytes.

    Bytes are represented as unsigned numbers in the range [0, 255]. Bits are either 0 or 1.

    Args:
        bits (list[int]): The bit array (of a length that is a multiple of 8).

    Returns:
        list[int]: The array of bytes equivalent to the bit array.
    """
    length = len(bits)
    if length % BITS_IN_BYTE != 0:
        raise ValueError(
            f"Bit array must have a length that is a multiple of 8 (got {length})."
        )

    result = [0 for _ in range(length // BITS_IN_BYTE)]
    for i in range(length):
        bitval = bits[i] * (1 << (i % BITS_IN_BYTE))
        result[i // BITS_IN_BYTE] = result[i // BITS_IN_BYTE] + bitval

    return result


def bytes_to_bits(byts: list[int]) -> list[int]:
    """Converts a byte array into an array of bits.

    Bytes are represented as unsigned numbers in the range [0, 255]. Bits are either 0 or 1.

    Args:
        byts (list[int]): The byte array.

    Returns:
        list[int]: The array of bits equivalent to the byte array.
    """
    c = byts.copy()

    result: list[int] = []
    for i in range(len(c)):
        for _ in range(BITS_IN_BYTE):
            result.append(c[i] & 1)
            c[i] //= 2

    return result


def _round_fraction(x: int, y: int) -> int:
    """Round the fraction x/y to the nearest integer."""
    return (2 * x + y) // (2 * y)


def compress(d: int, x: Zm) -> Zm:
    if not d < MAX_D:
        raise ValueError(f"d must be less than {MAX_D} (got {d}).")
    if x.m != q:
        raise ValueError(f"Element being compressed must be in Z_q (got Z_{x.m}).")

    m = 1 << d
    val = _round_fraction(m * x.val, q) % m
    return Zm(val, m)


def decompress(d: int, y: Zm) -> Zm:
    if not d < MAX_D:
        raise ValueError(f"d must be less than {MAX_D} (got {d}).")

    m = 1 << d
    val = _round_fraction(q * y.val, m)
    return Zm(val, q)


def byte_encode(d: int, f: list[Zm]) -> list[int]:
    if len(f) != n:
        raise ValueError(f"f must have {n} elements (got {len(f)}).")

    if d > MAX_D or d < 1:
        raise ValueError(f"d may not be greater than {MAX_D} or less than 1 (got {d}).")

    b = [0 for _ in range(n * d)]
    for i in range(n):
        a = f[i].val

        for j in range(d):
            x = a & 1
            b[i * d + j] = x
            a = (a - x) // 2

    return bits_to_bytes(b)


def byte_decode(d: int, b: list[int]) -> list[Zm]:
    if d > MAX_D or d < 1:
        raise ValueError(f"d may not be greater than {MAX_D} or less than 1 (got {d}).")

    m = q if d == MAX_D else 1 << d
    bits = bytes_to_bits(b)

    f = []
    for i in range(n):
        fi = sum([bits[i * d + j] * (1 << j) for j in range(d)])
        fi_m = Zm(fi, m)
        f.append(fi_m)

    return f
