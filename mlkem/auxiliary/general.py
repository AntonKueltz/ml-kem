from mlkem.math.constants import n, q
from mlkem.math.field import Zm

BITS_IN_BYTE = 8
MAX_D = q.bit_length()


def bits_to_bytes(bits: list[int]) -> list[int]:
    """Converts a bit array (of a length that is a multiple of 8) into an array of bytes.

    Bytes are represented as unsigned numbers in the range [0, 255]. Bits are either 0 or 1.

    Args:
        | bits (:type:`list[int]`): The bit array (of a length that is a multiple of 8).

    Returns:
        :type:`list[int]`: The array of bytes equivalent to the bit array.
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
        | byts (:type:`list[int]`): The byte array.

    Returns:
        :type:`list[int]`: The array of bits equivalent to the byte array.
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
    r"""Map an element from :math:`\mathbb{Z}_q` to :math:`\mathbb{Z}_{2^d}`.

    Note that :math:`q` is 12 bits and :math:`d` must be less than 12 bits, so this
    operation is always lossy.

    Args:
        | d (:type:`int`): The number of bits (0 < d < 12) to compress :code:`x` to.
        | x (:type:`mlkem.math.field.Zm`): An element of :math:`\mathbb{Z}_q`.

    Returns:
        :type:`mlkem.math.field.Zm`: :code:`x` compressed to an element of :math:`\mathbb{Z}_{2^d}`.
    """
    if not d < MAX_D:
        raise ValueError(f"d must be less than {MAX_D} (got {d}).")
    if x.m != q:
        raise ValueError(f"Element being compressed must be in Z_q (got Z_{x.m}).")

    m = 1 << d
    val = _round_fraction(m * x.val, q) % m
    return Zm(val, m)


def decompress(d: int, y: Zm) -> Zm:
    r"""Map an element from :math:`\mathbb{Z}_{2^d}` to :math:`\mathbb{Z}_q`.

    Args:
        | d (:type:`int`): The number of bits (0 < d < 12) to decompress :code:`x` from.
        | x (:type:`mlkem.math.field.Zm`): An element of :math:`\mathbb{Z}_{2^d}`.

    Returns:
        :type:`mlkem.math.field.Zm`: :code:`x` decompressed to an element of :math:`\mathbb{Z}_q`.
    """
    if not d < MAX_D:
        raise ValueError(f"d must be less than {MAX_D} (got {d}).")

    m = 1 << d
    val = _round_fraction(q * y.val, m)
    return Zm(val, q)


def byte_encode(d: int, f: list[Zm]) -> bytes:
    r"""Encode a list of integers into bytes.

    The integers are all interpreted as d-bits in size, with :math:`1 \le d \le 12`.

    Args:
        | d (:type:`int`): The bit size of the integers in the list.
        | f (:type:`list[mlkem.math.field.Zm]`): The integer list. If d=12 then the field order is :code:`mlkem.math.constants.q`, otherwise it is :code:`2**d`.

    Returns:
        :type:`bytes`: The byte-encoding of the integer list.
    """
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

    return bytes(bits_to_bytes(b))


def byte_decode(d: int, b: bytes) -> list[Zm]:
    r"""Decode bytes into a list of integers.

    Bytes are parsed as d-bit integers, with :math:`1 \le d \le 12`.

    Args:
        | d (:type:`int`): The bit size of the integers in the list.
        | b (:type:`bytes`): The byte-encoding of an integer list.

    Returns:
        :type:`list[mlkem.math.field.Zm]`: The decoded integer list. If d=12 then the field order is :code:`mlkem.math.constants.q`, otherwise it is :code:`2**d`.
    """
    if d > MAX_D or d < 1:
        raise ValueError(f"d may not be greater than {MAX_D} or less than 1 (got {d}).")

    m = q if d == MAX_D else 1 << d
    bits = bytes_to_bits([x for x in b])

    f = []
    for i in range(n):
        fi = sum([bits[i * d + j] * (1 << j) for j in range(d)])
        fi_m = Zm(fi, m)
        f.append(fi_m)

    return f
