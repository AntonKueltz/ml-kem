from mlkem.auxiliary.crypto import XOF
from mlkem.auxiliary.general import bytes_to_bits
from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.polynomial_ring import PolynomialRing


def sample_ntt(b: bytes) -> PolynomialRing:
    if len(b) != 34:
        raise ValueError(
            f"Input must be 34 bytes (32-byte seed and two indices). Got {len(b)}."
        )

    a = PolynomialRing()
    xof = XOF()
    xof.absorb(b)

    j = 0
    while j < n:
        c = xof.squeeze(3)
        d1 = c[0] + n * (c[1] % 16)
        d2 = c[1] // 16 + 16 * c[2]

        if d1 < q:
            a[j] = Zm(d1, q)
            j += 1

        if d2 < q and j < n:
            a[j] = Zm(d2, q)
            j += 1

    return a


def sample_poly_cbd(eta: int, b: bytes) -> PolynomialRing:
    if len(b) != 64 * eta:
        raise ValueError(f"Input must be {64 * eta} bytes (got {len(b)}).")

    f = PolynomialRing()
    bits = bytes_to_bits([x for x in b])

    for i in range(n):
        x = sum([bits[i * eta + j] for j in range(eta)])
        y = sum([bits[2 * i * eta + eta + j] for j in range(eta)])
        f[i] = Zm(x - y, q)

    return f
