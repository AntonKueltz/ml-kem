from mlkem.auxiliary.crypto import XOF
from mlkem.auxiliary.general import bytes_to_bits
from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.polynomial_ring import PolynomialRing, RingRepresentation


def sample_ntt(b: bytes) -> PolynomialRing:
    r"""Take a seed and two indices and sample a pseudorandom elements in :math:`T_q`.

    Args:
        | b (:type:`bytes`): A 32-byte seed concatenated with two one byte indices as :code:`seed + i0 + i1`.

    Returns:
        :type:`mlkem.math.polynomial_ring.PolynomialRing`: A polynomial in NTT representation.
    """
    if len(b) != 34:
        raise ValueError(
            f"Input must be 34 bytes (32-byte seed and two indices). Got {len(b)}."
        )

    a = PolynomialRing(representation=RingRepresentation.NTT)
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
    r"""Take a seed and output a sample from the distribution :math:`\mathcal{D}_{\eta}(R_q)`.

    The distribution :math:`\mathcal{D}_{\eta}(R_q)` is a special distribution of polynomials
    in :math:`R_q` with small coefficients. These are used as "noise" (or, for those familiar
    with \*LWE terminology, "error") terms in the ML-KEM algorithm.

    Args:
        | eta (:type:`int`): A parameter of the ML-KEM instance determining the distribution of the noise.
        | b (:type:`bytes`): A :code:`64 * eta`-byte seed.

    Returns:
        :type:`mlkem.math.polynomial_ring.PolynomialRing`: A polynomial with small coefficients.
    """
    if len(b) != 64 * eta:
        raise ValueError(f"Input must be {64 * eta} bytes (got {len(b)}).")

    f = PolynomialRing(representation=RingRepresentation.STANDARD)
    bits = bytes_to_bits([x for x in b])

    for i in range(n):
        x = sum([bits[2 * i * eta + j] for j in range(eta)])
        y = sum([bits[2 * i * eta + eta + j] for j in range(eta)])
        f[i] = Zm(x - y, q)

    return f
