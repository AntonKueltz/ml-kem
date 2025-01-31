from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.polynomial_ring import PolynomialRing, RingRepresentation

# see Appendix A - Precomputed Values for the NTT
ZETA_LOOKUP = [
    Zm(x, q) for x in
    [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848,
        1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
        1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
        650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
        2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100,
        1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
        939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
        1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
        1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
    ]
]  # fmt: skip

GAMMA_LOOKUP = [
    Zm(x, q) for x in
    [
        17, -17, 2761, -2761, 583, -583, 2649, -2649,
        1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
        1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
        756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
        1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
        1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
        939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
        733, -733, 2337, -2337, 268, -268, 641, -641,
        1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
        375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
        1063, -1063, 319, -319, 2773, -2773, 757, -757,
        2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
        2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
        1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
        1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
        2110, -2110, 2935, -2935, 885, -885, 2154, -2154
    ]
]  # fmt: skip


def ntt(f: PolynomialRing) -> PolynomialRing:
    if f.representation != RingRepresentation.STANDARD:
        raise ValueError(
            "NTT can only be applied to polynomials in standard representation."
        )

    f_ = PolynomialRing(f.coefficients, RingRepresentation.NTT)
    i = 1
    length = 128

    while length >= 2:
        for start in range(0, n, 2 * length):
            zeta = ZETA_LOOKUP[i]
            i += 1

            for j in range(start, start + length):
                t = zeta * f_[j + length]
                f_[j + length] = f_[j] - t
                f_[j] += t

        length //= 2

    return f_


def ntt_inv(f_: PolynomialRing) -> PolynomialRing:
    if f_.representation != RingRepresentation.NTT:
        raise ValueError(
            "Inverse NTT can only be applied to polynomials in NTT representation."
        )

    f = PolynomialRing(f_.coefficients, RingRepresentation.STANDARD)
    i = 127
    length = 2

    while length <= 128:
        for start in range(0, n, 2 * length):
            zeta = ZETA_LOOKUP[i]
            i -= 1

            for j in range(start, start + length):
                t = f[j]
                f[j] = t + f[j + length]
                f[j + length] = zeta * (f[j + length] - t)

        length *= 2

    scale = Zm(3303, q)  # 3303 = 128^{-1} mod q
    for i, fi in enumerate(f.coefficients):
        f[i] = fi * scale

    return f


def multiply_ntt(f_: PolynomialRing, g_: PolynomialRing) -> PolynomialRing:
    if (
        f_.representation != RingRepresentation.NTT
        or g_.representation != RingRepresentation.NTT
    ):
        raise ValueError(
            "NTT multiplication can only be applied to polynomials in NTT representation."
        )

    h_ = PolynomialRing(representation=RingRepresentation.NTT)

    for i in range(128):
        gamma = GAMMA_LOOKUP[i]
        h_[2 * i], h_[2 * i + 1] = _base_case_multiply(
            f_[2 * i], f_[2 * i + 1], g_[2 * i], g_[2 * i + 1], gamma
        )

    return h_


def _base_case_multiply(a0: Zm, a1: Zm, b0: Zm, b1: Zm, gamma: Zm) -> tuple[Zm, Zm]:
    c0 = a0 * b0 + a1 * b1 * gamma
    c1 = a0 * b1 + a1 * b0
    return c0, c1
