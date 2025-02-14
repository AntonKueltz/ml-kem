from os import urandom
from random import randint
from unittest import TestCase

from mlkem.auxiliary.sampling import sample_ntt
from mlkem.fastmath import byte_decode_matrix, byte_encode_matrix, mul_matrix, ntt_inv  # type: ignore
from mlkem.math.constants import n, q
from mlkem.math.matrix import Matrix
from mlkem.math.polynomial_ring import PolynomialRing


class TestFastMath(TestCase):
    def test_fast_ntt_inv(self) -> None:
        initial = [
            1837, 3137, 1722, 738, 222, 252, 512, 591, 630, 2953, 635, 1388, 3151, 1951, 272, 319,3323, 2008, 3211, 913,
            3201, 2394, 2264, 1162, 391, 3048, 474, 2331, 486, 1801, 3093, 705, 745, 404, 1554, 1687, 2846, 926, 604,
            2476, 1789, 158, 277, 3273, 1007, 2208, 1001, 1442, 1312, 257, 238, 335, 1621, 612, 3073, 2384, 1908, 3278,
            1786, 1397, 2512, 2377, 1605, 1030, 2885, 527, 2722, 1458, 2097, 614, 651, 2737, 2555, 825, 2274, 1764,
            2117, 1211, 2445, 1843, 3192, 2277, 2325, 344, 2555, 2372, 147, 414, 1884, 79, 3139, 3147, 2897, 1991, 963,
            2818, 2821, 2609, 1050, 1214, 475, 1508, 1635, 1788, 416, 1087, 1844, 1519, 1079, 278, 3001, 2929, 2601,
            390, 1011, 2914, 2031, 3043, 2277, 2956, 2894, 2924, 3167, 9, 189, 1205, 2609, 2470, 3178, 1543, 657, 2301,
            3302, 837, 1334, 3227, 2240, 2479, 71, 1137, 1895, 2831, 2807, 2297, 194, 473, 841, 366, 529, 2843, 652,
            2901, 3088, 90, 590, 1577, 1321, 815, 2258, 1889, 1111, 1154, 1334, 1218, 25, 323, 2045, 1646, 744, 2317,
            56, 2622, 1928, 1223, 949, 853, 1859, 809, 955, 560, 921, 572, 1281, 672, 1423, 1505, 2362, 2612, 1081,
            1409, 2327, 2834, 31, 1550, 2603, 3163, 2379, 1476, 1562, 2905, 1791, 337, 1322, 2406, 1815, 2940, 669,
            1112, 1223, 2749, 2982, 1493, 3164, 2380, 1054, 3074, 2717, 622, 304, 2765, 2266, 278, 2994, 1921, 2476,
            2920, 2146, 453, 1722, 1412, 1890, 3189, 52, 552, 2403, 1154, 3275, 3201, 3233, 2242, 615, 369, 366, 1350,
            725, 3307, 1950, 2849, 1806, 1805, 1532, 2553, 1027, 2607, 482, 2117
        ]  # fmt: skip
        expected = [
            1, 0, 3328, 1, 3328, 0, 0, 2, 0, 3328, 1, 0, 2, 2, 0, 3328, 3328, 2, 1, 3328, 3328, 1, 3328, 1, 0, 0, 1,
            3328, 3328, 1, 3327, 0, 3328, 0, 1, 1, 0, 1, 0, 0, 3328, 3327, 1, 0, 3328, 0, 1, 1, 3328, 0, 3328, 2, 1, 0,
            0, 2, 1, 2, 1, 3328, 0, 1, 3326, 3327, 1, 0, 0, 2, 3326, 3328, 0, 3328, 3328, 3327, 1, 3328, 3328, 3327, 0,
            0, 1, 2, 3, 2, 1, 3327, 3328, 0, 3, 1, 0, 0, 2, 1, 0, 0, 3328, 3327, 0, 0, 1, 1, 0, 1, 1, 3328, 3327, 1, 1,
            3328, 0, 0, 0, 3327, 3328, 2, 1, 0, 3328, 1, 3327, 1, 0, 0, 3327, 3328, 2, 0, 0, 0, 1, 0, 1, 3328, 0, 1, 0,
            3328, 3328, 1, 1, 1, 3328, 2, 1, 1, 1, 3328, 3328, 3328, 3328, 3328, 2, 1, 1, 3328, 1, 0, 0, 1, 3328, 1,
            3328, 1, 1, 2, 3, 0, 0, 0, 3328, 0, 0, 1, 2, 3328, 3327, 3327, 1, 1, 3328, 3328, 3328, 1, 1, 2, 0, 3328, 1,
            3328, 3328, 3327, 0, 0, 0, 3328, 3328, 1, 0, 1, 3326, 3327, 3328, 3327, 1, 2, 3326, 3328, 1, 0, 0, 0, 1, 0,
            0, 3, 3, 3327, 1, 3328, 3328, 0, 0, 2, 1, 3328, 0, 0, 0, 0, 0, 0, 3328, 0, 0, 1, 0, 0, 0, 3328, 3328, 3328,
            0, 3327, 0, 1, 3328, 3328, 0, 3328, 0, 2, 0, 0, 1, 3328
        ]  # fmt: skip

        actual = ntt_inv(initial)

        self.assertEqual(expected, actual)

    def test_fast_mul_matrix(self) -> None:
        x: Matrix[PolynomialRing] = Matrix(
            rows=2, cols=2, entries=[sample_ntt(urandom(34)) for _ in range(4)]
        )
        y: Matrix[PolynomialRing] = Matrix(
            rows=2, cols=1, entries=[sample_ntt(urandom(34)) for _ in range(2)]
        )
        z: Matrix[PolynomialRing] = x * y
        expected = [[b.val for b in a.coefficients] for a in z.entries]

        x_ = [[b.val for b in a.coefficients] for a in x.entries]
        y_ = [[b.val for b in a.coefficients] for a in y.entries]
        actual = mul_matrix(x_, y_, 2, 2, 2, 1)

        self.assertEqual(expected, actual)

    def test_byte_decode_matrix(self) -> None:
        k, d = 3, 12
        expected = [[randint(0, q - 1) for _ in range(n)] for _ in range(k)]
        encoded = byte_encode_matrix(expected, d)

        actual = byte_decode_matrix(encoded, d, k)

        self.assertEqual(expected, actual)
