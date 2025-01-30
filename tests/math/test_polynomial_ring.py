import unittest

from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.polynomial_ring import PolynomialRing


class TestRingZnq(unittest.TestCase):
    def test_init(self) -> None:
        actual = PolynomialRing()
        expected = [Zm(0, q) for _ in range(n)]
        self.assertEqual(expected, actual.coefficients)

    def test_init_wrong_size(self) -> None:
        with self.assertRaises(ValueError):
            PolynomialRing([Zm(0, q)])

    def test_getitem(self) -> None:
        coefficients = [Zm(i, q) for i in range(n)]
        actual = PolynomialRing(coefficients)

        for i in range(n):
            expected = Zm(i, q)
            self.assertEqual(expected, actual[i])

    def test_add(self) -> None:
        coefficients = [Zm(i, q) for i in range(n)]
        f = PolynomialRing(coefficients)
        g = PolynomialRing(coefficients)

        h = f + g

        for i in range(n):
            expected = Zm(i * 2, q)
            self.assertEqual(expected, h[i])

    def test_mul(self) -> None:
        a = Zm(100, q)
        coefficients = [Zm(i, q) for i in range(n)]
        f = PolynomialRing(coefficients)

        h = f * a

        for i in range(n):
            expected = Zm(i, q) * a
            self.assertEqual(expected, h[i])
