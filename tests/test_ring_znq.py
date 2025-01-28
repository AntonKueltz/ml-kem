import unittest

from mlkem.constants import n
from mlkem.ring_znq import RingZnq
from mlkem.zq import Zq


class TestRingZnq(unittest.TestCase):
    def test_init(self) -> None:
        actual = RingZnq()
        expected = [Zq(0) for _ in range(n)]
        self.assertEqual(expected, actual.coefficients)

    def test_init_wrong_size(self) -> None:
        with self.assertRaises(ValueError):
            RingZnq([Zq(0)])

    def test_getitem(self) -> None:
        coefficients = [Zq(i) for i in range(n)]
        actual = RingZnq(coefficients)

        for i in range(n):
            expected = Zq(i)
            self.assertEqual(expected, actual[i])

    def test_add(self) -> None:
        coefficients = [Zq(i) for i in range(n)]
        f = RingZnq(coefficients)
        g = RingZnq(coefficients)

        h = f + g

        for i in range(n):
            expected = Zq(i * 2)
            self.assertEqual(expected, h[i])

    def test_mul(self) -> None:
        a = Zq(100)
        coefficients = [Zq(i) for i in range(n)]
        f = RingZnq(coefficients)

        h = f * a

        for i in range(n):
            expected = Zq(i) * a
            self.assertEqual(expected, h[i])
