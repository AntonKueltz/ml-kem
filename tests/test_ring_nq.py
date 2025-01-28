import unittest

from mlkem.constants import n
from mlkem.ring_nq import RingNQ
from mlkem.z_q import Zq


class TestRingRq(unittest.TestCase):
    def test_init(self) -> None:
        actual = RingNQ()
        expected = [Zq(0) for _ in range(n)]
        self.assertEqual(expected, actual.coefficients)

    def test_init_wrong_size(self) -> None:
        with self.assertRaises(ValueError):
            RingNQ([Zq(0)])

    def test_getitem(self) -> None:
        coefficients = [Zq(i) for i in range(n)]
        actual = RingNQ(coefficients)

        for i in range(n):
            expected = Zq(i)
            self.assertEqual(expected, actual[i])

    def test_add(self) -> None:
        coefficients = [Zq(i) for i in range(n)]
        f = RingNQ(coefficients)
        g = RingNQ(coefficients)

        h = f + g

        for i in range(n):
            expected = Zq(i * 2)
            self.assertEqual(expected, h[i])

    def test_mul(self) -> None:
        a = Zq(100)
        coefficients = [Zq(i) for i in range(n)]
        f = RingNQ(coefficients)

        h = f * a

        for i in range(n):
            expected = Zq(i) * a
            self.assertEqual(expected, h[i])
