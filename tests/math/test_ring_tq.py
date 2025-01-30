from unittest import TestCase

from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.ring_tq import RingTq


class TestRingTq(TestCase):
    def test_mul(self) -> None:
        a = Zm(100, q)
        coefficients = [Zm(i, q) for i in range(n)]
        f = RingTq(coefficients)

        h = f * a

        for i in range(n):
            expected = Zm(i, q) * a
            self.assertEqual(expected, h[i])
