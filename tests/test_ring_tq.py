from unittest import TestCase

from mlkem.math.constants import n
from mlkem.math.ring_tq import RingTq
from mlkem.math.zq import Zq


class TestRingTq(TestCase):
    def test_mul(self) -> None:
        a = Zq(100)
        coefficients = [Zq(i) for i in range(n)]
        f = RingTq(coefficients)

        h = f * a

        for i in range(n):
            expected = Zq(i) * a
            self.assertEqual(expected, h[i])
