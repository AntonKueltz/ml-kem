import unittest

from mlkem.constants import n
from mlkem.ring_t_q import RingTq


class TestRingRq(unittest.TestCase):
    def test_init(self) -> None:
        actual = RingTq()
        expected = [0 for _ in range(n)]
        self.assertEqual(expected, actual.coefficients)

    def test_init_wrong_size(self) -> None:
        with self.assertRaises(ValueError):
            RingTq([0, 1, 2, 3])
