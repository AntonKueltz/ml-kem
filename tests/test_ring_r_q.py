import unittest

from mlkem.constants import n
from mlkem.ring_r_q import RingRq


class TestRingRq(unittest.TestCase):
    def test_init(self) -> None:
        actual = RingRq()
        expected = [0 for _ in range(n)]
        self.assertEqual(expected, actual.coefficients)

    def test_init_wrong_size(self) -> None:
        with self.assertRaises(ValueError):
            RingRq([0, 1, 2, 3])
