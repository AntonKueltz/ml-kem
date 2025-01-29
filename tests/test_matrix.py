from unittest import TestCase

from mlkem.math.matrix import Matrix


class TestMatrix(TestCase):
    def test_init_with_constructor(self) -> None:
        m = Matrix(rows=1, cols=1, constructor=int)

        self.assertEqual(0, m[(0, 0)])

    def test_getitem(self) -> None:
        m = Matrix(rows=2, cols=3, entries=[1, 2, 3, 4, 5, 6])

        self.assertEqual(2, m[(0, 1)])
        self.assertEqual(4, m[(1, 0)])

    def test_add(self) -> None:
        a = Matrix(rows=3, cols=2, entries=[1, 3, 1, 0, 1, 2])
        b = Matrix(rows=3, cols=2, entries=[0, 0, 7, 5, 2, 1])
        expected = Matrix(rows=3, cols=2, entries=[1, 3, 8, 5, 3, 3])

        actual = a + b

        self.assertEqual(expected, actual)

    def test_mul(self) -> None:
        a = Matrix(rows=4, cols=3, entries=[1, 0, 1, 2, 1, 1, 0, 1, 1, 1, 1, 2])
        b = Matrix(rows=3, cols=3, entries=[1, 2, 1, 2, 3, 1, 4, 2, 2])
        expected = Matrix(rows=4, cols=3, entries=[5, 4, 3, 8, 9, 5, 6, 5, 3, 11, 9, 6])

        actual = a * b

        self.assertEqual(expected, actual)

    def test_mul_scalar(self) -> None:
        f = 2
        a = Matrix(rows=2, cols=2, entries=[2, 1, 4, 3])
        expected = Matrix(rows=2, cols=2, entries=[4, 2, 8, 6])

        actual = a * f

        self.assertEqual(expected, actual)
