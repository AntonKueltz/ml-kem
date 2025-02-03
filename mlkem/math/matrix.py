from __future__ import annotations
from typing import Callable, Generic, TypeVar

from mlkem.data_types import Field

T = TypeVar("T", bound=Field)


class Matrix(Generic[T]):
    rows: int
    cols: int
    entries: list[T]

    def __init__(
        self,
        rows: int,
        cols: int,
        entries: list[T] | None = None,
        constructor: Callable[[], T] | None = None,
    ) -> None:
        self.rows = rows
        self.cols = cols

        if entries is not None:
            assert (
                len(entries) == rows * cols
            ), f"Entries had {len(entries)} entries, expected {rows} * {cols} entries."
            self.entries = entries
        elif constructor is not None:
            self.entries = [constructor() for _ in range(rows * cols)]
        else:
            raise ValueError("Must provide either entries or constructor")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Matrix):
            return NotImplemented

        if self.rows != other.rows or self.cols != other.cols:
            return False

        return all([x == y for (x, y) in zip(self.entries, other.entries)])

    def __repr__(self) -> str:
        result = "[ "
        result += ", ".join(
            [
                "[ " + ", ".join([repr(self[(i, j)]) for j in range(self.cols)]) + " ]"
                for i in range(self.rows)
            ]
        )
        result += " ]"
        return result

    def __getitem__(self, index: tuple[int, int]) -> T:
        r"""Get the element at index (i, j) of the matrix.

        The elements of the matrix are interpreted in row-major order. Since the matrix
        is represented as a flat list, this means that each row advances the index by the
        amount of columns in the matrix.

        Args:
            | index (:type:`tuple[int, int]`): A tuple of (row index, column index).

        Returns:
            :type:`T`: The element at index (i, j) of the matrix.
        """
        row, col = index
        if row >= self.rows or col >= self.cols:
            raise IndexError(
                f"{row}, {col} is not a valid index for a {self.rows}x{self.cols} matrix."
            )

        i = row * self.cols + col
        return self.entries[i]

    def __setitem__(self, index: tuple[int, int], value: T) -> None:
        r"""Set the element at index (i, j) of the matrix.

        The elements of the matrix are interpreted in row-major order. Since the matrix
        is represented as a flat list, this means that each row advances the index by the
        amount of columns in the matrix.

        Args:
            | index (:type:`tuple[int, int]`): A tuple of (row index, column index).
            | value (:type:`T`): The value to set at the given index.
        """
        row, col = index
        if row >= self.rows or col >= self.cols:
            raise IndexError(
                f"{row}, {col} is not a valid index for a {self.rows}x{self.cols} matrix."
            )

        i = row * self.cols + col
        self.entries[i] = value

    def __add__(self, other: Matrix[T]) -> Matrix[T]:
        r"""Add two matrices together.

        The two matrices must have the same dimensions, otherwise a :class:`ValueError` is raised.
        Addition is done by going element by element, thus for :math:`C = A + B` we would have
        :math:`C_{i,j} = A_{i,j} + B_{i,j}` for all valid indices :math:`(i, j)`.

        Args:
            | other (:class:`Matrix`): The matrix to add.

        Returns:
            :class:`Matrix`: The sum of the matrices.
        """
        if self.rows != other.rows or self.cols != other.cols:
            raise ValueError(
                f"Cannot add matrices of different sizes. {self.rows}x{self.cols} + {other.rows}x{other.cols}"
            )

        entries = [x + y for (x, y) in zip(self.entries, other.entries)]
        return Matrix(self.rows, self.cols, entries)

    def __mul__(self, g: T | Matrix[T]) -> Matrix[T]:
        r"""Multiply a matrix.

        Two versions of this algorithm exist. One is multiplication by a scalar, the other is multiplication
        by a matrix. When multiplying by a scalar g, the multiplication is applied to each entry in the matrix
        such that if :math:`C = A * g` then :math:`C_{i,j} = A_{i,j} * g`. For multiplication by a matrix, the
        standard matrix multiplication algorithm is applied. If :math:`C = A * B` then :math:`C_{i,j}` is
        calculated as the dot product of the i-th row of A and the j-th column of B.

        Args:
            | g (:type:`T` | :class:`Matrix`): The scalar or matrix to multiply by.

        Returns:
            :class:`Matrix`: The result of the multiplication.
        """
        if isinstance(g, Matrix):
            # matrix multiplication
            if self.cols != g.rows:
                raise ValueError(
                    f"Matrix multiplication requires left hand matrix cols={self.cols} equal right hand matrix rows={g.rows}"
                )

            entries: list[T] = []
            for i in range(self.rows):
                for j in range(g.cols):
                    entry = self[(i, 0)] * g[(0, j)]
                    for k in range(1, g.rows):
                        entry += self[(i, k)] * g[(k, j)]
                    entries.append(entry)

            return Matrix(self.rows, g.cols, entries)
        else:
            # scalar multiplication
            entries = [u * g for u in self.entries]
            return Matrix(self.rows, self.cols, entries)

    def map(self, f: Callable[[T], T]) -> Matrix[T]:
        return Matrix(self.rows, self.cols, [f(x) for x in self.entries])

    def transpose(self) -> Matrix[T]:
        t = Matrix(self.cols, self.rows, self.entries[:])

        for i in range(self.rows):
            for j in range(self.cols):
                t[(j, i)] = self[(i, j)]

        return t

    def get_singleton_element(self) -> T:
        if len(self.entries) == 1:
            return self.entries[0]

        raise ValueError(
            f"Can only get singleton elements from 1x1 matrix (got {self.rows}x{self.cols})."
        )
