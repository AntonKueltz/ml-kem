from __future__ import annotations

from abc import abstractmethod
from typing import Callable, Generic, Protocol, Self, TypeVar


# the entries of a matrix must have a type supporting addition
# define that interface via this protocol
class Addable(Protocol):
    @abstractmethod
    def __add__(self, other: Self) -> Self:
        pass


T = TypeVar("T", bound=Addable)


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

    def __getitem__(self, index: tuple[int, int]) -> T:
        r"""Get the element at index (i, j) of the matrix.

        The elements of the matrix are interpreted in row-major order. Since the matrix
        is represented as a flat list, this means that each row advances the index by the
        amount of columns in the matrix.

        Args:
            index (tuple[int, int]): A tuple of (row index, column index).

        Returns:
            T: The element at index (i, j) of the matrix.
        """
        row, col = index
        i = row * self.cols + col
        return self.entries[i]

    def __add__(self, other: Matrix[T]) -> Matrix[T]:
        r"""Add two matrices together.

        The two matrices must have the same dimensions, otherwise a :class:`ValueError` is raised.
        Addition is done by going element by element, thus for :math:`C = A + B` we would have
        :math:`C_{i,j} = A_{i,j} + B_{i,j}` for all valid indices :math:`(i, j)`.

        Args:
            other (:class:`Matrix`): The matrix to add.

        Returns:
            :class:`Matrix`: The sum of the matrices.
        """
        if self.rows != other.rows or self.cols != other.cols:
            raise ValueError(
                f"Cannot add matrices of different sizes. {self.rows}x{self.cols} + {other.rows}x{other.cols}"
            )

        entries = [x + y for (x, y) in zip(self.entries, other.entries)]
        return Matrix(self.rows, self.cols, entries)
