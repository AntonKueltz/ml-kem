from typing import Callable


class Matrix[T]:
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

    def __getitem__(self, index: tuple[int, int]) -> T:
        """Get the element at index (i, j) of the matrix.

        The elements of the matrix are interpreted in row-major order. Since the matrix
        is represented as a flat list, this means that row advances the index by the
        amount of columns in the matrix.

        Args:
            index (tuple[int, int]): A tuple of (row index, column index).

        Returns:
            T: The element at index (i, j) of the matrix.
        """
        row, col = index
        i = row * self.cols + col
        return self.entries[i]
