from __future__ import annotations

from mlkem.math.constants import n, q
from mlkem.math.field import Zm


class Ring:
    r"""Represents elements of the ring :math:`\mathbb{Z}^n_q`."""

    coefficients: list[Zm]

    def __init__(self, coefficients: list[Zm] | None = None):
        if coefficients is None:
            coefficients = [Zm(0, q) for _ in range(n)]

        if len(coefficients) != n:
            raise ValueError(f"coefficients must have length {n}")

        self.coefficients = coefficients

    def __getitem__(self, index: int) -> Zm:
        if index >= n:
            raise IndexError(
                f"Index for Rq coefficient must be less than {n}. Got {index}."
            )

        return self.coefficients[index]

    def __add__(self, g: Ring) -> Ring:
        r"""Add two elements f and g where :math:`f, g \in \mathbb{Z}^n_m`.

        The resulting element will also be in :math:`\mathbb{Z}^n_m`.

        Args:
            g (:class:`Ring`): The element to add to f (represent by self).

        Returns:
            :class:`Ring`: An element equal to :math:`f + g`.
        """
        coefficients = [fi + gi for (fi, gi) in zip(self.coefficients, g.coefficients)]
        return Ring(coefficients)

    def __mul__(self, a: Zm) -> Ring:
        r"""Multiply an element in :math:`\mathbb{Z}^n_m`.

        If :math:`a \in Z_m` and :math:`f \in \mathbb{Z}^n_m` the i-th coefficient of the polynomial
        :math:`a \cdot f \in \mathbb{Z}^n_m` is equal to :math:`a \cdot f_i \pmod{m}`.

        Args:
            a (:class:`Zm`): The coefficient to multiply.

        Returns:
            :class:`Ring`: The element in :math:`\mathbb{Z}^n_m` multiplied by `a`.
        """
        coefficients = [a * fi for fi in self.coefficients]
        return Ring(coefficients)

    def __rmul__(self, a: Zm) -> Ring:
        r"""Equivalent to :code:`self.__mul__(a)`."""
        return self.__mul__(a)
