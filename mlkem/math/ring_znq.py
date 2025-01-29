from __future__ import annotations

from mlkem.math.constants import n
from mlkem.math.zq import Zq


class RingZnq:
    r"""Represents elements of the ring :math:`\mathbb{Z}^n_q`."""

    coefficients: list[Zq]

    def __init__(self, coefficients: list[Zq] | None = None):
        if coefficients is None:
            coefficients = [Zq(0) for _ in range(n)]

        if len(coefficients) != n:
            raise ValueError(f"coefficients must have length {n}")

        self.coefficients = coefficients

    def __getitem__(self, index: int) -> Zq:
        if index >= n:
            raise IndexError(
                f"Index for Rq coefficient must be less than {n}. Got {index}."
            )

        return self.coefficients[index]

    def __add__(self, g: RingZnq) -> RingZnq:
        r"""Add two elements f and g where :math:`f, g \in \mathbb{Z}^n_q`.

        The resulting element will also be in :math:`\mathbb{Z}^n_q`.

        Args:
            g (:class:`RingZnq`): The element to add to f (represent by self).

        Returns:
            :class:`RingZnq`: An element equal to :math:`f + g`.
        """
        coefficients = [fi + gi for (fi, gi) in zip(self.coefficients, g.coefficients)]
        return RingZnq(coefficients)

    def __mul__(self, a: Zq) -> RingZnq:
        r"""Multiply an element in :math:`\mathbb{Z}^n_q`.

        If :math:`a \in Z_q` and :math:`f \in \mathbb{Z}^n_q` the i-th coefficient of the polynomial
        :math:`a \cdot f \in \mathbb{Z}^n_q` is equal to :math:`a \cdot f_i \pmod{q}`.

        Args:
            a (:class:`Zq`): The coefficient to multiply.

        Returns:
            :class:`RingZnq`: The element in :math:`\mathbb{Z}^n_q` multiplied by `a`.
        """
        coefficients = [a * fi for fi in self.coefficients]
        return RingZnq(coefficients)

    def __rmul__(self, a: Zq) -> RingZnq:
        r"""Equivalent to :code:`self.__mul__(a)`."""
        return self.__mul__(a)
