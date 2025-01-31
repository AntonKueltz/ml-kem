from __future__ import annotations
from enum import StrEnum

from mlkem.math.constants import n, q
from mlkem.math.field import Zm


class RingRepresentation(StrEnum):
    STANDARD = "Standard Polynomial Ring (Rq)"
    NTT = "NTT Representation (Tq)"


class PolynomialRing:
    r"""Represents elements of the ring :math:`\mathbb{Z}^n_q`."""

    coefficients: list[Zm]
    representation: RingRepresentation

    def __init__(
        self,
        coefficients: list[Zm] | None = None,
        representation: RingRepresentation = RingRepresentation.STANDARD,
    ):
        if coefficients is None:
            coefficients = [Zm(0, q) for _ in range(n)]

        if len(coefficients) != n:
            raise ValueError(f"coefficients must have length {n}")

        self.coefficients = coefficients
        self.representation = representation

    def __eq__(self, other: object) -> bool:
        """Compare two polynomial rings for equality.

        They must have the following conditions met to be equal:
          * The same representation
          * The same coefficients
          * The same order (length of coefficients)

        Args:
            | other (:class:`object`): The object to compare to (must be a :class:`PolynomialRing` instance).

        Returns:
            :type:`bool`: Whether the two objects are equal.
        """
        if not isinstance(other, PolynomialRing):
            return NotImplemented

        if self.representation != other.representation:
            return False

        if len(self.coefficients) != len(other.coefficients):
            return False

        return all(
            [fi == gi for (fi, gi) in zip(self.coefficients, other.coefficients)]
        )

    def __repr__(self) -> str:
        return "[ " + ", ".join([repr(x) for x in self.coefficients]) + " ]"

    def __getitem__(self, index: int) -> Zm:
        """Get the coefficient at :code:`index`."""
        if index >= n:
            raise IndexError(
                f"Index for Rq coefficient must be less than {n}. Got {index}."
            )

        return self.coefficients[index]

    def __setitem__(self, index: int, value: Zm) -> None:
        """Set the coefficient at :code:`index` to :code:`value`."""
        if index >= n:
            raise IndexError(
                f"Index for Rq coefficient must be less than {n}. Got {index}."
            )

        self.coefficients[index] = value

    def __add__(self, g: PolynomialRing) -> PolynomialRing:
        r"""Add two elements f and g where :math:`f, g \in \mathbb{Z}^n_m`.

        The resulting element will also be in :math:`\mathbb{Z}^n_m`.

        Args:
            | g (:class:`PolynomialRing`): The element to add to f (represent by self).

        Returns:
            :class:`PolynomialRing`: An element equal to :math:`f + g`.
        """
        if self.representation != g.representation:
            raise ValueError(
                "PolynomialRing representation must be the same in order to perform arithmetic."
            )

        coefficients = [fi + gi for (fi, gi) in zip(self.coefficients, g.coefficients)]
        return PolynomialRing(coefficients, representation=self.representation)

    def __sub__(self, g: PolynomialRing) -> PolynomialRing:
        r"""Subtract two elements f and g where :math:`f, g \in \mathbb{Z}^n_m`.

        The resulting element will also be in :math:`\mathbb{Z}^n_m`.

        Args:
            | g (:class:`PolynomialRing`): The element to subtract from f (represent by self).

        Returns:
            :class:`PolynomialRing`: An element equal to :math:`f - g`.
        """
        if self.representation != g.representation:
            raise ValueError(
                "PolynomialRing representation must be the same in order to perform arithmetic."
            )

        coefficients = [fi - gi for (fi, gi) in zip(self.coefficients, g.coefficients)]
        return PolynomialRing(coefficients, representation=self.representation)

    def __mul__(self, a: Zm | PolynomialRing) -> PolynomialRing:
        r"""Multiply by an element in :math:`\mathbb{Z}^m` or :math:`\mathbb{Z}^n_m`.

        If :math:`a \in \mathbb{Z}_m` and :math:`f \in \mathbb{Z}^n_m` the i-th coefficient of the polynomial
        :math:`a \cdot f \in \mathbb{Z}^n_m` is equal to :math:`a \cdot f_i \pmod{m}`.

        If :math:`a \in \mathbb{Z}^n_m` and :math:`f \in \mathbb{Z}^n_m` then both polynomials must be in NTT
        representation. NTT multiplication is then used to multiply the two together.

        Args:
            | a (:class:`Zm` | :class:`PolynomialRing`): The value to multiply by.

        Returns:
            :class:`PolynomialRing`: The element in :math:`\mathbb{Z}^n_m` multiplied by `a`.
        """
        # scalar multiplication
        if isinstance(a, Zm):
            coefficients = [a * fi for fi in self.coefficients]
            return PolynomialRing(coefficients, representation=self.representation)

        # polynomial multiplication
        elif isinstance(a, PolynomialRing):
            from mlkem.auxiliary.ntt import multiply_ntt

            if (
                self.representation != RingRepresentation.NTT
                or a.representation != RingRepresentation.NTT
            ):
                raise ValueError(
                    "Multiplying PolynomialRings is only possible if both are in NTT representation."
                )

            return multiply_ntt(self, a)

        else:
            raise NotImplementedError(
                f"Cannot multiply PolynomialRing by type {type(a)}."
            )

    def __rmul__(self, a: Zm | PolynomialRing) -> PolynomialRing:
        r"""Equivalent to :code:`self.__mul__(a)`."""
        return self.__mul__(a)
