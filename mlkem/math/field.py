from __future__ import annotations


class Zm:
    r"""Represents elements of the field :math:`\mathbb{Z}_m`."""

    val: int

    def __init__(self, val: int, m: int):
        self.m = m
        self.val = val % m

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Zm):
            return NotImplemented

        return self.m == other.m and self.val == other.val

    def __repr__(self) -> str:
        return f"{self.val} mod {self.m}"

    def __add__(self, y: Zm) -> Zm:
        r"""Add two elements x and y where :math:`x, y \in \mathbb{Z}_m`.

        The resulting element will also be in :math:`\mathbb{Z}_m`.

        Args:
            y (:class:`Zm`): The element to add to x (represented by self).

        Returns:
            :class:`Zm`: An element equal to :math:`x + y \pmod{m}`.
        """
        if self.m != y.m:
            raise ValueError(
                f"Cannot add elements in different fields ({self.m} and {y.m})."
            )
        return Zm(self.val + y.val, self.m)

    def __sub__(self, y: Zm) -> Zm:
        r"""Subtract two elements x and y where :math:`x, y \in \mathbb{Z}_m`.

        The resulting element will also be in :math:`\mathbb{Z}_m`.

        Args:
            y (:class:`Zm`): The element to subtract from x (represented by self).

        Returns:
            :class:`Zm`: An element equal to :math:`x - y \pmod{m}`.
        """
        return Zm(self.val - y.val, self.m)

    def __mul__(self, y: Zm) -> Zm:
        r"""Multiply two elements x and y where :math:`x, y \in \mathbb{Z}_m`.

        The resulting element will also be in :math:`\mathbb{Z}_m`.

        Args:
            y (:class:`Zm`): The element to multiply x by (represented by self).

        Returns:
            :class:`Zm`: An element equal to :math:`x * y \pmod{m}`.
        """
        if self.m != y.m:
            raise ValueError(
                f"Cannot add elements in different fields ({self.m} and {y.m})."
            )
        return Zm(self.val * y.val, self.m)
