from __future__ import annotations

from mlkem.constants import q


class Zq:
    r"""Represents elements of the field :math:`\mathbb{Z}_q`."""

    val: int

    def __init__(self, val: int):
        self.val = val % q

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Zq):
            return NotImplemented

        return self.val == other.val

    def __add__(self, y: Zq) -> Zq:
        r"""Add two elements x and y where :math:`x, y \in \mathbb{Z}_q`.

        The resulting element will also be in :math:`\mathbb{Z}_q`.

        Args:
            y (:class:`Zq`): The element to add to x (represented by self).

        Returns:
            :class:`Zq`: An element equal to :math:`x + y \pmod{q}`.
        """
        return Zq(self.val + y.val)

    def __mul__(self, y: Zq) -> Zq:
        r"""Multiply two elements x and y where :math:`x, y \in \mathbb{Z}_q`.

        The resulting element will also be in :math:`\mathbb{Z}_q`.

        Args:
            y (:class:`Zq`): The element to multiply x by (represented by self).

        Returns:
            :class:`Zq`: An element equal to :math:`x * y \pmod{q}`.
        """
        return Zq(self.val * y.val)
