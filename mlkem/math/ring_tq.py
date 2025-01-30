from __future__ import annotations

from mlkem.math.field import Zm
from mlkem.math.ring import Ring


class RingTq(Ring):
    def __init__(self, coefficients: list[Zm] | None = None):
        super().__init__(coefficients=coefficients)

    def __mul__(self, g: Zm | RingTq) -> RingTq:
        if isinstance(g, Zm):
            result = super().__mul__(g)
            return RingTq(result.coefficients)

        # TODO - implement multiplication in Tq
        return self
