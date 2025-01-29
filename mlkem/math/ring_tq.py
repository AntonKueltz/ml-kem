from __future__ import annotations

from mlkem.math.ring_znq import RingZnq
from mlkem.math.zq import Zq


class RingTq(RingZnq):
    def __init__(self, coefficients: list[Zq] | None = None):
        super().__init__(coefficients=coefficients)

    def __mul__(self, g: Zq | RingTq) -> RingTq:
        if isinstance(g, Zq):
            result = super().__mul__(g)
            return RingTq(result.coefficients)

        # TODO - implement multiplication in Tq
        return self
