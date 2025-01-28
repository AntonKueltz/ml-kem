from __future__ import annotations

from mlkem.ring_znq import RingZnq
from mlkem.zq import Zq


class RingTq(RingZnq):
    def __mul__(self, g: Zq | RingTq) -> RingTq:
        if isinstance(g, Zq):
            result = super().__mul__(g)
            return RingTq(result.coefficients)

        # TODO - implement multiplication in Tq
        return self
