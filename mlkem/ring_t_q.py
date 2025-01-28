from mlkem.constants import n


class RingTq:
    coefficients: list[int]

    def __init__(self, coefficients: list[int] | None = None):
        if coefficients is None:
            coefficients = [0 for _ in range(n)]

        if len(coefficients) != n:
            raise ValueError(f"coefficients must have length {n}")

        self.coefficients = coefficients
