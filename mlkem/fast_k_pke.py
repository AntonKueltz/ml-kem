from hashlib import shake_128

from mlkem.auxiliary.crypto import g, prf
from mlkem.fastmath import (  # type: ignore
    add_matrix,
    byte_encode_matrix,
    map_ntt_matrix,
    mul_matrix,
    sample_ntt,
    sample_poly_cbd,
)
from mlkem.parameter_set import ParameterSet


class Fast_K_PKE:
    """A public key encryption (PKE) scheme based on the module learning with errors (MLWE) problem."""

    def __init__(self, parameters: ParameterSet):
        self.parameters = parameters

    def key_gen(self, d: bytes) -> tuple[bytes, bytes]:
        k = self.parameters.k
        rho, sigma = g(d + bytes([k]))
        N = 0
        # generate matrix A in (Z^n_q)^{k*k}
        a_ = self._generate_a(rho)

        # generate vector s in (Z^n_q)^{k}
        s = self._sample_column_vector(sigma, N)
        N += k

        # generate vector e in (Z^n_q)^{k}
        e = self._sample_column_vector(sigma, N)
        N += k

        s_ = map_ntt_matrix(s)
        e_ = map_ntt_matrix(e)
        a_s_ = mul_matrix(a_, s_, k, k, k, 1)
        t_ = add_matrix(a_s_, e_)

        ek = byte_encode_matrix(t_, 12) + rho
        dk = byte_encode_matrix(s_, 12)
        return ek, dk

    def _generate_a(self, rho: bytes) -> list[list[int]]:
        k = self.parameters.k
        result: list[list[int]] = []

        for i in range(k):
            for j in range(k):
                xof = shake_128()
                xof.update(rho + bytes([j, i]))

                # why 840? - # https://cryptojedi.org/papers/terminate-20230516.pdf
                element = sample_ntt(xof.digest(840))
                result.append(element)

        return result

    def _sample_column_vector(self, r: bytes, N: int) -> list[list[int]]:
        """Generate a column vector in :math:`(Z^n_q)^{k}"""
        eta = self.parameters.eta1
        v: list[list[int]] = []

        for _ in range(self.parameters.k):
            seed = prf(eta, r, bytes([N]))
            v.append(sample_poly_cbd(seed, eta))
            N += 1

        return v
