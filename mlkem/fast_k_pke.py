from hashlib import shake_128

from mlkem.auxiliary.crypto import g, prf
from mlkem.fastmath import (  # type: ignore
    add_matrix,
    add_poly,
    byte_decode_matrix,
    byte_decode_poly,
    byte_encode_matrix,
    byte_encode_poly,
    compress_matrix,
    compress_poly,
    decompress_matrix,
    decompress_poly,
    map_ntt_inv_matrix,
    map_ntt_matrix,
    mul_matrix,
    ntt_inv,
    sample_ntt,
    sample_poly_cbd,
    sub_poly,
)
from mlkem.k_pke import PKE_Interface
from mlkem.parameter_set import ParameterSet


class Fast_K_PKE(PKE_Interface):
    """C extension implementation of the PKE Interface."""

    def __init__(self, parameters: ParameterSet):
        self.parameters = parameters

    def key_gen(self, d: bytes) -> tuple[bytes, bytes]:
        k = self.parameters.k
        rho, sigma = g(d + bytes([k]))
        N = 0
        # generate matrix A in (Z^n_q)^{k*k}
        a_ = self._generate_a(rho)

        # generate vector s in (Z^n_q)^{k}
        s = self._sample_column_vector(self.parameters.eta1, sigma, N)
        N += k

        # generate vector e in (Z^n_q)^{k}
        e = self._sample_column_vector(self.parameters.eta1, sigma, N)
        N += k

        s_ = map_ntt_matrix(s)
        e_ = map_ntt_matrix(e)
        a_s_ = mul_matrix(a_, s_, k, k, k, 1)
        t_ = add_matrix(a_s_, e_)

        ek = byte_encode_matrix(t_, 12) + rho
        dk = byte_encode_matrix(s_, 12)
        return ek, dk

    def encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        k = self.parameters.k
        du = self.parameters.du
        dv = self.parameters.dv
        N = 0

        # run byte_decode k times to decode t_ and extract 32 byte seed from ek
        t_ = byte_decode_matrix(ek[: 384 * k], 12, k)
        rho = ek[384 * k : 384 * k + 32]

        # regenerate matrix A that was sampled in key_gen
        a_ = self._generate_a(rho)
        # generate column vector y with entries sampled from CBD
        y = self._sample_column_vector(self.parameters.eta1, r, N)
        N += k
        # generate column vector e1 with entries sampled from CBD
        e1 = self._sample_column_vector(self.parameters.eta2, r, N)
        N += k
        e2 = sample_poly_cbd(
            prf(self.parameters.eta2, r, bytes([N])), self.parameters.eta2
        )

        y_ = map_ntt_matrix(y)
        a_y_ = mul_matrix(self._transpose(a_, k, k), y_, k, k, k, 1)
        u = add_matrix(map_ntt_inv_matrix(a_y_), e1)

        # encode plaintext m into polynomial v
        mu = decompress_poly(byte_decode_poly(m, 1), 1)
        t_y_ = mul_matrix(self._transpose(t_, k, 1), y_, 1, k, k, 1)
        ty = ntt_inv(t_y_[0])
        v = add_poly(add_poly(ty, e2), mu)

        # compress and encode c1 and c2
        c1 = byte_encode_matrix(compress_matrix(u, du), du)
        c2 = byte_encode_poly(compress_poly(v, dv), dv)

        return c1 + c2

    def decrypt(self, dk: bytes, c: bytes) -> bytes:
        du = self.parameters.du
        dv = self.parameters.dv
        k = self.parameters.k

        c1 = c[: 32 * du * k]
        c2 = c[32 * du * k : 32 * (du * k + dv)]

        # decode u, v and s
        u_prime = decompress_matrix(byte_decode_matrix(c1, du, k), du)
        v_prime = decompress_poly(byte_decode_poly(c2, dv), dv)
        s_ = byte_decode_matrix(dk, 12, k)

        # decode plaintext m from polynomial v
        s_u_ = mul_matrix(
            self._transpose(s_, k, 1), map_ntt_matrix(u_prime), 1, k, k, 1
        )
        w = sub_poly(v_prime, ntt_inv(s_u_[0]))
        m = byte_encode_poly(compress_poly(w, 1), 1)
        return m

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

    def _sample_column_vector(self, eta: int, r: bytes, N: int) -> list[list[int]]:
        """Generate a column vector in :math:`(Z^n_q)^{k}"""
        v: list[list[int]] = []

        for _ in range(self.parameters.k):
            seed = prf(eta, r, bytes([N]))
            v.append(sample_poly_cbd(seed, eta))
            N += 1

        return v

    def _transpose(self, m: list[list[int]], rows: int, cols: int) -> list[list[int]]:
        t: list[list[int]] = [[] for _ in range(rows * cols)]
        for i in range(rows):
            for j in range(cols):
                t[j * rows + i] = m[i * cols + j]
        return t
