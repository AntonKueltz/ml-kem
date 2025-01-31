from binascii import hexlify
from functools import reduce
from logging import getLogger

from mlkem.auxiliary.crypto import g, prf
from mlkem.auxiliary.general import (
    BITS_IN_BYTE,
    byte_decode,
    byte_encode,
    compress,
    decompress,
)
from mlkem.auxiliary.ntt import ntt, ntt_inv
from mlkem.auxiliary.sampling import sample_ntt, sample_poly_cbd
from mlkem.math.constants import n, q
from mlkem.math.field import Zm
from mlkem.math.matrix import Matrix
from mlkem.math.polynomial_ring import PolynomialRing, RingRepresentation
from mlkem.parameter_set import ParameterSet

LOG = getLogger(__name__)


class KPKE:
    """A public key encryption (PKE) scheme based on the module learning with errors (MLWE) problem."""

    def __init__(self, parameters: ParameterSet):
        self.parameters = parameters

    def key_gen(self, d: bytes) -> tuple[bytes, bytes]:
        """Creates a keypair used for encapsulation and decapsulation.

        The decryption (private) key is a vector :math:`s` of length k (where k is defined by the ML-KEM parameter set)
        with elements in :math:`R_q`. The encryption (public) key is a collection of "noisy" linear equations
        :math:`(A, As + e)` in the secret variable :math:`s`. The rows of matrix A, which is generated pseudorandomly,
        for the equation coeffients.

        Args:
            d (bytes): The random seed used to derive the keypair. This should come from a random source suitable for
            cryptographic applications.

        Returns:
            tuple[bytes, bytes]: The keypair with the encryption key first and the decryption key second.
        """
        k = self.parameters.k
        eta1 = self.parameters.eta1
        rho, sigma = g(d + bytes([k]))
        N = 0
        LOG.debug(f"rho: {hexlify(rho).decode()}")
        LOG.debug(f"sigma: {hexlify(sigma).decode()}")

        # generate matrix A in (Z^n_q)^{k*k}
        a_ = self._generate_a(rho)
        LOG.debug(f"aHat: {a_}")

        # generate vector s in (Z^n_q)^{k}
        s, N = self._sample_column_vector(eta1, sigma, N)
        LOG.debug(f"s: {s}")

        # generate vector e in (Z^n_q)^{k}
        e, N = self._sample_column_vector(eta1, sigma, N)
        LOG.debug(f"e: {e}")

        s_ = s.map(ntt)
        LOG.debug(f"sHat: {s_}")
        e_ = e.map(ntt)
        LOG.debug(f"eHat: {e_}")
        a_s_ = a_ * s_
        LOG.debug(f"aHat * sHat: {a_s_}")
        t_ = a_s_ + e_
        LOG.debug(f"tHat = aHat * sHat + eHat:: {t_}")

        # use reduce to map byte encoding over the vectors
        # 1. start with an empty byte sequence
        # 2. grab the next entry in the vector
        # 3. apply byte_encode to the coefficients of the entry (the entry is a polynomial ring element)
        # 4. append the bytes from encoding to the end of the byte sequence
        ek = (
            reduce(
                lambda x, y: x + byte_encode(q.bit_length(), y.coefficients),
                t_.entries,
                b"",
            )
            + rho
        )
        dk = reduce(
            lambda x, y: x + byte_encode(q.bit_length(), y.coefficients),
            s_.entries,
            b"",
        )
        LOG.debug(f"ek: {hexlify(ek).decode()}")
        LOG.debug(f"dk: {hexlify(dk).decode()}")

        return ek, dk

    def encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        k = self.parameters.k
        du = self.parameters.du
        dv = self.parameters.dv
        N = 0
        coefficient_size = n * q.bit_length() // BITS_IN_BYTE

        # run byte_decode k times to decode t_ and extract 32 byte seed from ek
        t_ = Matrix(
            rows=k,
            cols=1,
            entries=[
                PolynomialRing(
                    byte_decode(q.bit_length(), ek[i : i + coefficient_size]),
                    RingRepresentation.NTT,
                )
                for i in range(0, coefficient_size * k, coefficient_size)
            ],
        )
        rho = ek[coefficient_size * k : coefficient_size * k + 32]

        # regenerate matrix A that was sampled in key_gen
        a_ = self._generate_a(rho)
        # generate column vector y with entries sampled from CBD
        y, N = self._sample_column_vector(self.parameters.eta1, r, N)
        # generate column vector e1 with entries sampled from CBD
        e1, N = self._sample_column_vector(self.parameters.eta2, r, N)
        e2 = sample_poly_cbd(
            self.parameters.eta2, prf(self.parameters.eta2, r, bytes([N]))
        )

        y_ = y.map(ntt)
        u = (a_.transpose() * y_).map(ntt_inv) + e1

        # encode plaintext m into polynomial v
        mu = PolynomialRing(
            [decompress(1, x) for x in byte_decode(1, m)], RingRepresentation.STANDARD
        )
        v = ntt_inv((t_.transpose() * y_).get_singleton_element()) + e2 + mu

        # compress and encode c1 and c2
        compressed_u: list[list[Zm]] = reduce(
            lambda x, y: x + [[compress(du, z) for z in y.coefficients]],
            u.entries,
            [],
        )
        c1 = reduce(
            lambda x, y: x + byte_encode(du, y),
            compressed_u,
            b"",
        )
        c2 = byte_encode(dv, [compress(dv, x) for x in v.coefficients])

        return c1 + c2

    def _generate_a(self, rho: bytes) -> Matrix[PolynomialRing]:
        k = self.parameters.k
        a_ = Matrix(
            rows=k,
            cols=k,
            constructor=lambda: PolynomialRing(representation=RingRepresentation.NTT),
        )
        for i in range(k):
            for j in range(k):
                a_[(i, j)] = sample_ntt(rho + bytes([j, i]))

        return a_

    def _sample_column_vector(
        self, eta: int, r: bytes, N: int
    ) -> tuple[Matrix[PolynomialRing], int]:
        """Generate a column vector in :math:`(Z^n_q)^{k}"""
        v: Matrix[PolynomialRing] = Matrix(
            rows=self.parameters.k,
            cols=1,
            constructor=lambda: PolynomialRing(
                representation=RingRepresentation.STANDARD
            ),
        )
        for i in range(self.parameters.k):
            seed = prf(eta, r, bytes([N]))
            # vectors are columnar, so column index is always 0
            v[(i, 0)] = sample_poly_cbd(eta, seed)
            N += 1

        return v, N
