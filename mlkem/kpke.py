from binascii import hexlify
from functools import reduce
from logging import getLogger

from mlkem.auxiliary.crypto import g, prf
from mlkem.auxiliary.general import byte_encode
from mlkem.auxiliary.ntt import ntt
from mlkem.auxiliary.sampling import sample_ntt, sample_poly_cbd
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
        n = 0

        LOG.debug(f"rho: {hexlify(rho).decode()}")
        LOG.debug(f"sigma: {hexlify(sigma).decode()}")

        # generate matrix A in (Z^n_q)^{k*k}
        a_: Matrix[PolynomialRing] = Matrix(
            rows=k,
            cols=k,
            constructor=lambda: PolynomialRing(representation=RingRepresentation.NTT),
        )
        for i in range(k):
            for j in range(k):
                a_[(i, j)] = sample_ntt(d + bytes([j, i]))

        LOG.debug(f"aHat: {a_}")

        # generate vector s in (Z^n_q)^{k}
        s: Matrix[PolynomialRing] = Matrix(
            rows=k,
            cols=1,
            constructor=lambda: PolynomialRing(
                representation=RingRepresentation.STANDARD
            ),
        )
        for i in range(k):
            seed = prf(eta1, sigma, bytes([n]))
            # vectors are columnar, so column index is always 0
            s[(i, 0)] = sample_poly_cbd(eta1, seed)
            n += 1

        LOG.debug(f"s: {s}")

        # generate vector e in (Z^n_q)^{k}
        e: Matrix[PolynomialRing] = Matrix(
            rows=k,
            cols=1,
            constructor=lambda: PolynomialRing(
                representation=RingRepresentation.STANDARD
            ),
        )
        for i in range(k):
            seed = prf(eta1, sigma, bytes([n]))
            # vectors are columnar, so column index is always 0
            e[(i, 0)] = sample_poly_cbd(eta1, seed)
            n += 1

        LOG.debug(f"e: {e}")

        s_ = Matrix(rows=s.rows, cols=s.cols, entries=[ntt(x) for x in s.entries])
        LOG.debug(f"sHat: {s_}")
        e_ = Matrix(rows=e.rows, cols=e.cols, entries=[ntt(x) for x in e.entries])
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
                lambda x, y: x + bytes(byte_encode(12, y.coefficients)), t_.entries, b""
            )
            + rho
        )
        dk = reduce(
            lambda x, y: x + bytes(byte_encode(12, y.coefficients)), s_.entries, b""
        )

        LOG.debug(f"ek: {hexlify(ek).decode()}")
        LOG.debug(f"dk: {hexlify(dk).decode()}")

        return ek, dk
