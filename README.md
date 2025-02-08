[![PyPI](https://img.shields.io/pypi/v/mlkem.svg)](https://pypi.org/project/mlkem/)
[![ReadTheDocs](https://readthedocs.org/projects/mlkem/badge/?version=latest)](https://mlkem.readthedocs.io/en/latest/?badge=latest)

# Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
An implementation of the module-lattice-based key encapsulation mechanism (ML-KEM)
as described in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
At this time the package is in alpha and _SHOULD NOT_ be considered for real-world
cryptographic applications.

# Usage

The package includes includes a pure python implementation of the K-PKE function
(`mlkem.k_pke.K_PKE`) and an implementation that leverages C extensions
(`mlkem.fast_k_pke.Fast_K_PKE`). The implementations have interchangeable interfaces
and can be selected in their wrapper class `mlkem.ml_kem.ML_KEM` by setting the
`fast` param to `True` for C extensions and `False` for pure python e.g.

```python
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

ML_KEM(ML_KEM_768, fast=True)  # C extensions
ML_KEM(ML_KEM_768, fast=False)  # Pure python
```

Both implementations are self contained and portable (assuming you have 8 bits per byte
on your system) with no dependencies on third party libraries in either the C or python
code.

NIST recommends the ML-KEM-768 parameter set, which offers 192 bit security. ML-KEM-512
and ML-KEM-1024 are also available, which provide 128 and 256 bit security respectively.
ML-KEM-768 is used by default in this package. Thus, the two instantiations below are
equivalent -

```python
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

ML_KEM()
ML_KEM(ML_KEM_768, fast=True)
```

The interface follows the one defined in section 7 of the standard for the functions KeyGen,
Encaps and Decaps.

```python
from mlkem.ml_kem import ML_KEM

ml_kem = ML_KEM()
ek, dk = ml_kem.key_gen()  # encapsulation and decapsulation key
k, c = ml_kem.encaps(ek)  # shared secret key and ciphertext
k_ = ml_kem.decaps(dk, c)  # shared secret key
```

In a less contrived scenario, Alice might run KeyGen and send the encapsulation key
to Bob. Bob would then run Encaps and generate a shared secret key and a ciphertext.
Bob would send the ciphertext to Alice, who would derive the shared secret key from the
ciphertext. Alice and Bob can then use the shared secret key to generate additional
secret material by passing it to a KDF, use the shared secret to directly key a symmetric
cipher like AES, etc.

# Development

As a prerequisite, `uv` is required for this project

    pip install uv

Build the C extensions

    uv run python setup.py build_ext --inplace

Run the test suite

    uv run pytest

Build the docs

    uv run make -C docs html

# Performance

Below are some benchmarks for each parameter set, running on an 2021 M1 MacBook Pro and python3.13
```
===== C Extensions =====
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_512 took 0.544 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_768 took 0.794 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_1024 took 1.095 seconds
===== Pure Python =====
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_512 took 32.670 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_768 took 51.277 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_1024 took 72.187 seconds
```

You can also run the benchmark yourself as well

```bash
uv run benchmark  # for local development
python -m mlkem.benchmark  # for pip installed package
```

The performance of the C extensions is _significantly_ faster (benchmark shows ~60-70x). The python implementation is
primarily included for those  that wish to explore and interactively debug the algorithm using pure python tooling.
