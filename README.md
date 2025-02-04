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
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_512 took 0.635 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_768 took 0.931 seconds
1000 KeyGen, Encaps and Decaps operations with parameter set ML_KEM_1024 took 1.289 seconds
```

You can run the benchmark yourself using the below code -
```python
import timeit
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def run(params):
    ml_kem = ML_KEM(params)
    ek, dk = ml_kem.key_gen()
    k, c = ml_kem.encaps(ek)
    k_ = ml_kem.decaps(dk, c)
    assert k == k_

for p, n in [(ML_KEM_512, "ML_KEM_512"), (ML_KEM_768, "ML_KEM_768"), (ML_KEM_1024, "ML_KEM_1024")]:
   time = timeit.timeit(stmt=lambda: run(p), number=1000)
   print(f"1000 KeyGen, Encaps and Decaps operations with parameter set {n} took {time:.3f} seconds")
```

The performance of the C extensions is _significantly_ faster. The python
implementation is primarily included for those that wish to explore and debug the algorithm.
Performance against the NIST
[keygen](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203) and
[encap/decap](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)
test vectors can be seen below -

#### C Extensions
```
uv run pytest -k "key_gen or encaps or decaps"
================================================ test session starts ================================================
platform darwin -- Python 3.11.11, pytest-8.3.4, pluggy-1.5.0
rootdir: /Users/antonku/dev/github/mlkem
configfile: pyproject.toml
plugins: cov-6.0.0
collected 261 items / 36 deselected / 225 selected

tests/test_decaps.py ...........................................................................              [ 33%]
tests/test_encaps.py ...........................................................................              [ 66%]
tests/test_key_gen.py ...........................................................................             [100%]

======================================== 225 passed, 36 deselected in 0.23s =========================================
```

#### Pure Python
```
uv run pytest -k "key_gen or encaps or decaps"                                                              1 ↵
================================================ test session starts ================================================
platform darwin -- Python 3.11.11, pytest-8.3.4, pluggy-1.5.0
rootdir: /Users/antonku/dev/github/mlkem
configfile: pyproject.toml
plugins: cov-6.0.0
collected 261 items / 36 deselected / 225 selected

tests/test_decaps.py ...........................................................................              [ 33%]
tests/test_encaps.py ...........................................................................              [ 66%]
tests/test_key_gen.py ...........................................................................             [100%]

======================================== 225 passed, 36 deselected in 4.42s =========================================
```
