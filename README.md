# Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
An implementation of the module-lattice-based key encapsulation mechanism (ML-KEM)
as described in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
At this time the package is in alpha and _SHOULD NOT_ be considered for real-world
cryptographic applications.

The package includes includes a pure python implementation of the K-PKE function
(`mlkem.k_pke.K_PKE`) and an implementation that leverages C extensions
(`mlkem.fast_k_pke.Fast_K_PKE`). The implementations have interchangeable interfaces
and can be selected in their wrapper class `mlkem.ml_kem.ML_KEM` by setting the
`fast` param to `True` for C extensions and `False` for pure python e.g.

    ML_KEM(ParameterSet.ML_KEM_768, fast=True)  # C extensions
    ML_KEM(ParameterSet.ML_KEM_768, fast=False)  # Pure python

Both implementations are self contained and portable (assuming you have 8 bits per byte
on your system) with no dependencies on third party libraries in either the C or python
code. Note that the performance of the C extensions is _significantly_ faster. The python
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

# Development

As a prerequisite, `uv` is required for this project

    pip install uv

Build the C extensions

    uv run python setup.py build_ext --inplace

Run the test suite

    uv run pytest

Build the docs

    uv run make -C docs html
