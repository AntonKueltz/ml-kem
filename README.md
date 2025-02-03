# Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
An implementation of the module-lattice-based key encapsulation mechanism (ML-KEM)
as described in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

# Development

As a prerequisite, `uv` is required for this project

    pip install uv

Build the C extensions

    uv run python setup.py build_ext --inplace

Run the test suite

    uv run pytest

Build the docs

    uv run make -C docs html
