[![PyPI](https://img.shields.io/pypi/v/mlkem.svg)](https://pypi.org/project/mlkem/)
[![ReadTheDocs](https://readthedocs.org/projects/mlkem/badge/?version=latest)](https://mlkem.readthedocs.io/en/latest/?badge=latest)

# Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
An implementation of the module-lattice-based key encapsulation mechanism (ML-KEM)
as described in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
At this time the package is in beta and _SHOULD NOT_ be considered for real-world
cryptographic applications.

# Usage

The interface follows the one defined in section 7 of the standard for the functions KeyGen,
Encaps and Decaps. All functions operate on, and return, `bytes`.

```python
from mlkem import ML_KEM

kem = ML_KEM()
ek, dk = kem.key_gen()  # encapsulation and decapsulation key
k, c = kem.encaps(ek)  # shared secret key and ciphertext
k_ = kem.decaps(dk, c)  # shared secret key
```

In a less contrived scenario, Alice might run KeyGen and send the encapsulation key
to Bob. Bob would then run Encaps and generate a shared secret key and a ciphertext.
Bob would send the ciphertext to Alice, who would derive the shared secret key from the
ciphertext. Alice and Bob can then use the shared secret key to generate additional
secret material by passing it to a KDF, use the shared secret to directly key a symmetric
cipher like AES, etc.

## Parameter Sets

NIST recommends the `ML_KEM_768` parameter set, which offers 192 bit security. `ML_KEM_512`
and `ML_KEM_1024` are also available, which provide 128 and 256 bit security respectively.
`ML_KEM_768` is used by default in this package. Below is an example of using the params
for `ML_KEM_1024`.

```python
from mlkem import ML_KEM, ParameterSet

kem = ML_KEM(ParameterSet.ML_KEM_1024)
ek, dk = kem.key_gen()  # encapsulation and decapsulation key
k, c = kem.encaps(ek)  # shared secret key and ciphertext
k_ = kem.decaps(dk, c)  # shared secret key
```

# Implementation

The implementation follows the spec and the reference implementation closely. Many of the
optimizations from the reference implementation are included, including optimized integer
representations (see below), specialized encoding/decoding and compressing/decompressing
code, and also several precomputations for commonly used values. Hashing is handled by the
[sha3](https://crates.io/crates/sha3) and [shake](https://crates.io/crates/shake) crates.

## Integer Representations

This implementation makes use of the `i16` type to represent integers mod Q = 3329. Since Q
can be represented in 12 bits this allows addition and subtraction to be done without reductions
(to save cycles) and only applies reductions when e.g. multiplication is done. There are several
reduced forms that exist throughout the implementation.
* *Canonical*: represented as a value in [0, Q).
* *Montgomery reduced*: represented as a value _x*R mod Q_ where R = 2^16.
* *Barrett reduced*: represented as a value centered at 0 i.e. in ~[-Q/2, Q/2].

The core arithmetic is generally done in the NTT domain using a montgomery represenation. When
data needs to be serialized back to bytes it is then usually canonicalized via the process of
doing a Barrett reduction and then doing a constant time conditional addition of Q for Barrett
reduced values that are less than zero.

## Randomness

NIST requires that an approved RBG (random bit generator) be used as the source of randomness
for all operations requiring randomness. The current implementation uses `rand::rngs::StdRng`.
You can read more about the RNG [here](https://rust-random.github.io/book/guide-rngs.html). While
it is a cryptographically secure pseudorandom number generator (CSPRNG), it is not one that is
NIST approved, so this implementation is currently not entirely NIST / FIPS compliant.

# Development

As a prerequisite, the [rust toolchain](https://rust-lang.org/tools/install/) and
[`uv`](https://docs.astral.sh/uv/#installation) are required  for this project.

Build the rust code and bindings.

```bash
uv run maturin develop -r
```

Run the test suite.

```bash
cargo test     # tests the rust code
uv run pytest  # tests the python interface
```

Build the docs.

```bash
uv run make -C docs html
```

# Performance

Below are some benchmarks for each parameter set, running on 64bit OS with a i9-9900k and
python3.14.

```
ops=['keygen', 'encaps', 'decaps'] duration=1.0s repeats=5 warmup=0.5s

op      param set      ops/sec (med)     µs/op           min           max       stdev
--------------------------------------------------------------------------------------
keygen  ML_KEM_512            39,319      25.4        39,188        39,549         150
keygen  ML_KEM_768            24,260      41.2        24,106        24,504         170
keygen  ML_KEM_1024           15,701      63.7        15,631        15,746          44
encaps  ML_KEM_512            52,025      19.2        51,338        52,948         686
encaps  ML_KEM_768            37,789      26.5        36,666        38,014         539
encaps  ML_KEM_1024           27,732      36.1        27,067        27,811         302
decaps  ML_KEM_512            42,433      23.6        42,362        42,987         260
decaps  ML_KEM_768            30,796      32.5        30,664        31,060         146
decaps  ML_KEM_1024           22,960      43.6        22,535        22,999         192
```

You can also run the benchmark yourself as well

```bash
uv run benchmark           # for local development
python -m mlkem.benchmark  # for pip installed package
```

Compared to openSSL below you can see that performance is a bit slower, but is on the same
order of magnitude.

```
Doing ML-KEM-512 keygen ops for 1s: 43784 ML-KEM-512 KEM keygen ops in 1.00s
Doing ML-KEM-512 encaps ops for 1s: 65276 ML-KEM-512 KEM encaps ops in 0.99s
Doing ML-KEM-512 decaps ops for 1s: 42353 ML-KEM-512 KEM decaps ops in 1.00s
Doing ML-KEM-768 keygen ops for 1s: 28874 ML-KEM-768 KEM keygen ops in 0.98s
Doing ML-KEM-768 encaps ops for 1s: 49158 ML-KEM-768 KEM encaps ops in 1.00s
Doing ML-KEM-768 decaps ops for 1s: 31662 ML-KEM-768 KEM decaps ops in 1.00s
Doing ML-KEM-1024 keygen ops for 1s: 19272 ML-KEM-1024 KEM keygen ops in 1.00s
Doing ML-KEM-1024 encaps ops for 1s: 36791 ML-KEM-1024 KEM encaps ops in 1.00s
Doing ML-KEM-1024 decaps ops for 1s: 24031 ML-KEM-1024 KEM decaps ops in 1.00s
```

## Rust

You can also benchmark the rust code directly.

```bash
cargo bench
```

Flamegraphs are also available, provided your system has the `perf` (Linux) or `dtrace` (MacOS)
binary available. Note that this may write several hundred MB of data to your hard drive. See
below for an example.

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo flamegraph --bench kem -- --bench --profile-time 5 "keygen/768"
```

# References

* [FIPS-203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
* [Kyber reference implementation](https://github.com/pq-crystals/kyber)
* [CRYSTALS-Kyber: a CCA-secure module-lattice-based KEM](https://eprint.iacr.org/2017/634.pdf)
* [Kyber terminates](https://cryptojedi.org/papers/terminate-20230516.pdf)
