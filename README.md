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

## Keys

When `ML_KEM.key_gen` is run it returns two objects, `EncapsKey` and a `DecapsKey`. You can
serialize these to `bytes` as follows.

```python
from mlkem import ML_KEM

kem = ML_KEM()
ek, dk = kem.key_gen()
ek_bytes = bytes(ek)  # ek.to_bytes() is also valid
dk_bytes = bytes(dk)  # dk.to_bytes() is also valid
```

You can also deserialize bytes into a key, provided that the byte encoding is canonical and
compliant with FIPS-203.

```python
from mlkem import DecapsKey, EncapsKey

ek_bytes = b"..."  # canonically encodeed encapsulation key
ek = EncapsKey.from_bytes(ek_bytes)

dk_bytes = b"..."  # canonically encodeed decapsulation key
dk = DecapsKey.from_bytes(dk_bytes)
```

You can also check which parameter set a key was generated with. A mismatch between a key and
the KEM parameter set will cause an error.

```python
from mlkem import ML_KEM, ParameterSet

kem512 = ML_KEM(ParameterSet.ML_KEM_512)
kem768 = ML_KEM(ParameterSet.ML_KEM_768)
ek512, _ = kem512.key_gen()

ek512.parameter_set  # => ParameterSet.ML_KEM_512
kem768.encaps(ek512)  # => ValueError: Key does not match this ML_KEM parameter set
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

## Memory

All secrets and sensitive values in the rust code are zeroized as soon as they go out of scope.
Memory inside the rust core logic is entirely stack allocated and does not use any dynamically
allocated memory. Since the source of variance in memory sizes throughout MLKEM is the parameter
set each parameter set is a specialized implementation of the `Kem` trait that allows that impl
to use constants for its array sizes. `Vec<u8>` _is_ used in the pyo3 bindings to represent bytes
at the border between python and rust code. I do not know of a way to avoid this and use a rust
`u8` array reference or slice to represent python `bytes` in a way that plays nice with PyO3. The performance penalty is negligible, the main consideration is management of values that are
considered secret if they are copied across the language boundary and if they are not promptly
garbage collected and zeroizeed by python.

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

op             param set      ops/sec (med)     µs/op           min           max       stdev
---------------------------------------------------------------------------------------------
keygen         ML_KEM_512            37,682      26.5        37,340        37,884         197
encaps         ML_KEM_512            51,044      19.6        48,785        51,625       1,378
decaps         ML_KEM_512            39,242      25.5        38,953        39,433         187
keygen         ML_KEM_768            23,389      42.8        23,251        23,459          79
encaps         ML_KEM_768            38,051      26.3        37,607        38,221         236
decaps         ML_KEM_768            28,865      34.6        28,441        29,093         238
keygen         ML_KEM_1024           14,862      67.3        14,542        15,093         254
encaps         ML_KEM_1024           28,033      35.7        27,863        28,229         157
decaps         ML_KEM_1024           21,342      46.9        21,247        21,390          66
```

You can also run the benchmark yourself as well

```bash
uv run benchmark           # for local development
python -m mlkem.benchmark  # for pip installed package
```

Compared to OpenSSL below you can see that performance is a bit slower, but is on the same
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

Depending on your specific CPU architecture, you may be able to see significant performance
improvements compiling the rust source specifically for your instruction set. For example,
compiling with `RUSTFLAGS='-C target-cpu=native'` yields the following performance gains
on the same i9-9900k. With this change we see performance a bit faster than OpenSSL.

```
$ RUSTFLAGS='-C target-cpu=native' uv run maturin develop -r
$ uv run benchmark --duration 1

ops=['keygen', 'encaps', 'decaps'] duration=1.0s repeats=5 warmup=0.5s

op             param set      ops/sec (med)     µs/op           min           max       stdev
---------------------------------------------------------------------------------------------
keygen         ML_KEM_512            46,707      21.4        46,169        46,913         291
encaps         ML_KEM_512            70,186      14.2        66,056        70,378       1,835
decaps         ML_KEM_512            54,587      18.3        54,033        54,688         267
keygen         ML_KEM_768            30,481      32.8        30,057        30,525         196
encaps         ML_KEM_768            57,913      17.3        56,916        58,017         456
decaps         ML_KEM_768            43,660      22.9        42,439        43,704         545
keygen         ML_KEM_1024           19,431      51.5        19,081        19,520         170
encaps         ML_KEM_1024           42,444      23.6        42,293        42,529          90
decaps         ML_KEM_1024           31,716      31.5        31,225        31,757         220
```

## Rust

You can also benchmark the rust code directly.

```bash
cargo bench --bench kem
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
* [KyberSlash: Exploiting secret-dependent division timings in Kyber implementations](https://kyberslash.cr.yp.to/kyberslash-20250115.pdf)
