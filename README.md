[![PyPI](https://img.shields.io/pypi/v/mlkem.svg)](https://pypi.org/project/mlkem/)
[![ReadTheDocs](https://readthedocs.org/projects/mlkem/badge/?version=latest)](https://mlkem.readthedocs.io/en/latest/?badge=latest)

# Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
An implementation of the module-lattice-based key encapsulation mechanism (ML-KEM)
as described in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
The implementation aims to be both performant and secure. For more details on security
see the "Security" section of this README. This package has not been audited by a third
party. For security critical use cases I recommend more established libraries.

- [Usage](#usage)
- [Installation](#installation)
- [Security](#security)
- [Implementation](#implementation)
- [Development](#development)
- [Performance](#performance)
- [References](#references)

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

# Installation

You can use the usual package managers to install. Wheels are available for most
operating systems and architectures.

```bash
$ pip install mlkem
$ uv add mlkem
# etc
```

You can also build from source, which has the advantage of e.g. compiling the rust code
for your specific target architecture. See the "Performance" section for some analysis
of potential performance gains using this approach.

```bash
$ RUSTFLAGS="-C target-cpu=native" pip install --no-binary mlkem mlkem
```

# Security

The implementation does not use any conditional branching and aims to be constant time
for all operations involving secret material and considers timing side channels as part
of its threat model. The threat model assumes that all inputs to this package's interface
are attacker controlled. Memory management aims to be compliant with the FIPS spec, which
states

> Data used in intermediate computation steps of KEM algorithms could be used by an
> adversary to compromise security. Therefore, implementers shall ensure that intermediate
> data is destroyed as soon as it is no longer needed.

Memory management on the python side is not as straightforward. Once secret material like
the decaps key passes onto the python side (by being put on the heap in the PyO3 bindings)
it is harder to enforce (by this package) that the value is properly zero-ed out in memory
once it is no longer needed. This means that once the secret material is generated in python
by the consumer of this package, it is up to them to ensure proper zero-ing / garbage
collection of the secret material commensurate with the threat model of the consumer.

With regard to timing side channels, while the rust code underpinning this implementation
does no branching on secret material, it cannot be guaranteed that all compilers and all
target architectures have assembly produced for them where this assumption holds. The
easiest way to check if a particular compiler / architecture combination produce constant
time code is to run the [example](./examples), which are a suite of constant time tests
using the [rust port of the dudect tool](https://docs.rs/dudect-bencher/latest/dudect_bencher).
A constant time implementation will show a stable `max t`.

```bash
$ cargo run --release --example ct -- --continuous decaps_valid_vs_invalid_ctxt
    Finished `release` profile [optimized] target(s) in 0.06s
     Running `target/release/examples/ct --continuous decaps_valid_vs_invalid_ctxt`
running 1 benchmark continuously
bench decaps_valid_vs_invalid_ctxt seeded with 0xb9cf8dcf1467007c
bench decaps_valid_vs_invalid_ctxt ... : n == +0.091M, max t = +1.13915, max tau = +0.00377, (5/tau)^2 = 1762447
bench decaps_valid_vs_invalid_ctxt ... : n == +0.129M, max t = +1.54041, max tau = +0.00428, (5/tau)^2 = 1362416
bench decaps_valid_vs_invalid_ctxt ... : n == +0.192M, max t = +1.21802, max tau = +0.00278, (5/tau)^2 = 3241852
bench decaps_valid_vs_invalid_ctxt ... : n == +0.356M, max t = +1.39719, max tau = +0.00234, (5/tau)^2 = 4558998
bench decaps_valid_vs_invalid_ctxt ... : n == +0.454M, max t = +1.33999, max tau = +0.00199, (5/tau)^2 = 6315576
bench decaps_valid_vs_invalid_ctxt ... : n == +0.568M, max t = -1.45313, max tau = -0.00193, (5/tau)^2 = 6719253
bench decaps_valid_vs_invalid_ctxt ... : n == +0.440M, max t = +1.75852, max tau = +0.00265, (5/tau)^2 = 3559450
bench decaps_valid_vs_invalid_ctxt ... : n == +0.504M, max t = +2.09895, max tau = +0.00296, (5/tau)^2 = 2862346
bench decaps_valid_vs_invalid_ctxt ... : n == +0.571M, max t = +2.09054, max tau = +0.00277, (5/tau)^2 = 3268192
bench decaps_valid_vs_invalid_ctxt ... : n == +0.637M, max t = +1.62036, max tau = +0.00203, (5/tau)^2 = 6066478
bench decaps_valid_vs_invalid_ctxt ... : n == +0.694M, max t = +1.91953, max tau = +0.00230, (5/tau)^2 = 4709694
bench decaps_valid_vs_invalid_ctxt ... : n == +0.757M, max t = +1.79421, max tau = +0.00206, (5/tau)^2 = 5882404
bench decaps_valid_vs_invalid_ctxt ... : n == +0.819M, max t = +2.22930, max tau = +0.00246, (5/tau)^2 = 4119858
bench decaps_valid_vs_invalid_ctxt ... : n == +0.881M, max t = +2.21609, max tau = +0.00236, (5/tau)^2 = 4485546
bench decaps_valid_vs_invalid_ctxt ... : n == +0.944M, max t = +2.07783, max tau = +0.00214, (5/tau)^2 = 5468792
bench decaps_valid_vs_invalid_ctxt ... : n == +1.010M, max t = +2.42622, max tau = +0.00241, (5/tau)^2 = 4288152
```

The current approach of these tests is to compare the timing of unmodified inputs to the
various interfaces in this package against inputs that have been modified in ways that would
potentially be useful for the attacker to learn secret material. As an example,
`decaps_valid_vs_invalid_ctxt` runs `decaps` against both a valid and a randomized ciphertext.
See [`examples/ct.rs`](./examples/ct.rs) for the full selection of supported constant time
tests.

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
* *Canonical*: represented as a value in `[0, Q)`.
* *Montgomery reduced*: represented as a value `x * R^-1 mod Q` where `R = 2^16`.
* *Barrett reduced*: representation centered at 0 i.e. in `~[-Q/2, Q/2]`.

The core arithmetic is generally done in the NTT domain using a montgomery represenation. When
data needs to be serialized back to bytes it is then usually canonicalized via the process of
doing a Barrett reduction and then doing a constant time conditional addition of Q for Barrett
reduced values that are less than zero.

## Memory

All secrets and sensitive values in the rust code are zeroized as soon as they go out of scope.
Memory inside the rust core logic is entirely stack allocated and does not use any dynamically
allocated memory. Since the source of variance in memory sizes throughout MLKEM is the parameter
set each parameter set is a specialized implementation of the `Kem` trait that allows that impl
to use constants for its array sizes.

## Testing

Test vectors currently include the NIST
[Automated Cryptographic Validation Test System](https://github.com/usnistgov/ACVP-Server/tree/master)
cases, several cases from the [Wycheproof project](https://github.com/C2SP/wycheproof/tree/main)
and also a thousand rounds of randomized testing for each parameter set on each test run.

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
keygen         ML_KEM_512            41,944      23.8        40,828        42,558         699
encaps         ML_KEM_512            65,717      15.2        64,260        65,727         650
decaps         ML_KEM_512            52,241      19.1        52,010        52,525         199
keygen         ML_KEM_768            25,251      39.6        24,922        25,385         200
encaps         ML_KEM_768            46,171      21.7        45,035        46,186         496
decaps         ML_KEM_768            37,259      26.8        36,735        37,417         262
keygen         ML_KEM_1024           16,262      61.5        16,181        16,298          43
encaps         ML_KEM_1024           33,433      29.9        33,218        33,651         163
decaps         ML_KEM_1024           27,121      36.9        27,032        27,257          94
```

You can also run the benchmark yourself as well

```bash
uv run benchmark           # for local development
python -m mlkem.benchmark  # for pip installed package
```

Compared to OpenSSL below you can see that performance is about on par, perhaps slightly slower
for some param set / op combinations on this particular architecture.

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

The widely-used `cryptography` package also implements the 768 and 1024 param sets for MLKEM.
Performance provided below for reference.

```
cryptography 50.0.1
ops=['keygen', 'encaps', 'decaps'] duration=1.0s repeats=5 warmup=0.5s

op        param set      ops/sec (med)     µs/op           min           max       stdev
----------------------------------------------------------------------------------------
keygen    ML_KEM_768            11,365      88.0        11,286        11,425          55
keygen    ML_KEM_1024            8,105     123.4         7,985         8,195          87
encaps    ML_KEM_768            46,580      21.5        43,977        46,944       1,210
encaps    ML_KEM_1024           35,255      28.4        34,493        35,285         382
decaps    ML_KEM_768            30,989      32.3        30,833        31,005          72
decaps    ML_KEM_1024           23,818      42.0        23,612        24,057         201
```

Depending on your specific CPU architecture, you may be able to see significant performance
improvements compiling the rust source specifically for your instruction set. For example,
compiling with `RUSTFLAGS='-C target-cpu=native'` yields the following performance gains
on the same i9-9900k. With this change we see performance faster than OpenSSL.

```
$ RUSTFLAGS='-C target-cpu=native' uv run maturin develop -r
$ uv run benchmark

ops=['keygen', 'encaps', 'decaps'] duration=1.0s repeats=5 warmup=0.5s

op             param set      ops/sec (med)     µs/op           min           max       stdev
---------------------------------------------------------------------------------------------
keygen         ML_KEM_512            51,656      19.4        51,198        53,992       1,216
encaps         ML_KEM_512            98,699      10.1        98,523        98,903         144
decaps         ML_KEM_512            77,929      12.8        77,819        78,900         452
keygen         ML_KEM_768            32,329      30.9        31,807        32,493         303
encaps         ML_KEM_768            72,446      13.8        71,064        72,978         827
decaps         ML_KEM_768            56,300      17.8        56,162        56,640         199
keygen         ML_KEM_1024           20,577      48.6        20,125        20,764         238
encaps         ML_KEM_1024           52,144      19.2        51,324        52,241         374
decaps         ML_KEM_1024           40,489      24.7        39,998        41,075         399
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
* [Dude, is my code constant time?](https://eprint.iacr.org/2016/1123.pdf)
