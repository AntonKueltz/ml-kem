use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto_primitives::{g, j, prf};
use crate::decaps_key::DecapsKey;
use crate::encaps_key::EncapsKey;
use crate::matrix::Matrix;
use crate::polynomial::{Polynomial, PolynomialRepresentation};
use crate::vector::Vector;

mod sealed {
    pub trait Sealed {}
}

pub struct MlKem512 {}
pub struct MlKem768 {}
pub struct MlKem1024 {}

pub trait Kem: sealed::Sealed {
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;

    type EncapsKey;
    type EncapsKeyBytes: AsRef<[u8]> + AsMut<[u8]>;

    type DecapsKey;
    type DecapsKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Zeroize;

    type Ctxt: AsRef<[u8]> + AsMut<[u8]> + for<'a> TryFrom<&'a [u8]>;

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey);
    fn encaps(ek: &Self::EncapsKey) -> (Zeroizing<[u8; 32]>, Self::Ctxt);
    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<Zeroizing<[u8; 32]>, String>;

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes;
    fn serialize_dk(dk: &Self::DecapsKey) -> Zeroizing<Self::DecapsKeyBytes>;
    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String>;
    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String>;
}

impl sealed::Sealed for MlKem512 {}

impl Kem for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type EncapsKey = EncapsKey<{ Self::K }>;
    type EncapsKeyBytes = [u8; 800];

    type DecapsKey = DecapsKey<{ Self::K }>;
    type DecapsKeyBytes = [u8; 1632];

    type Ctxt = [u8; 768];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        key_gen_random::<Self, { Self::K }>()
    }

    fn encaps(ek: &Self::EncapsKey) -> (Zeroizing<[u8; 32]>, Self::Ctxt) {
        let mut c = [0u8; 768];
        let k = encaps_random::<Self, { Self::K }>(ek, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut c_ = Zeroizing::new([0u8; 768]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut out = [0u8; 800];
        serialize_ek::<{ Self::K }>(ek, &mut out);
        out
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Zeroizing<Self::DecapsKeyBytes> {
        let mut out = Zeroizing::new([0u8; 1632]);
        serialize_dk::<{ Self::K }>(dk, &mut *out);
        out
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        deserialize_ek::<{ Self::K }>(bytes)
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        deserialize_dk::<{ Self::K }>(bytes)
    }
}

impl sealed::Sealed for MlKem768 {}

impl Kem for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type EncapsKey = EncapsKey<{ Self::K }>;
    type EncapsKeyBytes = [u8; 1184];

    type DecapsKey = DecapsKey<{ Self::K }>;
    type DecapsKeyBytes = [u8; 2400];

    type Ctxt = [u8; 1088];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        key_gen_random::<Self, { Self::K }>()
    }

    fn encaps(ek: &Self::EncapsKey) -> (Zeroizing<[u8; 32]>, Self::Ctxt) {
        let mut c = [0u8; 1088];
        let k = encaps_random::<Self, { Self::K }>(ek, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut c_ = Zeroizing::new([0u8; 1088]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut out = [0u8; 1184];
        serialize_ek::<{ Self::K }>(ek, &mut out);
        out
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Zeroizing<Self::DecapsKeyBytes> {
        let mut out = Zeroizing::new([0u8; 2400]);
        serialize_dk::<{ Self::K }>(dk, &mut *out);
        out
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        deserialize_ek::<{ Self::K }>(bytes)
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        deserialize_dk::<{ Self::K }>(bytes)
    }
}

impl sealed::Sealed for MlKem1024 {}

impl Kem for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;

    type EncapsKey = EncapsKey<{ Self::K }>;
    type EncapsKeyBytes = [u8; 1568];

    type DecapsKey = DecapsKey<{ Self::K }>;
    type DecapsKeyBytes = [u8; 3168];

    type Ctxt = [u8; 1568];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        key_gen_random::<Self, { Self::K }>()
    }

    fn encaps(ek: &Self::EncapsKey) -> (Zeroizing<[u8; 32]>, Self::Ctxt) {
        let mut c = [0u8; 1568];
        let k = encaps_random::<Self, { Self::K }>(ek, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut c_ = Zeroizing::new([0u8; 1568]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut out = [0u8; 1568];
        serialize_ek::<{ Self::K }>(ek, &mut out);
        out
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Zeroizing<Self::DecapsKeyBytes> {
        let mut out = Zeroizing::new([0u8; 3168]);
        serialize_dk::<{ Self::K }>(dk, &mut *out);
        out
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        deserialize_ek::<{ Self::K }>(bytes)
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        deserialize_dk::<{ Self::K }>(bytes)
    }
}

fn key_gen_random<P: Kem, const K: usize>() -> (EncapsKey<K>, DecapsKey<K>) {
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *d).expect("RNG failure.");
    getrandom::fill(&mut *z).expect("RNG failure.");
    key_gen_internal::<P, K>(&d, &z)
}

fn encaps_random<P: Kem, const K: usize>(ek: &EncapsKey<K>, c: &mut [u8]) -> Zeroizing<[u8; 32]> {
    let mut m = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *m).expect("RNG failure.");
    encaps_internal::<P, K>(ek, &m, c)
}

fn key_gen_internal<P: Kem, const K: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> (EncapsKey<K>, DecapsKey<K>) {
    let (ek, s) = pke_key_gen::<P, K>(d);
    let ek_hash = ek.h();
    let dk = DecapsKey::<K>::new(s.reduce(), ek.clone(), ek_hash, *z);
    (ek, dk)
}

fn encaps_internal<P: Kem, const K: usize>(
    ek: &EncapsKey<K>,
    m: &[u8; 32],
    c: &mut [u8],
) -> Zeroizing<[u8; 32]> {
    let (k, r) = g(&[m, &ek.h()]);
    pke_encrypt::<P, K>(ek, m, &r, c);
    k
}

fn decaps_internal<P: Kem, const K: usize>(
    dk: &DecapsKey<K>,
    c: &[u8],
    c_: &mut [u8],
) -> Zeroizing<[u8; 32]> {
    let m = pke_decrypt::<P, K>(dk.s(), c);
    let (k, r) = g(&[&*m, dk.ek_hash()]);
    let kbar = j(dk.z(), c);

    pke_encrypt::<P, K>(dk.ek(), &m, &r, c_);
    let choice = c.ct_eq(&c_);

    let mut r = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        r[i] = u8::conditional_select(&kbar[i], &k[i], choice);
    }

    r
}

fn pke_key_gen<P: Kem, const K: usize>(d: &[u8; 32]) -> (EncapsKey<K>, Zeroizing<Vector<K>>) {
    let (rho, sigma) = g(&[d, &[K as u8]]);

    let a = sample_a(&rho, false);

    let mut n: u8 = 0;
    let s = sample_vec::<K>(&sigma, &mut n, P::ETA1, true);
    let e = sample_vec::<K>(&sigma, &mut n, P::ETA1, true);

    let mut t = Zeroizing::new(&a * &*s);
    *t = &t.to_mont() + &*e;

    (EncapsKey::<K>::new(t.reduce(), *rho, a.transpose()), s)
}

fn pke_encrypt<P: Kem, const K: usize>(
    ek: &EncapsKey<K>,
    m: &[u8; 32],
    r: &[u8; 32],
    c: &mut [u8],
) {
    let mut n: u8 = 0;

    let y = sample_vec::<K>(r, &mut n, P::ETA1, true);
    let e1 = sample_vec::<K>(r, &mut n, P::ETA2, false);

    let mut prf_buf = Zeroizing::new([0u8; 192]);
    prf(r, n, &mut prf_buf[..(P::ETA2 << 6)]);
    let e2 = Zeroizing::new(Polynomial::sample_cbd(P::ETA2, &prf_buf[..(P::ETA2 << 6)]));

    let mut u = Zeroizing::new(ek.at() * &*y);
    *u = (&u.inv_ntt() + &*e1).reduce();
    let mu = Zeroizing::new(Polynomial::from_msg(m));
    let mut v = Zeroizing::new(ek.t() * &*y);
    *v = (&(&v.inv_ntt() + &*e2) + &*mu).reduce();

    let du_len = (P::DU * K) << 5;
    u.compress_encode(P::DU, &mut c[..du_len]);
    v.compress_encode(P::DV, &mut c[du_len..]);
}

fn pke_decrypt<P: Kem, const K: usize>(s: &Vector<K>, c: &[u8]) -> Zeroizing<[u8; 32]> {
    let du_len = (P::DU * K) << 5;
    let (c1, c2) = c.split_at(du_len);

    let u = Vector::decode_decompress(P::DU, c1);
    let v = Polynomial::decode_decompress(P::DV, c2);
    let mut w = Zeroizing::new(s * &u.ntt());
    *w = &v - &w.inv_ntt();

    Zeroizing::new(w.to_msg())
}

fn sample_a<const K: usize>(rho: &[u8; 32], transposed: bool) -> Matrix<K> {
    let mut a = Matrix::<K>::new();

    for i in 0..K {
        let mut row = Vector::new(PolynomialRepresentation::NTT);

        for j in 0..K {
            if transposed {
                row[j] = Polynomial::sample_ntt(rho, i as u8, j as u8);
            } else {
                row[j] = Polynomial::sample_ntt(rho, j as u8, i as u8)
            };
        }

        a[i] = row;
    }

    a
}

fn sample_vec<const K: usize>(
    seed: &[u8; 32],
    n: &mut u8,
    eta: usize,
    ntt: bool,
) -> Zeroizing<Vector<K>> {
    let t = if ntt {
        PolynomialRepresentation::NTT
    } else {
        PolynomialRepresentation::STANDARD
    };
    let mut v = Zeroizing::new(Vector::<K>::new(t));
    let prf_len = eta << 6;
    let mut prf_buf = Zeroizing::new([0u8; 192]);

    for i in 0..K {
        prf(seed, *n, &mut prf_buf[..prf_len]);
        *n += 1;

        let mut p = Zeroizing::new(Polynomial::sample_cbd(eta, &prf_buf[..prf_len]));
        if ntt {
            *p = p.ntt();
        }
        v[i] = (*p).clone()
    }

    v
}

fn serialize_ek<const K: usize>(ek: &EncapsKey<K>, buf: &mut [u8]) {
    let vec_bytes = 384 * K;
    let ek_len = vec_bytes + 32;

    assert_eq!(buf.len(), ek_len);

    let (t_buf, rho_buf) = buf.split_at_mut(vec_bytes);

    ek.t().to_bytes(t_buf);
    rho_buf.copy_from_slice(ek.rho());
}

fn serialize_dk<const K: usize>(dk: &DecapsKey<K>, buf: &mut [u8]) {
    let vec_bytes = 384 * K;
    let dk_len = (vec_bytes << 1) + 96;

    assert_eq!(buf.len(), dk_len);

    let (s_bytes, rest) = buf.split_at_mut(vec_bytes);
    let (ek_bytes, rest) = rest.split_at_mut(vec_bytes + 32);
    let (ek_hash_bytes, z_bytes) = rest.split_at_mut(32);

    dk.s().to_bytes(s_bytes);
    serialize_ek(dk.ek(), ek_bytes);
    ek_hash_bytes.copy_from_slice(dk.ek_hash());
    z_bytes.copy_from_slice(dk.z());
}

fn deserialize_ek<const K: usize>(bytes: &[u8]) -> Result<EncapsKey<K>, String> {
    let vec_bytes = 384 * K;
    let ek_len = vec_bytes + 32;

    if bytes.len() != ek_len {
        return Err(String::from("Invalid length for serialized encaps key."));
    }

    let (t_bytes, rho_bytes) = bytes.split_at(vec_bytes);
    let t = Vector::<K>::try_from((t_bytes, PolynomialRepresentation::NTT))?;
    let rho: [u8; 32] = rho_bytes.try_into().unwrap();
    let at = sample_a(&rho, true);

    Ok(EncapsKey::<K>::new(t, rho, at))
}

fn deserialize_dk<const K: usize>(bytes: &[u8]) -> Result<DecapsKey<K>, String> {
    let vec_bytes = 384 * K;
    let dk_len = (vec_bytes << 1) + 96;

    if bytes.len() != dk_len {
        return Err(String::from("Invalid length for serialized decaps key."));
    }

    let (s_bytes, rest) = bytes.split_at(vec_bytes);
    let (ek_bytes, rest) = rest.split_at(vec_bytes + 32);
    let (ek_hash_bytes, z_bytes) = rest.split_at(32);

    let s = Vector::<K>::try_from((s_bytes, PolynomialRepresentation::NTT))?;
    let ek = deserialize_ek::<K>(ek_bytes)?;

    let dk = DecapsKey::<K>::new(
        s,
        ek,
        ek_hash_bytes.try_into().unwrap(),
        z_bytes.try_into().unwrap(),
    );
    dk.check()?;

    Ok(dk)
}

#[cfg(test)]
#[path = "unit_tests/key_gen_test.rs"]
mod key_gen_test;

#[cfg(test)]
#[path = "unit_tests/encaps_test.rs"]
mod encaps_test;

#[cfg(test)]
#[path = "unit_tests/decaps_test.rs"]
mod decaps_test;
