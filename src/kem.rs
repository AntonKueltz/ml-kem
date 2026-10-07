use rand::{RngExt, make_rng, rngs::StdRng};
use zeroize::Zeroizing;

use crate::crypto_primitives::{ct_cmp, g, j, prf};
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
    type DecapsKeyBytes: AsRef<[u8]> + AsMut<[u8]>;

    type Ctxt: AsRef<[u8]> + AsMut<[u8]> + for<'a> TryFrom<&'a [u8]>;

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey);
    fn encaps(ek: &Self::EncapsKey) -> (Zeroizing<[u8; 32]>, Self::Ctxt);
    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<Zeroizing<[u8; 32]>, String>;

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes;
    fn serialize_dk(dk: &Self::DecapsKey) -> Self::DecapsKeyBytes;
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
        dk.check()?;
        let mut c_ = Zeroizing::new([0u8; 768]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 800];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = (&t[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[1]).into();
        serialized[384..768].copy_from_slice(&bytes);

        serialized[768..].copy_from_slice(rho);
        serialized
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Self::DecapsKeyBytes {
        let mut serialized = [0u8; 1632];
        let s = dk.s();
        let ek_bytes = Self::serialize_ek(dk.ek());
        let ek_hash = dk.ek_hash();
        let z = dk.z();

        let bytes: [u8; 384] = (&s[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[1]).into();
        serialized[384..768].copy_from_slice(&bytes);

        serialized[768..1568].copy_from_slice(&ek_bytes);
        serialized[1568..1600].copy_from_slice(ek_hash);
        serialized[1600..].copy_from_slice(z);

        serialized
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        if bytes.len() != 800 {
            return Err(String::from("Invalid length for serialized encaps key."));
        }

        let (t_bytes, rho_bytes) = bytes.split_at(768);
        let t = match Vector::<{ Self::K }>::try_from((t_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let rho: [u8; 32] = rho_bytes.try_into().unwrap();
        let at = sample_a(&rho, true);

        Ok(EncapsKey::<{ Self::K }>::new(t, rho, at))
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        if bytes.len() != 1632 {
            return Err(String::from("Invalid length for serialized decaps key."));
        }

        let s_bytes = &bytes[..768];
        let ek_bytes = &bytes[768..1568];
        let ek_hash_bytes = &bytes[1568..1600];
        let z_bytes = &bytes[1600..];

        let s = match Vector::<{ Self::K }>::try_from((s_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let ek = match Self::deserialize_ek(ek_bytes) {
            Err(msg) => return Err(msg),
            Ok(k) => k,
        };
        let ek_hash: [u8; 32] = ek_hash_bytes.try_into().unwrap();
        let z: [u8; 32] = z_bytes.try_into().unwrap();

        Ok(DecapsKey::<{ Self::K }>::new(s, ek, ek_hash, z))
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
        dk.check()?;
        let mut c_ = Zeroizing::new([0u8; 1088]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 1184];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = (&t[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[1]).into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[2]).into();
        serialized[768..1152].copy_from_slice(&bytes);

        serialized[1152..].copy_from_slice(rho);
        serialized
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Self::DecapsKeyBytes {
        let mut serialized = [0u8; 2400];
        let s = dk.s();
        let ek_bytes = Self::serialize_ek(dk.ek());
        let ek_hash = dk.ek_hash();
        let z = dk.z();

        let bytes: [u8; 384] = (&s[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[1]).into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[2]).into();
        serialized[768..1152].copy_from_slice(&bytes);

        serialized[1152..2336].copy_from_slice(&ek_bytes);
        serialized[2336..2368].copy_from_slice(ek_hash);
        serialized[2368..].copy_from_slice(z);

        serialized
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        if bytes.len() != 1184 {
            return Err(String::from("Invalid length for serialized encaps key."));
        }

        let (t_bytes, rho_bytes) = bytes.split_at(1152);
        let t = match Vector::<{ Self::K }>::try_from((t_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let rho: [u8; 32] = rho_bytes.try_into().unwrap();
        let at = sample_a(&rho, true);

        Ok(EncapsKey::<{ Self::K }>::new(t, rho, at))
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        if bytes.len() != 2400 {
            return Err(String::from("Invalid length for serialized decaps key."));
        }

        let s_bytes = &bytes[..1152];
        let ek_bytes = &bytes[1152..2336];
        let ek_hash_bytes = &bytes[2336..2368];
        let z_bytes = &bytes[2368..];

        let s = match Vector::<{ Self::K }>::try_from((s_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let ek = match Self::deserialize_ek(ek_bytes) {
            Err(msg) => return Err(msg),
            Ok(k) => k,
        };
        let ek_hash: [u8; 32] = ek_hash_bytes.try_into().unwrap();
        let z: [u8; 32] = z_bytes.try_into().unwrap();

        Ok(DecapsKey::<{ Self::K }>::new(s, ek, ek_hash, z))
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
        dk.check()?;
        let mut c_ = Zeroizing::new([0u8; 1568]);

        Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut *c_))
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 1568];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = (&t[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[1]).into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[2]).into();
        serialized[768..1152].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&t[3]).into();
        serialized[1152..1536].copy_from_slice(&bytes);

        serialized[1536..].copy_from_slice(rho);
        serialized
    }

    fn serialize_dk(dk: &Self::DecapsKey) -> Self::DecapsKeyBytes {
        let mut serialized = [0u8; 3168];
        let s = dk.s();
        let ek_bytes = Self::serialize_ek(dk.ek());
        let ek_hash = dk.ek_hash();
        let z = dk.z();

        let bytes: [u8; 384] = (&s[0]).into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[1]).into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[2]).into();
        serialized[768..1152].copy_from_slice(&bytes);
        let bytes: [u8; 384] = (&s[3]).into();
        serialized[1152..1536].copy_from_slice(&bytes);

        serialized[1536..3104].copy_from_slice(&ek_bytes);
        serialized[3104..3136].copy_from_slice(ek_hash);
        serialized[3136..].copy_from_slice(z);

        serialized
    }

    fn deserialize_ek(bytes: &[u8]) -> Result<Self::EncapsKey, String> {
        if bytes.len() != 1568 {
            return Err(String::from("Invalid length for serialized encaps key."));
        }

        let (t_bytes, rho_bytes) = bytes.split_at(1536);
        let t = match Vector::<{ Self::K }>::try_from((t_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let rho: [u8; 32] = rho_bytes.try_into().unwrap();
        let at = sample_a(&rho, true);

        Ok(EncapsKey::<{ Self::K }>::new(t, rho, at))
    }

    fn deserialize_dk(bytes: &[u8]) -> Result<Self::DecapsKey, String> {
        if bytes.len() != 3168 {
            return Err(String::from("Invalid length for serialized decaps key."));
        }

        let s_bytes = &bytes[..1536];
        let ek_bytes = &bytes[1536..3104];
        let ek_hash_bytes = &bytes[3104..3136];
        let z_bytes = &bytes[3136..];

        let s = match Vector::<{ Self::K }>::try_from((s_bytes, PolynomialRepresentation::NTT)) {
            Ok(val) => val,
            Err(msg) => return Err(msg),
        };
        let ek = match Self::deserialize_ek(ek_bytes) {
            Err(msg) => return Err(msg),
            Ok(k) => k,
        };
        let ek_hash: [u8; 32] = ek_hash_bytes.try_into().unwrap();
        let z: [u8; 32] = z_bytes.try_into().unwrap();

        Ok(DecapsKey::<{ Self::K }>::new(s, ek, ek_hash, z))
    }
}

fn key_gen_random<P: Kem, const K: usize>() -> (EncapsKey<K>, DecapsKey<K>) {
    let mut rng: StdRng = make_rng();
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *d);
    rng.fill(&mut *z);
    key_gen_internal::<P, K>(&d, &z)
}

fn encaps_random<P: Kem, const K: usize>(ek: &EncapsKey<K>, c: &mut [u8]) -> Zeroizing<[u8; 32]> {
    let mut rng: StdRng = make_rng();
    let mut m = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *m);
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
    if !ct_cmp(c, c_) { kbar } else { k }
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
    let e2 = Zeroizing::new(Polynomial::sample_cbd(
        P::ETA2,
        &prf(r, n)[..(P::ETA2 << 6)],
    ));

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

    for i in 0..K {
        let bytes = prf(seed, *n);
        *n += 1;

        let mut p = Zeroizing::new(Polynomial::sample_cbd(eta, &bytes[..prf_len]));
        if ntt {
            *p = p.ntt();
        }
        v[i] = (*p).clone()
    }

    v
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
