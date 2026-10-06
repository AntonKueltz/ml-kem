use rand::{RngExt, make_rng, rngs::StdRng};
use sha3::{Digest, Sha3_512};

use crate::crypto_primitives::{ct_cmp, j, prf};
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
    fn encaps(ek: &Self::EncapsKey) -> ([u8; 32], Self::Ctxt);
    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<[u8; 32], String>;

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
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        key_gen_internal::<Self, { Self::K }>(&d, &z)
    }

    fn encaps(ek: &Self::EncapsKey) -> ([u8; 32], Self::Ctxt) {
        let mut rng: StdRng = make_rng();
        let mut m = [0u8; 32];
        rng.fill(&mut m);

        let mut c = [0u8; 768];
        let k = encaps_internal::<Self, { Self::K }>(&ek, &m, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<[u8; 32], String> {
        match dk.check() {
            Err(msg) => Err(msg),
            Ok(()) => Ok(decaps_internal::<Self, { Self::K }>(dk, c, &mut [0u8; 768])),
        }
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 800];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = t[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[1].into();
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

        let bytes: [u8; 384] = s[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[1].into();
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
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        key_gen_internal::<Self, { Self::K }>(&d, &z)
    }

    fn encaps(ek: &Self::EncapsKey) -> ([u8; 32], Self::Ctxt) {
        let mut rng: StdRng = make_rng();
        let mut m = [0u8; 32];
        rng.fill(&mut m);

        let mut c = [0u8; 1088];
        let k = encaps_internal::<Self, { Self::K }>(&ek, &m, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<[u8; 32], String> {
        match dk.check() {
            Err(msg) => Err(msg),
            Ok(()) => Ok(decaps_internal::<Self, { Self::K }>(
                dk,
                c,
                &mut [0u8; 1088],
            )),
        }
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 1184];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = t[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[1].into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[2].into();
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

        let bytes: [u8; 384] = s[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[1].into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[2].into();
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
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        key_gen_internal::<Self, { Self::K }>(&d, &z)
    }

    fn encaps(ek: &Self::EncapsKey) -> ([u8; 32], Self::Ctxt) {
        let mut rng: StdRng = make_rng();
        let mut m = [0u8; 32];
        rng.fill(&mut m);

        let mut c = [0u8; 1568];
        let k = encaps_internal::<Self, { Self::K }>(&ek, &m, &mut c);
        (k, c)
    }

    fn decaps(dk: &Self::DecapsKey, c: &Self::Ctxt) -> Result<[u8; 32], String> {
        match dk.check() {
            Err(msg) => Err(msg),
            Ok(()) => Ok(decaps_internal::<Self, { Self::K }>(
                dk,
                c,
                &mut [0u8; 1568],
            )),
        }
    }

    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes {
        let mut serialized = [0u8; 1568];
        let t = ek.t();
        let rho = ek.rho();

        let bytes: [u8; 384] = t[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[1].into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[2].into();
        serialized[768..1152].copy_from_slice(&bytes);
        let bytes: [u8; 384] = t[3].into();
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

        let bytes: [u8; 384] = s[0].into();
        serialized[..384].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[1].into();
        serialized[384..768].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[2].into();
        serialized[768..1152].copy_from_slice(&bytes);
        let bytes: [u8; 384] = s[3].into();
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
) -> [u8; 32] {
    let mut hasher = Sha3_512::new();
    hasher.update(m);
    hasher.update(ek.h());
    let hashed = hasher.finalize();
    let (x, y) = hashed.split_at(32);
    let (k, r): ([u8; 32], [u8; 32]) = (x.try_into().unwrap(), y.try_into().unwrap());

    pke_encrypt::<P, K>(ek, m, &r, c);
    k
}

fn decaps_internal<P: Kem, const K: usize>(dk: &DecapsKey<K>, c: &[u8], c_: &mut [u8]) -> [u8; 32] {
    let m = pke_decrypt::<P, K>(dk.s(), c);

    let mut sha512 = Sha3_512::default();
    sha512.update(&m);
    sha512.update(dk.ek_hash());
    let hashed = sha512.finalize();
    let (x, y) = hashed.split_at(32);
    let (k, r): ([u8; 32], [u8; 32]) = (x.try_into().unwrap(), y.try_into().unwrap());

    let kbar = j(dk.z(), c);
    pke_encrypt::<P, K>(dk.ek(), &m, &r, c_);
    if !ct_cmp(c, c_) { kbar } else { k }
}

fn pke_key_gen<P: Kem, const K: usize>(d: &[u8; 32]) -> (EncapsKey<K>, Vector<K>) {
    let mut hasher = Sha3_512::new();
    hasher.update(d);
    hasher.update(&[K as u8]);
    let hashed = hasher.finalize();
    let (l, r) = hashed.split_at(32);
    let (rho, sigma): ([u8; 32], [u8; 32]) = (l.try_into().unwrap(), r.try_into().unwrap());

    let a = sample_a(&rho, false);
    let mut n: u8 = 0;
    let prf_len = P::ETA1 << 6;

    let mut s = Vector::<K>::new(PolynomialRepresentation::NTT);
    for i in 0..K {
        let prf_bytes = &prf(&sigma, n)[..prf_len];
        let p = Polynomial::sample_cbd(P::ETA1, prf_bytes);
        s[i] = p.ntt();
        n += 1;
    }

    let mut e = Vector::<K>::new(PolynomialRepresentation::NTT);
    for i in 0..K {
        let prf_bytes = &prf(&sigma, n)[..prf_len];
        let p = Polynomial::sample_cbd(P::ETA1, prf_bytes);
        e[i] = p.ntt();
        n += 1;
    }

    let t = &(&a * &s).to_mont() + &e;
    let ek_pke = EncapsKey::<K>::new(t.reduce(), rho, a.transpose());
    (ek_pke, s)
}

fn pke_encrypt<P: Kem, const K: usize>(
    ek: &EncapsKey<K>,
    m: &[u8; 32],
    r: &[u8; 32],
    c: &mut [u8],
) {
    let mut n: u8 = 0;
    let prf_len1 = P::ETA1 << 6;

    let mut y = Vector::<K>::new(PolynomialRepresentation::NTT);
    for i in 0..K {
        let prf_bytes = &prf(r, n)[..prf_len1];
        let p = Polynomial::sample_cbd(P::ETA1, prf_bytes);
        y[i] = p.ntt();
        n += 1;
    }

    let prf_len2 = P::ETA2 << 6;

    let mut e1 = Vector::<K>::new(PolynomialRepresentation::STANDARD);
    for i in 0..K {
        let prf_bytes = &prf(r, n)[..prf_len2];
        let p = Polynomial::sample_cbd(P::ETA2, prf_bytes);
        e1[i] = p;
        n += 1;
    }

    let prf_bytes = &prf(r, n)[..prf_len2];
    let e2 = Polynomial::sample_cbd(P::ETA2, prf_bytes);
    let u = &(ek.at() * &y).inv_ntt() + &e1;
    let mu = Polynomial::from_msg(m);
    let v = (ek.t() * &y).inv_ntt() + e2 + mu;

    let du_len = (P::DU * K) << 5;
    u.reduce().compress_encode(P::DU, &mut c[..du_len]);
    v.reduce().compress_encode(P::DV, &mut c[du_len..]);
}

fn pke_decrypt<P: Kem, const K: usize>(s: &Vector<K>, c: &[u8]) -> [u8; 32] {
    let du_len = (P::DU * K) << 5;
    let (c1, c2) = c.split_at(du_len);

    let u = Vector::decode_decompress(P::DU, c1);
    let v = Polynomial::decode_decompress(P::DV, c2);
    let w = v - (s * &u.ntt()).inv_ntt();

    w.to_msg()
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

#[cfg(test)]
#[path = "unit_tests/key_gen_test.rs"]
mod key_gen_test;

#[cfg(test)]
#[path = "unit_tests/encaps_test.rs"]
mod encaps_test;

#[cfg(test)]
#[path = "unit_tests/decaps_test.rs"]
mod decaps_test;
