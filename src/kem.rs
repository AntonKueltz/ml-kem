use rand::{RngExt, make_rng, rngs::StdRng};
use sha3::{Digest, Sha3_512};

use crate::crypto_primitives::prf;
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

    type Ctxt: AsRef<[u8]> + AsMut<[u8]>;
    type DuEncoded: AsRef<[u8]> + AsMut<[u8]>;
    type DvEncoded: AsRef<[u8]> + AsMut<[u8]>;

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey);
    fn serialize_ek(ek: &Self::EncapsKey) -> Self::EncapsKeyBytes;
    fn serialize_dk(dk: &Self::DecapsKey) -> Self::DecapsKeyBytes;
    // fn encaps(Self::EncapsKey) -> ([u8; 32], Self::Ctxt);
    // fn decaps(Self::DecapsKey, Self::Ctxt) -> [u8; 32];
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
    type DuEncoded = [u8; 640];
    type DvEncoded = [u8; 128];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        key_gen_internal::<{ Self::K }>(&d, &z, Self::ETA1)
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
    type DuEncoded = [u8; 960];
    type DvEncoded = [u8; 128];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        let (ek, dk) = key_gen_internal::<{ Self::K }>(&d, &z, Self::ETA1);
        (ek, dk)
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
    type DuEncoded = [u8; 1408];
    type DvEncoded = [u8; 160];

    fn key_gen() -> (Self::EncapsKey, Self::DecapsKey) {
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        key_gen_internal::<{ Self::K }>(&d, &z, Self::ETA1)
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
}

fn key_gen_internal<const K: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
    eta: usize,
) -> (EncapsKey<K>, DecapsKey<K>) {
    let (ek, s) = pke_key_gen::<K>(d, eta);
    let ek_hash = ek.h();
    let dk = DecapsKey::<K>::new(s.reduce(), ek.clone(), ek_hash, *z);
    (ek, dk)
}

fn pke_key_gen<const K: usize>(d: &[u8; 32], eta: usize) -> (EncapsKey<K>, Vector<K>) {
    let mut hasher = Sha3_512::new();
    hasher.update(d);
    hasher.update(&[K as u8]);
    let hashed = hasher.finalize();
    let (l, r) = hashed.split_at(32);
    let (rho, sigma): ([u8; 32], [u8; 32]) = (l.try_into().unwrap(), r.try_into().unwrap());

    let a = sample_a(&rho, false);
    let mut n: u8 = 0;
    let prf_len = eta << 6;

    let mut s = Vector::<K>::new(PolynomialRepresentation::NTT);
    for i in 0..K {
        let prf_bytes = &prf(&sigma, n)[..prf_len];
        let p = Polynomial::sample_cbd(eta, prf_bytes);
        s[i] = p.ntt();
        n += 1;
    }

    let mut e = Vector::<K>::new(PolynomialRepresentation::NTT);
    for i in 0..K {
        let prf_bytes = &prf(&sigma, n)[..prf_len];
        let p = Polynomial::sample_cbd(eta, prf_bytes);
        e[i] = p.ntt();
        n += 1;
    }

    let t = &(&a * &s).to_mont() + &e;
    let ek_pke = EncapsKey::<K>::new(t.reduce(), rho, a.transpose());
    (ek_pke, s)
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
