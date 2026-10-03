use rand::RngExt;
use rand::{make_rng, rngs::StdRng};

use crate::crypto_primitives::{ct_cmp, g, h, j, prf};
use crate::matrix::{Matrix, Vector};
use crate::polynomial::{Polynomial, PolynomialRepresentation};

pub struct KEM {
    k: usize,
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    at: Option<Matrix>,
}

impl KEM {
    pub fn ml_kem_512() -> Self {
        Self {
            k: 2,
            eta1: 3,
            eta2: 2,
            du: 10,
            dv: 4,
            at: None,
        }
    }

    pub fn ml_kem_768() -> Self {
        Self {
            k: 3,
            eta1: 2,
            eta2: 2,
            du: 10,
            dv: 4,
            at: None,
        }
    }

    pub fn ml_kem_1024() -> Self {
        Self {
            k: 4,
            eta1: 2,
            eta2: 2,
            du: 11,
            dv: 5,
            at: None,
        }
    }

    pub fn key_gen(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut rng: StdRng = make_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];

        rng.fill(&mut d);
        rng.fill(&mut z);

        self.key_gen_internal(d, z)
    }

    pub fn encaps(&self, ek: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng: StdRng = make_rng();
        let mut m = [0u8; 32];

        rng.fill(&mut m);
        self.encaps_internal(ek, m)
    }

    pub fn decaps(&self, dk: &[u8], c: &[u8]) -> Result<Vec<u8>, &str> {
        match self.decaps_ciphertext_check(c) {
            true => Ok(self.decaps_internal(dk, c)),
            false => Err("Invalid ciphertext passed to decaps."),
        }
    }

    pub fn encaps_key_check(&self, ek_bytes: &Vec<u8>) -> bool {
        let ek_len = 384 * self.k;
        if ek_bytes.len() != ek_len + 32 {
            return false;
        }

        let ek = &ek_bytes[..ek_len];
        let p = Vector::from((ek, PolynomialRepresentation::NTT));
        let test: Vec<u8> = p.into();

        ek == test
    }

    fn decaps_ciphertext_check(&self, c_bytes: &[u8]) -> bool {
        c_bytes.len() == (self.du * self.k + self.dv) << 5
    }

    pub fn decaps_key_check(&self, dk_bytes: &Vec<u8>) -> bool {
        let i = 768 * self.k + 32;
        if dk_bytes.len() != (i + 64) {
            return false;
        }
        let test = h(&dk_bytes[384 * self.k..i]);

        ct_cmp(&test, &dk_bytes[i..i + 32].to_vec())
    }

    fn key_gen_internal(&mut self, d: [u8; 32], z: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let (ek, mut dk) = self.pke_key_gen(d);
        dk.append(&mut ek.clone());
        dk.append(&mut h(&ek.clone()));
        dk.append(&mut z.to_vec());
        (ek, dk)
    }

    fn encaps_internal(&self, ek: &[u8], m: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut g_in = m.to_vec();
        g_in.append(&mut h(ek));

        let (k, r) = g(&g_in);
        let c = self.pke_encrypt(ek, &m, r);

        (k, c)
    }

    fn decaps_internal(&self, dk: &[u8], c: &[u8]) -> Vec<u8> {
        let i1 = 384 * self.k;
        let i2 = 768 * self.k + 32;
        let i3 = i2 + 32;
        let i4 = i3 + 32;

        let dk_pke = &dk[0..i1];
        let ek_pke = &dk[i1..i2];
        let h = &dk[i2..i3];
        let z = &dk[i3..i4];

        let m = self.pke_decrypt(dk_pke, c);

        let mut g_in = m.clone();
        g_in.append(&mut h.to_vec());
        let (k, r) = g(&g_in);

        let mut j_in = z.to_vec();
        j_in.append(&mut c.to_vec());
        let kbar = j(&j_in);

        let c_ = self.pke_encrypt(ek_pke, &m, r);
        if !ct_cmp(&c.to_vec(), &c_) { kbar } else { k }
    }

    fn pke_key_gen(&mut self, d: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut n: u8 = 0;
        let mut data = d.to_vec();
        data.push(self.k as u8);
        let (mut rho, sigma) = g(&data);

        let a = self.sample_a(&rho, false);
        self.at = Some(a.transpose());

        let mut s = Vector::new(self.k);
        for _ in 0..self.k {
            let p = Polynomial::sample_cbd(self.eta1, &prf(self.eta1, &sigma, n));
            s.push(p.ntt());
            n += 1;
        }

        let mut e = Vector::new(self.k);
        for _ in 0..self.k {
            let p = Polynomial::sample_cbd(self.eta1, &prf(self.eta1, &sigma, n));
            e.push(p.ntt());
            n += 1;
        }

        let t = &(&a * &s).to_mont() + &e;
        let mut ek_pke: Vec<u8> = t.reduce().into();
        ek_pke.append(&mut rho);
        let dk_pke: Vec<u8> = s.reduce().into();

        (ek_pke, dk_pke)
    }

    fn pke_encrypt(&self, ek_pke: &[u8], m: &[u8], r: Vec<u8>) -> Vec<u8> {
        debug_assert_eq!(m.len(), 32);
        debug_assert_eq!(r.len(), 32);

        let mut n: u8 = 0;
        let (tbytes, rho) = ek_pke.split_at(384 * self.k);
        let t = Vector::from((tbytes, PolynomialRepresentation::NTT));

        let at = match &self.at {
            None => &self.sample_a(&rho.to_vec(), true),
            Some(m) => m,
        };

        let mut y = Vector::new(self.k);
        for _ in 0..self.k {
            let p = Polynomial::sample_cbd(self.eta1, &prf(self.eta1, &r, n));
            y.push(p.ntt());
            n += 1;
        }

        let mut e1 = Vector::new(self.k);
        for _ in 0..self.k {
            let p = Polynomial::sample_cbd(self.eta2, &prf(self.eta2, &r, n));
            e1.push(p);
            n += 1;
        }

        let e2 = Polynomial::sample_cbd(self.eta2, &prf(self.eta2, &r, n));
        let u = &(at * &y).inv_ntt() + &e1;
        let mu = Polynomial::from_msg(m);
        let v = (&t * &y).inv_ntt() + e2 + mu;

        let mut c1 = u.reduce().compress_encode(self.du);
        let mut c2 = v.reduce().compress_encode(self.dv);
        c1.append(&mut c2);
        c1
    }

    fn pke_decrypt(&self, dk_pke: &[u8], c: &[u8]) -> Vec<u8> {
        let (c1, c2) = c.split_at(32 * self.du * self.k);

        let u = Vector::decode_decompress(c1, self.k, self.du);
        let v = Polynomial::decode_decompress(c2, self.dv);
        let s = Vector::from((dk_pke, PolynomialRepresentation::NTT));

        let w = v - (&s * &u.ntt()).inv_ntt();
        w.to_msg()
    }

    fn sample_a(&self, rho: &Vec<u8>, transposed: bool) -> Matrix {
        let mut a = Matrix::new(self.k);

        for i in 0..self.k {
            let mut row = Vector::new(self.k);

            for j in 0..self.k {
                let mut bytes = rho.clone(); // TODO - optimize
                if transposed {
                    bytes.push(i as u8);
                    bytes.push(j as u8);
                } else {
                    bytes.push(j as u8);
                    bytes.push(i as u8);
                }

                let item = Polynomial::sample_ntt(&bytes);
                row.push(item);
            }

            a.add_row(row);
        }

        a
    }
}

#[cfg(test)]
#[path = "unit_tests/kem_test.rs"]
mod kem_test;
