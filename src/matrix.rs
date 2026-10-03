use std::ops::{Add, Mul};

use crate::integer_field::norm_q;
use crate::polynomial::{N, Polynomial, PolynomialRepresentation, Q};

pub struct Vector {
    coords: Vec<Polynomial>,
}

pub struct Matrix {
    rows: Vec<Vector>,
}

impl Matrix {
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: Vec::<Vector>::with_capacity(capacity),
        }
    }

    pub fn add_row(&mut self, row: Vector) {
        self.rows.push(row);
    }

    pub fn transpose(&self) -> Self {
        let k = self.rows.len();
        let mut r = Self::new(k);

        for i in 0..k {
            let mut row = Vector::new(k);

            for j in 0..k {
                row.push(self.rows[j].coords[i]);
            }

            r.add_row(row);
        }

        r
    }
}

impl Mul<&Vector> for &Matrix {
    type Output = Vector;

    fn mul(self, rhs: &Vector) -> Self::Output {
        let n = self.rows.len();
        let mut r = Vector {
            coords: Vec::<Polynomial>::with_capacity(n),
        };

        for i in 0..n {
            r.coords.push(&self.rows[i] * rhs);
        }

        r
    }
}

impl Vector {
    pub fn new(capacity: usize) -> Self {
        Self {
            coords: Vec::<Polynomial>::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, item: Polynomial) {
        self.coords.push(item);
    }

    pub fn reduce(&self) -> Self {
        let k = self.coords.len();
        let mut r = Self::new(k);

        for i in 0..k {
            r.push(self.coords[i].reduce());
        }

        r
    }

    pub fn to_mont(&self) -> Self {
        let k = self.coords.len();
        let mut r = Self::new(k);

        for i in 0..k {
            r.push(self.coords[i].to_mont());
        }

        r
    }

    pub fn ntt(&self) -> Self {
        let k = self.coords.len();
        let mut r = Self::new(k);

        for i in 0..k {
            r.push(self.coords[i].ntt());
        }

        r
    }

    pub fn inv_ntt(&self) -> Self {
        let k = self.coords.len();
        let mut r = Self::new(k);

        for i in 0..k {
            r.push(self.coords[i].inv_ntt());
        }

        r
    }

    pub fn compress_encode(&self, du: usize) -> Vec<u8> {
        match du {
            11 => self.compress_encode_11(),
            10 => self.compress_encode_10(),
            _ => vec![],
        }
    }

    fn compress_encode_11(&self) -> Vec<u8> {
        let k = self.coords.len();
        let mut r = vec![0; 352 * k];
        let mut ri = 0;
        let mut t = [0u16; 8];

        for i in 0..self.coords.len() {
            for j in 0..32 {
                let base = j << 3;

                for k in 0..8 {
                    // compress
                    t[k] = norm_q(self.coords[i].f[base + k]) as u16;
                    let mut d0 = t[k] as u64;
                    d0 <<= 11;
                    d0 += 1664;
                    d0 *= 645084;
                    d0 >>= 31;
                    t[k] = (d0 & 0x7ff) as u16;
                }

                // encode
                r[ri] = (t[0] >> 0) as u8;
                r[ri + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                r[ri + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                r[ri + 3] = (t[2] >> 2) as u8;
                r[ri + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                r[ri + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                r[ri + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                r[ri + 7] = (t[5] >> 1) as u8;
                r[ri + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                r[ri + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                r[ri + 10] = (t[7] >> 3) as u8;
                ri += 11;
            }
        }

        r
    }

    fn compress_encode_10(&self) -> Vec<u8> {
        let k = self.coords.len();
        let mut r = vec![0; 320 * k];
        let mut ri = 0;
        let mut t = [0u16; 8];

        for i in 0..self.coords.len() {
            for j in 0..64 {
                let base = j << 2;

                for k in 0..4 {
                    // compress
                    t[k] = norm_q(self.coords[i].f[base + k]) as u16;
                    let mut d0 = t[k] as u64;
                    d0 <<= 10;
                    d0 += 1665;
                    d0 *= 1290167;
                    d0 >>= 32;
                    t[k] = (d0 & 0x3ff) as u16;
                }

                // encode
                r[ri] = (t[0] >> 0) as u8;
                r[ri + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                r[ri + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                r[ri + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                r[ri + 4] = (t[3] >> 2) as u8;
                ri += 5;
            }
        }

        r
    }

    pub fn decode_decompress(c: &[u8], k: usize, du: usize) -> Self {
        match du {
            11 => Self::decode_decompress_11(c, k),
            10 => Self::decode_decompress_10(c, k),
            _ => Self::new(k),
        }
    }

    fn decode_decompress_11(c: &[u8], k: usize) -> Self {
        let mut r = Self::new(k);
        let mut ci = 0;
        let mut t = [0u16; 8];

        for _ in 0..k {
            let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);

            for j in 0..32 {
                // decode
                t[0] = (c[ci] as u16) | ((c[ci + 1] as u16) << 8);
                t[1] = ((c[ci + 1] as u16) >> 3) | ((c[ci + 2] as u16) << 5);
                t[2] = ((c[ci + 2] as u16) >> 6)
                    | ((c[ci + 3] as u16) << 2)
                    | ((c[ci + 4] as u16) << 10);
                t[3] = ((c[ci + 4] as u16) >> 1) | ((c[ci + 5] as u16) << 7);
                t[4] = ((c[ci + 5] as u16) >> 4) | ((c[ci + 6] as u16) << 4);
                t[5] = ((c[ci + 6] as u16) >> 7)
                    | ((c[ci + 7] as u16) << 1)
                    | ((c[ci + 8] as u16) << 9);
                t[6] = ((c[ci + 8] as u16) >> 2) | ((c[ci + 9] as u16) << 6);
                t[7] = ((c[ci + 9] as u16) >> 5) | ((c[ci + 10] as u16) << 3);
                ci += 11;

                // decompress
                let base = j << 3;
                for l in 0..8 {
                    p.f[base + l] = (((t[l] & 0x7ff) as u32 * Q as u32 + 1024) >> 11) as i16;
                }
            }

            r.push(p);
        }

        r
    }

    fn decode_decompress_10(c: &[u8], k: usize) -> Self {
        let mut r = Self::new(k);
        let mut ci = 0;
        let mut t = [0u16; 8];

        for _ in 0..k {
            let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);

            for j in 0..64 {
                t[0] = (c[ci] as u16) | ((c[ci + 1] as u16) << 8);
                t[1] = ((c[ci + 1] as u16) >> 2) | ((c[ci + 2] as u16) << 6);
                t[2] = ((c[ci + 2] as u16) >> 4) | ((c[ci + 3] as u16) << 4);
                t[3] = ((c[ci + 3] as u16) >> 6) | ((c[ci + 4] as u16) << 2);
                ci += 5;

                let base = j << 2;
                for l in 0..4 {
                    p.f[base + l] = (((t[l] & 0x3ff) as u32 * Q as u32 + 512) >> 10) as i16;
                }
            }

            r.push(p);
        }

        r
    }
}

impl Add for &Vector {
    type Output = Vector;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.coords.len(), rhs.coords.len());
        let k = self.coords.len();
        let mut r = Vector::new(k);

        for i in 0..k {
            r.coords.push(self.coords[i] + rhs.coords[i]);
        }

        r
    }
}

impl Mul for &Vector {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.coords.len(), rhs.coords.len());
        let mut c: Polynomial = Polynomial::new(PolynomialRepresentation::NTT);

        for i in 0..self.coords.len() {
            let s: Polynomial = self.coords[i] * rhs.coords[i];
            c = c + s;
        }

        c.reduce()
    }
}

impl From<(&[u8], PolynomialRepresentation)> for Vector {
    fn from((value, t): (&[u8], PolynomialRepresentation)) -> Self {
        let k = value.len() / 384;
        let mut r = Self::new(k);
        let mut byte_idx = 0;

        for _ in 0..k {
            let mut p = Polynomial::new(t);
            let mut p_idx = 0;

            for _ in 0..128 {
                let (a0, a1, a2) = (value[byte_idx], value[byte_idx + 1], value[byte_idx + 2]);
                byte_idx += 3;

                let b0 = (a0 as i16) | (((a1 & 0xf) as i16) << 8);
                let b1 = ((a1 >> 4) as i16) | ((a2 as i16) << 4);
                p.f[p_idx] = b0;
                p.f[p_idx + 1] = b1;
                p_idx += 2;
            }

            r.push(p);
        }

        r
    }
}

impl From<Vector> for Vec<u8> {
    fn from(value: Vector) -> Self {
        let k = value.coords.len();
        let mut r = Vec::<u8>::with_capacity(384 * k);

        for i in 0..k {
            let p = value.coords[i];

            for j in (0..N).step_by(2) {
                let a0 = norm_q(p.f[j]) as u16;
                let a1 = norm_q(p.f[j + 1]) as u16;

                r.push(a0 as u8);
                r.push(((a0 >> 8) as u8) | (((a1 & 0xf) << 4) as u8));
                r.push((a1 >> 4) as u8);
            }
        }

        r
    }
}

#[cfg(test)]
#[path = "unit_tests/matrix_test.rs"]
mod matrix_test;
