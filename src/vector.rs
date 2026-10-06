use std::ops::{Add, Index, IndexMut, Mul};

use zeroize::Zeroize;

use crate::integer_field::norm_q;
use crate::polynomial::{Polynomial, PolynomialRepresentation, Q};

#[derive(Clone, Copy)]
pub struct Vector<const K: usize> {
    coords: [Polynomial; K],
}

impl<const K: usize> Vector<K> {
    pub fn new(representation: PolynomialRepresentation) -> Self {
        Self {
            coords: [Polynomial::new(representation); K],
        }
    }

    pub fn reduce(&self) -> Self {
        self.map(Polynomial::reduce)
    }

    pub fn to_mont(&self) -> Self {
        self.map(Polynomial::to_mont)
    }

    pub fn ntt(&self) -> Self {
        self.map(Polynomial::ntt)
    }

    pub fn inv_ntt(&self) -> Self {
        self.map(Polynomial::inv_ntt)
    }

    pub fn compress_encode_11(&self, r: &mut [u8]) {
        assert_eq!(r.len(), 1408);

        let mut t = [0u16; 8];
        let mut ri = 0;

        for i in 0..K {
            for j in 0..32 {
                let base = j << 3;

                for k in 0..8 {
                    // compress
                    t[k] = norm_q(self[i].f[base + k]) as u16;
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
    }

    pub fn compress_encode_10(&self, r: &mut [u8]) {
        assert_eq!(r.len(), K * 320);

        let mut t = [0u16; 8];
        let mut ri = 0;

        for i in 0..K {
            for j in 0..64 {
                let base = j << 2;

                for k in 0..4 {
                    // compress
                    t[k] = norm_q(self[i].f[base + k]) as u16;
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
    }

    pub fn decode_decompress_11(c: &[u8]) -> Self {
        assert_eq!(c.len(), 1408);

        let mut r = Self::new(PolynomialRepresentation::STANDARD);
        let mut ci = 0;
        let mut t = [0u16; 8];

        for i in 0..K {
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

            r.coords[i] = p;
        }

        r
    }

    pub fn decode_decompress_10(c: &[u8]) -> Self {
        assert_eq!(c.len(), K * 320);

        let mut r = Self::new(PolynomialRepresentation::STANDARD);
        let mut ci = 0;
        let mut t = [0u16; 8];

        for i in 0..K {
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

            r[i] = p;
        }

        r
    }

    fn from_fn(f: impl FnMut(usize) -> Polynomial) -> Self {
        Self {
            coords: core::array::from_fn(f),
        }
    }

    fn map(&self, f: impl Fn(&Polynomial) -> Polynomial) -> Self {
        Self::from_fn(|i| f(&self[i]))
    }
}

impl<const K: usize> Add for &Vector<K> {
    type Output = Vector<K>;

    fn add(self, rhs: Self) -> Self::Output {
        // TODO - allocates k polynomials that get thrown away
        // representation doesn't matter here as polynomial addition will produce the correct representation
        let mut r = Vector::<K>::new(PolynomialRepresentation::STANDARD);

        for i in 0..K {
            r[i] = self[i] + rhs[i];
        }

        r
    }
}

impl<const K: usize> Mul for &Vector<K> {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut c: Polynomial = Polynomial::new(PolynomialRepresentation::NTT);

        for i in 0..K {
            let s: Polynomial = self[i] * rhs[i];
            c = c + s;
        }

        c.reduce()
    }
}

impl<const K: usize> Index<usize> for Vector<K> {
    type Output = Polynomial;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coords[index]
    }
}

impl<const K: usize> IndexMut<usize> for Vector<K> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coords[index]
    }
}

impl<const K: usize> Zeroize for Vector<K> {
    fn zeroize(&mut self) {
        for i in 0..K {
            self[i].zeroize();
        }
    }
}

impl<const K: usize> From<(&[u8], PolynomialRepresentation)> for Vector<K> {
    fn from((value, t): (&[u8], PolynomialRepresentation)) -> Self {
        assert_eq!(value.len(), 384 * K);
        let mut r = Self::new(t);

        for i in 0..K {
            let (start, end) = (i * 384, (i + 1) * 384);
            let p = Polynomial::from((value[start..end].try_into().unwrap(), t));
            r[i] = p;
        }

        r
    }
}

// impl<const K: usize> From<Vector<K>> for &[u8] {
//     fn from(value: Vector) -> Self {
//         let k = value.coords.len();
//         let mut r = Vec::<u8>::with_capacity(384 * k);

//         for i in 0..k {
//             let p = value.coords[i];

//             for j in (0..N).step_by(2) {
//                 let a0 = norm_q(p.f[j]) as u16;
//                 let a1 = norm_q(p.f[j + 1]) as u16;

//                 r.push(a0 as u8);
//                 r.push(((a0 >> 8) as u8) | (((a1 & 0xf) << 4) as u8));
//                 r.push((a1 >> 4) as u8);
//             }
//         }

//         r
//     }
// }

#[cfg(test)]
#[path = "unit_tests/vector_test.rs"]
mod vector_test;
