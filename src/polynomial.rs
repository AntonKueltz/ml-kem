use core::arch::asm;
use core::ptr::write_bytes;
use core::sync::atomic::{Ordering::SeqCst, compiler_fence};
use std::ops::{Add, Index, IndexMut, Mul, Sub};

use shake::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::integer_field::{barr_q, mul_q, norm_q};

pub const N: usize = 256;
pub const Q: i16 = 3329;
pub const HALF_Q: i16 = 1665;
pub const R2: i16 = 1353;

const ZETAS_MONT_FORM: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PolynomialRepresentation {
    STANDARD,
    NTT,
}

#[derive(Clone)]
pub struct Polynomial {
    pub f: [i16; N],
    t: PolynomialRepresentation,
}

impl Polynomial {
    pub fn new(t: PolynomialRepresentation) -> Self {
        Self { f: [0; N], t }
    }

    pub fn sample_cbd(eta: usize, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 64 * eta);
        let mut r = Self::new(PolynomialRepresentation::STANDARD);

        if eta == 2 {
            const MASK: u32 = 0b01010101_01010101_01010101_01010101;

            for i in (0..128).step_by(4) {
                let n = u32::from_le_bytes(bytes[i..(i + 4)].try_into().unwrap());
                let two_bit_sums = (n & MASK) + ((n >> 1) & MASK);

                for j in 0..8 {
                    let base = j << 2;
                    let x = ((two_bit_sums >> base) & 0b11) as i16;
                    let y = ((two_bit_sums >> (base + 2)) & 0b11) as i16;
                    r[(i << 1) + j] = x - y;
                }
            }
        } else {
            const MASK: u32 = 0b00100100_10010010_01001001;
            let mut ri = 0;

            for i in (0..192).step_by(3) {
                let n = u32::from(bytes[i])
                    | u32::from(bytes[i + 1]) << 8
                    | u32::from(bytes[i + 2]) << 16;
                let three_bit_sums = (n & MASK) + ((n >> 1) & MASK) + ((n >> 2) & MASK);

                for j in 0..4 {
                    let base = j * 6;
                    let x = ((three_bit_sums >> base) & 0b111) as i16;
                    let y = ((three_bit_sums >> (base + 3)) & 0b11) as i16;
                    r[ri + j] = x - y;
                }

                ri += 4;
            }
        }

        r
    }

    pub fn sample_ntt(rho: &[u8; 32], x: u8, y: u8) -> Self {
        let mut r = Polynomial::new(PolynomialRepresentation::NTT);
        let mut j: usize = 0;

        let mut xof = Shake128::default();
        xof.update(rho);
        xof.update(&[x]);
        xof.update(&[y]);
        let mut xof_reader = xof.finalize_xof();

        while j < N {
            let mut c = [0u8; 3];
            xof_reader.read(&mut c);

            let d1: i16 = c[0] as i16 + (((c[1] & 0xf) as i16) << 8);
            let d2: i16 = ((c[1] as i16) >> 4) + ((c[2] as i16) << 4);

            if d1 < Q {
                r[j] = d1;
                j += 1;
            }
            if d2 < Q && j < N {
                r[j] = d2;
                j += 1;
            }
        }

        r
    }

    pub fn ntt(&self) -> Self {
        debug_assert_eq!(self.t, PolynomialRepresentation::STANDARD);
        let mut r = Self {
            f: self.f,
            t: PolynomialRepresentation::NTT,
        };

        let mut i = 1;
        let mut len = 128;

        while len >= 2 {
            let mut start = 0;

            while start < N {
                let zeta = ZETAS_MONT_FORM[i];
                i += 1;

                for j in start..start + len {
                    let t = mul_q(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                }

                start += len << 1;
            }

            len = len >> 1;
        }

        r
    }

    pub fn inv_ntt(&self) -> Self {
        debug_assert_eq!(self.t, PolynomialRepresentation::NTT);
        let mut r = Self {
            f: self.f,
            t: PolynomialRepresentation::STANDARD,
        };

        let mut i = 127;
        let mut len = 2;

        while len <= 128 {
            let mut start = 0;

            while start < N {
                let zeta = ZETAS_MONT_FORM[i];
                i -= 1;

                for j in start..start + len {
                    let t = r[j];
                    r[j] = barr_q(t + r[j + len]);
                    r[j + len] = mul_q(zeta, r[j + len] - t);
                }

                start += len << 1;
            }

            len <<= 1;
        }

        for j in 0..N {
            r[j] = mul_q(1441, r[j]);
        }

        r
    }

    pub fn to_mont(&self) -> Self {
        let mut r = Self::new(self.t);

        for i in 0..N {
            r[i] = mul_q(self[i], R2);
        }

        r
    }

    pub fn reduce(&self) -> Self {
        let mut r = Self::new(self.t);

        for i in 0..N {
            r[i] = barr_q(self[i])
        }

        r
    }

    pub(crate) fn from_bytes(bytes: &[u8], t: PolynomialRepresentation) -> Result<Self, String> {
        assert_eq!(bytes.len(), 384);

        let mut p = Polynomial::new(t);
        let mut p_idx = 0;
        let mut bi = 0;

        for _ in 0..128 {
            let b0 = (bytes[bi] as i16) | (((bytes[bi + 1] & 0xf) as i16) << 8);
            let b1 = ((bytes[bi + 1] >> 4) as i16) | ((bytes[bi + 2] as i16) << 4);
            bi += 3;

            if b0 >= Q || b1 >= Q {
                p.zeroize();
                return Err(String::from(
                    "Polynomial coefficients must be canonically encoded (in range [0, q-1]).",
                ));
            }

            p[p_idx] = b0;
            p[p_idx + 1] = b1;
            p_idx += 2;
        }

        Ok(p)
    }

    pub(crate) fn to_bytes(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), 384);

        let mut s_idx = 0;
        let mut b_idx = 0;

        for _ in 0..128 {
            let a0 = norm_q(self[s_idx]) as u16;
            let a1 = norm_q(self[s_idx + 1]) as u16;
            s_idx += 2;

            let b0 = a0 as u8;
            let b1 = ((a0 >> 8) | (a1 << 4)) as u8;
            let b2 = (a1 >> 4) as u8;

            buf[b_idx] = b0;
            buf[b_idx + 1] = b1;
            buf[b_idx + 2] = b2;
            b_idx += 3;
        }
    }

    pub fn from_msg(value: &[u8]) -> Self {
        let mut r = Polynomial::new(PolynomialRepresentation::STANDARD);

        for i in 0..N {
            let mask = 0u16.wrapping_sub(test_bit(value, i) as u16) as i16;
            r[i] += HALF_Q & mask;
        }

        r
    }

    pub fn to_msg(&self) -> [u8; 32] {
        let mut r = [0u8; 32];

        for i in 0..32 {
            let base = i << 3;

            for j in 0..8 {
                let mut t = self[base + j] as u32;
                t <<= 1;
                t = t.wrapping_add(1665);
                t = t.wrapping_mul(80635);
                t >>= 28;
                t &= 1;
                r[i] |= (t as u8) << j;
            }
        }

        r
    }

    pub fn compress_encode(&self, dv: usize, r: &mut [u8]) {
        match dv {
            5 => self.compress_encode_5(r),
            4 => self.compress_encode_4(r),
            _ => unreachable!(),
        }
    }

    fn compress_encode_5(&self, r: &mut [u8]) {
        let mut ri = 0;
        let mut t = [0u8; 8];

        for i in 0..32 {
            let base = i << 3;

            for j in 0..8 {
                let u = norm_q(self[base + j]) as u16;
                let mut d0 = (u as u32) << 5;
                d0 += 1664;
                d0 = d0.wrapping_mul(40318);
                d0 >>= 27;
                t[j] = (d0 & 0x1f) as u8;
            }

            r[ri] = (t[0]) | (t[1] << 5);
            r[ri + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[ri + 2] = (t[3] >> 1) | (t[4] << 4);
            r[ri + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[ri + 4] = (t[6] >> 2) | (t[7] << 3);
            ri += 5;
        }
    }

    fn compress_encode_4(&self, r: &mut [u8]) {
        let mut ri = 0;
        let mut t = [0u8; 8];

        for i in 0..32 {
            let base = i << 3;

            for j in 0..8 {
                let u = norm_q(self[base + j]) as u16;
                let mut d0 = (u as u32) << 4;
                d0 += 1665;
                d0 = d0.wrapping_mul(80635);
                d0 >>= 28;
                t[j] = (d0 & 0xf) as u8;
            }

            r[ri] = t[0] | (t[1] << 4);
            r[ri + 1] = t[2] | (t[3] << 4);
            r[ri + 2] = t[4] | (t[5] << 4);
            r[ri + 3] = t[6] | (t[7] << 4);
            ri += 4;
        }
    }

    pub fn decode_decompress(dv: usize, c: &[u8]) -> Self {
        match dv {
            5 => Self::decode_decompress_5(c),
            4 => Self::decode_decompress_4(c),
            _ => unreachable!(),
        }
    }

    fn decode_decompress_5(c: &[u8]) -> Self {
        assert_eq!(c.len(), 160);

        let mut r = Self::new(PolynomialRepresentation::STANDARD);
        let mut t = [0u8; 8];
        let mut ci = 0;

        for i in 0..32 {
            t[0] = c[ci];
            t[1] = (c[ci] >> 5) | (c[ci + 1] << 3);
            t[2] = c[ci + 1] >> 2;
            t[3] = (c[ci + 1] >> 7) | (c[ci + 2] << 1);
            t[4] = (c[ci + 2] >> 4) | (c[ci + 3] << 4);
            t[5] = c[ci + 3] >> 1;
            t[6] = (c[ci + 3] >> 6) | (c[ci + 4] << 2);
            t[7] = c[ci + 4] >> 3;
            ci += 5;

            let base = i << 3;
            for j in 0..8 {
                r[base + j] = (((t[j] & 0x1f) as u32 * Q as u32 + 16) >> 5) as i16;
            }
        }

        r
    }

    fn decode_decompress_4(c: &[u8]) -> Self {
        assert_eq!(c.len(), 128);

        let mut r = Self::new(PolynomialRepresentation::STANDARD);

        for i in 0..128 {
            r[i << 1] = (((c[i] & 0xf) as u16 * Q as u16 + 8) >> 4) as i16;
            r[(i << 1) + 1] = (((c[i] >> 4) as u16 * Q as u16 + 8) >> 4) as i16;
        }

        r
    }
}

impl Add for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.t, rhs.t);
        let mut r = Polynomial::new(self.t);

        for i in 0..N {
            r[i] = self[i] + rhs[i];
        }

        r
    }
}

impl Mul for &Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.t, PolynomialRepresentation::NTT);
        debug_assert_eq!(rhs.t, PolynomialRepresentation::NTT);
        let mut r = Polynomial::new(PolynomialRepresentation::NTT);

        for i in 0..(N >> 2) {
            base_case_multiply(&mut r.f, &self.f, &rhs.f, ZETAS_MONT_FORM[64 + i], i << 2);
            base_case_multiply(
                &mut r.f,
                &self.f,
                &rhs.f,
                -ZETAS_MONT_FORM[64 + i],
                (i << 2) + 2,
            );
        }

        r
    }
}

impl Sub for &Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.t, rhs.t);
        let mut r = Polynomial::new(self.t);

        for i in 0..N {
            r[i] = self[i] - rhs[i];
        }

        r
    }
}

impl Index<usize> for Polynomial {
    type Output = i16;

    fn index(&self, index: usize) -> &Self::Output {
        &self.f[index]
    }
}

impl IndexMut<usize> for Polynomial {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.f[index]
    }
}

impl Zeroize for Polynomial {
    fn zeroize(&mut self) {
        unsafe {
            write_bytes(self.f.as_mut_ptr(), 0, N);
            asm!("/* {0} */", in(reg) self.f.as_ptr(), options(nostack, preserves_flags));
        }
        compiler_fence(SeqCst);
    }
}

#[inline]
fn base_case_multiply(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16, i: usize) {
    r[i] = mul_q(a[i], b[i]) + mul_q(mul_q(a[i + 1], b[i + 1]), zeta);
    r[i + 1] = mul_q(a[i], b[i + 1]) + mul_q(a[i + 1], b[i]);
}

#[inline]
fn test_bit(bytes: &[u8], i: usize) -> u8 {
    let byte = i >> 3;
    let bit = i & 0b111;
    (bytes[byte] >> bit) & 1
}

#[cfg(test)]
#[path = "unit_tests/polynomial_test.rs"]
mod polynomial_test;
