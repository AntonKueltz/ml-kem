const Q: i32 = 3329;
const QINV: i32 = -3327;

const BIT26: i32 = 1 << 26;
const BIT25: i32 = 1 << 25;

pub fn mul_q(a: i16, b: i16) -> i16 {
    let c: i32 = a as i32 * b as i32;
    mont_q(c)
}

fn mont_q(a: i32) -> i16 {
    debug_assert!(a >= -(Q << 15) && a < (Q << 15));

    let m = ((a as i16) as i32 * QINV) as i16;
    let t: i32 = a - (m as i32) * Q;
    (t >> 16) as i16
}

pub fn barr_q(a: i16) -> i16 {
    let v: i16 = ((BIT26 + Q / 2) / Q) as i16;
    let t: i16 = (((v as i32 * a as i32) + BIT25) >> 26) as i16;
    a - t * Q as i16
}

pub fn norm_q(a: i16) -> i16 {
    let mask = 0u16.wrapping_sub((a < 0) as u16) as i16;
    a + (Q as i16 & mask)
}

#[cfg(test)]
#[path = "unit_tests/integer_field_test.rs"]
mod integer_field_test;
