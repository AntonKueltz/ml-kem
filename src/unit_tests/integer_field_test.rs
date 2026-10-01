use crate::integer_field::*;

#[test]
fn test_mul_q() {
    let t = mul_q(100, 2226);
    assert_eq!(t, -1629);
}

#[test]
fn test_barr_q() {
    let t = barr_q(5000);
    assert_eq!(t, -1658);
}

#[test]
fn test_norm_q() {
    let t = norm_q(-1658);
    assert_eq!(t, 1671);
}
