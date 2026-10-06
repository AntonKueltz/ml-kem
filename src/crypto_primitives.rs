use std::iter::zip;

use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

pub fn prf(s: &[u8; 32], b: u8) -> Zeroizing<[u8; 192]> {
    let mut xof = Shake256::default();
    xof.update(s);
    xof.update(&[b]);

    let mut output = [0u8; 192];
    xof.finalize_xof().read(&mut output);
    output.into()
}

pub fn j(z: &[u8], c: &[u8]) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(z);
    xof.update(c);

    let mut output = [0u8; 32];
    xof.finalize_xof().read(&mut output);
    output.into()
}

pub fn ct_cmp(a: &[u8], b: &[u8]) -> bool {
    let mut r = 0;

    for (c, d) in zip(a, b) {
        r |= c ^ d
    }

    r == 0 && a.len() == b.len()
}
