use std::iter::zip;

use sha3::{Digest, Sha3_256, Sha3_512};
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

pub fn g(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hashed = Sha3_512::digest(data);
    let (l, r) = hashed.split_at(32);
    (l.try_into().unwrap(), r.try_into().unwrap())
}

pub fn h(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

pub fn j(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    Shake256::digest_xof(data, &mut output);
    output
}

pub fn ct_cmp(a: &[u8], b: &[u8]) -> bool {
    let mut r = 0;

    for (c, d) in zip(a, b) {
        r |= c ^ d
    }

    r == 0 && a.len() == b.len()
}
