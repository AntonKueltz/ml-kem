use std::iter::zip;

use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{Shake256, digest::ExtendableOutput};

pub fn prf(eta: usize, s: &[u8], b: u8) -> Vec<u8> {
    let mut input = s.to_vec();
    input.push(b);

    let sz = eta << 6;
    let mut output = vec![0u8; sz];

    Shake256::digest_xof(input, &mut output);
    output
}

pub fn g(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hashed = Sha3_512::digest(data);
    (hashed[..32].to_vec(), hashed[32..64].to_vec())
}

pub fn h(data: &[u8]) -> Vec<u8> {
    let hashed = Sha3_256::digest(data);
    hashed.to_vec()
}

pub fn j(input: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; 32];
    Shake256::digest_xof(input, &mut output);
    output
}

pub fn ct_cmp(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    let mut r = 0;

    for (c, d) in zip(a, b) {
        r |= c ^ d
    }

    r == 0 && a.len() == b.len()
}
