use sha3::{Digest, Sha3_512, digest::Output};
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::{Zeroize, Zeroizing};

pub fn prf(s: &[u8; 32], b: u8, buf: &mut [u8]) {
    let mut xof = Shake256::default();
    xof.update(s);
    xof.update(&[b]);
    xof.finalize_xof().read(buf);
}

pub fn g(chunks: &[&[u8]]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut hasher = Sha3_512::new();

    for bytes in chunks {
        Digest::update(&mut hasher, bytes);
    }

    let mut hashed = Output::<Sha3_512>::default();
    hasher.finalize_into(&mut hashed);

    let (mut l, mut r) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    l.copy_from_slice(&hashed[..32]);
    r.copy_from_slice(&hashed[32..]);
    hashed[..].zeroize();

    (l, r)
}

pub fn j(z: &[u8], c: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut xof = Shake256::default();
    xof.update(z);
    xof.update(c);

    let mut output = Zeroizing::new([0u8; 32]);
    xof.finalize_xof().read(&mut *output);
    output
}
