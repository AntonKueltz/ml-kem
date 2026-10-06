use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encaps_key::EncapsKey;
use crate::vector::Vector;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsKey<const K: usize> {
    s: Vector<K>,
    #[zeroize(skip)]
    ek: EncapsKey<K>,
    #[zeroize(skip)]
    ek_hash: [u8; 32],
    z: [u8; 32],
}

impl<const K: usize> DecapsKey<K> {
    pub fn new(s: Vector<K>, ek: EncapsKey<K>, ek_hash: [u8; 32], z: [u8; 32]) -> Self {
        Self { s, ek, ek_hash, z }
    }

    pub fn s(&self) -> &Vector<K> {
        &self.s
    }

    pub fn ek(&self) -> &EncapsKey<K> {
        &self.ek
    }

    pub fn ek_hash(&self) -> &[u8; 32] {
        &self.ek_hash
    }

    pub fn z(&self) -> &[u8; 32] {
        &self.z
    }
}
