use sha3::{Digest, Sha3_256};

use crate::matrix::Matrix;
use crate::vector::Vector;

#[derive(Clone)]
pub struct EncapsKey<const K: usize> {
    t: Vector<K>,
    rho: [u8; 32],
    at: Matrix<K>,
}

impl<const K: usize> EncapsKey<K> {
    pub fn new(t: Vector<K>, rho: [u8; 32], at: Matrix<K>) -> Self {
        Self { t, rho, at }
    }

    pub fn t(&self) -> &Vector<K> {
        &self.t
    }

    pub fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    pub fn at(&self) -> &Matrix<K> {
        &self.at
    }

    pub fn h(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        for i in 0..K {
            let bytes: [u8; 384] = self.t[i].into();
            hasher.update(&bytes);
        }
        hasher.update(&self.rho);

        let hashed = hasher.finalize();
        hashed.try_into().unwrap()
    }
}
