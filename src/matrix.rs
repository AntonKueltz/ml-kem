use std::array::from_fn;
use std::ops::{Index, IndexMut, Mul};

use crate::polynomial::PolynomialRepresentation;
use crate::vector::Vector;

#[derive(Clone)]
pub struct Matrix<const K: usize> {
    rows: [Vector<K>; K],
}

impl<const K: usize> Matrix<K> {
    pub fn new() -> Self {
        let rows: [Vector<K>; K] = from_fn(|_| Vector::<K>::new(PolynomialRepresentation::NTT));

        Self { rows }
    }

    pub fn transpose(&self) -> Self {
        let mut r = Self::new();

        for i in 0..K {
            for j in 0..K {
                r[i][j] = self[j][i].clone();
            }
        }

        r
    }
}

impl<const K: usize> Mul<&Vector<K>> for &Matrix<K> {
    type Output = Vector<K>;

    fn mul(self, rhs: &Vector<K>) -> Self::Output {
        let mut r = Vector::<K>::new(PolynomialRepresentation::NTT);

        for i in 0..K {
            r[i] = &self.rows[i] * rhs;
        }

        r
    }
}

impl<const K: usize> Index<usize> for Matrix<K> {
    type Output = Vector<K>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}

impl<const K: usize> IndexMut<usize> for Matrix<K> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.rows[index]
    }
}
