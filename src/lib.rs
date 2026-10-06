use pyo3::{exceptions::PyValueError, prelude::*};

use crate::decaps_key::DecapsKey;
use crate::encaps_key::EncapsKey;
use crate::kem::{Kem, MlKem512, MlKem768, MlKem1024};

pub mod crypto_primitives;
pub mod decaps_key;
pub mod encaps_key;
pub mod integer_field;
pub mod kem;
pub mod matrix;
pub mod polynomial;
pub mod vector;

#[pyclass(from_py_object)]
#[derive(PartialEq, Clone, Copy)]
pub enum ParameterSet {
    #[pyo3(name = "ML_KEM_512")]
    MlKem512 = 512,
    #[pyo3(name = "ML_KEM_768")]
    MlKem768 = 768,
    #[pyo3(name = "ML_KEM_1024")]
    MlKem1024 = 1024,
}

enum EkInner {
    P512(EncapsKey<2>),
    P768(EncapsKey<3>),
    P1024(EncapsKey<4>),
}

enum DkInner {
    P512(DecapsKey<2>),
    P768(DecapsKey<3>),
    P1024(DecapsKey<4>),
}

#[pyclass(name = "EncapsKey", frozen)]
struct PyEncapsKey {
    inner: EkInner,
}

#[pyclass(name = "DecapsKey", frozen)]
struct PyDecapsKey {
    inner: DkInner,
}

#[pyclass(name = "ML_KEM", frozen)]
struct MlKem {
    params: ParameterSet,
}

fn ek_to_bytes<P: Kem>(ek: &P::EncapsKey) -> Vec<u8> {
    P::serialize_ek(ek).as_ref().to_vec()
}

fn dk_to_bytes<P: Kem>(dk: &P::DecapsKey) -> Vec<u8> {
    P::serialize_dk(dk).as_ref().to_vec()
}

fn mismatch() -> PyErr {
    PyValueError::new_err("Key does not match this ML_KEM parameter set")
}

fn key_gen_impl<P: Kem>() -> (P::EncapsKey, P::DecapsKey) {
    P::key_gen()
}

fn encaps_impl<P: Kem>(ek: &P::EncapsKey) -> (Vec<u8>, Vec<u8>) {
    let (k, c) = P::encaps(ek);
    (k.to_vec(), c.as_ref().to_vec())
}

fn decaps_impl<P: Kem>(dk: &P::DecapsKey, c: &[u8]) -> PyResult<Vec<u8>>
where
    for<'a> P::Ctxt: TryFrom<&'a [u8]>,
{
    let c: P::Ctxt = c
        .try_into()
        .map_err(|_| PyValueError::new_err("Invalid ciphertext"))?;
    P::decaps(dk, &c)
        .map(|k| k.to_vec())
        .map_err(PyValueError::new_err)
}

#[pymethods]
impl PyEncapsKey {
    fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            EkInner::P512(k) => ek_to_bytes::<MlKem512>(k),
            EkInner::P768(k) => ek_to_bytes::<MlKem768>(k),
            EkInner::P1024(k) => ek_to_bytes::<MlKem1024>(k),
        }
    }

    fn __bytes__(&self) -> Vec<u8> {
        self.to_bytes()
    }

    #[getter]
    fn parameter_set(&self) -> ParameterSet {
        match &self.inner {
            EkInner::P512(_) => ParameterSet::MlKem512,
            EkInner::P768(_) => ParameterSet::MlKem768,
            EkInner::P1024(_) => ParameterSet::MlKem1024,
        }
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = match data.len() {
            800 => EkInner::P512(MlKem512::deserialize_ek(data).map_err(PyValueError::new_err)?),
            1184 => EkInner::P768(MlKem768::deserialize_ek(data).map_err(PyValueError::new_err)?),
            1568 => EkInner::P1024(MlKem1024::deserialize_ek(data).map_err(PyValueError::new_err)?),
            n => {
                return Err(PyValueError::new_err(format!(
                    "Invalid encapsulation key length {n}; expected 800, 1184, or 1568"
                )));
            }
        };
        Ok(Self { inner })
    }
}

#[pymethods]
impl PyDecapsKey {
    fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            DkInner::P512(k) => dk_to_bytes::<MlKem512>(k),
            DkInner::P768(k) => dk_to_bytes::<MlKem768>(k),
            DkInner::P1024(k) => dk_to_bytes::<MlKem1024>(k),
        }
    }

    fn __bytes__(&self) -> Vec<u8> {
        self.to_bytes()
    }

    #[getter]
    fn parameter_set(&self) -> ParameterSet {
        match &self.inner {
            DkInner::P512(_) => ParameterSet::MlKem512,
            DkInner::P768(_) => ParameterSet::MlKem768,
            DkInner::P1024(_) => ParameterSet::MlKem1024,
        }
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = match data.len() {
            1632 => DkInner::P512(MlKem512::deserialize_dk(data).map_err(PyValueError::new_err)?),
            2400 => DkInner::P768(MlKem768::deserialize_dk(data).map_err(PyValueError::new_err)?),
            3168 => DkInner::P1024(MlKem1024::deserialize_dk(data).map_err(PyValueError::new_err)?),
            n => {
                return Err(PyValueError::new_err(format!(
                    "Invalid decapsulation key length {n}; expected 1632, 2400, or 3168"
                )));
            }
        };
        Ok(Self { inner })
    }
}

#[pymethods]
impl MlKem {
    #[new]
    #[pyo3(signature = (parameter_set = ParameterSet::MlKem768))]
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            params: parameter_set,
        }
    }

    fn key_gen(&self) -> (PyEncapsKey, PyDecapsKey) {
        match self.params {
            ParameterSet::MlKem512 => {
                let (ek, dk) = key_gen_impl::<MlKem512>();
                (
                    PyEncapsKey {
                        inner: EkInner::P512(ek),
                    },
                    PyDecapsKey {
                        inner: DkInner::P512(dk),
                    },
                )
            }
            ParameterSet::MlKem768 => {
                let (ek, dk) = key_gen_impl::<MlKem768>();
                (
                    PyEncapsKey {
                        inner: EkInner::P768(ek),
                    },
                    PyDecapsKey {
                        inner: DkInner::P768(dk),
                    },
                )
            }
            ParameterSet::MlKem1024 => {
                let (ek, dk) = key_gen_impl::<MlKem1024>();
                (
                    PyEncapsKey {
                        inner: EkInner::P1024(ek),
                    },
                    PyDecapsKey {
                        inner: DkInner::P1024(dk),
                    },
                )
            }
        }
    }

    fn encaps(&self, ek: &PyEncapsKey) -> PyResult<(Vec<u8>, Vec<u8>)> {
        match (self.params, &ek.inner) {
            (ParameterSet::MlKem512, EkInner::P512(k)) => Ok(encaps_impl::<MlKem512>(k)),
            (ParameterSet::MlKem768, EkInner::P768(k)) => Ok(encaps_impl::<MlKem768>(k)),
            (ParameterSet::MlKem1024, EkInner::P1024(k)) => Ok(encaps_impl::<MlKem1024>(k)),
            _ => Err(mismatch()),
        }
    }

    fn decaps(&self, dk: &PyDecapsKey, c: &[u8]) -> PyResult<Vec<u8>> {
        match (self.params, &dk.inner) {
            (ParameterSet::MlKem512, DkInner::P512(k)) => decaps_impl::<MlKem512>(k, &c),
            (ParameterSet::MlKem768, DkInner::P768(k)) => decaps_impl::<MlKem768>(k, &c),
            (ParameterSet::MlKem1024, DkInner::P1024(k)) => decaps_impl::<MlKem1024>(k, &c),
            _ => Err(mismatch()),
        }
    }
}

#[pymodule]
fn rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ParameterSet>()?;
    m.add_class::<PyEncapsKey>()?;
    m.add_class::<PyDecapsKey>()?;
    m.add_class::<MlKem>()?;
    Ok(())
}
