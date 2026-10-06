use pyo3::{exceptions::PyValueError, prelude::*};

// use crate::kem::{DecapsKey, EncapsKey, KEM};

pub mod crypto_primitives;
pub mod decaps_key;
pub mod encaps_key;
pub mod integer_field;
pub mod kem;
pub mod matrix;
pub mod param_set;
pub mod polynomial;
pub mod vector;

// #[pyclass(from_py_object)]
// #[derive(PartialEq, Clone, Copy)]
// pub enum ParameterSet {
//     #[pyo3(name = "ML_KEM_512")]
//     MlKem512 = 512,
//     #[pyo3(name = "ML_KEM_768")]
//     MlKem768 = 768,
//     #[pyo3(name = "ML_KEM_1024")]
//     MlKem1024 = 1024,
// }

// #[pyclass(name = "ML_KEM")]
// struct MlKem {
//     kem: KEM,
// }

// #[pyclass(name = "EncapsKey")]
// struct PyEncapsKey {
//     key: EncapsKey,
// }

// #[pyclass(name = "DecapsKey")]
// struct PyDecapsKey {
//     key: DecapsKey,
// }

// #[pymethods]
// impl MlKem {
//     #[new]
//     #[pyo3(signature = (parameter_set = ParameterSet::MlKem768))]
//     fn new(parameter_set: ParameterSet) -> PyResult<Self> {
//         match parameter_set {
//             ParameterSet::MlKem512 => Ok(Self {
//                 kem: KEM::ml_kem_512(),
//             }),
//             ParameterSet::MlKem768 => Ok(Self {
//                 kem: KEM::ml_kem_768(),
//             }),
//             ParameterSet::MlKem1024 => Ok(Self {
//                 kem: KEM::ml_kem_1024(),
//             }),
//         }
//     }

//     fn key_gen(&mut self) -> (PyEncapsKey, PyDecapsKey) {
//         let (ek, dk) = self.kem.key_gen();
//         (PyEncapsKey { key: ek }, PyDecapsKey { key: dk })
//     }

//     #[pyo3(signature = (ek, check_key = true))]
//     fn encaps(&mut self, ek: &PyEncapsKey, check_key: bool) -> PyResult<(Vec<u8>, Vec<u8>)> {
//         match self.kem.encaps(&ek.key, check_key) {
//             Ok(result) => Ok(result),
//             Err(err) => Err(PyValueError::new_err(err)),
//         }
//     }

//     #[pyo3(signature = (dk, c, check_key = true))]
//     fn decaps(&mut self, dk: &PyDecapsKey, c: Vec<u8>, check_key: bool) -> PyResult<Vec<u8>> {
//         match self.kem.decaps(&dk.key, &c, check_key) {
//             Ok(bytes) => Ok(bytes),
//             Err(err) => Err(PyValueError::new_err(err)),
//         }
//     }
// }

// #[pymodule]
// fn rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
//     m.add_class::<ParameterSet>()?;
//     m.add_class::<MlKem>()?;
//     Ok(())
// }
