use pyo3::prelude::*;

use crate::kem::KEM;

pub mod crypto_primitives;
pub mod integer_field;
pub mod kem;
pub mod matrix;
pub mod polynomial;

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

#[pyclass(name = "ML_KEM")]
struct MlKem {
    kem: KEM,
}

#[pymethods]
impl MlKem {
    #[new]
    #[pyo3(signature = (parameter_set = ParameterSet::MlKem768))]
    fn new(parameter_set: ParameterSet) -> PyResult<Self> {
        match parameter_set {
            ParameterSet::MlKem512 => Ok(Self {
                kem: KEM::ml_kem_512(),
            }),
            ParameterSet::MlKem768 => Ok(Self {
                kem: KEM::ml_kem_768(),
            }),
            ParameterSet::MlKem1024 => Ok(Self {
                kem: KEM::ml_kem_1024(),
            }),
        }
    }

    fn key_gen(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.kem.key_gen()
    }

    fn encaps(&self, ek: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        self.kem.encaps(&ek)
    }

    fn decaps(&self, dk: Vec<u8>, c: Vec<u8>) -> Vec<u8> {
        self.kem.decaps(&dk, &c)
    }
}

#[pymodule]
fn rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ParameterSet>()?;
    m.add_class::<MlKem>()?;
    Ok(())
}
