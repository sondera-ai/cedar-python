//! Python bindings for Cedar Policy
//!
//! This crate provides comprehensive Python bindings for Cedar policy and schema
//! validation, parsing, and analysis using PyO3.

mod authorizer;
mod entity;
mod expression;
mod policy;
use pyo3::prelude::*;

// Python module registration
#[pymodule]
fn cedar(m: &Bound<'_, PyModule>) -> PyResult<()> {
    entity::register(m)?;
    authorizer::register(m)?;
    policy::register(m)?;
    Ok(())
}
