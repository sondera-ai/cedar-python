use crate::entity::PyEntityUid;
use cedar_policy::RestrictedExpression;
use pyo3::prelude::{PyAnyMethods, PyDictMethods, PyListMethods, PyTypeMethods};
use pyo3::types::{PyBool, PyDict, PyInt, PyList, PyString};
use pyo3::{Bound, PyAny, PyResult};
use std::collections::HashMap;

/// Convert a Python value to a Cedar RestrictedExpression
pub fn py_to_restricted_expr(value: &Bound<'_, PyAny>) -> PyResult<RestrictedExpression> {
    if value.is_none() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "None is not a valid Cedar value",
        ));
    }
    // Check bool before int since bool is a subclass of int in Python
    if value.is_instance_of::<PyBool>() {
        return Ok(RestrictedExpression::new_bool(value.extract::<bool>()?));
    }
    if value.is_instance_of::<PyInt>() {
        return Ok(RestrictedExpression::new_long(value.extract::<i64>()?));
    }
    if value.is_instance_of::<PyString>() {
        return Ok(RestrictedExpression::new_string(value.extract::<String>()?));
    }
    if value.is_instance_of::<PyEntityUid>() {
        let uid = value.extract::<PyEntityUid>()?;
        return Ok(RestrictedExpression::new_entity_uid(uid.inner));
    }
    if value.is_instance_of::<PyList>() {
        let list = value.extract::<Bound<'_, PyList>>()?;
        let items: Vec<RestrictedExpression> = list
            .iter()
            .map(|item| py_to_restricted_expr(&item))
            .collect::<PyResult<_>>()?;
        return Ok(RestrictedExpression::new_set(items));
    }
    if value.is_instance_of::<PyDict>() {
        let dict = value.extract::<Bound<'_, PyDict>>()?;
        let fields: HashMap<String, RestrictedExpression> = dict
            .iter()
            .map(|(k, v)| {
                let key: String = k.extract()?;
                let val = py_to_restricted_expr(&v)?;
                Ok((key, val))
            })
            .collect::<PyResult<_>>()?;
        return RestrictedExpression::new_record(fields)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
    }
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "Cannot convert {} to Cedar value. Supported types: bool, int, str, EntityUid, list, dict",
        value.get_type().name()?
    )))
}
