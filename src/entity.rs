use pyo3::prelude::*;

use crate::expression;
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use pyo3::types::{PyDict, PyList, PyType};
use std::collections::{HashMap, HashSet};

#[pyclass(name = "EntityType", frozen, eq, hash)]
#[derive(Clone, PartialEq, Hash)]
pub struct PyEntityType {
    pub(crate) inner: EntityTypeName,
}

#[pymethods]
impl PyEntityType {
    #[new]
    fn new(name: &str) -> PyResult<Self> {
        let type_name: EntityTypeName = name.parse().map_err(|e: cedar_policy::ParseErrors| {
            pyo3::exceptions::PyValueError::new_err(e.to_string())
        })?;
        Ok(Self { inner: type_name })
    }

    /// Get the basename of the entity type (without namespace)
    fn basename(&self) -> &str {
        self.inner.basename()
    }

    /// Get the namespace of the entity type (empty string if no namespace)
    fn namespace(&self) -> String {
        self.inner.namespace()
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("EntityType({:?})", self.inner.to_string())
    }
}

#[pyclass(name = "Entity")]
pub struct PyEntity {
    pub(crate) inner: Entity,
}

#[pymethods]
impl PyEntity {
    #[new]
    #[pyo3(signature = (uid, attrs, parents=None))]
    fn new(
        uid: &Bound<'_, PyEntityUid>,
        attrs: &Bound<'_, PyDict>,
        parents: Option<&Bound<'_, PyList>>,
    ) -> PyResult<Self> {
        let entity_uid = uid.borrow().inner.clone();

        // Convert attrs dict to HashMap<String, RestrictedExpression>
        let attributes: HashMap<String, RestrictedExpression> = attrs
            .iter()
            .map(|(k, v)| {
                let key: String = k.extract()?;
                let val = expression::py_to_restricted_expr(&v)?;
                Ok((key, val))
            })
            .collect::<PyResult<_>>()?;

        // Convert parents list to HashSet<EntityUid>
        let parent_set: HashSet<EntityUid> = if let Some(parent_list) = parents {
            parent_list
                .iter()
                .map(|p| {
                    let parent_uid: PyRef<PyEntityUid> = p.extract()?;
                    Ok(parent_uid.inner.clone())
                })
                .collect::<PyResult<_>>()?
        } else {
            HashSet::new()
        };

        let entity = Entity::new(entity_uid, attributes, parent_set)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Self { inner: entity })
    }

    fn uid(&self) -> PyEntityUid {
        PyEntityUid {
            inner: self.inner.uid().clone(),
        }
    }
}

#[pyclass(name = "EntityUid", frozen, eq, hash)]
#[derive(Clone, PartialEq, Hash)]
pub struct PyEntityUid {
    pub(crate) inner: EntityUid,
}

#[pymethods]
impl PyEntityUid {
    #[new]
    fn new(entity_type: &str, id: &str) -> PyResult<Self> {
        // EntityId::parse() returns Infallible error, so it can't fail
        let eid: EntityId = id.parse().expect("EntityId parsing is infallible");
        let entity_type: EntityTypeName =
            entity_type
                .parse()
                .map_err(|e: cedar_policy::ParseErrors| {
                    pyo3::exceptions::PyValueError::new_err(e.to_string())
                })?;
        let eid = EntityUid::from_type_name_and_id(entity_type, eid);
        Ok(Self { inner: eid })
    }

    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, json: &str) -> PyResult<Self> {
        let value = serde_json::from_str(json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {}", e)))?;
        let eid = EntityUid::from_json(value).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid EntityUid JSON: {}", e))
        })?;
        Ok(Self { inner: eid })
    }

    fn id(&self) -> &str {
        self.inner.id().unescaped()
    }

    fn to_json(&self) -> String {
        let json_data = serde_json::json!(
            { "__entity":
                { "type": self.inner.type_name().to_string(),
                    "id": self.inner.id().unescaped()
                }
            }
        );
        json_data.to_string()
    }

    fn entity_type(&self) -> String {
        self.inner.type_name().to_string()
    }

    fn __str__(&self) -> String {
        format!(
            "{}::\"{}\"",
            self.inner.type_name(),
            self.inner.id().unescaped()
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "EntityUid({:?}, {:?})",
            self.inner.type_name().to_string(),
            self.inner.id().unescaped()
        )
    }
}

impl From<PyEntityUid> for EntityUid {
    fn from(entity: PyEntityUid) -> Self {
        entity.inner
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEntityType>()?;
    m.add_class::<PyEntity>()?;
    m.add_class::<PyEntityUid>()?;
    Ok(())
}
