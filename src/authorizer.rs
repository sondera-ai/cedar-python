//! Engine module for Cedar policy authorization and evaluation
//!
//! This module provides the core authorization engine functionality
//! for evaluating Cedar policies against authorization requests.

use crate::entity::{PyEntity, PyEntityUid};
use crate::policy::{PyPolicy, PyPolicySet, PySchema};
use cedar_policy::{Authorizer, Context, Decision, Entities, PolicySet, Request, Response, Schema};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

#[pyclass(name = "Context")]
#[derive(Clone)]
pub struct PyContext {
    pub(crate) inner: Context,
}

#[pymethods]
impl PyContext {
    #[new]
    #[pyo3(signature = (context, schema=None, action=None))]
    fn new(
        context: &Bound<'_, PyDict>,
        schema: Option<&Bound<'_, PySchema>>,
        action: Option<&Bound<'_, PyEntityUid>>,
    ) -> PyResult<Self> {
        let json_module = context.py().import("json")?;
        let json_str: String = json_module.call_method1("dumps", (context,))?.extract()?;
        let schema_info = match (schema, action) {
            (Some(s), Some(a)) => Some((s.borrow().inner.clone(), a.borrow().inner.clone())),
            (Some(_), None) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "action is required when schema is provided for context validation",
                ));
            }
            _ => None,
        };
        let inner = Context::from_json_str(&json_str, schema_info.as_ref().map(|(s, a)| (s, a)))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn empty() -> Self {
        Self {
            inner: Context::empty(),
        }
    }

    #[staticmethod]
    #[pyo3(signature = (json, schema=None, action=None))]
    fn from_json(
        json: &str,
        schema: Option<&Bound<'_, PySchema>>,
        action: Option<&Bound<'_, PyEntityUid>>,
    ) -> PyResult<Self> {
        let schema_info = match (schema, action) {
            (Some(s), Some(a)) => Some((s.borrow().inner.clone(), a.borrow().inner.clone())),
            (Some(_), None) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "action is required when schema is provided for context validation",
                ));
            }
            _ => None,
        };
        let context = Context::from_json_str(json, schema_info.as_ref().map(|(s, a)| (s, a)))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: context })
    }
}

#[pyclass(name = "Request")]
pub struct PyRequest {
    inner: Request,
}

#[pymethods]
impl PyRequest {
    #[new]
    #[pyo3(signature = (principal, action, resource, context=None, schema=None))]
    fn new(
        principal: &Bound<'_, PyEntityUid>,
        action: &Bound<'_, PyEntityUid>,
        resource: &Bound<'_, PyEntityUid>,
        context: Option<&Bound<'_, PyContext>>,
        schema: Option<&Bound<'_, PySchema>>,
    ) -> PyResult<Self> {
        let ctx = context
            .map(|c| c.borrow().inner.clone())
            .unwrap_or_else(Context::empty);
        let schema_ref = schema.map(|s| s.borrow().inner.clone());
        let request = Request::new(
            principal.borrow().inner.clone(),
            action.borrow().inner.clone(),
            resource.borrow().inner.clone(),
            ctx,
            schema_ref.as_ref(),
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid request: {}", e)))?;
        Ok(Self { inner: request })
    }
}

#[pyclass(name = "Response")]
pub struct PyResponse {
    decision: String,
    allowed: bool,
    reason: Vec<String>,
    errors: Vec<String>,
}

#[pymethods]
impl PyResponse {
    /// Get the authorization decision ("Allow" or "Deny")
    #[getter]
    fn decision(&self) -> &str {
        &self.decision
    }

    /// Check if the request was allowed
    #[getter]
    fn allowed(&self) -> bool {
        self.allowed
    }

    /// Get the policy IDs that contributed to the decision
    #[getter]
    fn reason(&self) -> Vec<String> {
        self.reason.clone()
    }

    /// Get any errors that occurred during evaluation
    #[getter]
    fn errors(&self) -> Vec<String> {
        self.errors.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Response(decision={}, reason={:?}, errors={:?})",
            self.decision, self.reason, self.errors
        )
    }

    fn __bool__(&self) -> bool {
        self.allowed
    }
}

impl From<Response> for PyResponse {
    fn from(response: Response) -> Self {
        let decision = response.decision();
        let diagnostics = response.diagnostics();

        Self {
            decision: format!("{:?}", decision),
            allowed: matches!(decision, Decision::Allow),
            reason: diagnostics.reason().map(|id| id.to_string()).collect(),
            errors: diagnostics.errors().map(|e| e.to_string()).collect(),
        }
    }
}

#[pyclass(name = "Authorizer")]
pub struct PyAuthorizer {
    authorizer: Authorizer,
    entities: Entities,
    schema: Option<Schema>,
}

#[pymethods]
impl PyAuthorizer {
    #[new]
    #[pyo3(signature = (entities=None, schema=None))]
    fn new(
        entities: Option<&Bound<'_, PyList>>,
        schema: Option<&Bound<'_, PySchema>>,
    ) -> PyResult<Self> {
        let authorizer = Authorizer::new();
        let schema_inner = schema.map(|s| s.borrow().inner.clone());
        let entity_set = if let Some(entity_list) = entities {
            let cedar_entities: Vec<cedar_policy::Entity> = entity_list
                .iter()
                .map(|e| {
                    let py_entity: PyRef<PyEntity> = e.extract()?;
                    Ok(py_entity.inner.clone())
                })
                .collect::<PyResult<_>>()?;
            Entities::from_entities(cedar_entities, schema_inner.as_ref())
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?
        } else {
            Entities::empty()
        };
        Ok(Self {
            authorizer,
            entities: entity_set,
            schema: schema_inner,
        })
    }

    /// Check if request is authorized against a policy set
    pub fn is_authorized(
        &self,
        request: &Bound<'_, PyRequest>,
        policies: &Bound<'_, PyPolicySet>,
    ) -> PyResponse {
        let req = request.borrow().inner.clone();
        let policy_set = &policies.borrow().inner;
        let response = self
            .authorizer
            .is_authorized(&req, policy_set, &self.entities);
        PyResponse::from(response)
    }

    /// Check if request is authorized against a single policy
    pub fn is_authorized_for_policy(
        &self,
        request: &Bound<'_, PyRequest>,
        policy: &Bound<'_, PyPolicy>,
    ) -> PyResult<PyResponse> {
        let req = request.borrow().inner.clone();
        let mut policy_set = PolicySet::new();
        policy_set
            .add(policy.borrow().inner.clone())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let response = self
            .authorizer
            .is_authorized(&req, &policy_set, &self.entities);
        Ok(PyResponse::from(response))
    }

    /// Validate request components against the authorizer's schema.
    /// Raises ValueError if no schema was provided to the authorizer.
    #[pyo3(signature = (principal, action, resource, context=None))]
    pub fn validate_request(
        &self,
        principal: &Bound<'_, PyEntityUid>,
        action: &Bound<'_, PyEntityUid>,
        resource: &Bound<'_, PyEntityUid>,
        context: Option<&Bound<'_, PyContext>>,
    ) -> PyResult<()> {
        let schema = self.schema.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "Cannot validate request: no schema provided to Authorizer",
            )
        })?;
        let ctx = context
            .map(|c| c.borrow().inner.clone())
            .unwrap_or_else(Context::empty);
        Request::new(
            principal.borrow().inner.clone(),
            action.borrow().inner.clone(),
            resource.borrow().inner.clone(),
            ctx,
            Some(schema),
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid request: {}", e)))?;
        Ok(())
    }

    /// Add an entity to the authorizer's entity store.
    /// Raises ValueError if an entity with the same UID already exists or if
    /// schema validation fails.
    pub fn add_entity(&mut self, entity: &Bound<'_, PyEntity>) -> PyResult<()> {
        let cedar_entity = entity.borrow().inner.clone();
        let entities = std::mem::take(&mut self.entities);
        self.entities = entities
            .add_entities([cedar_entity], self.schema.as_ref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(())
    }

    /// Upsert an entity into the authorizer's entity store.
    /// If an entity with the same UID exists, it will be replaced.
    /// Raises ValueError if schema validation fails.
    pub fn upsert_entity(&mut self, entity: &Bound<'_, PyEntity>) -> PyResult<()> {
        let cedar_entity = entity.borrow().inner.clone();
        let entities = std::mem::take(&mut self.entities);
        self.entities = entities
            .upsert_entities([cedar_entity], self.schema.as_ref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(())
    }

    /// Remove an entity from the authorizer's entity store by its UID.
    /// Raises ValueError if removal fails (e.g., entity not found).
    pub fn remove_entity(&mut self, uid: &Bound<'_, PyEntityUid>) -> PyResult<()> {
        let entity_uid = uid.borrow().inner.clone();
        let entities = std::mem::take(&mut self.entities);
        self.entities = entities
            .remove_entities([entity_uid])
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(())
    }
}

/// Register engine functions with the Python module
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyContext>()?;
    m.add_class::<PyRequest>()?;
    m.add_class::<PyResponse>()?;
    m.add_class::<PyAuthorizer>()?;
    Ok(())
}
