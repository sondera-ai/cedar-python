//! Policy module for Cedar policy and schema types
//!
//! This module provides Python bindings for Cedar Policy, PolicySet, and Schema types.

use crate::entity::PyEntityType;
use cedar_policy::{Policy, PolicyId, PolicySet, Schema, SchemaFragment, Validator};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::str::FromStr;

/// Represents a single Cedar policy
#[pyclass(name = "Policy")]
pub struct PyPolicy {
    pub(crate) inner: Policy,
}

#[pymethods]
impl PyPolicy {
    /// Create a policy from Cedar syntax
    /// If no id is provided, looks for an @id annotation on the policy
    #[new]
    #[pyo3(signature = (text, id=None))]
    fn new(text: &str, id: Option<&str>) -> PyResult<Self> {
        // If explicit ID provided, use it directly
        if let Some(explicit_id) = id {
            let policy_id = PolicyId::from_str(explicit_id)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let policy = Policy::parse(Some(policy_id), text)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            return Ok(Self { inner: policy });
        }

        // Parse first to check for @id annotation
        let policy = Policy::parse(None, text)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        // Check for @id annotation
        if let Some(annotation_id) = policy.annotation("id") {
            let policy_id = PolicyId::from_str(annotation_id)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let policy = Policy::parse(Some(policy_id), text)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            Ok(Self { inner: policy })
        } else {
            Ok(Self { inner: policy })
        }
    }

    /// Create a policy from Cedar syntax string
    #[staticmethod]
    #[pyo3(signature = (text, id=None))]
    fn from_str(text: &str, id: Option<&str>) -> PyResult<Self> {
        Self::new(text, id)
    }

    /// Create a policy from JSON representation
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let policy = Policy::from_json(None, value)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: policy })
    }

    /// Get the policy ID
    fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Get the policy effect ("Permit" or "Forbid")
    fn effect(&self) -> String {
        format!("{:?}", self.inner.effect())
    }

    /// Check if this is a static policy
    fn is_static(&self) -> bool {
        self.inner.is_static()
    }

    /// Get annotations as a dictionary
    fn annotations(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in self.inner.annotations() {
            dict.set_item(key, value)?;
        }
        Ok(dict.into())
    }

    /// Get a specific annotation value
    fn annotation(&self, key: &str) -> Option<String> {
        self.inner.annotation(key).map(|s| s.to_string())
    }

    /// Convert to JSON representation
    fn to_json(&self) -> PyResult<String> {
        let value = self
            .inner
            .to_json()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        serde_json::to_string(&value)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Convert to Cedar syntax
    fn to_cedar(&self) -> Option<String> {
        self.inner.to_cedar()
    }

    fn __str__(&self) -> String {
        self.inner.to_cedar().unwrap_or_else(|| self.id())
    }

    fn __repr__(&self) -> String {
        format!("Policy(id={:?}, effect={})", self.id(), self.effect())
    }
}

/// Represents a collection of Cedar policies
#[pyclass(name = "PolicySet")]
pub struct PyPolicySet {
    pub(crate) inner: PolicySet,
}

#[pymethods]
impl PyPolicySet {
    /// Create a PolicySet, optionally parsing from Cedar syntax
    #[new]
    #[pyo3(signature = (text=None))]
    fn new(text: Option<&str>) -> PyResult<Self> {
        match text {
            Some(t) => {
                let policy_set = PolicySet::from_str(t)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
                Ok(Self { inner: policy_set })
            }
            None => Ok(Self {
                inner: PolicySet::new(),
            }),
        }
    }

    /// Create from JSON representation
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let policy_set = PolicySet::from_json_str(json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: policy_set })
    }

    /// Add a policy to the set
    fn add(&mut self, policy: &PyPolicy) -> PyResult<()> {
        self.inner
            .add(policy.inner.clone())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Get all policies as a list
    fn policies(&self) -> Vec<PyPolicy> {
        self.inner
            .policies()
            .map(|p| PyPolicy { inner: p.clone() })
            .collect()
    }

    /// Get a policy by ID
    fn policy(&self, id: &str) -> PyResult<Option<PyPolicy>> {
        let policy_id = PolicyId::from_str(id)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(self
            .inner
            .policy(&policy_id)
            .map(|p| PyPolicy { inner: p.clone() }))
    }

    /// Convert to JSON representation
    fn to_json(&self) -> PyResult<String> {
        let value = self
            .inner
            .clone()
            .to_json()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        serde_json::to_string(&value)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Convert to Cedar syntax
    fn to_cedar(&self) -> Option<String> {
        self.inner.to_cedar()
    }

    /// Check if the policy set is empty
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        self.inner.policies().count()
    }

    fn __str__(&self) -> String {
        self.inner.to_cedar().unwrap_or_default()
    }

    fn __repr__(&self) -> String {
        format!("PolicySet(policies={})", self.__len__())
    }

    fn __iter__(&self) -> PyPolicySetIterator {
        PyPolicySetIterator {
            policies: self.policies(),
            index: 0,
        }
    }
}

#[pyclass]
pub struct PyPolicySetIterator {
    policies: Vec<PyPolicy>,
    index: usize,
}

#[pymethods]
impl PyPolicySetIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyPolicy> {
        if slf.index < slf.policies.len() {
            let policy = slf.policies[slf.index].inner.clone();
            slf.index += 1;
            Some(PyPolicy { inner: policy })
        } else {
            None
        }
    }
}

/// Represents a Cedar Schema Fragment
#[pyclass(name = "SchemaFragment")]
pub struct PySchemaFragment {
    pub(crate) inner: SchemaFragment,
}

#[pymethods]
impl PySchemaFragment {
    /// Create a schema fragment from JSON
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let fragment = SchemaFragment::from_json_str(json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: fragment })
    }

    /// Create a schema fragment from Cedar schema syntax
    #[staticmethod]
    fn from_cedarschema(text: &str) -> PyResult<Self> {
        let (fragment, _warnings) = SchemaFragment::from_cedarschema_str(text)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: fragment })
    }

    /// Convert to JSON representation
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json_string()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Convert to Cedar schema syntax
    fn to_cedarschema(&self) -> PyResult<String> {
        self.inner
            .to_cedarschema()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Get the namespaces defined in this schema fragment
    fn namespaces(&self) -> Vec<String> {
        self.inner
            .namespaces()
            .map(|ns| match ns {
                Some(namespace) => namespace.to_string(),
                None => String::new(),
            })
            .collect()
    }

    fn __str__(&self) -> PyResult<String> {
        self.to_cedarschema()
    }

    fn __repr__(&self) -> String {
        format!("SchemaFragment(namespaces={})", self.namespaces().len())
    }
}

/// Represents a Cedar schema
#[pyclass(name = "Schema")]
pub struct PySchema {
    pub(crate) inner: Schema,
    /// Store the original JSON source for faithful serialization
    source_json: Option<String>,
}

#[pymethods]
impl PySchema {
    /// Create a schema from JSON
    /// Create a schema from one or more schema fragments
    #[staticmethod]
    fn from_schema_fragments(
        py: Python<'_>,
        fragments: Vec<Py<PySchemaFragment>>,
    ) -> PyResult<Self> {
        let inner_fragments: Vec<SchemaFragment> = fragments
            .iter()
            .map(|f| f.borrow(py).inner.clone())
            .collect();

        let schema = Schema::from_schema_fragments(inner_fragments)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            inner: schema,
            source_json: None,
        })
    }

    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let schema = Schema::from_json_str(json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: schema,
            source_json: Some(json.to_string()),
        })
    }

    /// Create a schema from Cedar schema syntax
    #[staticmethod]
    fn from_cedarschema(text: &str) -> PyResult<Self> {
        let (schema, _warnings) = Schema::from_cedarschema_str(text)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        // Convert cedarschema to JSON for storage (preserves attributes)
        let (fragment, _warnings) = SchemaFragment::from_cedarschema_str(text)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let json_str = fragment
            .to_json_string()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            inner: schema,
            source_json: Some(json_str),
        })
    }

    /// Get all entity types defined in the schema
    fn entity_types(&self) -> Vec<PyEntityType> {
        self.inner
            .entity_types()
            .map(|t| PyEntityType { inner: t.clone() })
            .collect()
    }

    /// Get all actions defined in the schema
    fn actions(&self) -> Vec<String> {
        self.inner.actions().map(|a| a.to_string()).collect()
    }

    /// Get entity types that can be principals
    fn principals(&self) -> Vec<String> {
        self.inner.principals().map(|t| t.to_string()).collect()
    }

    /// Get entity types that can be resources
    fn resources(&self) -> Vec<String> {
        self.inner.resources().map(|t| t.to_string()).collect()
    }

    /// Convert to Cedar schema syntax
    fn to_cedarschema(&self) -> PyResult<String> {
        // Use stored JSON source if available (preserves entity attributes)
        let json = match &self.source_json {
            Some(json) => json.clone(),
            None => serde_json::to_string(&self.to_json_value()?)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?,
        };
        let fragment = SchemaFragment::from_json_str(&json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        fragment
            .to_cedarschema()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Convert to JSON representation
    fn to_json(&self) -> PyResult<String> {
        match &self.source_json {
            Some(json) => Ok(json.clone()),
            None => serde_json::to_string(&self.to_json_value()?)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string())),
        }
    }

    /// Validate a policy set against this schema
    fn validate_policyset(&self, policies: &PyPolicySet) -> PyValidationResult {
        let validator = Validator::new(self.inner.clone());
        let result = validator.validate(&policies.inner, cedar_policy::ValidationMode::default());

        let errors: Vec<PyValidationError> = result
            .validation_errors()
            .map(|e| PyValidationError {
                policy_id: e.policy_id().to_string(),
                message: e.to_string(),
            })
            .collect();

        let warnings: Vec<PyValidationWarning> = result
            .validation_warnings()
            .map(|w| PyValidationWarning {
                policy_id: w.policy_id().to_string(),
                message: w.to_string(),
            })
            .collect();

        PyValidationResult {
            valid: result.validation_passed(),
            errors,
            warnings,
        }
    }

    fn __str__(&self) -> PyResult<String> {
        self.to_cedarschema()
    }

    fn __repr__(&self) -> String {
        format!(
            "Schema(entity_types={}, actions={})",
            self.entity_types().len(),
            self.actions().len()
        )
    }
}

impl PySchema {
    fn to_json_value(&self) -> PyResult<serde_json::Value> {
        // Build a JSON representation of the schema
        let mut namespaces = serde_json::Map::new();
        let mut entity_types = serde_json::Map::new();
        let mut actions = serde_json::Map::new();

        for entity_type in self.inner.entity_types() {
            entity_types.insert(
                entity_type.to_string(),
                serde_json::json!({"shape": {"type": "Record", "attributes": {}}}),
            );
        }

        for action in self.inner.actions() {
            // Get principal types for this action
            let principal_types: Vec<String> = self
                .inner
                .principals_for_action(action)
                .map(|iter| iter.map(|t| t.to_string()).collect())
                .unwrap_or_default();

            // Get resource types for this action
            let resource_types: Vec<String> = self
                .inner
                .resources_for_action(action)
                .map(|iter| iter.map(|t| t.to_string()).collect())
                .unwrap_or_default();

            actions.insert(
                action.id().unescaped().to_string(),
                serde_json::json!({
                    "appliesTo": {
                        "principalTypes": principal_types,
                        "resourceTypes": resource_types
                    }
                }),
            );
        }

        let namespace = serde_json::json!({
            "entityTypes": entity_types,
            "actions": actions
        });
        namespaces.insert("".to_string(), namespace);

        Ok(serde_json::Value::Object(namespaces))
    }
}

/// Represents a validation error from Cedar's validator
#[pyclass(name = "ValidationError", frozen)]
#[derive(Clone)]
pub struct PyValidationError {
    policy_id: String,
    message: String,
}

#[pymethods]
impl PyValidationError {
    /// Get the policy ID that caused the error
    #[getter]
    fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Get the error message
    #[getter]
    fn message(&self) -> &str {
        &self.message
    }

    fn __str__(&self) -> String {
        format!("{}: {}", self.policy_id, self.message)
    }

    fn __repr__(&self) -> String {
        format!(
            "ValidationError(policy_id={:?}, message={:?})",
            self.policy_id, self.message
        )
    }
}

/// Represents a validation warning from Cedar's validator
#[pyclass(name = "ValidationWarning", frozen)]
#[derive(Clone)]
pub struct PyValidationWarning {
    policy_id: String,
    message: String,
}

#[pymethods]
impl PyValidationWarning {
    /// Get the policy ID that caused the warning
    #[getter]
    fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Get the warning message
    #[getter]
    fn message(&self) -> &str {
        &self.message
    }

    fn __str__(&self) -> String {
        format!("{}: {}", self.policy_id, self.message)
    }

    fn __repr__(&self) -> String {
        format!(
            "ValidationWarning(policy_id={:?}, message={:?})",
            self.policy_id, self.message
        )
    }
}

/// Represents the result of policy validation against a schema
#[pyclass(name = "ValidationResult", frozen)]
#[derive(Clone)]
pub struct PyValidationResult {
    valid: bool,
    errors: Vec<PyValidationError>,
    warnings: Vec<PyValidationWarning>,
}

#[pymethods]
impl PyValidationResult {
    /// Whether validation passed (no errors)
    #[getter]
    fn valid(&self) -> bool {
        self.valid
    }

    /// List of validation errors (empty if valid)
    #[getter]
    fn errors(&self) -> Vec<PyValidationError> {
        self.errors.clone()
    }

    /// List of validation warnings
    #[getter]
    fn warnings(&self) -> Vec<PyValidationWarning> {
        self.warnings.clone()
    }

    fn __bool__(&self) -> bool {
        self.valid
    }

    fn __repr__(&self) -> String {
        format!(
            "ValidationResult(valid={}, errors={}, warnings={})",
            self.valid,
            self.errors.len(),
            self.warnings.len()
        )
    }
}

/// Register policy types with the Python module
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicy>()?;
    m.add_class::<PyPolicySet>()?;
    m.add_class::<PyPolicySetIterator>()?;
    m.add_class::<PySchemaFragment>()?;
    m.add_class::<PySchema>()?;
    m.add_class::<PyValidationError>()?;
    m.add_class::<PyValidationWarning>()?;
    m.add_class::<PyValidationResult>()?;
    Ok(())
}
