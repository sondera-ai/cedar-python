"""Python bindings for Cedar Policy.

Provides Cedar policy and schema validation using PyO3 bindings.
"""

from __future__ import annotations

from typing import Any, Iterator

class EntityType:
    """Represents a Cedar Entity Type."""

    def __new__(cls, name: str) -> EntityType:
        """Create a new EntityType.

        Args:
            name: The entity type name (e.g., "User" or "MyApp::User")

        Raises:
            ValueError: If the name is invalid
        """
        ...

    def basename(self) -> str:
        """Get the basename of the entity type (without namespace).

        Returns:
            The entity type basename (e.g., "User" for "MyApp::User")
        """
        ...

    def namespace(self) -> str:
        """Get the namespace of the entity type.

        Returns:
            The namespace (empty string if no namespace)
        """
        ...

    def __str__(self) -> str:
        """Get the full entity type name as a string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the entity type."""
        ...

    def __eq__(self, other: object) -> bool:
        """Check equality with another EntityType."""
        ...

    def __hash__(self) -> int:
        """Get the hash value for use in sets and dicts."""
        ...

class EntityUid:
    """Represents a Cedar Entity Unique Identifier."""

    def __new__(cls, entity_type: str, id: str) -> EntityUid:
        """Create a new EntityUid.

        Args:
            entity_type: The entity type name
            id: The entity identifier
        """
        ...

    @classmethod
    def from_json(cls, json: str) -> EntityUid:
        """Create an EntityUid from a JSON string.

        Args:
            json: JSON string containing entity reference

        Returns:
            EntityUid instance
        """
        ...

    def id(self) -> str:
        """Get the entity identifier.

        Returns:
            The entity id string
        """
        ...

    def entity_type(self) -> str:
        """Get the entity type name.

        Returns:
            The entity type name string
        """
        ...

    def to_json(self) -> str:
        """Serialize the EntityUid to JSON.

        Returns:
            JSON string representation
        """
        ...

    def __str__(self) -> str:
        """Get the EntityUid as Cedar syntax (e.g., 'User::"alice"')."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the EntityUid."""
        ...

    def __eq__(self, other: object) -> bool:
        """Check equality with another EntityUid."""
        ...

    def __hash__(self) -> int:
        """Get the hash value for use in sets and dicts."""
        ...

class Entity:
    """Represents a Cedar Entity with attributes and parent relationships."""

    def __new__(
        cls,
        uid: EntityUid,
        attrs: dict[str, Any],
        parents: list[EntityUid] | None = None,
    ) -> Entity:
        """Create a new Entity.

        Args:
            uid: The unique identifier for this entity
            attrs: Dictionary of entity attributes
            parents: Optional list of parent entity UIDs

        Raises:
            ValueError: If entity cannot be created from provided data
        """
        ...

    def uid(self) -> EntityUid:
        """Get the entity's unique identifier.

        Returns:
            The EntityUid for this entity
        """
        ...

class Context:
    """Represents context data for a Cedar authorization request."""

    def __new__(
        cls,
        context: dict[str, Any],
        schema: Schema | None = None,
        action: EntityUid | None = None,
    ) -> "Context":
        """Create a new Context from a dictionary.

        Args:
            context: Dictionary of context key-value pairs
            schema: Optional schema to validate context against
            action: Required when schema is provided; specifies which action's
                context shape to validate against

        Raises:
            ValueError: If context cannot be serialized to valid Cedar context,
                or if schema is provided without action, or if validation fails
        """
        ...

    @staticmethod
    def empty() -> Context:
        """Create an empty context.

        Returns:
            Empty Context instance
        """
        ...

    @staticmethod
    def from_json(
        json: str,
        schema: Schema | None = None,
        action: EntityUid | None = None,
    ) -> Context:
        """Create a Context from a JSON string.

        Args:
            json: JSON string containing context data
            schema: Optional schema to validate context against
            action: Required when schema is provided; specifies which action's
                context shape to validate against

        Returns:
            Context instance

        Raises:
            ValueError: If JSON is invalid, cannot be parsed as context,
                schema is provided without action, or validation fails
        """
        ...

class Request:
    """Represents a Cedar authorization request."""

    def __new__(
        cls,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context | None = None,
        schema: Schema | None = None,
    ) -> Request:
        """Create a new authorization request.

        Args:
            principal: The principal (actor) making the request
            action: The action being performed
            resource: The resource being accessed
            context: Optional context data for the request
            schema: Optional schema to validate request components against

        Raises:
            ValueError: If schema validation fails (e.g., principal type
                not valid for action, resource type not valid, etc.)
        """
        ...

class Response:
    """Represents the result of an authorization decision."""

    @property
    def decision(self) -> str:
        """Get the authorization decision ('Allow' or 'Deny')."""
        ...

    @property
    def allowed(self) -> bool:
        """Check if the request was allowed."""
        ...

    @property
    def reason(self) -> list[str]:
        """Get the policy IDs that contributed to the decision."""
        ...

    @property
    def errors(self) -> list[str]:
        """Get any errors that occurred during evaluation."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the Response."""
        ...

    def __bool__(self) -> bool:
        """Returns True if allowed, False if denied."""
        ...

class Authorizer:
    """Cedar policy authorizer for evaluating authorization requests."""

    def __new__(
        cls,
        entities: list[Entity] | None = None,
        schema: Schema | None = None,
    ) -> Authorizer:
        """Create a new Authorizer instance.

        Args:
            entities: Optional list of entities for hierarchy lookups
            schema: Optional schema to validate entities against

        Raises:
            ValueError: If entity validation against schema fails
        """
        ...

    def is_authorized(self, request: Request, policies: PolicySet) -> Response:
        """Evaluate an authorization request against a policy set.

        Args:
            request: The authorization request to evaluate
            policies: PolicySet to evaluate against

        Returns:
            Response object with decision, reason, and any errors
        """
        ...

    def is_authorized_for_policy(self, request: Request, policy: Policy) -> Response:
        """Evaluate an authorization request against a single policy.

        Args:
            request: The authorization request to evaluate
            policy: Single Policy to evaluate against

        Returns:
            Response object with decision, reason, and any errors
        """
        ...

    def validate_request(
        self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Context | None = None,
    ) -> None:
        """Validate request components against the authorizer's schema.

        Args:
            principal: The principal (actor) making the request
            action: The action being performed
            resource: The resource being accessed
            context: Optional context data for the request

        Raises:
            ValueError: If no schema was provided to the Authorizer,
                or if validation fails
        """
        ...

    def add_entity(self, entity: Entity) -> None:
        """Add an entity to the authorizer's entity store.

        This method adds a new entity to the entity hierarchy. If schema
        validation is enabled (schema was provided to the Authorizer),
        the entity will be validated against the schema.

        Args:
            entity: The entity to add

        Raises:
            ValueError: If an entity with the same UID already exists,
                or if schema validation fails
        """
        ...

    def upsert_entity(self, entity: Entity) -> None:
        """Upsert an entity into the authorizer's entity store.

        This method adds a new entity or replaces an existing entity with
        the same UID. If schema validation is enabled (schema was provided
        to the Authorizer), the entity will be validated against the schema.

        Args:
            entity: The entity to add or update

        Raises:
            ValueError: If schema validation fails
        """
        ...

    def remove_entity(self, uid: EntityUid) -> None:
        """Remove an entity from the authorizer's entity store by its UID.

        This method removes an entity and re-computes the transitive closure
        of the entity hierarchy.

        Args:
            uid: The EntityUid of the entity to remove

        Raises:
            ValueError: If removal fails (e.g., entity not found)
        """
        ...

class Policy:
    """Represents a single Cedar policy."""

    def __new__(cls, text: str, id: str | None = None) -> Policy:
        """Create a policy from Cedar syntax.

        Args:
            text: Cedar policy text
            id: Optional policy identifier

        Raises:
            ValueError: If policy text is invalid
        """
        ...

    @staticmethod
    def from_str(text: str, id: str | None = None) -> Policy:
        """Create a policy from Cedar syntax string.

        Args:
            text: Cedar policy text
            id: Optional policy identifier

        Returns:
            Policy instance

        Raises:
            ValueError: If policy text is invalid
        """
        ...

    @staticmethod
    def from_json(json: str) -> Policy:
        """Create a policy from JSON representation.

        Args:
            json: JSON string containing policy

        Returns:
            Policy instance

        Raises:
            ValueError: If JSON is invalid
        """
        ...

    def id(self) -> str:
        """Get the policy ID."""
        ...

    def effect(self) -> str:
        """Get the policy effect ('Permit' or 'Forbid')."""
        ...

    def is_static(self) -> bool:
        """Check if this is a static policy."""
        ...

    def annotations(self) -> dict[str, str]:
        """Get all annotations as a dictionary."""
        ...

    def annotation(self, key: str) -> str | None:
        """Get a specific annotation value."""
        ...

    def to_json(self) -> str:
        """Convert to JSON representation."""
        ...

    def to_cedar(self) -> str | None:
        """Convert to Cedar syntax."""
        ...

    def __str__(self) -> str:
        """Get the policy as Cedar syntax string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the Policy."""
        ...

class PolicySet:
    """Represents a collection of Cedar policies."""

    def __new__(cls, text: str | None = None) -> PolicySet:
        """Create a PolicySet, optionally parsing from Cedar syntax.

        Args:
            text: Optional Cedar policy text containing one or more policies.
                  If None, creates an empty PolicySet.

        Returns:
            PolicySet instance

        Raises:
            ValueError: If policy text is invalid
        """
        ...

    @staticmethod
    def from_json(json: str) -> PolicySet:
        """Create from JSON representation.

        Args:
            json: JSON string containing policies

        Returns:
            PolicySet instance

        Raises:
            ValueError: If JSON is invalid
        """
        ...

    def add(self, policy: Policy) -> None:
        """Add a policy to the set."""
        ...

    def policies(self) -> list[Policy]:
        """Get all policies as a list."""
        ...

    def policy(self, id: str) -> Policy | None:
        """Get a policy by ID."""
        ...

    def to_json(self) -> str:
        """Convert to JSON representation."""
        ...

    def to_cedar(self) -> str | None:
        """Convert to Cedar syntax."""
        ...

    def is_empty(self) -> bool:
        """Check if the policy set is empty."""
        ...

    def __len__(self) -> int: ...
    def __str__(self) -> str:
        """Get the policy set as Cedar syntax string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the PolicySet."""
        ...

    def __iter__(self) -> Iterator[Policy]: ...

class PolicySetIterator:
    """Iterator for PolicySet."""

    def __iter__(self) -> PolicySetIterator: ...
    def __next__(self) -> Policy: ...

class SchemaFragment:
    """Represents a Cedar schema fragment.

    A schema fragment is a portion of a Cedar schema that can be combined with
    other fragments to create a complete schema. This is useful for modular
    schema definitions.
    """

    @staticmethod
    def from_json(json: str) -> SchemaFragment:
        """Create a schema fragment from JSON.

        Args:
            json: JSON string containing schema fragment

        Returns:
            SchemaFragment instance

        Raises:
            ValueError: If JSON is invalid
        """
        ...

    @staticmethod
    def from_cedarschema(text: str) -> SchemaFragment:
        """Create a schema fragment from Cedar schema syntax.

        Args:
            text: Cedar schema text

        Returns:
            SchemaFragment instance

        Raises:
            ValueError: If schema text is invalid
        """
        ...

    def to_json(self) -> str:
        """Convert to JSON representation.

        Returns:
            JSON string representation of the schema fragment
        """
        ...

    def to_cedarschema(self) -> str:
        """Convert to Cedar schema syntax.

        Returns:
            Cedar schema syntax string

        Raises:
            ValueError: If conversion fails
        """
        ...

    def namespaces(self) -> list[str]:
        """Get the namespaces defined in this schema fragment.

        Returns:
            List of namespace names (empty string for default namespace)
        """
        ...

    def __str__(self) -> str:
        """Get the schema fragment as Cedar schema syntax string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the SchemaFragment."""
        ...

class Schema:
    """Represents a Cedar schema."""

    @staticmethod
    def from_schema_fragments(fragments: list[SchemaFragment]) -> Schema:
        """Create a schema from one or more schema fragments.

        Args:
            fragments: List of SchemaFragment instances to combine

        Returns:
            Schema instance

        Raises:
            ValueError: If fragments cannot be combined or are invalid
        """
        ...

    @staticmethod
    def from_json(json: str) -> Schema:
        """Create a schema from JSON.

        Args:
            json: JSON string containing schema

        Returns:
            Schema instance

        Raises:
            ValueError: If JSON is invalid
        """
        ...

    @staticmethod
    def from_cedarschema(text: str) -> Schema:
        """Create a schema from Cedar schema syntax.

        Args:
            text: Cedar schema text

        Returns:
            Schema instance

        Raises:
            ValueError: If schema text is invalid
        """
        ...

    def entity_types(self) -> list[EntityType]:
        """Get all entity types defined in the schema."""
        ...

    def actions(self) -> list[str]:
        """Get all actions defined in the schema."""
        ...

    def principals(self) -> list[str]:
        """Get entity types that can be principals."""
        ...

    def resources(self) -> list[str]:
        """Get entity types that can be resources."""
        ...

    def to_cedarschema(self) -> str:
        """Convert to Cedar schema syntax."""
        ...

    def to_json(self) -> str:
        """Convert to JSON representation."""
        ...

    def validate_policyset(self, policies: PolicySet) -> ValidationResult:
        """Validate a policy set against this schema.

        Args:
            policies: The PolicySet to validate

        Returns:
            ValidationResult with validation status, errors, and warnings
        """
        ...

    def __str__(self) -> str:
        """Get the schema as Cedar schema syntax string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the Schema."""
        ...

class ValidationError:
    """Represents a validation error from Cedar's validator."""

    @property
    def policy_id(self) -> str:
        """Get the policy ID that caused the error."""
        ...

    @property
    def message(self) -> str:
        """Get the error message."""
        ...

    def __str__(self) -> str:
        """Get the error as a string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the ValidationError."""
        ...

class ValidationWarning:
    """Represents a validation warning from Cedar's validator."""

    @property
    def policy_id(self) -> str:
        """Get the policy ID that caused the warning."""
        ...

    @property
    def message(self) -> str:
        """Get the warning message."""
        ...

    def __str__(self) -> str:
        """Get the warning as a string."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the ValidationWarning."""
        ...

class ValidationResult:
    """Represents the result of policy validation against a schema."""

    @property
    def valid(self) -> bool:
        """Whether validation passed (no errors)."""
        ...

    @property
    def errors(self) -> list[ValidationError]:
        """List of validation errors (empty if valid)."""
        ...

    @property
    def warnings(self) -> list[ValidationWarning]:
        """List of validation warnings."""
        ...

    def __repr__(self) -> str:
        """Get a debug representation of the ValidationResult."""
        ...

    def __bool__(self) -> bool:
        """Returns True if validation passed."""
        ...

__version__: str

__all__ = [
    "__version__",
    "Entity",
    "EntityType",
    "EntityUid",
    "Context",
    "Request",
    "Response",
    "Authorizer",
    "Policy",
    "PolicySet",
    "PolicySetIterator",
    "SchemaFragment",
    "Schema",
    "ValidationError",
    "ValidationWarning",
    "ValidationResult",
]
