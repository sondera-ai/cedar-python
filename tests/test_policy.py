"""Tests for Policy, PolicySet, and Schema classes."""

import json

import pytest

from cedar import EntityType, Policy, PolicySet, Schema
from cedar.schema.types import CedarSchema


def has_entity_type(schema: Schema, name: str) -> bool:
    """Check if schema has an entity type matching the given name (by basename or full name)."""
    return any(t.basename() == name or str(t) == name for t in schema.entity_types())


BASIC_SCHEMA_JSON = """
{
    "": {
        "entityTypes": {
            "User": {},
            "Document": {},
            "Resource": {}
        },
        "actions": {
            "read": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document", "Resource"]}},
            "write": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}
        }
    }
}
"""


class TestPolicy:
    """Tests for Policy."""

    @pytest.mark.parametrize(
        "text,expected_effect",
        [
            ("permit(principal, action, resource);", "Permit"),
            ("forbid(principal, action, resource);", "Forbid"),
            (
                'permit(principal == User::"alice", action, resource) when { resource.public == true };',
                "Permit",
            ),
        ],
    )
    def test_parse_effects(self, text, expected_effect):
        """Test parsing policies with different effects."""
        policy = Policy(text)
        assert policy.effect() == expected_effect
        assert policy.is_static() is True

    def test_policy_with_id(self):
        """Test policy ID handling from parameter and @id annotation."""
        # Explicit ID
        p1 = Policy("permit(principal, action, resource);", "my_policy")
        assert p1.id() == "my_policy"

        # ID from annotation
        p2 = Policy('@id("from_annotation")\npermit(principal, action, resource);')
        assert p2.id() == "from_annotation"

        # Explicit overrides annotation
        p3 = Policy(
            '@id("annotation")\npermit(principal, action, resource);', "explicit"
        )
        assert p3.id() == "explicit"

    def test_invalid_raises(self):
        """Test that invalid policy text raises ValueError."""
        with pytest.raises(ValueError):
            Policy("not a valid policy")

    def test_json_roundtrip(self):
        """Test JSON serialization and deserialization."""
        policy = Policy("permit(principal, action, resource);")
        json_str = policy.to_json()
        assert "effect" in json_str

        restored = Policy.from_json(json_str)
        assert restored.effect() == policy.effect()

    def test_to_cedar(self):
        """Test conversion to Cedar syntax."""
        policy = Policy("permit(principal, action, resource);")
        assert "permit" in policy.to_cedar()

    def test_annotations(self):
        """Test policy annotations."""
        policy = Policy(
            '@description("Allow all")\n@id("p1")\npermit(principal, action, resource);'
        )
        assert policy.annotations()["description"] == "Allow all"
        assert policy.annotation("id") == "p1"
        assert policy.annotation("nonexistent") is None

    def test_str_repr(self):
        """Test string representations."""
        policy = Policy("permit(principal, action, resource);")
        assert "permit" in str(policy)
        assert "Policy" in repr(policy) and "Permit" in repr(policy)


class TestPolicySet:
    """Tests for PolicySet."""

    def test_empty(self):
        """Test empty PolicySet."""
        ps = PolicySet()
        assert ps.is_empty() and len(ps) == 0

    def test_from_str_and_iteration(self):
        """Test parsing and iterating PolicySet."""
        ps = PolicySet("""
            permit(principal, action, resource);
            forbid(principal, action == Action::"delete", resource);
        """)
        assert len(ps) == 2
        effects = {p.effect() for p in ps}
        assert effects == {"Permit", "Forbid"}

    def test_invalid_raises(self):
        """Test that invalid policy text raises ValueError."""
        with pytest.raises(ValueError):
            PolicySet("not valid")

    def test_add_and_lookup(self):
        """Test adding policies and looking up by ID."""
        ps = PolicySet()
        ps.add(Policy("permit(principal, action, resource);"))
        assert len(ps) == 1

        ps2 = PolicySet("permit(principal, action, resource);")
        assert ps2.policy("policy0").effect() == "Permit"
        assert ps2.policy("nonexistent") is None

    def test_json_roundtrip(self):
        """Test JSON serialization and deserialization."""
        ps = PolicySet("permit(principal, action, resource);")
        restored = PolicySet.from_json(ps.to_json())
        assert len(restored) == 1

    def test_to_cedar_and_repr(self):
        """Test Cedar syntax conversion and string repr."""
        ps = PolicySet("permit(principal, action, resource);")
        assert "permit" in ps.to_cedar()
        assert "permit" in str(ps)
        assert "PolicySet" in repr(ps)


class TestSchema:
    """Tests for Schema."""

    def test_from_json(self):
        """Test creating Schema from JSON."""
        schema = Schema.from_json(BASIC_SCHEMA_JSON)
        assert schema is not None
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "Document")

    def test_invalid_raises(self):
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError):
            Schema.from_json("not valid json")

    def test_from_cedarschema(self):
        """Test creating Schema from Cedar schema syntax."""
        schema_str = """
            entity User;
            entity Resource;
            action read appliesTo { principal: User, resource: Resource };
        """
        schema = Schema.from_cedarschema(schema_str)
        assert schema is not None
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "Resource")

        schema_str_2 = schema.to_cedarschema()
        schema_2 = Schema.from_cedarschema(schema_str_2)
        assert schema_2 is not None

        schema_str_3 = schema_2.to_cedarschema()
        assert schema_str_2 == schema_str_3

    def test_introspection(self):
        """Test schema introspection methods."""
        schema = Schema.from_json(BASIC_SCHEMA_JSON)
        assert len(schema.entity_types()) == 3
        assert len(schema.actions()) == 2
        assert "User" in schema.principals()
        assert "Document" in schema.resources()

    def test_str(self):
        """Test Schema __str__ returns Cedar schema syntax."""
        schema = Schema.from_json(BASIC_SCHEMA_JSON)
        str_output = str(schema)
        assert isinstance(str_output, str)
        assert "User" in str_output
        assert "Document" in str_output

    def test_with_namespace(self):
        """Test schema with namespace."""
        schema = Schema.from_json("""
        {
            "MyApp": {
                "entityTypes": {"User": {}, "Resource": {}},
                "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}}}
            }
        }
        """)
        assert has_entity_type(schema, "User")
        assert "Schema" in repr(schema)


class TestSchemaWithAttributes:
    """Tests for Schema with entity and context attributes."""

    def test_schema_with_required_entity_attribute(self):
        """Test schema with required entity attribute parses and round-trips."""
        schema = Schema.from_cedarschema("""
            entity User { level: Long };
            entity Document;
            action read appliesTo { principal: User, resource: Document };
        """)
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "Document")
        # Verify actions() returns qualified names
        assert any("read" in action for action in schema.actions())

        # Verify to_cedarschema() preserves the attribute
        cedar_str = schema.to_cedarschema()
        assert "level" in cedar_str
        schema2 = Schema.from_cedarschema(cedar_str)
        assert has_entity_type(schema2, "User")

    def test_schema_with_optional_entity_attribute(self):
        """Test schema with optional entity attribute parses and round-trips."""
        schema = Schema.from_cedarschema("""
            entity User { level?: Long };
            entity Document;
            action read appliesTo { principal: User, resource: Document };
        """)
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "Document")

        # Verify to_cedarschema() preserves the optional attribute
        cedar_str = schema.to_cedarschema()
        assert "level" in cedar_str
        schema2 = Schema.from_cedarschema(cedar_str)
        assert has_entity_type(schema2, "User")

    def test_schema_with_context_attribute(self):
        """Test schema with context attribute parses and round-trips."""
        schema = Schema.from_cedarschema("""
            entity User;
            entity Document;
            action read appliesTo {
                principal: User,
                resource: Document,
                context: { addr: String }
            };
        """)
        assert has_entity_type(schema, "User")
        # actions() returns fully qualified names like 'Action::"read"'
        assert any("read" in action for action in schema.actions())

        # Verify to_cedarschema() preserves the context attribute
        cedar_str = schema.to_cedarschema()
        assert "addr" in cedar_str
        schema2 = Schema.from_cedarschema(cedar_str)
        assert any("read" in action for action in schema2.actions())

    def test_schema_with_multiple_attributes(self):
        """Test schema with multiple entity attributes of different types."""
        schema = Schema.from_cedarschema("""
            entity User {
                name: String,
                age: Long,
                active: Bool,
                tags: Set<String>
            };
            entity Document { owner: User };
            action read appliesTo { principal: User, resource: Document };
        """)
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "Document")

        # Verify to_cedarschema() preserves all attributes
        cedar_str = schema.to_cedarschema()
        assert "name" in cedar_str
        assert "age" in cedar_str
        assert "active" in cedar_str
        assert "tags" in cedar_str
        assert "owner" in cedar_str

    def test_schema_with_entity_hierarchy(self):
        """Test schema with entity memberOf relationships."""
        schema = Schema.from_cedarschema("""
            entity UserGroup;
            entity User in [UserGroup] { department: String };
            entity Document;
            action read appliesTo { principal: User, resource: Document };
        """)
        assert has_entity_type(schema, "User")
        assert has_entity_type(schema, "UserGroup")

        # Verify to_cedarschema() preserves hierarchy and attributes
        cedar_str = schema.to_cedarschema()
        assert "department" in cedar_str
        assert "UserGroup" in cedar_str


class TestPolicyWithAttributes:
    """Tests for Policy accessing entity and context attributes."""

    def test_policy_accessing_entity_attribute(self):
        """Test policy that accesses entity attribute parses correctly."""
        policy = Policy(
            "permit(principal, action, resource) when { principal.level > 5 };"
        )
        assert policy.effect() == "Permit"

        cedar_str = policy.to_cedar()
        assert "principal.level" in cedar_str

    def test_policy_accessing_optional_attribute_with_has(self):
        """Test policy using has() for optional attribute."""
        policy = Policy(
            "permit(principal, action, resource) when { principal has level && principal.level > 5 };"
        )
        assert policy.effect() == "Permit"
        assert "has level" in policy.to_cedar()

    def test_policy_accessing_context_attribute(self):
        """Test policy that accesses context attribute parses correctly."""
        policy = Policy(
            "permit(principal, action, resource) when { context.authenticated == true };"
        )
        assert policy.effect() == "Permit"
        assert "context.authenticated" in policy.to_cedar()

    def test_policy_with_ip_extension(self):
        """Test policy using ip() extension function."""
        policy = Policy(
            "permit(principal, action, resource) when { ip(context.addr).isLoopback() };"
        )
        assert policy.effect() == "Permit"
        assert "ip(" in policy.to_cedar()
        assert "isLoopback" in policy.to_cedar()

    def test_policy_with_decimal_extension(self):
        """Test policy using decimal() extension function."""
        policy = Policy(
            'permit(principal, action, resource) when { decimal(context.amount) > decimal("100.00") };'
        )
        assert policy.effect() == "Permit"
        assert "decimal(" in policy.to_cedar()

    def test_policy_with_nested_attribute_access(self):
        """Test policy accessing nested attributes."""
        policy = Policy(
            'permit(principal, action, resource) when { resource.owner.department == "engineering" };'
        )
        assert policy.effect() == "Permit"
        assert "resource.owner.department" in policy.to_cedar()


class TestCedarSchemaModel:
    """Tests for CedarSchema Pydantic model."""

    def test_model_validation(self):
        """Test CedarSchema model validates and provides typed access."""
        json_schema = {
            "PhotoFlash": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": ["UserGroup"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "department": {"type": "String"},
                                "jobLevel": {"type": "Long"},
                            },
                        },
                    },
                    "UserGroup": {},
                },
                "actions": {
                    "viewPhoto": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Photo"],
                            "context": {
                                "type": "Record",
                                "attributes": {"authenticated": {"type": "Boolean"}},
                            },
                        }
                    }
                },
            }
        }
        schema = CedarSchema.model_validate(json_schema)
        assert schema is not None
        user_shape = schema.root["PhotoFlash"].entityTypes["User"].shape
        assert user_shape.type == "Record"


class TestEntityTypeRust:
    """Tests for EntityType (Rust class)."""

    def test_constructor(self):
        """Test EntityType creation."""
        et = EntityType("User")
        assert et is not None

    def test_constructor_with_namespace(self):
        """Test EntityType creation with namespace."""
        et = EntityType("MyApp::User")
        assert et is not None

    def test_invalid_name_raises(self):
        """Test that invalid entity type name raises ValueError."""
        with pytest.raises(ValueError):
            EntityType("")

    def test_basename(self):
        """Test basename() returns type name without namespace."""
        assert EntityType("User").basename() == "User"
        assert EntityType("MyApp::User").basename() == "User"
        assert EntityType("A::B::C").basename() == "C"

    def test_namespace(self):
        """Test namespace() returns namespace portion."""
        assert EntityType("User").namespace() == ""
        assert EntityType("MyApp::User").namespace() == "MyApp"
        assert EntityType("A::B::C").namespace() == "A::B"

    def test_str(self):
        """Test __str__ returns full type name."""
        assert str(EntityType("User")) == "User"
        assert str(EntityType("MyApp::User")) == "MyApp::User"

    def test_repr(self):
        """Test __repr__ returns debug representation."""
        assert "EntityType" in repr(EntityType("User"))
        assert "User" in repr(EntityType("User"))

    def test_equality(self):
        """Test __eq__ compares EntityType to EntityType."""
        et1 = EntityType("User")
        et2 = EntityType("User")
        et3 = EntityType("Admin")

        assert et1 == et2
        assert et1 != et3
        assert et2 != et3

    def test_hash(self):
        """Test __hash__ allows use in sets and dicts."""
        et1 = EntityType("User")
        et2 = EntityType("User")
        et3 = EntityType("Admin")

        # Can be used in sets
        s = {et1, et2, et3}
        assert len(s) == 2  # et1 and et2 are equal

        # Can be used as dict keys
        d = {et1: "value1"}
        assert d[et2] == "value1"  # et2 == et1


class TestSchemaToJson:
    """Tests for Schema.to_json() method."""

    def test_to_json_basic(self):
        """Test to_json() returns valid JSON."""
        schema = Schema.from_json(BASIC_SCHEMA_JSON)
        json_str = schema.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_to_json_roundtrip(self):
        """Test to_json() output can be used to recreate schema."""
        schema1 = Schema.from_json(BASIC_SCHEMA_JSON)
        json_str = schema1.to_json()
        schema2 = Schema.from_json(json_str)

        # Both schemas should have same entity types
        types1 = {str(t) for t in schema1.entity_types()}
        types2 = {str(t) for t in schema2.entity_types()}
        assert types1 == types2

    def test_to_json_preserves_attributes(self):
        """Test to_json() preserves entity attributes."""
        schema = Schema.from_cedarschema("""
            entity User { name: String, level: Long };
            entity Document;
            action read appliesTo { principal: User, resource: Document };
        """)
        json_str = schema.to_json()

        # Verify it's valid JSON and contains attribute definitions
        json.loads(json_str)  # Raises if invalid JSON
        assert "name" in json_str
        assert "level" in json_str

    def test_to_json_from_cedarschema(self):
        """Test to_json() works for schemas created from Cedar syntax."""
        schema = Schema.from_cedarschema("""
            entity User;
            entity Resource;
            action view appliesTo { principal: User, resource: Resource };
        """)
        json_str = schema.to_json()

        # Should be valid JSON that can recreate the schema
        schema2 = Schema.from_json(json_str)
        assert has_entity_type(schema2, "User")
        assert has_entity_type(schema2, "Resource")


class TestValidationResult:
    """Tests for ValidationResult, ValidationError, and ValidationWarning."""

    @pytest.fixture
    def schema_with_user_document(self):
        """Schema with User principal and Document resource."""
        return Schema.from_json("""
        {
            "": {
                "entityTypes": {
                    "User": {},
                    "Document": {}
                },
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Document"]
                        }
                    }
                }
            }
        }
        """)

    def test_valid_result(self, schema_with_user_document):
        """Test ValidationResult for valid policies."""
        policies = PolicySet("""
            permit(principal == User::"alice", action == Action::"read", resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        assert result.valid is True
        assert len(result.errors) == 0
        assert isinstance(result.warnings, list)

    def test_valid_result_bool(self, schema_with_user_document):
        """Test ValidationResult __bool__ returns True for valid."""
        policies = PolicySet("permit(principal, action, resource);")
        result = schema_with_user_document.validate_policyset(policies)

        assert bool(result) is True
        # Can use in if statements
        if result:
            passed = True
        else:
            passed = False
        assert passed is True

    def test_invalid_result(self, schema_with_user_document):
        """Test ValidationResult for invalid policies."""
        # Policy references non-existent entity type
        policies = PolicySet("""
            permit(principal == NonExistent::"alice", action, resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        assert result.valid is False
        assert len(result.errors) > 0

    def test_invalid_result_bool(self, schema_with_user_document):
        """Test ValidationResult __bool__ returns False for invalid."""
        policies = PolicySet("""
            permit(principal == NonExistent::"alice", action, resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        assert bool(result) is False

    def test_validation_error_properties(self, schema_with_user_document):
        """Test ValidationError has policy_id and message properties."""
        policies = PolicySet("""
            @id("my_policy")
            permit(principal == NonExistent::"alice", action, resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        assert len(result.errors) > 0
        error = result.errors[0]

        # Check properties exist and are strings
        assert isinstance(error.policy_id, str)
        assert isinstance(error.message, str)
        assert len(error.message) > 0

    def test_validation_error_str(self, schema_with_user_document):
        """Test ValidationError __str__ method."""
        policies = PolicySet("""
            permit(principal == NonExistent::"alice", action, resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        error = result.errors[0]
        error_str = str(error)

        # __str__ should include policy_id and message
        assert isinstance(error_str, str)
        assert len(error_str) > 0

    def test_validation_warning_properties(self):
        """Test ValidationWarning has policy_id and message properties."""
        # Create a schema and policy that generates warnings
        # Impossible policy condition generates a warning
        schema = Schema.from_json("""
        {
            "": {
                "entityTypes": {"User": {}},
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["User"]
                        }
                    }
                }
            }
        }
        """)
        # Policy with impossible condition (1 == 2) generates warning
        policies = PolicySet("""
            permit(principal, action, resource) when { 1 == 2 };
        """)
        result = schema.validate_policyset(policies)

        # Even if no warnings, verify the warnings list structure
        assert isinstance(result.warnings, list)
        for warning in result.warnings:
            assert isinstance(warning.policy_id, str)
            assert isinstance(warning.message, str)

    def test_multiple_errors(self, schema_with_user_document):
        """Test ValidationResult with multiple errors."""
        policies = PolicySet("""
            permit(principal == NonExistent::"a", action, resource);
            permit(principal == AlsoNonExistent::"b", action, resource);
        """)
        result = schema_with_user_document.validate_policyset(policies)

        assert result.valid is False
        assert len(result.errors) >= 2
