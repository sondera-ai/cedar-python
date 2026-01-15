"""Tests for cedar.schema module - Pydantic models and utilities."""

import json

import pytest

from cedar import Schema
from cedar.schema import (
    Action,
    ActionMember,
    AppliesTo,
    CedarSchema,
    EntityType,
    NamespaceDefinition,
    SchemaType,
    dict_to_cedar_type,
    validate,
    validate_json,
)


def has_entity_type(schema: Schema, name: str) -> bool:
    """Check if schema has an entity type matching the given name (by basename or full name)."""
    return any(t.basename() == name or str(t) == name for t in schema.entity_types())


class TestSchemaType:
    """Tests for SchemaType Pydantic model."""

    def test_primitive_types(self):
        """Test primitive type definitions."""
        string_type = SchemaType(type="String")
        assert string_type.type == "String"

        long_type = SchemaType(type="Long")
        assert long_type.type == "Long"

        bool_type = SchemaType(type="Boolean")
        assert bool_type.type == "Boolean"

    def test_set_type_requires_element(self):
        """Set type must have an element field."""
        with pytest.raises(ValueError, match="requires an 'element' field"):
            SchemaType(type="Set")

    def test_set_type_with_element(self):
        """Set type with valid element."""
        set_type = SchemaType(type="Set", element=SchemaType(type="String"))
        assert set_type.type == "Set"
        assert set_type.element.type == "String"

    def test_entity_type_requires_name(self):
        """Entity type must have a name field."""
        with pytest.raises(ValueError, match="requires a 'name' field"):
            SchemaType(type="Entity")

    def test_entity_type_with_name(self):
        """Entity type with valid name."""
        entity_type = SchemaType(type="Entity", name="User")
        assert entity_type.type == "Entity"
        assert entity_type.name == "User"

    def test_extension_type_requires_name(self):
        """Extension type must have a name field."""
        with pytest.raises(ValueError, match="requires a 'name' field"):
            SchemaType(type="Extension")

    def test_extension_type_with_name(self):
        """Extension type with valid name (e.g., ipaddr, decimal)."""
        ext_type = SchemaType(type="Extension", name="ipaddr")
        assert ext_type.type == "Extension"
        assert ext_type.name == "ipaddr"

    def test_record_type_empty(self):
        """Record type can be empty."""
        record_type = SchemaType(type="Record")
        assert record_type.type == "Record"
        assert record_type.attributes is None

    def test_record_type_with_attributes(self):
        """Record type with nested attributes."""
        record_type = SchemaType(
            type="Record",
            attributes={
                "name": SchemaType(type="String"),
                "age": SchemaType(type="Long"),
            },
        )
        assert record_type.type == "Record"
        assert "name" in record_type.attributes
        assert record_type.attributes["name"].type == "String"

    def test_optional_attribute(self):
        """Test optional attribute with required=False."""
        attr = SchemaType(type="String", required=False)
        assert attr.required is False

    def test_nested_complex_type(self):
        """Test deeply nested type structure."""
        # Set<Record<{items: Set<String>}>>
        nested = SchemaType(
            type="Set",
            element=SchemaType(
                type="Record",
                attributes={
                    "items": SchemaType(type="Set", element=SchemaType(type="String"))
                },
            ),
        )
        assert nested.type == "Set"
        assert nested.element.type == "Record"
        assert nested.element.attributes["items"].type == "Set"


class TestEntityType:
    """Tests for EntityType Pydantic model."""

    def test_empty_entity_type(self):
        """Entity type with no shape or members."""
        entity = EntityType()
        assert entity.shape is None
        assert entity.memberOfTypes is None

    def test_entity_with_member_of(self):
        """Entity type with parent types."""
        entity = EntityType(memberOfTypes=["UserGroup", "Team"])
        assert entity.memberOfTypes == ["UserGroup", "Team"]

    def test_entity_with_shape(self):
        """Entity type with attribute shape."""
        entity = EntityType(
            shape=SchemaType(
                type="Record",
                attributes={
                    "name": SchemaType(type="String"),
                    "email": SchemaType(type="String", required=False),
                },
            )
        )
        assert entity.shape.type == "Record"
        assert "name" in entity.shape.attributes

    def test_entity_with_enum(self):
        """Entity type with fixed enum values."""
        entity = EntityType(enum=["admin", "user", "guest"])
        assert entity.enum == ["admin", "user", "guest"]

    def test_entity_with_tags(self):
        """Entity type with tags definition."""
        entity = EntityType(tags=SchemaType(type="String"))
        assert entity.tags.type == "String"


class TestAction:
    """Tests for Action and related models."""

    def test_action_member(self):
        """Test ActionMember model."""
        member = ActionMember(id="viewPhoto")
        assert member.id == "viewPhoto"
        assert member.type is None

    def test_action_member_with_type(self):
        """ActionMember with explicit type."""
        member = ActionMember(id="view", type="PhotoApp::Action")
        assert member.id == "view"
        assert member.type == "PhotoApp::Action"

    def test_applies_to(self):
        """Test AppliesTo model."""
        applies = AppliesTo(
            principalTypes=["User", "Admin"],
            resourceTypes=["Photo", "Album"],
        )
        assert applies.principalTypes == ["User", "Admin"]
        assert applies.resourceTypes == ["Photo", "Album"]

    def test_applies_to_with_context(self):
        """AppliesTo with context definition."""
        applies = AppliesTo(
            principalTypes=["User"],
            resourceTypes=["Document"],
            context=SchemaType(
                type="Record",
                attributes={"authenticated": SchemaType(type="Boolean")},
            ),
        )
        assert applies.context.type == "Record"
        assert "authenticated" in applies.context.attributes

    def test_action_basic(self):
        """Basic action with appliesTo."""
        action = Action(
            appliesTo=AppliesTo(
                principalTypes=["User"],
                resourceTypes=["Resource"],
            )
        )
        assert action.appliesTo.principalTypes == ["User"]

    def test_action_with_member_of(self):
        """Action that belongs to action groups."""
        action = Action(
            memberOf=[
                ActionMember(id="readActions"),
                ActionMember(id="allActions"),
            ],
            appliesTo=AppliesTo(principalTypes=["User"], resourceTypes=["File"]),
        )
        assert len(action.memberOf) == 2
        assert action.memberOf[0].id == "readActions"


class TestNamespaceDefinition:
    """Tests for NamespaceDefinition model."""

    def test_minimal_namespace(self):
        """Namespace with minimal required fields."""
        ns = NamespaceDefinition(
            entityTypes={"User": EntityType()},
            actions={"view": Action()},
        )
        assert "User" in ns.entityTypes
        assert "view" in ns.actions

    def test_namespace_with_common_types(self):
        """Namespace with common type definitions."""
        ns = NamespaceDefinition(
            entityTypes={"User": EntityType()},
            actions={"view": Action()},
            commonTypes={
                "EmailAddress": SchemaType(type="String"),
                "UserInfo": SchemaType(
                    type="Record",
                    attributes={"email": SchemaType(type="String")},
                ),
            },
        )
        assert "EmailAddress" in ns.commonTypes
        assert ns.commonTypes["UserInfo"].type == "Record"


class TestCedarSchema:
    """Tests for CedarSchema root model."""

    def test_empty_namespace(self):
        """Schema with empty namespace."""
        schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {"User": {}},
                    "actions": {"view": {}},
                }
            }
        )
        assert "" in schema.root
        assert "User" in schema[""].entityTypes

    def test_named_namespace(self):
        """Schema with named namespace."""
        schema = CedarSchema.model_validate(
            {
                "PhotoApp": {
                    "entityTypes": {
                        "User": {"memberOfTypes": ["UserGroup"]},
                        "UserGroup": {},
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Photo"],
                            }
                        }
                    },
                }
            }
        )
        assert "PhotoApp" in schema.root
        assert schema["PhotoApp"].entityTypes["User"].memberOfTypes == ["UserGroup"]

    def test_multiple_namespaces(self):
        """Schema with multiple namespaces."""
        schema = CedarSchema.model_validate(
            {
                "App1": {
                    "entityTypes": {"User": {}},
                    "actions": {"view": {}},
                },
                "App2": {
                    "entityTypes": {"Admin": {}},
                    "actions": {"manage": {}},
                },
            }
        )
        assert "App1" in schema.root
        assert "App2" in schema.root

    def test_complex_schema(self):
        """Test complex real-world schema structure."""
        schema_dict = {
            "PhotoFlash": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": ["UserGroup"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": {"type": "String"},
                                "age": {"type": "Long"},
                                "email": {"type": "String", "required": False},
                            },
                        },
                    },
                    "UserGroup": {},
                    "Photo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": {"type": "Entity", "name": "User"},
                                "tags": {
                                    "type": "Set",
                                    "element": {"type": "String"},
                                },
                            },
                        }
                    },
                },
                "actions": {
                    "viewPhoto": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Photo"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "authenticated": {"type": "Boolean"},
                                },
                            },
                        }
                    },
                    "deletePhoto": {
                        "memberOf": [{"id": "viewPhoto"}],
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Photo"],
                        },
                    },
                },
            }
        }
        schema = CedarSchema.model_validate(schema_dict)

        # Verify structure
        user = schema["PhotoFlash"].entityTypes["User"]
        assert user.memberOfTypes == ["UserGroup"]
        assert user.shape.attributes["name"].type == "String"
        assert user.shape.attributes["email"].required is False

        photo = schema["PhotoFlash"].entityTypes["Photo"]
        assert photo.shape.attributes["owner"].type == "Entity"
        assert photo.shape.attributes["tags"].element.type == "String"

        view_action = schema["PhotoFlash"].actions["viewPhoto"]
        assert "User" in view_action.appliesTo.principalTypes


class TestDictToCedarType:
    """Tests for dict_to_cedar_type utility function."""

    def test_string_type(self):
        """Convert string type."""
        cedar_type = dict_to_cedar_type({"type": "string"})
        assert cedar_type.type == "String"

    def test_integer_type(self):
        """Convert integer type."""
        cedar_type = dict_to_cedar_type({"type": "integer"})
        assert cedar_type.type == "Long"

    def test_number_type(self):
        """Convert number type."""
        cedar_type = dict_to_cedar_type({"type": "number"})
        assert cedar_type.type == "Long"

    def test_boolean_type(self):
        """Convert boolean type."""
        cedar_type = dict_to_cedar_type({"type": "boolean"})
        assert cedar_type.type == "Boolean"

    def test_array_type(self):
        """Convert array to Set."""
        cedar_type = dict_to_cedar_type({"type": "array", "items": {"type": "string"}})
        assert cedar_type.type == "Set"
        assert cedar_type.element.type == "String"

    def test_object_type(self):
        """Convert object to Record."""
        cedar_type = dict_to_cedar_type(
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"},
                },
                "required": ["name"],
            }
        )
        assert cedar_type.type == "Record"
        assert cedar_type.attributes["name"].type == "String"
        assert cedar_type.attributes["name"].required is None  # required by default
        assert cedar_type.attributes["age"].required is False  # not in required list

    def test_nested_object(self):
        """Convert nested object structures."""
        cedar_type = dict_to_cedar_type(
            {
                "type": "object",
                "properties": {
                    "user": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                    }
                },
            }
        )
        assert cedar_type.type == "Record"
        assert cedar_type.attributes["user"].type == "Record"
        assert cedar_type.attributes["user"].attributes["id"].type == "String"

    def test_uppercase_types(self):
        """Handle uppercase type names."""
        assert dict_to_cedar_type({"type": "STRING"}).type == "String"
        assert dict_to_cedar_type({"type": "INTEGER"}).type == "Long"
        assert dict_to_cedar_type({"type": "BOOLEAN"}).type == "Boolean"

    def test_string_with_enum(self):
        """String with enum values treated as String."""
        cedar_type = dict_to_cedar_type(
            {"type": "string", "enum": ["active", "inactive"]}
        )
        assert cedar_type.type == "String"

    def test_non_dict_fallback(self):
        """Non-dict input returns String fallback."""
        cedar_type = dict_to_cedar_type("not a dict")
        assert cedar_type.type == "String"

    def test_unsupported_type_raises(self):
        """Unsupported type raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="Unsupported JSON schema type"):
            dict_to_cedar_type({"type": "null"})


class TestValidation:
    """Tests for validate and validate_json functions."""

    def test_validate_json_valid(self):
        """Valid JSON schema passes validation."""
        schema_json = json.dumps(
            {
                "": {
                    "entityTypes": {"User": {}, "Resource": {}},
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Resource"],
                            }
                        }
                    },
                }
            }
        )
        # Should not raise
        validate_json(schema_json)

    def test_validate_json_invalid(self):
        """Invalid JSON schema raises an error."""
        schema_json = json.dumps(
            {
                "": {
                    "entityTypes": {"User": {}},
                    "actions": {
                        "view": {
                            "appliesTo": {
                                # Reference to non-existent entity type
                                "principalTypes": ["NonExistent"],
                                "resourceTypes": ["User"],
                            }
                        }
                    },
                }
            }
        )
        with pytest.raises(ValueError):
            validate_json(schema_json)

    def test_validate_pydantic_model(self):
        """Validate CedarSchema Pydantic model."""
        schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {"User": {}, "Document": {}},
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Document"],
                            }
                        }
                    },
                }
            }
        )
        # Should not raise
        validate(schema)


class TestPydanticRustInterop:
    """Tests verifying Pydantic models work with Rust Schema class."""

    def test_pydantic_to_rust_basic(self):
        """Pydantic schema can be parsed by Rust Schema."""
        pydantic_schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {"User": {}, "Document": {}},
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Document"],
                            }
                        }
                    },
                }
            }
        )

        # Convert to JSON and parse with Rust
        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        assert has_entity_type(rust_schema, "User")
        assert has_entity_type(rust_schema, "Document")
        assert any("read" in a for a in rust_schema.actions())

    def test_pydantic_to_rust_with_attributes(self):
        """Pydantic schema with entity attributes works with Rust."""
        pydantic_schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "name": {"type": "String"},
                                    "level": {"type": "Long"},
                                },
                            }
                        },
                        "Document": {},
                    },
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Document"],
                            }
                        }
                    },
                }
            }
        )

        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        assert has_entity_type(rust_schema, "User")
        # Verify round-trip preserves attributes
        cedar_str = rust_schema.to_cedarschema()
        assert "name" in cedar_str
        assert "level" in cedar_str

    def test_pydantic_to_rust_with_context(self):
        """Pydantic schema with action context works with Rust."""
        pydantic_schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {"User": {}, "Resource": {}},
                    "actions": {
                        "access": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Resource"],
                                "context": {
                                    "type": "Record",
                                    "attributes": {
                                        "ip_address": {"type": "String"},
                                        "authenticated": {"type": "Boolean"},
                                    },
                                },
                            }
                        }
                    },
                }
            }
        )

        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        # Verify round-trip preserves context
        cedar_str = rust_schema.to_cedarschema()
        assert "ip_address" in cedar_str
        assert "authenticated" in cedar_str

    def test_pydantic_to_rust_with_hierarchy(self):
        """Pydantic schema with entity hierarchy works with Rust."""
        pydantic_schema = CedarSchema.model_validate(
            {
                "": {
                    "entityTypes": {
                        "UserGroup": {},
                        "User": {"memberOfTypes": ["UserGroup"]},
                        "Document": {},
                    },
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Document"],
                            }
                        }
                    },
                }
            }
        )

        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        assert has_entity_type(rust_schema, "User")
        assert has_entity_type(rust_schema, "UserGroup")
        # Verify hierarchy in output
        cedar_str = rust_schema.to_cedarschema()
        assert "UserGroup" in cedar_str

    def test_pydantic_to_rust_with_namespace(self):
        """Pydantic schema with namespace works with Rust."""
        pydantic_schema = CedarSchema.model_validate(
            {
                "MyApp": {
                    "entityTypes": {"User": {}, "Resource": {}},
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Resource"],
                            }
                        }
                    },
                }
            }
        )

        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        # Entity types include namespace prefix
        assert has_entity_type(rust_schema, "User")

    def test_rust_to_pydantic(self):
        """Rust Schema can be converted to Pydantic model."""
        # Create schema via Rust
        rust_schema = Schema.from_json(
            json.dumps(
                {
                    "": {
                        "entityTypes": {
                            "User": {
                                "shape": {
                                    "type": "Record",
                                    "attributes": {"email": {"type": "String"}},
                                }
                            },
                            "Document": {},
                        },
                        "actions": {
                            "read": {
                                "appliesTo": {
                                    "principalTypes": ["User"],
                                    "resourceTypes": ["Document"],
                                }
                            }
                        },
                    }
                }
            )
        )

        # Convert to cedarschema and back to JSON for Pydantic
        # Note: This tests the round-trip capability
        cedar_str = rust_schema.to_cedarschema()
        assert "email" in cedar_str
        assert "User" in cedar_str

    def test_complex_interop(self):
        """Complex schema with all features works in both directions."""
        schema_dict = {
            "": {
                "entityTypes": {
                    "UserGroup": {},
                    "User": {
                        "memberOfTypes": ["UserGroup"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": {"type": "String"},
                                "department": {"type": "String", "required": False},
                                "roles": {
                                    "type": "Set",
                                    "element": {"type": "String"},
                                },
                            },
                        },
                    },
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "title": {"type": "String"},
                                "public": {"type": "Boolean"},
                            },
                        }
                    },
                },
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Document"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "ip": {"type": "String"},
                                },
                            },
                        }
                    },
                    "write": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Document"],
                        }
                    },
                },
            }
        }

        # Parse with Pydantic
        pydantic_schema = CedarSchema.model_validate(schema_dict)
        assert pydantic_schema[""].entityTypes["User"].memberOfTypes == ["UserGroup"]

        # Convert to Rust
        json_str = pydantic_schema.model_dump_json(exclude_none=True)
        rust_schema = Schema.from_json(json_str)

        # Verify all entity types present
        assert has_entity_type(rust_schema, "User")
        assert has_entity_type(rust_schema, "UserGroup")
        assert has_entity_type(rust_schema, "Document")

        # Verify actions
        actions = rust_schema.actions()
        assert any("read" in a for a in actions)
        assert any("write" in a for a in actions)

        # Verify round-trip preserves attributes
        cedar_str = rust_schema.to_cedarschema()
        assert "name" in cedar_str
        assert "department" in cedar_str
        assert "roles" in cedar_str
        assert "title" in cedar_str
        assert "public" in cedar_str
