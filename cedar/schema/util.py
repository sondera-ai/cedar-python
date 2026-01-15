"""Schema functions and utilities."""

from typing import Any

from .types import (
    CedarSchema,
    SchemaType,
)

from .. import Schema


def dict_to_cedar_type(schema: dict[str, Any]) -> SchemaType:
    """Convert a dict object to Cedar SchemaType.

    Maps JSON Schema types to Cedar types:
    - object/OBJECT -> Record with attributes
    - array/ARRAY -> Set with element type
    - string/STRING -> String
    - number/integer/NUMBER/INTEGER -> Long
    - boolean/BOOLEAN -> Boolean
    """
    if not isinstance(schema, dict):
        return SchemaType(type="String")  # Default fallback

    # Handle both lowercase and uppercase type names
    json_type = schema.get("type", "object").lower()

    if json_type == "object":
        properties = schema.get("properties", {})
        required_fields = set(schema.get("required", []))

        attributes = {}
        for prop_name, prop_schema in properties.items():
            cedar_type = dict_to_cedar_type(prop_schema)
            # Only set required=False if the field is optional
            # Cedar defaults to required=true, so we don't need to set it explicitly
            if prop_name not in required_fields:
                cedar_type.required = False
            attributes[prop_name] = cedar_type

        return SchemaType(type="Record", attributes=attributes)

    elif json_type == "array":
        items = schema.get("items", {})
        element_type = dict_to_cedar_type(items)
        return SchemaType(type="Set", element=element_type)

    elif json_type == "string":
        # Check for enum values which could be treated as specific strings
        if "enum" in schema:
            # For now, just treat as String
            return SchemaType(type="String")
        return SchemaType(type="String")

    elif json_type in ["number", "integer"]:
        return SchemaType(type="Long")

    elif json_type == "boolean":
        return SchemaType(type="Boolean")

    else:
        raise NotImplementedError(f"Unsupported JSON schema type: {json_type}")


def validate(schema: CedarSchema) -> None:
    """Validate a Cedar schema from schema CedarSchema type.

    Args:
        schema: The CedarSchema to validate

    Returns:
        None if the schema is valid

    Raises:
        ValueError: If the schema is invalid with error details
    """
    schema_json = schema.model_dump_json(exclude_none=True)
    return validate_json(schema_json)


def validate_json(schema_json: str) -> None:
    """Validate a Cedar schema from JSON string.

    Args:
        schema_json: The JSON schema string to validate

    Returns:
        None if the schema is valid

    Raises:
        ValueError: If the schema is invalid with error details

    Example:
        >>> schema = '''
        ... {
        ...   "MyApp": {
        ...     "entityTypes": {
        ...       "User": {
        ...         "shape": {
        ...           "type": "Record",
        ...           "attributes": {
        ...             "name": {"type": "String"}
        ...           }
        ...         }
        ...       }
        ...     },
        ...     "actions": {
        ...       "view": {
        ...         "appliesTo": {
        ...           "principalTypes": ["User"],
        ...           "resourceTypes": ["User"]
        ...         }
        ...       }
        ...     }
        ...   }
        ... }
        ... '''
        >>> validate_json(schema)
        >>> # Returns None - schema is valid
    """
    # Schema.from_json raises ValueError if invalid
    Schema.from_json(schema_json)
