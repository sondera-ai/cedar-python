try:
    from fastmcp import FastMCP
except ImportError:
    raise ImportError(
        "fastmcp is required for MCP support. Install via `uv add cedar-python[mcp]` or `uv sync --group mcp`."
    )

from cedar import (
    Policy,
    PolicySet,
    Schema,
)

mcp = FastMCP(
    name="cedar",
    instructions="""Cedar Policy Language Tools

Cedar is an open-source policy language for access control. These tools help you:
- Validate and format Cedar policies
- Validate schemas in JSON or Cedar syntax

Key concepts:
- Policies use permit/forbid with principal, action, resource constraints
- Entities have a type and ID (e.g., User::"alice")
- Schemas define entity types, their attributes, and valid actions
""",
)


@mcp.tool()
def validate_policy(policy_text: str, policy_id: str | None = None) -> dict:
    """Validate a Cedar policy and return its parsed representation.

    Args:
        policy_text: The Cedar policy text to validate.
            Example: 'permit(principal == User::"alice", action, resource);'
        policy_id: Optional ID for the policy. If not provided, extracted from
            @id annotation or auto-generated.

    Returns:
        A dict with:
        - valid: True if policy is valid
        - effect: "Permit" or "Forbid"
        - id: The policy ID
        - annotations: Dict of policy annotations
        - cedar: The formatted Cedar policy text
        - error: Error message if invalid
    """
    try:
        policy = Policy(policy_text, policy_id)
        return {
            "valid": True,
            "effect": policy.effect(),
            "id": policy.id(),
            "annotations": policy.annotations(),
            "cedar": policy.to_cedar(),
        }
    except ValueError as e:
        return {"valid": False, "error": str(e)}


@mcp.tool()
def validate_policy_set(policies_text: str) -> dict:
    """Validate multiple Cedar policies and return their parsed representation.

    Args:
        policies_text: Multiple Cedar policies as text.
            Example:
            '''
            permit(principal, action == Action::"read", resource);
            forbid(principal, action == Action::"delete", resource);
            '''

    Returns:
        A dict with:
        - valid: True if all policies are valid
        - count: Number of policies
        - policies: List of policy summaries (id, effect)
        - cedar: The formatted Cedar policy text
        - error: Error message if invalid
    """
    try:
        policy_set = PolicySet(policies_text)
        policies = [{"id": p.id(), "effect": p.effect()} for p in policy_set]
        return {
            "valid": True,
            "count": len(policy_set),
            "policies": policies,
            "cedar": policy_set.to_cedar(),
        }
    except ValueError as e:
        return {"valid": False, "error": str(e)}


@mcp.tool()
def validate_schema(schema_text: str, schema_format: str = "json") -> dict:
    """Validate a Cedar schema and return entity/action information.

    Args:
        schema_text: The schema definition.
        schema_format: Schema format - "json" for JSON schema or "cedar" for Cedar syntax.

    Returns:
        A dict with:
        - valid: True if schema is valid
        - entity_types: List of entity type names
        - actions: List of action names
        - principals: Entity types that can be principals
        - resources: Entity types that can be resources
        - error: Error message if invalid

    JSON Schema Example:
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

    Cedar Schema Example:
        entity User;
        entity Document;
        action read appliesTo { principal: User, resource: Document };
    """
    try:
        if schema_format == "json":
            schema = Schema.from_json(schema_text)
        elif schema_format == "cedar":
            schema = Schema.from_cedarschema(schema_text)
        else:
            return {"valid": False, "error": f"Unknown format: {schema_format}"}

        return {
            "valid": True,
            "entity_types": [str(t) for t in schema.entity_types()],
            "actions": list(schema.actions()),
            "principals": list(schema.principals()),
            "resources": list(schema.resources()),
        }
    except ValueError as e:
        return {"valid": False, "error": str(e)}


@mcp.tool()
def format_policy(policy_text: str) -> dict:
    """Format Cedar policy text to canonical form.

    Args:
        policy_text: The Cedar policy or policies to format.

    Returns:
        A dict with:
        - valid: True if formatting succeeded
        - formatted: The formatted Cedar text
        - error: Error message if invalid
    """
    try:
        # Try as policy set first (handles multiple policies)
        policy_set = PolicySet(policy_text)
        return {"valid": True, "formatted": policy_set.to_cedar()}
    except ValueError:
        try:
            # Fall back to single policy
            policy = Policy(policy_text)
            return {"valid": True, "formatted": policy.to_cedar()}
        except ValueError as e:
            return {"valid": False, "error": str(e)}
