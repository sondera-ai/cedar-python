# Cedar Python

Python bindings for [Cedar](https://www.cedarpolicy.com/), the open-source policy language for access control. This library lets you define, validate, and evaluate authorization policies directly from Python.

## Installation

```bash
pip install cedar-python
```

## Quick Start

```python
from cedar import Authorizer, EntityUid, Policy, PolicySet, Request

# Create policies
policies = PolicySet('''
    permit(principal == User::"alice", action == Action::"read", resource);
    forbid(principal, action == Action::"delete", resource);
''')

# Create and evaluate a request
request = Request(
    EntityUid("User", "alice"),
    EntityUid("Action", "read"),
    EntityUid("Document", "doc1"),
)

authorizer = Authorizer()
response = authorizer.is_authorized(request, policies)
print(response.allowed)  # True
```

## Core API

### Entities

```python
from cedar import Entity, EntityUid, Context

# Entity identifiers
uid = EntityUid("User", "alice")
uid.entity_type()  # "User"
uid.id()           # "alice"

# Entities with attributes and hierarchy
user = Entity(
    uid=EntityUid("User", "alice"),
    attrs={"email": "alice@example.com", "role": "admin"},
    parents=[EntityUid("Group", "admins")]
)

# Context for requests
context = Context({"ip_address": "10.0.0.1", "authenticated": True})
```

### Authorization

```python
from cedar import Authorizer, Request, Response

# Authorizer with entity hierarchy
authorizer = Authorizer(entities=[user, group])

# Full request with context
request = Request(
    principal=EntityUid("User", "alice"),
    action=EntityUid("Action", "read"),
    resource=EntityUid("Document", "doc1"),
    context=Context({"time": "2024-01-01T00:00:00Z"})
)

response = authorizer.is_authorized(request, policies)
response.allowed    # bool
response.decision   # "Allow" or "Deny"
response.reason     # Policy IDs that contributed to decision
response.errors     # Any evaluation errors
```

#### Schema Validation

Validate entities, requests, and context against a schema:

```python
from cedar import Authorizer, Context, EntityUid, Request, Schema

schema = Schema.from_json('''...''')
action = EntityUid("Action", "read")

# Validate context against schema (requires action to determine expected shape)
context = Context({"ip_address": "10.0.0.1"}, schema=schema, action=action)

# Validate request components against schema
request = Request(
    principal=EntityUid("User", "alice"),
    action=action,
    resource=EntityUid("Document", "doc1"),
    context=context,
    schema=schema
)

# Validate entities when creating the authorizer
authorizer = Authorizer(entities=[user, doc], schema=schema)

# Validate request components using stored schema
authorizer.validate_request(principal, action, resource, context)
```

#### Dynamic Entity Management

Add, update, or remove entities in an existing authorizer:

```python
from cedar import Authorizer, Entity, EntityUid

authorizer = Authorizer()

# Add a new entity (fails if entity already exists)
alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
authorizer.add_entity(alice)

# Upsert an entity (adds or replaces existing)
alice_updated = Entity(EntityUid("User", "alice"), {"role": "user"})
authorizer.upsert_entity(alice_updated)

# Remove an entity by UID
authorizer.remove_entity(EntityUid("User", "alice"))

# With schema validation
schema = Schema.from_json('''...''')
authorizer = Authorizer(schema=schema)
doc = Entity(EntityUid("Document", "doc1"), {"owner": "alice"})
authorizer.add_entity(doc)  # Validates against schema
```

### Policies

```python
from cedar import Policy, PolicySet

# Single policy
policy = Policy('permit(principal, action, resource);', id="policy1")
policy.id()          # "policy1"
policy.effect()      # "Permit"
policy.annotations() # {"id": "policy1"}
policy.to_cedar()    # Formatted Cedar syntax
policy.to_json()     # JSON representation

# Policy sets
policy_set = PolicySet('''
    @id("read-access")
    permit(principal, action == Action::"read", resource);
''')
policy_set.policies()      # List of Policy objects
policy_set.policy("read-access")  # Get by ID
len(policy_set)            # Number of policies
```

### Schemas

```python
from cedar import Schema

# From JSON
schema = Schema.from_json('''{
    "": {
        "entityTypes": {"User": {}, "Document": {}},
        "actions": {
            "read": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}
        }
    }
}''')

# From Cedar schema syntax
schema = Schema.from_cedarschema('''
    entity User;
    entity Document;
    action read appliesTo { principal: User, resource: Document };
''')

schema.entity_types()  # ["User", "Document"]
schema.actions()       # ["read"]
schema.principals()    # Entity types that can be principals
schema.resources()     # Entity types that can be resources
```

## Validation

Validate policies against a schema for type checking and error detection:

```python
from cedar import PolicySet, Schema

# Create schema and policies
schema = Schema.from_cedarschema('''
    entity User;
    entity Document;
    action read appliesTo { principal: User, resource: Document };
''')

policies = PolicySet('''
    permit(principal == User::"alice", action == Action::"read", resource);
''')

# Validate policies against schema
result = schema.validate_policyset(policies)
result.valid     # True if validation passed
result.errors    # List of ValidationError objects
result.warnings  # List of ValidationWarning objects

# ValidationError/ValidationWarning have policy_id and message attributes
for error in result.errors:
    print(f"{error.policy_id}: {error.message}")
```

## Schema Module

Pydantic models for building [schemas](#schemas) programmatically:

```python
from cedar.schema import CedarSchema, NamespaceDefinition, EntityType, Action, AppliesTo

schema = CedarSchema(root={
    "": NamespaceDefinition(
        entityTypes={"User": EntityType()},
        actions={"read": Action(appliesTo=AppliesTo(principalTypes=["User"]))}
    )
})
```

## Lean Module (Formal Verification)

Symbolic policy analysis using [cedar-lean-cli](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean-cli):

```python
from cedar.lean import (
    check_equivalent,
    check_implies,
    check_disjoint,
    compare_policysets,
    analyze_policies,
)

# Check if two policies are equivalent
result = check_equivalent(policy1, policy2, schema)
result.satisfied      # True if equivalent
result.counterexample # Example where they differ (if not equivalent)

# Compare policy sets
comparison = compare_policysets(old_policies, new_policies, schema)
comparison.is_equivalent   # True if all request signatures are equivalent
comparison.more_permissive # Request envs where source allows more
comparison.less_permissive # Request envs where source allows less
```

## CLI

```bash
# Validate a policy against a schema
cedar schema validate policy.cedar schema.json

# Run the MCP server
cedar mcp
```

## MCP Server

For AI coding assistants, Cedar provides an MCP server with policy tools:

```bash
pip install cedar-python[mcp]
cedar mcp
```

**Available tools:** `validate_policy`, `validate_policy_set`, `validate_schema`, `format_policy`

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)

