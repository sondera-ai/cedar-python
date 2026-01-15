"""Tests for Authorizer, Request, and Response classes."""

import pytest

from cedar import (
    Authorizer,
    Context,
    Entity,
    EntityUid,
    Policy,
    PolicySet,
    Request,
    Schema,
)


class TestRequest:
    """Tests for Request."""

    def test_creation(self):
        """Test Request creation with EntityUid objects."""
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )
        assert request is not None


class TestAuthorizer:
    """Tests for Authorizer."""

    @pytest.fixture
    def request_alice_read_doc1(self):
        return Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )

    def test_creation(self):
        """Test Authorizer creation."""
        assert Authorizer() is not None

    def test_creation_with_entities(self):
        """Test Authorizer with entity hierarchy."""
        alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
        admins = Entity(EntityUid("Group", "admins"), {})
        authorizer = Authorizer([alice, admins])
        assert authorizer is not None

    @pytest.mark.parametrize(
        "user,expected_allowed",
        [
            ("alice", True),
            ("bob", False),
        ],
    )
    def test_principal_matching(self, user, expected_allowed):
        """Test permit/deny based on principal matching."""
        request = Request(
            EntityUid("User", user),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )
        policies = PolicySet("""
        permit(
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
        """)
        response = Authorizer().is_authorized(request, policies)
        assert response.allowed == expected_allowed
        if expected_allowed:
            assert response.decision == "Allow"
            assert "policy0" in response.reason
        else:
            assert response.decision == "Deny"

    def test_forbid_policy(self, request_alice_read_doc1):
        """Test forbid policy denies matching requests."""
        policies = PolicySet("""
        forbid(
            principal == User::"alice",
            action == Action::"read",
            resource == Document::"doc1"
        );
        """)
        response = Authorizer().is_authorized(request_alice_read_doc1, policies)
        assert not response.allowed
        assert "policy0" in response.reason

    def test_default_deny(self, request_alice_read_doc1):
        """Test default deny with empty policy set."""
        response = Authorizer().is_authorized(request_alice_read_doc1, PolicySet())
        assert not response.allowed
        assert response.reason == []

    def test_any_principal(self):
        """Test policy that permits any principal."""
        request = Request(
            EntityUid("User", "anyone"),
            EntityUid("Action", "read"),
            EntityUid("Document", "public"),
        )
        policies = PolicySet("""
        permit(principal, action == Action::"read", resource == Document::"public");
        """)
        assert Authorizer().is_authorized(request, policies).allowed

    def test_forbid_overrides_permit(self):
        """Test forbid takes precedence over permit."""
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "delete"),
            EntityUid("Document", "doc1"),
        )
        policies = PolicySet("""
        permit(principal == User::"alice", action, resource == Document::"doc1");
        forbid(principal, action == Action::"delete", resource);
        """)
        response = Authorizer().is_authorized(request, policies)
        assert not response.allowed
        assert "policy1" in response.reason

    def test_single_policy(self, request_alice_read_doc1):
        """Test is_authorized_for_policy with single Policy."""
        policy = Policy('permit(principal == User::"alice", action, resource);')
        response = Authorizer().is_authorized_for_policy(
            request_alice_read_doc1, policy
        )
        assert response.allowed

    def test_entity_hierarchy(self):
        """Test authorization with entity hierarchy (in clause)."""
        alice_uid = EntityUid("User", "alice")
        admins_uid = EntityUid("Group", "admins")
        alice = Entity(alice_uid, {}, [admins_uid])
        admins = Entity(admins_uid, {})

        request = Request(
            alice_uid,
            EntityUid("Action", "admin_action"),
            EntityUid("Resource", "system"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')

        response = Authorizer([alice, admins]).is_authorized(request, policies)
        assert response.allowed
        assert "policy0" in response.reason


class TestContext:
    """Tests for Context."""

    def test_empty(self):
        """Test Context.empty() creates an empty context."""
        ctx = Context.empty()
        assert ctx is not None

    def test_empty_in_request(self):
        """Test Context.empty() can be used in a Request."""
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            Context.empty(),
        )
        assert request is not None

    def test_empty_in_authorization(self):
        """Test Context.empty() works in authorization."""
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            Context.empty(),
        )
        authorizer = Authorizer()
        policies = PolicySet("permit(principal, action, resource);")
        response = authorizer.is_authorized(request, policies)
        assert response.allowed


class TestResponse:
    """Tests for Response."""

    @pytest.fixture
    def auth_request(self):
        return Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )

    def test_boolean_context(self, auth_request):
        """Test Response works in boolean context."""
        authorizer = Authorizer()
        allow_policy = PolicySet("permit(principal, action, resource);")

        assert authorizer.is_authorized(auth_request, allow_policy)
        assert not authorizer.is_authorized(auth_request, PolicySet())

    def test_errors(self, auth_request):
        """Test Response captures evaluation errors."""
        policies = PolicySet("""
        permit(principal, action, resource) when { resource.nonexistent == "value" };
        """)
        response = Authorizer().is_authorized(auth_request, policies)
        assert not response.allowed
        assert len(response.errors) > 0


class TestSchemaValidation:
    """Tests for schema validation in Context, Request, and Authorizer."""

    @pytest.fixture
    def schema(self):
        """A schema with User, Document, and Action types."""
        return Schema.from_json("""{
            "": {
                "entityTypes": {
                    "User": {},
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Document"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "ip_address": { "type": "String" }
                                }
                            }
                        }
                    },
                    "delete": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Document"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "ip_address": { "type": "String" },
                                    "reason": { "type": "String" }
                                }
                            }
                        }
                    }
                }
            }
        }""")

    @pytest.fixture
    def action_read(self):
        return EntityUid("Action", "read")

    @pytest.fixture
    def action_delete(self):
        return EntityUid("Action", "delete")


class TestContextWithSchema(TestSchemaValidation):
    """Tests for Context schema validation."""

    def test_context_with_valid_schema(self, schema, action_read):
        """Test Context creation with valid schema validation."""
        ctx = Context({"ip_address": "192.168.1.1"}, schema=schema, action=action_read)
        assert ctx is not None

    def test_context_from_json_with_valid_schema(self, schema, action_read):
        """Test Context.from_json with valid schema validation."""
        ctx = Context.from_json(
            '{"ip_address": "192.168.1.1"}', schema=schema, action=action_read
        )
        assert ctx is not None

    def test_context_with_invalid_schema(self, schema, action_read):
        """Test Context creation fails with invalid context for schema."""
        with pytest.raises(ValueError):
            Context({"wrong_field": "value"}, schema=schema, action=action_read)

    def test_context_schema_requires_action(self, schema):
        """Test Context raises error when schema provided without action."""
        with pytest.raises(ValueError, match="action is required"):
            Context({"ip_address": "192.168.1.1"}, schema=schema)

    def test_context_from_json_schema_requires_action(self, schema):
        """Test Context.from_json raises error when schema provided without action."""
        with pytest.raises(ValueError, match="action is required"):
            Context.from_json('{"ip_address": "192.168.1.1"}', schema=schema)

    def test_context_different_actions_different_shapes(
        self, schema, action_read, action_delete
    ):
        """Test that different actions require different context shapes."""
        # read action only needs ip_address
        ctx_read = Context(
            {"ip_address": "192.168.1.1"}, schema=schema, action=action_read
        )
        assert ctx_read is not None

        # delete action needs both ip_address and reason
        ctx_delete = Context(
            {"ip_address": "192.168.1.1", "reason": "cleanup"},
            schema=schema,
            action=action_delete,
        )
        assert ctx_delete is not None


class TestRequestWithSchema(TestSchemaValidation):
    """Tests for Request schema validation."""

    def test_request_with_valid_schema(self, schema):
        """Test Request creation with valid schema validation."""
        ctx = Context({"ip_address": "192.168.1.1"})
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            context=ctx,
            schema=schema,
        )
        assert request is not None

    def test_request_with_invalid_principal_type(self, schema):
        """Test Request fails when principal type doesn't match schema."""
        with pytest.raises(ValueError):
            Request(
                EntityUid("InvalidType", "alice"),
                EntityUid("Action", "read"),
                EntityUid("Document", "doc1"),
                schema=schema,
            )

    def test_request_with_invalid_resource_type(self, schema):
        """Test Request fails when resource type doesn't match schema."""
        with pytest.raises(ValueError):
            Request(
                EntityUid("User", "alice"),
                EntityUid("Action", "read"),
                EntityUid("InvalidResource", "doc1"),
                schema=schema,
            )

    def test_request_with_context_and_schema(self, schema):
        """Test Request with both context and schema."""
        ctx = Context({"ip_address": "192.168.1.1"})
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            context=ctx,
            schema=schema,
        )
        assert request is not None


class TestAuthorizerWithSchema(TestSchemaValidation):
    """Tests for Authorizer schema validation."""

    def test_authorizer_with_schema_validates_entities(self, schema):
        """Test Authorizer validates entities against schema."""
        doc = Entity(EntityUid("Document", "doc1"), {"owner": "alice"})
        authorizer = Authorizer([doc], schema=schema)
        assert authorizer is not None

    def test_authorizer_with_schema_rejects_invalid_entities(self, schema):
        """Test Authorizer rejects entities that don't match schema."""
        # Document requires 'owner' attribute per schema
        doc = Entity(EntityUid("Document", "doc1"), {"wrong_attr": "value"})
        with pytest.raises(ValueError):
            Authorizer([doc], schema=schema)

    def test_validate_request_success(self, schema):
        """Test validate_request succeeds for valid request."""
        authorizer = Authorizer(schema=schema)
        ctx = Context({"ip_address": "192.168.1.1"})
        # Should not raise
        authorizer.validate_request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            context=ctx,
        )

    def test_validate_request_with_context(self, schema):
        """Test validate_request with context."""
        authorizer = Authorizer(schema=schema)
        ctx = Context({"ip_address": "192.168.1.1"})
        # Should not raise
        authorizer.validate_request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
            context=ctx,
        )

    def test_validate_request_fails_invalid_principal(self, schema):
        """Test validate_request fails for invalid principal type."""
        authorizer = Authorizer(schema=schema)
        with pytest.raises(ValueError):
            authorizer.validate_request(
                EntityUid("InvalidType", "alice"),
                EntityUid("Action", "read"),
                EntityUid("Document", "doc1"),
            )

    def test_validate_request_requires_schema(self):
        """Test validate_request raises error when no schema provided."""
        authorizer = Authorizer()
        with pytest.raises(ValueError, match="no schema provided"):
            authorizer.validate_request(
                EntityUid("User", "alice"),
                EntityUid("Action", "read"),
                EntityUid("Document", "doc1"),
            )


class TestAddEntity:
    """Tests for Authorizer.add_entity method."""

    def test_add_entity_basic(self):
        """Test adding an entity to the authorizer."""
        authorizer = Authorizer()
        alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
        authorizer.add_entity(alice)
        # Verify the entity affects authorization
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')
        # Alice is not in admins group yet, so should be denied
        response = authorizer.is_authorized(request, policies)
        assert not response.allowed

    def test_add_entity_with_hierarchy(self):
        """Test adding entities with parent relationships."""
        authorizer = Authorizer()
        admins_uid = EntityUid("Group", "admins")
        admins = Entity(admins_uid, {})
        authorizer.add_entity(admins)

        alice_uid = EntityUid("User", "alice")
        alice = Entity(alice_uid, {"role": "admin"}, [admins_uid])
        authorizer.add_entity(alice)

        request = Request(
            alice_uid,
            EntityUid("Action", "admin_action"),
            EntityUid("Resource", "system"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')
        response = authorizer.is_authorized(request, policies)
        assert response.allowed

    def test_add_entity_duplicate_fails(self):
        """Test that adding a duplicate entity raises ValueError."""
        authorizer = Authorizer()
        alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
        authorizer.add_entity(alice)

        # Try to add the same entity again
        alice_duplicate = Entity(EntityUid("User", "alice"), {"role": "user"})
        with pytest.raises(ValueError):
            authorizer.add_entity(alice_duplicate)

    def test_add_entity_with_schema(self):
        """Test add_entity validates against schema."""
        schema = Schema.from_json("""{
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {}
            }
        }""")
        authorizer = Authorizer(schema=schema)
        doc = Entity(EntityUid("Document", "doc1"), {"owner": "alice"})
        authorizer.add_entity(doc)

    def test_add_entity_with_schema_invalid_fails(self):
        """Test add_entity fails when entity doesn't match schema."""
        schema = Schema.from_json("""{
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {}
            }
        }""")
        authorizer = Authorizer(schema=schema)
        # Document requires 'owner' attribute per schema
        doc = Entity(EntityUid("Document", "doc1"), {"wrong_attr": "value"})
        with pytest.raises(ValueError):
            authorizer.add_entity(doc)


class TestUpsertEntity:
    """Tests for Authorizer.upsert_entity method."""

    def test_upsert_entity_new(self):
        """Test upserting a new entity."""
        authorizer = Authorizer()
        alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
        authorizer.upsert_entity(alice)
        # Should work without error
        request = Request(
            EntityUid("User", "alice"),
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )
        policies = PolicySet('permit(principal == User::"alice", action, resource);')
        response = authorizer.is_authorized(request, policies)
        assert response.allowed

    def test_upsert_entity_replaces_existing(self):
        """Test that upsert replaces an existing entity."""
        admins_uid = EntityUid("Group", "admins")
        users_uid = EntityUid("Group", "users")

        # Start with alice as admin
        alice_uid = EntityUid("User", "alice")
        alice_admin = Entity(alice_uid, {}, [admins_uid])
        admins = Entity(admins_uid, {})
        users = Entity(users_uid, {})

        authorizer = Authorizer([alice_admin, admins, users])

        # Verify alice is in admins
        request = Request(
            alice_uid,
            EntityUid("Action", "admin_action"),
            EntityUid("Resource", "system"),
        )
        admin_policies = PolicySet(
            'permit(principal in Group::"admins", action, resource);'
        )
        assert authorizer.is_authorized(request, admin_policies).allowed

        # Now upsert alice to be in users instead of admins
        alice_user = Entity(alice_uid, {}, [users_uid])
        authorizer.upsert_entity(alice_user)

        # alice should no longer be in admins
        assert not authorizer.is_authorized(request, admin_policies).allowed

        # But alice should be in users
        user_policies = PolicySet(
            'permit(principal in Group::"users", action, resource);'
        )
        assert authorizer.is_authorized(request, user_policies).allowed

    def test_upsert_entity_duplicate_succeeds(self):
        """Test that upserting a duplicate entity succeeds (unlike add_entity)."""
        authorizer = Authorizer()
        alice = Entity(EntityUid("User", "alice"), {"role": "admin"})
        authorizer.upsert_entity(alice)

        # Upsert the same entity again - should succeed
        alice_updated = Entity(EntityUid("User", "alice"), {"role": "user"})
        authorizer.upsert_entity(alice_updated)  # Should not raise

    def test_upsert_entity_with_schema(self):
        """Test upsert_entity validates against schema."""
        schema = Schema.from_json("""{
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {}
            }
        }""")
        authorizer = Authorizer(schema=schema)
        doc = Entity(EntityUid("Document", "doc1"), {"owner": "alice"})
        authorizer.upsert_entity(doc)

        # Update the entity
        doc_updated = Entity(EntityUid("Document", "doc1"), {"owner": "bob"})
        authorizer.upsert_entity(doc_updated)

    def test_upsert_entity_with_schema_invalid_fails(self):
        """Test upsert_entity fails when entity doesn't match schema."""
        schema = Schema.from_json("""{
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": { "type": "String" }
                            }
                        }
                    }
                },
                "actions": {}
            }
        }""")
        authorizer = Authorizer(schema=schema)
        # Document requires 'owner' attribute per schema
        doc = Entity(EntityUid("Document", "doc1"), {"wrong_attr": "value"})
        with pytest.raises(ValueError):
            authorizer.upsert_entity(doc)


class TestRemoveEntity:
    """Tests for Authorizer.remove_entity method."""

    def test_remove_entity_basic(self):
        """Test removing an entity from the authorizer."""
        alice_uid = EntityUid("User", "alice")
        alice = Entity(alice_uid, {"role": "admin"})
        authorizer = Authorizer([alice])

        # Verify alice is recognized initially
        request = Request(
            alice_uid,
            EntityUid("Action", "read"),
            EntityUid("Document", "doc1"),
        )
        policies = PolicySet('permit(principal == User::"alice", action, resource);')
        assert authorizer.is_authorized(request, policies).allowed

        # Remove alice
        authorizer.remove_entity(alice_uid)

        # Alice should still match (entity existence doesn't affect principal matching)
        # but let's test with hierarchy instead
        admins_uid = EntityUid("Group", "admins")
        alice_in_admins = Entity(alice_uid, {}, [admins_uid])
        admins = Entity(admins_uid, {})
        authorizer2 = Authorizer([alice_in_admins, admins])

        hierarchy_policies = PolicySet(
            'permit(principal in Group::"admins", action, resource);'
        )
        assert authorizer2.is_authorized(request, hierarchy_policies).allowed

        # Remove alice - should no longer be in admins hierarchy
        authorizer2.remove_entity(alice_uid)
        # Note: After removal, the entity doesn't exist in hierarchy
        # The request still uses the principal, but hierarchy lookups fail
        response = authorizer2.is_authorized(request, hierarchy_policies)
        assert not response.allowed

    def test_remove_entity_from_hierarchy(self):
        """Test removing an entity affects hierarchy lookups."""
        admins_uid = EntityUid("Group", "admins")
        alice_uid = EntityUid("User", "alice")

        admins = Entity(admins_uid, {})
        alice = Entity(alice_uid, {"role": "admin"}, [admins_uid])
        authorizer = Authorizer([alice, admins])

        request = Request(
            alice_uid,
            EntityUid("Action", "admin_action"),
            EntityUid("Resource", "system"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')

        # Alice should be allowed (she's in admins)
        assert authorizer.is_authorized(request, policies).allowed

        # Remove alice from entities
        authorizer.remove_entity(alice_uid)

        # Now alice should be denied (no longer in hierarchy)
        assert not authorizer.is_authorized(request, policies).allowed

    def test_remove_entity_then_add_back(self):
        """Test removing and re-adding an entity."""
        alice_uid = EntityUid("User", "alice")
        admins_uid = EntityUid("Group", "admins")

        admins = Entity(admins_uid, {})
        alice = Entity(alice_uid, {}, [admins_uid])
        authorizer = Authorizer([alice, admins])

        request = Request(
            alice_uid,
            EntityUid("Action", "read"),
            EntityUid("Resource", "system"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')

        # Initially allowed
        assert authorizer.is_authorized(request, policies).allowed

        # Remove alice
        authorizer.remove_entity(alice_uid)
        assert not authorizer.is_authorized(request, policies).allowed

        # Add alice back
        alice_new = Entity(alice_uid, {}, [admins_uid])
        authorizer.add_entity(alice_new)
        assert authorizer.is_authorized(request, policies).allowed

    def test_remove_multiple_entities(self):
        """Test removing multiple entities sequentially."""
        alice_uid = EntityUid("User", "alice")
        bob_uid = EntityUid("User", "bob")
        admins_uid = EntityUid("Group", "admins")

        admins = Entity(admins_uid, {})
        alice = Entity(alice_uid, {}, [admins_uid])
        bob = Entity(bob_uid, {}, [admins_uid])
        authorizer = Authorizer([alice, bob, admins])

        policies = PolicySet('permit(principal in Group::"admins", action, resource);')

        alice_request = Request(
            alice_uid, EntityUid("Action", "read"), EntityUid("Resource", "sys")
        )
        bob_request = Request(
            bob_uid, EntityUid("Action", "read"), EntityUid("Resource", "sys")
        )

        # Both allowed initially
        assert authorizer.is_authorized(alice_request, policies).allowed
        assert authorizer.is_authorized(bob_request, policies).allowed

        # Remove alice
        authorizer.remove_entity(alice_uid)
        assert not authorizer.is_authorized(alice_request, policies).allowed
        assert authorizer.is_authorized(bob_request, policies).allowed

        # Remove bob
        authorizer.remove_entity(bob_uid)
        assert not authorizer.is_authorized(alice_request, policies).allowed
        assert not authorizer.is_authorized(bob_request, policies).allowed

    def test_remove_parent_entity(self):
        """Test removing a parent entity affects children's hierarchy."""
        admins_uid = EntityUid("Group", "admins")
        alice_uid = EntityUid("User", "alice")

        admins = Entity(admins_uid, {})
        alice = Entity(alice_uid, {}, [admins_uid])
        authorizer = Authorizer([alice, admins])

        request = Request(
            alice_uid,
            EntityUid("Action", "admin_action"),
            EntityUid("Resource", "system"),
        )
        policies = PolicySet('permit(principal in Group::"admins", action, resource);')

        # Alice is allowed (in admins)
        assert authorizer.is_authorized(request, policies).allowed

        # Remove the admins group
        authorizer.remove_entity(admins_uid)

        # Alice should now be denied (admins group no longer exists)
        assert not authorizer.is_authorized(request, policies).allowed
