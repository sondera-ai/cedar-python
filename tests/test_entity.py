"""Tests for Entity and EntityUid classes."""

import json

import pytest

from cedar import Entity, EntityUid


class TestEntityUid:
    """Tests for EntityUid."""

    @pytest.mark.parametrize(
        "type_name,id_value",
        [
            ("User", "alice"),
            ("MyApp::User", "bob"),
            ("A::B::C", "complex"),
        ],
    )
    def test_creation_and_accessors(self, type_name, id_value):
        """Test EntityUid creation with various type formats."""
        uid = EntityUid(type_name, id_value)
        assert uid.id() == id_value
        assert uid.entity_type() == type_name

    def test_json_roundtrip(self):
        """Test EntityUid JSON serialization and deserialization."""
        uid = EntityUid("MyApp::User", "alice")
        json_str = uid.to_json()
        result = json.loads(json_str)
        assert result == {"__entity": {"type": "MyApp::User", "id": "alice"}}

        restored = EntityUid.from_json(json_str)
        assert restored.id() == uid.id()
        assert restored.entity_type() == uid.entity_type()


class TestEntity:
    """Tests for Entity."""

    def test_basic_creation(self):
        """Test Entity creation with various attribute types."""
        uid = EntityUid("User", "alice")
        entity = Entity(
            uid,
            {
                "name": "Alice",
                "age": 30,
                "active": True,
                "profile": {"email": "alice@example.com"},
                "tags": ["admin", "active"],
            },
        )
        assert entity.uid().id() == "alice"
        assert entity.uid().entity_type() == "User"

    def test_empty_attrs(self):
        """Test Entity with empty attributes."""
        entity = Entity(EntityUid("Resource", "doc1"), {})
        assert entity.uid().id() == "doc1"

    @pytest.mark.parametrize("num_parents", [1, 2])
    def test_with_parents(self, num_parents):
        """Test Entity with parent relationships."""
        uid = EntityUid("User", "alice")
        parents = [EntityUid("Group", f"group{i}") for i in range(num_parents)]
        entity = Entity(uid, {"role": "admin"}, parents)
        assert entity.uid().id() == "alice"

    def test_namespaced_with_parent(self):
        """Test Entity with namespaced types and parent."""
        entity = Entity(
            EntityUid("MyApp::User", "alice"),
            {"department": "engineering"},
            [EntityUid("MyApp::Group", "staff")],
        )
        assert entity.uid().entity_type() == "MyApp::User"

    def test_invalid_attrs_raises(self):
        """Test that invalid attributes raise an exception."""
        with pytest.raises(Exception):
            Entity(EntityUid("User", "alice"), {"callback": lambda x: x})

    def test_entity_uid_as_attribute(self):
        """Test Entity with EntityUid as attribute value."""
        owner_uid = EntityUid("User", "alice")
        doc_uid = EntityUid("Document", "doc1")
        entity = Entity(doc_uid, {"owner": owner_uid})
        assert entity.uid().id() == "doc1"

    def test_entity_uid_attribute_in_nested_structure(self):
        """Test EntityUid in nested attribute structures."""
        owner_uid = EntityUid("User", "alice")
        reviewer_uid = EntityUid("User", "bob")
        doc_uid = EntityUid("Document", "doc1")

        entity = Entity(
            doc_uid,
            {
                "owner": owner_uid,
                "metadata": {
                    "reviewer": reviewer_uid,
                    "title": "Test Document",
                },
            },
        )
        assert entity.uid().id() == "doc1"

    def test_entity_uid_in_list_attribute(self):
        """Test EntityUid values in list attributes."""
        user1 = EntityUid("User", "alice")
        user2 = EntityUid("User", "bob")
        group_uid = EntityUid("Group", "admins")

        entity = Entity(
            group_uid,
            {
                "members": [user1, user2],
                "name": "Administrators",
            },
        )
        assert entity.uid().id() == "admins"
