"""Shared fixtures for Cedar tests."""

import pytest

from cedar import Authorizer, EntityUid, PolicySet, Request


@pytest.fixture
def alice_uid():
    return EntityUid("User", "alice")


@pytest.fixture
def read_action():
    return EntityUid("Action", "read")


@pytest.fixture
def doc1_resource():
    return EntityUid("Document", "doc1")


@pytest.fixture
def basic_request(alice_uid, read_action, doc1_resource):
    return Request(alice_uid, read_action, doc1_resource)


@pytest.fixture
def authorizer():
    return Authorizer()


@pytest.fixture
def permit_all_policy():
    return PolicySet("permit(principal, action, resource);")
