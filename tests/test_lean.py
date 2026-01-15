"""Tests for Cedar Lean CLI wrapper."""

import pytest

from cedar import Policy, PolicySet, Schema

try:
    from cedar.lean import (
        analyze_policies,
        check_always_allows,
        check_always_denies,
        check_disjoint,
        check_equivalent,
        check_implies,
        check_never_errors,
        compare_policysets,
    )

    LEAN_AVAILABLE = True
except Exception:
    LEAN_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not LEAN_AVAILABLE, reason="cedar-lean-cli not available"
)


BASIC_SCHEMA = """
entity User;
entity Document;
action read appliesTo { principal: User, resource: Document };
action write appliesTo { principal: User, resource: Document };
"""


class TestAnalyzePolicies:
    """Tests for analyze_policies function."""

    def test_redundant_policies(self):
        """Test detection of redundant (equivalent) policies."""
        # Two identical policies are redundant
        policies = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);

            @id("policy2")
            permit(principal, action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        analysis = analyze_policies(policies, schema)

        assert analysis.redundant_policies, "Expected redundant policies to be detected"
        # Both policies should be identified as redundant with each other
        all_redundant = set()
        for policy_id, redundant_with in analysis.redundant_policies.items():
            all_redundant.add(policy_id)
            all_redundant.update(redundant_with)
        assert "policy1" in all_redundant or "policy2" in all_redundant

    def test_shadowed_permit_policy(self):
        """Test detection of a permit policy shadowed by another permit policy."""
        # policy1 permits alice to read, policy2 permits all principals to read
        # policy1 is shadowed by policy2 (policy2 covers all requests that policy1 allows)
        policies = PolicySet("""
            @id("narrow_permit")
            permit(principal == User::"alice", action == Action::"read", resource);

            @id("broad_permit")
            permit(principal, action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        analysis = analyze_policies(policies, schema)

        assert analysis.shadowed_policies, "Expected shadowed policies to be detected"
        # narrow_permit should be shadowed by broad_permit
        all_shadowed = set()
        for policy_id, shadowed_by in analysis.shadowed_policies.items():
            all_shadowed.add(policy_id)
        assert "narrow_permit" in all_shadowed

    def test_overridden_permit_by_forbid(self):
        """Test detection of a permit policy overridden by a forbid policy."""
        # permit policy allows alice to read, but forbid policy denies alice from reading
        # The permit is overridden because every request it would allow is denied
        policies = PolicySet("""
            @id("allow_alice_read")
            permit(principal == User::"alice", action == Action::"read", resource);

            @id("deny_alice_reads")
            forbid(principal == User::"alice", action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        analysis = analyze_policies(policies, schema)

        assert analysis.overridden_policies, (
            "Expected overridden policies to be detected"
        )
        # allow_alice_read should be overridden by deny_alice_reads
        assert "allow_alice_read" in analysis.overridden_policies

    def test_shadowed_forbid_policy(self):
        """Test detection of a forbid policy shadowed by another forbid policy."""
        # narrow forbid denies alice from reading, broad forbid denies all reads
        # narrow forbid is shadowed by broad forbid
        policies = PolicySet("""
            @id("narrow_forbid")
            forbid(principal == User::"alice", action == Action::"read", resource);

            @id("broad_forbid")
            forbid(principal, action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        analysis = analyze_policies(policies, schema)

        assert analysis.shadowed_policies, "Expected shadowed policies to be detected"
        # narrow_forbid should be shadowed by broad_forbid
        assert "narrow_forbid" in analysis.shadowed_policies

    def test_no_issues(self):
        """Test that well-designed policies have no issues."""
        # Two policies with non-overlapping scopes
        policies = PolicySet("""
            @id("allow_read")
            permit(principal, action == Action::"read", resource);

            @id("deny_write")
            forbid(principal == User::"guest", action == Action::"write", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        analysis = analyze_policies(policies, schema)

        # These policies don't have obvious redundancy/shadow/override issues
        # (read and write are separate actions, forbid is on guest only)
        assert not analysis.redundant_policies
        assert not analysis.overridden_policies


class TestComparePolicysets:
    """Tests for compare_policysets function."""

    def test_equivalent_policysets(self):
        """Test that identical policy sets are equivalent."""
        policies = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        comparison = compare_policysets(policies, policies, schema)

        assert comparison.is_equivalent
        assert len(comparison.equivalent) == 2  # read and write actions
        assert not comparison.more_permissive
        assert not comparison.less_permissive
        assert not comparison.incomparable

    def test_more_permissive(self):
        """Test detection of more permissive source policy set."""
        source = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);

            @id("policy2")
            permit(principal, action == Action::"write", resource);
        """)
        target = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        comparison = compare_policysets(source, target, schema)

        assert not comparison.is_equivalent
        assert comparison.more_permissive
        # Source allows write, target doesn't
        assert any(r.action_uid == "write" for r in comparison.more_permissive)

    def test_less_permissive(self):
        """Test detection of less permissive source policy set."""
        source = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);
        """)
        target = PolicySet("""
            @id("policy1")
            permit(principal, action == Action::"read", resource);

            @id("policy2")
            permit(principal, action == Action::"write", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        comparison = compare_policysets(source, target, schema)

        assert not comparison.is_equivalent
        assert comparison.less_permissive
        # Source doesn't allow write, target does
        assert any(r.action_uid == "write" for r in comparison.less_permissive)

    def test_incomparable(self):
        """Test detection of incomparable policy sets."""
        source = PolicySet("""
            @id("policy1")
            permit(principal == User::"alice", action == Action::"read", resource);
        """)
        target = PolicySet("""
            @id("policy1")
            permit(principal == User::"bob", action == Action::"read", resource);
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        comparison = compare_policysets(source, target, schema)

        assert not comparison.is_equivalent
        assert comparison.incomparable
        # For read action, alice vs bob are incomparable
        assert any(r.action_uid == "read" for r in comparison.incomparable)


class TestCheckNeverErrors:
    """Tests for check_never_errors function."""

    def test_safe_policy_never_errors(self):
        """A simple policy without error-prone operations should never error."""
        policy = Policy("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_never_errors(policy, schema)

        assert result.satisfied, "Simple policy should never produce errors"
        assert not result.has_counterexample


class TestCheckAlwaysAllows:
    """Tests for check_always_allows function."""

    def test_permit_all_policy(self):
        """A policy that permits everything should always allow."""
        policies = PolicySet("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_always_allows(policies, schema)

        assert result.satisfied, "Permit-all policy should always allow"

    def test_restricted_policy_does_not_always_allow(self):
        """A policy with restrictions should not always allow."""
        policies = PolicySet('permit(principal == User::"alice", action, resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_always_allows(policies, schema)

        assert not result.satisfied, "Restricted policy should not always allow"


class TestCheckAlwaysDenies:
    """Tests for check_always_denies function."""

    def test_empty_policyset_always_denies(self):
        """An empty policy set denies all requests (default deny)."""
        policies = PolicySet()
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_always_denies(policies, schema)

        assert result.satisfied, "Empty policy set should always deny"

    def test_forbid_all_policy_always_denies(self):
        """A forbid-all policy should always deny."""
        policies = PolicySet("forbid(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_always_denies(policies, schema)

        assert result.satisfied, "Forbid-all policy should always deny"

    def test_permit_policy_does_not_always_deny(self):
        """A policy set with permits should not always deny."""
        policies = PolicySet("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_always_denies(policies, schema)

        assert not result.satisfied, "Permit policy should not always deny"


class TestCheckEquivalent:
    """Tests for check_equivalent function."""

    def test_identical_policies_are_equivalent(self):
        """Identical policy sets should be equivalent."""
        source = PolicySet("permit(principal, action, resource);")
        target = PolicySet("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_equivalent(source, target, schema)

        assert result.satisfied, "Identical policies should be equivalent"

    def test_different_policies_not_equivalent(self):
        """Different policy sets should not be equivalent."""
        source = PolicySet('permit(principal == User::"alice", action, resource);')
        target = PolicySet('permit(principal == User::"bob", action, resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_equivalent(source, target, schema)

        assert not result.satisfied, "Different policies should not be equivalent"

    def test_semantically_equivalent_policies(self):
        """Semantically equivalent but syntactically different policies."""
        # Both permit read for all users, just written differently
        source = PolicySet('permit(principal, action == Action::"read", resource);')
        target = PolicySet("""
            permit(principal, action, resource)
            when { action == Action::"read" };
        """)
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_equivalent(source, target, schema)

        assert result.satisfied, "Semantically equivalent policies should be equivalent"


class TestCheckImplies:
    """Tests for check_implies function."""

    def test_narrow_implies_broad(self):
        """A narrower policy should imply a broader one (subset relationship)."""
        # Alice-only policy implies permit-all (alice requests are subset of all)
        source = PolicySet('permit(principal == User::"alice", action, resource);')
        target = PolicySet("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_implies(source, target, schema)

        assert result.satisfied, "Narrow policy should imply broader policy"

    def test_broad_does_not_imply_narrow(self):
        """A broader policy should not imply a narrower one."""
        source = PolicySet("permit(principal, action, resource);")
        target = PolicySet('permit(principal == User::"alice", action, resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_implies(source, target, schema)

        assert not result.satisfied, "Broad policy should not imply narrow policy"

    def test_identical_policies_imply_each_other(self):
        """Identical policies should imply each other."""
        policies = PolicySet("permit(principal, action, resource);")
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_implies(policies, policies, schema)

        assert result.satisfied, "Identical policies should imply each other"


class TestCheckDisjoint:
    """Tests for check_disjoint function."""

    def test_disjoint_principal_policies(self):
        """Policies for different specific principals should be disjoint."""
        source = PolicySet('permit(principal == User::"alice", action, resource);')
        target = PolicySet('permit(principal == User::"bob", action, resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_disjoint(source, target, schema)

        assert result.satisfied, "Different principal policies should be disjoint"

    def test_disjoint_action_policies(self):
        """Policies for different actions should be disjoint."""
        source = PolicySet('permit(principal, action == Action::"read", resource);')
        target = PolicySet('permit(principal, action == Action::"write", resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_disjoint(source, target, schema)

        assert result.satisfied, "Different action policies should be disjoint"

    def test_overlapping_policies_not_disjoint(self):
        """Overlapping policies should not be disjoint."""
        source = PolicySet("permit(principal, action, resource);")
        target = PolicySet('permit(principal == User::"alice", action, resource);')
        schema = Schema.from_cedarschema(BASIC_SCHEMA)

        result = check_disjoint(source, target, schema)

        assert not result.satisfied, "Overlapping policies should not be disjoint"
