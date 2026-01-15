"""Cedar policy analysis functions."""

import json
from collections import defaultdict
from tempfile import NamedTemporaryFile
from typing import Literal

from pydantic import BaseModel, Field, computed_field

from .. import PolicySet, Schema
from .cli import cedar_lean_cli


class Policy(BaseModel):
    """A policy reference from the CLI output."""

    policy_id: str
    policy_str: str


class VacuousPolicy(BaseModel):
    """A vacuous policy with its status."""

    policy: Policy
    status: Literal["MatchesAll", "MatchesNone"]


class EquivalenceClass(BaseModel):
    """A set of equivalent (redundant) policies."""

    equivalent_policies: list[Policy]


class ShadowedPermit(BaseModel):
    """A permit policy shadowed by other permits."""

    permit: Policy
    shadowing_permits: list[Policy]


class ShadowedForbid(BaseModel):
    """A forbid policy shadowed by other forbids."""

    forbid: Policy
    shadowing_forbids: list[Policy]


class OverriddenPermit(BaseModel):
    """A permit policy overridden by forbids."""

    permit: Policy
    overriding_forbids: list[Policy]


class RequestEnv(BaseModel):
    """Request environment (principal type, action, resource type)."""

    principal_type: str
    action_uid: str
    resource_type: str


class PerSigFinding(BaseModel):
    """Findings for a specific request signature."""

    req_env: RequestEnv
    equiv_classes: list[EquivalenceClass] = Field(default_factory=list)
    permit_shadowed_by_permits: list[ShadowedPermit] = Field(default_factory=list)
    forbid_shadowed_by_forbids: list[ShadowedForbid] = Field(default_factory=list)
    permit_overriden_by_forbids: list[OverriddenPermit] = Field(default_factory=list)


class Analysis(BaseModel):
    """Analysis result from cedar-lean-cli analyze policies."""

    vacuous_result: Literal["MatchesAll", "MatchesSome", "MatchesNone"]
    vacuous_policies: list[VacuousPolicy] = Field(default_factory=list)
    per_sig_findings: list[PerSigFinding] = Field(default_factory=list)

    @computed_field
    @property
    def redundant_policies(self) -> dict[str, list[str]]:
        """Map of policy_id -> list of policy_ids it's redundant with."""
        result = defaultdict(list)
        for finding in self.per_sig_findings:
            for equiv_class in finding.equiv_classes:
                policy_ids = [p.policy_id for p in equiv_class.equivalent_policies]
                for policy_id in policy_ids:
                    result[policy_id].extend(
                        pid for pid in policy_ids if pid != policy_id
                    )
        return dict(result)

    @computed_field
    @property
    def shadowed_policies(self) -> dict[str, list[str]]:
        """Map of shadowed policy_id -> list of policy_ids that shadow it."""
        result = defaultdict(list)
        for finding in self.per_sig_findings:
            for shadowed in finding.permit_shadowed_by_permits:
                result[shadowed.permit.policy_id].extend(
                    p.policy_id for p in shadowed.shadowing_permits
                )
            for shadowed in finding.forbid_shadowed_by_forbids:
                # CLI quirk: permit-overridden-by-forbid is reported here
                if "permit(" in shadowed.forbid.policy_str:
                    continue
                result[shadowed.forbid.policy_id].extend(
                    p.policy_id for p in shadowed.shadowing_forbids
                )
            # CLI quirk: forbid-shadowed-by-forbid is reported in permit_overriden_by_forbids
            for overridden in finding.permit_overriden_by_forbids:
                if "forbid(" in overridden.permit.policy_str:
                    result[overridden.permit.policy_id].extend(
                        p.policy_id for p in overridden.overriding_forbids
                    )
        return dict(result)

    @computed_field
    @property
    def overridden_policies(self) -> dict[str, list[str]]:
        """Map of overridden permit policy_id -> list of forbid policy_ids that override it."""
        result = defaultdict(list)
        for finding in self.per_sig_findings:
            for overridden in finding.permit_overriden_by_forbids:
                # CLI quirk: forbid-shadowed-by-forbid is reported here
                if "forbid(" in overridden.permit.policy_str:
                    continue
                result[overridden.permit.policy_id].extend(
                    p.policy_id for p in overridden.overriding_forbids
                )
            # CLI quirk: permit-overridden-by-forbid is reported in forbid_shadowed_by_forbids
            for shadowed in finding.forbid_shadowed_by_forbids:
                if "permit(" in shadowed.forbid.policy_str:
                    result[shadowed.forbid.policy_id].extend(
                        p.policy_id for p in shadowed.shadowing_forbids
                    )
        return dict(result)


def analyze_policies(policy_set: PolicySet, schema: Schema) -> Analysis:
    """Analyze policies for issues like vacuous, redundant, or shadowed policies.

     > If a policy is vacuous, if a subset of policies are redundant (i.e., are equivalent to each other), if a permit policy is shadowed by another permit policy, if a permit policy is overrident by forbid policy, or if a fordid policy is shadowed by another forbid policy. We present the findings (other than vacuousness of policies) per request type.
     >  + A policy is vacuous if either (1) it applies to all requests (allows all) or (2) it applies to no requests (allows none).
     >  + A set of policies are redundant with each other if every policy within the set are equivalent (allows the same set of authorization requests).
     >  + A permit policy src is shadowed by a permit policy tgt if every request allowed by src is allowed by tgt and src and tgt are not redundant.
     >  + A permit policy src is overriden by a forbid policy tgt if every request allowed by src is denied by tgt.
     >  + A forbid policy src is shadowed by a forbid policy tgt if every request denied by src is denied by tgt and src and tgt are not redundant.

    https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean-cli#analyze-policies

    """
    cedar_text = policy_set.to_cedar()
    if cedar_text is None:
        raise ValueError("PolicySet cannot be converted to Cedar syntax")

    with NamedTemporaryFile() as policy_set_file, NamedTemporaryFile() as schema_file:
        policy_set_file.write(cedar_text.encode())
        policy_set_file.flush()

        schema_file.write(schema.to_cedarschema().encode())
        schema_file.flush()

        result = cedar_lean_cli(
            "analyze",
            "policies",
            policy_set_file.name,
            schema_file.name,
            json_output=True,
        )
        result.check_returncode()
        return Analysis.model_validate_json(result.stdout)


class PerSigComparison(BaseModel):
    """Comparison result for a specific request signature."""

    req_env: RequestEnv
    status: Literal["Equivalent", "MorePermissive", "LessPermissive", "Incomparable"]


class Comparison(BaseModel):
    """Comparison result from cedar-lean-cli analyze compare.

    Compares source PolicySet against target PolicySet per request signature.
    Status meanings (from source's perspective relative to target):
    - Equivalent: Both policy sets allow the same requests
    - MorePermissive: Source allows more requests than target
    - LessPermissive: Source allows fewer requests than target
    - Incomparable: Neither is a subset of the other
    """

    comparisons: list[PerSigComparison]

    @computed_field
    @property
    def equivalent(self) -> list[RequestEnv]:
        """Request environments where source and target are equivalent."""
        return [c.req_env for c in self.comparisons if c.status == "Equivalent"]

    @computed_field
    @property
    def more_permissive(self) -> list[RequestEnv]:
        """Request environments where source is more permissive than target."""
        return [c.req_env for c in self.comparisons if c.status == "MorePermissive"]

    @computed_field
    @property
    def less_permissive(self) -> list[RequestEnv]:
        """Request environments where source is less permissive than target."""
        return [c.req_env for c in self.comparisons if c.status == "LessPermissive"]

    @computed_field
    @property
    def incomparable(self) -> list[RequestEnv]:
        """Request environments where source and target are incomparable."""
        return [c.req_env for c in self.comparisons if c.status == "Incomparable"]

    @computed_field
    @property
    def is_equivalent(self) -> bool:
        """True if all request environments are equivalent."""
        return all(c.status == "Equivalent" for c in self.comparisons)


def compare_policysets(
    source: PolicySet,
    target: PolicySet,
    schema: Schema,
) -> Comparison:
    """Compare two PolicySets to understand differences.

    Compares the source PolicySet against the target PolicySet for each
    request signature defined in the schema.

    Args:
        source: Source PolicySet to compare
        target: Target PolicySet to compare against
        schema: Schema defining the valid request signatures

    Returns:
        Comparison result with per-signature status

    https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean-cli#compare-policysets

    """
    source_cedar = source.to_cedar()
    target_cedar = target.to_cedar()
    if source_cedar is None:
        raise ValueError("Source PolicySet cannot be converted to Cedar syntax")
    if target_cedar is None:
        raise ValueError("Target PolicySet cannot be converted to Cedar syntax")

    with (
        NamedTemporaryFile() as source_file,
        NamedTemporaryFile() as target_file,
        NamedTemporaryFile() as schema_file,
    ):
        source_file.write(source_cedar.encode())
        source_file.flush()

        target_file.write(target_cedar.encode())
        target_file.flush()

        schema_file.write(schema.to_cedarschema().encode())
        schema_file.flush()

        result = cedar_lean_cli(
            "analyze",
            "compare",
            source_file.name,
            target_file.name,
            schema_file.name,
            json_output=True,
        )
        result.check_returncode()
        # CLI returns a list directly, wrap it in our model
        comparisons = json.loads(result.stdout)
        return Comparison(comparisons=[PerSigComparison(**c) for c in comparisons])
