"""Cedar symbolic compilation functions for policy verification.

The symcc command provides an interface to Cedar's Symbolic Compiler,
offering lower-level access to Cedar's analysis capabilities.
"""

import re
from tempfile import NamedTemporaryFile
from typing import Any, TypedDict

from pydantic import BaseModel, computed_field

from .. import Policy, PolicySet, Schema
from .cli import cedar_lean_cli


def _to_cedar_str(obj: Policy | PolicySet) -> str:
    """Convert a Policy or PolicySet to Cedar syntax, raising if None."""
    cedar_text = obj.to_cedar()
    if cedar_text is None:
        raise ValueError(f"{type(obj).__name__} cannot be converted to Cedar syntax")
    return cedar_text


class RequestEnvironment(BaseModel):
    """Request environment filter for symbolic compilation.

    Used to restrict verification to specific request signatures.
    """

    principal_type: str | None = None
    action_name: str | None = None
    resource_type: str | None = None


class Counterexample(BaseModel):
    """A counterexample showing a request that violates the property."""

    principal: str | None = None
    action: str | None = None
    resource: str | None = None
    context: dict[str, Any] | None = None


class VerificationResult(BaseModel):
    """Result of symbolic verification.

    The `satisfied` field indicates whether the property holds:
    - For check_never_errors: True means policy never errors
    - For check_always_allows: True means policy allows all requests (overly permissive)
    - For check_always_denies: True means policy denies all requests (overly restrictive)
    - For check_equivalent: True means policies are equivalent
    - For check_implies: True means source implies target
    - For check_disjoint: True means policies allow disjoint request sets
    """

    satisfied: bool
    counterexample: Counterexample | None = None
    smt_formula: str | None = None
    raw_output: str | None = None

    @computed_field
    @property
    def has_counterexample(self) -> bool:
        """True if a counterexample was found (property is violated)."""
        return self.counterexample is not None


def _parse_counterexample(output: str) -> Counterexample | None:
    """Extract counterexample from SAT output."""
    try:
        counterexample_data: dict[str, Any] = {}

        # Extract principal
        principal_match = re.search(r"principal:\s*([^\n,]+)", output)
        if principal_match:
            counterexample_data["principal"] = principal_match.group(1).strip()

        # Extract action
        action_match = re.search(r"action:\s*([^\n,]+)", output)
        if action_match:
            counterexample_data["action"] = action_match.group(1).strip()

        # Extract resource
        resource_match = re.search(r"resource:\s*([^\n,]+)", output)
        if resource_match:
            counterexample_data["resource"] = resource_match.group(1).strip()

        return Counterexample(**counterexample_data) if counterexample_data else None
    except Exception:
        return None


def _parse_verification_result(
    output: str, print_smtlib: bool = False
) -> VerificationResult:
    """Parse verification output into a VerificationResult.

    The CLI outputs human-readable text with patterns like:
    - "Policy never errors" / "Policy may error"
    - "PolicySet always allows" / "PolicySet does not always allow"
    - "PolicySet always denies" / "PolicySet does not always deny"
    - "Source PolicySet is equivalent to Target PolicySet" / "not equivalent"
    - "Source PolicySet implies Target PolicySet" / "does not imply"
    - "Source PolicySet is disjoint with Target PolicySet" / "not disjoint"
    """
    if print_smtlib:
        return VerificationResult(
            satisfied=False,
            smt_formula=output,
            raw_output=output,
        )

    output_lower = output.strip().lower()

    # Check for positive confirmation patterns (property holds)
    positive_patterns = [
        "policy never errors",
        "policyset always allows",
        "always allows all",
        "allows all requests",
        "policyset always denies",
        "always denies all",
        "denies all requests",
        "is equivalent to",
        "are equivalent",
        "implies target",
        "is disjoint with",
        "are disjoint",
        "unsat",  # Keep for potential raw solver output
    ]

    # Check for negative patterns (property violated)
    negative_patterns = [
        "policy may error",
        "does not always allow",
        "not always allow",
        "does not always deny",
        "not always deny",
        "not equivalent",
        "does not imply",
        "not disjoint",
        "sat",  # Keep for potential raw solver output (but check it's not part of "unsat")
    ]

    # First check for explicit negative patterns
    for pattern in negative_patterns:
        if pattern in output_lower:
            # Special case: "sat" should not match "unsat"
            if pattern == "sat" and "unsat" in output_lower:
                continue
            counterexample = _parse_counterexample(output)
            return VerificationResult(
                satisfied=False,
                counterexample=counterexample,
                raw_output=output,
            )

    # Then check for positive patterns
    for pattern in positive_patterns:
        if pattern in output_lower:
            return VerificationResult(satisfied=True, raw_output=output)

    # Unknown result, default to not satisfied
    return VerificationResult(satisfied=False, raw_output=output)


class _RequestEnvArgs(TypedDict, total=False):
    """Type for request environment CLI arguments."""

    principal_type: str | None
    action_name: str | None
    resource_type: str | None


def _build_request_env_args(
    request_env: RequestEnvironment | None,
) -> _RequestEnvArgs:
    """Build CLI kwargs from RequestEnvironment."""
    if not request_env:
        return {}
    return {
        "principal_type": request_env.principal_type,
        "action_name": request_env.action_name,
        "resource_type": request_env.resource_type,
    }


def check_never_errors(
    policy: Policy,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if a policy never produces runtime errors during evaluation.

    Verifies that the given policy will not throw errors for any valid
    authorization request according to the schema.

    Args:
        policy: Policy to verify
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if policy never errors

    Example:
        >>> from cedar import Policy, Schema
        >>> from cedar.lean.symcc import check_never_errors
        >>> policy = Policy('permit(principal, action, resource);')
        >>> schema = Schema.from_cedarschema('entity User; action read appliesTo { principal: User };')
        >>> result = check_never_errors(policy, schema)
        >>> print(f"Policy is error-free: {result.satisfied}")
    """
    cedar_text = _to_cedar_str(policy)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as policy_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        policy_file.write(cedar_text)
        policy_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-never-errors",
            policy_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)


def check_always_allows(
    policy_set: PolicySet,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if a PolicySet allows all authorization requests.

    Determines if the policy set is overly permissive by allowing
    every possible valid request.

    Args:
        policy_set: PolicySet to verify
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if policy always allows (overly permissive)
    """
    cedar_text = _to_cedar_str(policy_set)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as policyset_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        policyset_file.write(cedar_text)
        policyset_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-always-allows",
            policyset_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)


def check_always_denies(
    policy_set: PolicySet,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if a PolicySet denies all authorization requests.

    Determines if the policy set is overly restrictive by denying
    every possible valid request.

    Args:
        policy_set: PolicySet to verify
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if policy always denies (overly restrictive)
    """
    cedar_text = _to_cedar_str(policy_set)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as policyset_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        policyset_file.write(cedar_text)
        policyset_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-always-denies",
            policyset_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)


def check_equivalent(
    source: PolicySet,
    target: PolicySet,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if two PolicySets are equivalent.

    Verifies that both policy sets allow exactly the same set of
    authorization requests.

    Args:
        source: Source PolicySet to compare
        target: Target PolicySet to compare against
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if policies are equivalent
    """
    source_cedar = _to_cedar_str(source)
    target_cedar = _to_cedar_str(target)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as source_file,
        NamedTemporaryFile(mode="w", suffix=".cedar") as target_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        source_file.write(source_cedar)
        source_file.flush()

        target_file.write(target_cedar)
        target_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-equivalent",
            source_file.name,
            target_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)


def check_implies(
    source: PolicySet,
    target: PolicySet,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if source PolicySet implies target PolicySet.

    Verifies that every authorization request allowed by source
    is also allowed by target (source ⊆ target).

    Args:
        source: Source PolicySet
        target: Target PolicySet
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if source implies target
    """
    source_cedar = _to_cedar_str(source)
    target_cedar = _to_cedar_str(target)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as source_file,
        NamedTemporaryFile(mode="w", suffix=".cedar") as target_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        source_file.write(source_cedar)
        source_file.flush()

        target_file.write(target_cedar)
        target_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-implies",
            source_file.name,
            target_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)


def check_disjoint(
    source: PolicySet,
    target: PolicySet,
    schema: Schema,
    request_env: RequestEnvironment | None = None,
    print_smtlib: bool = False,
) -> VerificationResult:
    """Check if two PolicySets allow disjoint request sets.

    Verifies that no authorization request is allowed by both
    policy sets (source ∩ target = ∅).

    Args:
        source: Source PolicySet
        target: Target PolicySet
        schema: Schema defining valid request signatures
        request_env: Optional filter to restrict to specific request types
        print_smtlib: If True, return SMT-LIB formula instead of running analysis

    Returns:
        VerificationResult with satisfied=True if policies are disjoint
    """
    source_cedar = _to_cedar_str(source)
    target_cedar = _to_cedar_str(target)
    with (
        NamedTemporaryFile(mode="w", suffix=".cedar") as source_file,
        NamedTemporaryFile(mode="w", suffix=".cedar") as target_file,
        NamedTemporaryFile(mode="w", suffix=".cedarschema") as schema_file,
    ):
        source_file.write(source_cedar)
        source_file.flush()

        target_file.write(target_cedar)
        target_file.flush()

        schema_file.write(schema.to_cedarschema())
        schema_file.flush()

        result = cedar_lean_cli(
            "symcc",
            "check-disjoint",
            source_file.name,
            target_file.name,
            schema_file.name,
            run_analysis=not print_smtlib,
            print_smtlib=print_smtlib,
            **_build_request_env_args(request_env),
        )
        result.check_returncode()
        return _parse_verification_result(result.stdout, print_smtlib)
