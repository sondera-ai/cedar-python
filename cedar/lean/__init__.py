"""Cedar Lean CLI Python wrapper."""

from subprocess import CalledProcessError

from .cli import cedar_lean_cli

try:
    result = cedar_lean_cli("--version", "")
    result.check_returncode()
except CalledProcessError as e:
    print(f"cedar-lean-cli healthcheck raised an error: {e}")
    raise

from .analyze import analyze_policies, compare_policysets
from .symcc import (
    check_always_allows,
    check_always_denies,
    check_disjoint,
    check_equivalent,
    check_implies,
    check_never_errors,
    Counterexample,
    RequestEnvironment,
    VerificationResult,
)

__all__ = [
    # analyze
    "analyze_policies",
    "compare_policysets",
    # symcc
    "check_always_allows",
    "check_always_denies",
    "check_disjoint",
    "check_equivalent",
    "check_implies",
    "check_never_errors",
    "Counterexample",
    "RequestEnvironment",
    "VerificationResult",
]
