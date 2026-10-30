"""Authorized, non-destructive vulnerability and exposure validation."""

from riskproof.validation.checks import (
    CHECK_METHODS,
    ValidationResult,
    run_authorized_check,
)
from riskproof.validation.targets import AuthorizedTarget, TargetAuthorizer

__all__ = [
    "CHECK_METHODS",
    "AuthorizedTarget",
    "TargetAuthorizer",
    "ValidationResult",
    "run_authorized_check",
]
