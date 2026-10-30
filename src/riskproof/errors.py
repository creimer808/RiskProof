"""Typed errors raised by RiskProof services.

Tools translate these into structured ``{"ok": false, "error": {...}}`` payloads
so an MCP agent can understand and recover from failures instead of guessing.
"""

from __future__ import annotations


class RiskProofError(Exception):
    """Base class for expected, user-facing RiskProof errors."""

    code = "riskproof_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(RiskProofError):
    """A referenced finding, investigation, or record does not exist."""

    code = "not_found"


class InvalidInputError(RiskProofError):
    """Input failed validation or normalization."""

    code = "invalid_input"


class AuthorizationDenied(RiskProofError):
    """An action was refused because it is not authorized by policy.

    The message always includes the human steps required to authorize the
    action. RiskProof never lets an agent self-authorize.
    """

    code = "authorization_denied"


class ProviderUnavailable(RiskProofError):
    """An external data source could not be reached or is not configured."""

    code = "provider_unavailable"


def error_payload(exc: Exception) -> dict:
    """Build the structured error body returned by MCP tools."""
    if isinstance(exc, RiskProofError):
        return {"code": exc.code, "message": exc.message}
    return {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"}
