"""validate_exposure must audit refusals, not just completed checks."""

from __future__ import annotations

import pytest

from riskproof.engine import investigation as inv
from riskproof.errors import AuthorizationDenied


async def test_refused_target_is_audit_logged(services):
    with pytest.raises(AuthorizationDenied):
        await inv.validate_exposure(
            services, host="203.0.113.9", port=443, method="tcp_connect", finding_id="f-1"
        )
    entry = services.audit.recent(limit=1)[0]
    assert entry["action"] == "validate_exposure:tcp_connect"
    assert entry["subject"] == "203.0.113.9:443"
    assert entry["outcome"] == "refused"
    assert "RISKPROOF_ALLOWED_TARGETS" in entry["rationale"]
    assert entry["details"] == {"finding_id": "f-1"}


async def test_unapproved_method_is_audit_logged(services):
    services.settings.approved_validation_methods = ["tcp_connect"]
    with pytest.raises(AuthorizationDenied):
        await inv.validate_exposure(services, host="127.0.0.1", port=443, method="http_banner")
    entry = services.audit.recent(limit=1)[0]
    assert entry["action"] == "validate_exposure:http_banner"
    assert entry["outcome"] == "refused"
