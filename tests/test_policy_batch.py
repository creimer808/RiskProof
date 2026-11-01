"""execute_risk_policy batches: idempotent and all-or-nothing."""

from __future__ import annotations

import pytest

from riskproof.engine import investigation as inv
from riskproof.errors import NotFoundError
from riskproof.models.evidence import ApplicabilityStatus
from riskproof.models.policy import PolicyAction, RiskPolicy

LOG4SHELL = "prod-web-01.demo.local-155999-8080tcp"
ZEROLOGON = "corp-db-02.demo.local-121080-445tcp"


def _policy_audit(services) -> list[dict]:
    return [e for e in services.audit.recent(limit=500) if e["action"].startswith("policy:")]


async def test_rerunning_policy_does_not_duplicate_actions(services):
    await inv.investigate(services, fixture="findings_sample.json")
    first = inv.execute_risk_policy(services, [LOG4SHELL, ZEROLOGON], RiskPolicy())
    pending_after_first = services.pending.list_open()
    assert pending_after_first
    assert all(d.existing_action_ids == [] for d in first)

    second = inv.execute_risk_policy(services, [LOG4SHELL, ZEROLOGON], RiskPolicy())
    assert services.pending.list_open() == pending_after_first
    for before, after in zip(first, second, strict=True):
        assert after.recorded_action_ids == before.recorded_action_ids
        assert after.existing_action_ids == before.recorded_action_ids
    # The re-evaluation is still in the audit trail.
    assert any(e["outcome"] == "already_recorded" for e in _policy_audit(services))


async def test_duplicate_ids_in_one_call_are_evaluated_once(services):
    await inv.investigate(services, fixture="findings_sample.json")
    decisions = inv.execute_risk_policy(services, [LOG4SHELL, LOG4SHELL], RiskPolicy())
    assert len(decisions) == 1


async def test_unknown_id_records_nothing(services):
    await inv.investigate(services, fixture="findings_sample.json")
    with pytest.raises(NotFoundError, match="nothing was recorded") as excinfo:
        inv.execute_risk_policy(services, [LOG4SHELL, "nope", "also-nope"], RiskPolicy())
    assert "nope" in str(excinfo.value) and "also-nope" in str(excinfo.value)
    assert services.pending.list_open() == []
    assert _policy_audit(services) == []


async def test_suspected_false_positive_escalates_once(services):
    await inv.investigate(services, fixture="findings_sample.json")
    record = services.investigations.get(LOG4SHELL)
    record.applicability = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    services.investigations.save(record)

    decision = inv.execute_risk_policy(services, [LOG4SHELL], RiskPolicy())[0]
    assert decision.priority is not None and decision.priority.value == "P3"
    assert decision.recommended_actions.count(PolicyAction.ESCALATE_TO_OWNER) == 1
    assert len(services.pending.list_open(LOG4SHELL)) == 1
