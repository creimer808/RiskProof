"""Compact tool output, batch loading, and the per-finding audit trail."""

from __future__ import annotations

import json

import pytest

from riskproof.engine import investigation as inv
from riskproof.errors import InvalidInputError, NotFoundError
from riskproof.models.policy import RiskPolicy

LOG4SHELL = "prod-web-01.demo.local-155999-8080tcp"
ZEROLOGON = "corp-db-02.demo.local-121080-445tcp"


async def test_each_record_carries_only_its_own_intel(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    batch_cves = {c for r in reports for c in r.finding.cve_ids}
    assert len(batch_cves) > 1
    for report in reports:
        intel = report.record.intel
        assert intel is not None
        assert set(intel.cve_ids) == set(report.finding.cve_ids)
        assert set(intel.epss) <= set(report.finding.cve_ids)
        assert {s.cve for s in intel.kev_status} == set(report.finding.cve_ids)
    # Persisted records are trimmed too.
    stored = services.investigations.get(LOG4SHELL).intel
    assert stored is not None and stored.cve_ids == ["CVE-2021-44228"]


async def test_summary_keeps_reporting_facts_and_drops_bulk(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    summary = inv.summarize_reports(reports)
    full = [r.model_dump(mode="json") for r in reports]
    assert len(json.dumps(summary)) < len(json.dumps(full)) / 2

    log4shell = next(s for s in summary["investigations"] if s["finding_id"] == LOG4SHELL)
    assert log4shell["priority"] == "P1"
    assert log4shell["priority_rationale"]
    assert log4shell["dimensions"]["exploitation_likelihood"] == "observed_in_the_wild"
    assert log4shell["asset"]["internet_facing"] is True
    assert any("EPSS" in e["statement"] for e in log4shell["evidence"])
    assert {"description", "plugin_output", "raw", "intel"}.isdisjoint(log4shell)

    # Provenance and the SAMPLE notice appear once for the batch, not per finding.
    assert summary["intel_provenance"] == [
        {"epss_source": "sample-fixture", "kev_source": "sample-fixture", "degraded": True}
    ]
    assert len(summary["intel_notices"]) == len(set(summary["intel_notices"]))
    assert any("SAMPLE" in n for n in summary["intel_notices"])
    # EPSS/KEV caveats are stated once for the response, not dropped.
    assert "not a claim about this specific system" in summary["intel_caveats"]["epss"]
    assert "not that this asset was compromised" in summary["intel_caveats"]["kev_listed"]
    statements = " ".join(e["statement"] for e in log4shell["evidence"])
    assert "not a claim about this specific system" not in statements
    assert "FIRST EPSS for CVE-2021-44228: 0.942" in statements
    # The stored evidence itself keeps the caveat inline.
    stored = services.investigations.get(LOG4SHELL).evidence
    assert any("not a claim about this specific system" in e.statement for e in stored)


async def test_batch_loader_validates_and_reports_all_missing(services):
    await inv.investigate(services, fixture="findings_sample.json")
    assert len(inv.recompute_assessments(services, [LOG4SHELL, LOG4SHELL, ZEROLOGON])) == 2
    with pytest.raises(InvalidInputError):
        inv.recompute_assessments(services, [])
    with pytest.raises(InvalidInputError):
        inv.recompute_assessments(services, [f"id-{i}" for i in range(26)], max_findings=25)
    with pytest.raises(NotFoundError, match=r"'a'.*'b'"):
        inv.recompute_assessments(services, [LOG4SHELL, "a", "b"])


async def test_investigation_is_audited_per_finding(services):
    await inv.investigate(services, fixture="findings_sample.json")
    entry = services.audit.recent(finding_id=LOG4SHELL)[0]
    assert entry["action"] == "investigate_finding"
    assert entry["outcome"] == "P1"
    assert entry["details"]["reinvestigation"] is False
    await inv.investigate(services, finding_id=LOG4SHELL)
    assert services.audit.recent(finding_id=LOG4SHELL)[0]["details"]["reinvestigation"] is True


async def test_audit_filter_includes_validation_and_excludes_other_findings(services):
    await inv.investigate(services, fixture="findings_sample.json")
    await inv.validate_exposure(
        services, host="127.0.0.1", port=9, method="tcp_connect", finding_id=LOG4SHELL
    )
    inv.execute_risk_policy(services, [ZEROLOGON], RiskPolicy())

    trail = services.audit.recent(finding_id=LOG4SHELL)
    actions = [e["action"] for e in trail]
    assert actions[0] == "validate_exposure:tcp_connect"  # subject is host:port
    assert "investigate_finding" in actions
    assert all(
        e["subject"] == LOG4SHELL or (e["details"] or {}).get("finding_id") == LOG4SHELL
        for e in trail
    )
    assert not any(a.startswith("policy:") for a in actions)  # those were ZEROLOGON's
