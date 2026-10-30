"""Tests for normalized models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from riskproof.models.findings import (
    NESSUS_SEVERITY_MAP,
    Asset,
    CVSSV3Observation,
    Finding,
    Severity,
    normalize_cve,
)


def test_normalize_cve_uppercases_and_validates():
    assert normalize_cve(" cve-2021-44228 ") == "CVE-2021-44228"


@pytest.mark.parametrize("bad", ["CVE-21-1234", "not-a-cve", "CVE-2021-", "XSS-2021-1234"])
def test_normalize_cve_rejects_garbage(bad: str):
    with pytest.raises(ValueError):
        normalize_cve(bad)


def test_nessus_severity_map_complete():
    assert NESSUS_SEVERITY_MAP[4] == Severity.CRITICAL
    assert NESSUS_SEVERITY_MAP[0] == Severity.INFO


def test_finding_normalizes_and_dedupes_cves():
    finding = Finding(
        finding_id="f-1",
        name="test",
        cve_ids=["cve-2021-44228", "CVE-2021-44228"],
        asset=Asset(asset_id="a-1"),
    )
    assert finding.cve_ids == ["CVE-2021-44228"]
    assert finding.severity == Severity.UNKNOWN


def test_finding_rejects_control_chars_in_ids():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="bad\nid",
            name="test",
            asset=Asset(asset_id="a-1"),
        )


def test_cvss_score_bounds():
    with pytest.raises(ValidationError):
        CVSSV3Observation(base_score=11.0)


def test_service_port_bounds():
    from riskproof.models.findings import ServiceObservation

    with pytest.raises(ValidationError):
        ServiceObservation(port=70000)
