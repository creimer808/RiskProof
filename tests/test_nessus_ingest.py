"""Tests for .nessus XML ingestion (untrusted input handling)."""

from __future__ import annotations

from pathlib import Path

import pytest

from riskproof.errors import InvalidInputError
from riskproof.ingest.nessus import parse_nessus_file
from riskproof.models.findings import Severity

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_scan.nessus"


@pytest.fixture(scope="module")
def result():
    return parse_nessus_file(FIXTURE)


def test_parses_hosts_and_findings(result):
    assert result.host_count == 3
    assert len(result.findings) == 5
    assert result.warnings == []


def test_finding_ids_stable(result):
    ids = {f.finding_id for f in result.findings}
    assert "prod-web-01.demo.local-155999-8080tcp" in ids
    assert "dev-jump-03.demo.local-10180-22tcp" in ids


def test_severity_mapping(result):
    by_id = {f.finding_id: f for f in result.findings}
    assert by_id["prod-web-01.demo.local-155999-8080tcp"].severity == Severity.CRITICAL
    assert by_id["corp-db-02.demo.local-215400-22tcp"].severity == Severity.MEDIUM
    assert by_id["dev-jump-03.demo.local-10180-22tcp"].severity == Severity.INFO


def test_cve_extraction_and_cvss(result):
    by_id = {f.finding_id: f for f in result.findings}
    log4shell = by_id["prod-web-01.demo.local-155999-8080tcp"]
    assert log4shell.cve_ids == ["CVE-2021-44228"]
    assert log4shell.cvss_v3 is not None
    assert log4shell.cvss_v3.base_score == 10.0
    assert log4shell.cvss_v3.vector.startswith("CVSS:3.1/AV:N")
    assert log4shell.vpr is not None and log4shell.vpr.score == 10.0


def test_host_tags_map_to_asset(result):
    by_id = {f.finding_id: f for f in result.findings}
    web = by_id["prod-web-01.demo.local-155999-8080tcp"]
    assert web.asset.hostname == "prod-web-01"
    assert web.asset.ip_address == "10.20.0.11"
    assert web.asset.operating_system == "Ubuntu 22.04 LTS"
    assert web.scanned_at is not None


def test_source_marked_nessus(result):
    assert all(f.source == "nessus" for f in result.findings)


def test_missing_file_raises():
    with pytest.raises(InvalidInputError):
        parse_nessus_file("/nonexistent/path.nessus")


def test_non_nessus_xml_raises(tmp_path: Path):
    bad = tmp_path / "bad.nessus"
    bad.write_text("<NotNessus><data/></NotNessus>", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        parse_nessus_file(bad)


def test_billion_laughs_style_xml_is_refused(tmp_path: Path):
    """defusedxml must refuse entity-expansion attacks in scanner files."""
    evil = tmp_path / "evil.nessus"
    evil.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<NessusClientData_v2><Report>&lol2;</Report></NessusClientData_v2>""",
        encoding="utf-8",
    )
    # defusedxml raises DefinitionsError/EntitiesForbidden (a subclass of Exception);
    # we only require that it does NOT parse happily.
    with pytest.raises(Exception):  # noqa: B017 - defusedxml raises its own types
        parse_nessus_file(evil)
