"""Tests for the import_nessus engine: path confinement, filtering, storage."""

from __future__ import annotations

import os

import pytest

from riskproof.engine import importer
from riskproof.engine import investigation as inv
from riskproof.errors import InvalidInputError, NotFoundError


async def test_import_stores_findings_and_summarizes(services):
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    assert summary["totals"]["parsed"] == 5
    assert summary["totals"]["imported"] == 5
    assert services.findings.count() == 5
    prov = summary["provenance"]
    assert prov["source"] == "nessus" and prov["file"] == "sample_scan.nessus"
    assert len(prov["sha256"]) == 64
    top = summary["candidates"][0]
    assert top["severity"] == "critical"  # Log4Shell outranks everything
    assert "not yet enriched" in summary["next_step"].lower()
    assert any(e["action"] == "import_nessus" for e in services.audit.recent())


async def test_min_severity_and_cve_filters(services):
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="high")
    assert set(summary["imported_by_severity"]) <= {"critical", "high"}
    assert summary["totals"]["filtered_out"] > 0
    assert services.findings.count() == summary["totals"]["imported"]

    summary = await importer.import_nessus(
        services, "sample_scan.nessus", min_severity="info", only_with_cve=True
    )
    assert all(c["cve_count"] > 0 for c in summary["candidates"])


async def test_reimport_is_idempotent(services):
    await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    assert services.findings.count() == 5


async def test_imported_findings_can_be_investigated_in_batch(services):
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="medium")
    ids = [c["finding_id"] for c in summary["candidates"]]
    reports = await inv.investigate(services, finding_ids=ids, intel_source="fixture")
    assert {r.finding_id for r in reports} == set(ids)
    assert all(r.finding.source == "nessus" for r in reports)


@pytest.mark.parametrize(
    "name",
    [
        "../sample_scan.nessus",
        "/etc/passwd",
        "sub/sample_scan.nessus",
        "..\\sample_scan.nessus",
        ".hidden.nessus",
        "sample_scan.xml",
        "sample_scan.nessus\x00.txt",
        "sample_scan.nessus\n",
        "",
    ],
)
async def test_path_traversal_and_bad_names_refused(services, name):
    with pytest.raises(InvalidInputError):
        await importer.import_nessus(services, name)


async def test_missing_file_is_not_found(services):
    with pytest.raises(NotFoundError):
        await importer.import_nessus(services, "nope.nessus")


async def test_symlink_escaping_import_dir_refused(services, tmp_path):
    outside = tmp_path / "outside.nessus"
    outside.write_text("<NessusClientData_v2/>")
    link = services.settings.effective_import_dir / "link.nessus"
    os.symlink(outside, link)
    with pytest.raises(InvalidInputError):
        await importer.import_nessus(services, "link.nessus")


async def test_oversize_file_refused(services):
    services.settings.max_import_bytes = 100
    with pytest.raises(InvalidInputError, match="limit"):
        await importer.import_nessus(services, "sample_scan.nessus")


async def test_invalid_min_severity_refused(services):
    with pytest.raises(InvalidInputError):
        await importer.import_nessus(services, "sample_scan.nessus", min_severity="urgent")


async def test_finding_ids_batch_rules(services):
    with pytest.raises(InvalidInputError):
        await inv.investigate(services, finding_ids=[])
    with pytest.raises(InvalidInputError):
        await inv.investigate(services, finding_ids=[f"x{i}" for i in range(26)])
    with pytest.raises(InvalidInputError):  # exactly one selector
        await inv.investigate(services, finding_id="a", finding_ids=["b"])
    with pytest.raises(NotFoundError):
        await inv.investigate(services, finding_ids=["never-imported"])


async def test_offline_import_ranks_without_kev_and_says_so(services):
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    assert services.settings.offline is True
    assert summary["totals"]["with_kev_cve"] is None
    assert all(c["kev_cve_count"] is None for c in summary["candidates"])
    assert any("Offline mode" in w for w in summary["warnings"])
    assert "no exploitation intel" in summary["candidate_ranking"]


async def test_live_kev_signal_outranks_severity(services, monkeypatch):
    from riskproof.providers.kev import KEVProvider

    # sample_scan: Log4Shell is critical (CVE-2021-44228); regreSSHion is high (CVE-2024-6387).
    catalog = KEVProvider.parse(
        {
            "catalogVersion": "test",
            "dateReleased": "2026-10-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-6387",
                    "vendorProject": "OpenBSD",
                    "product": "OpenSSH",
                    "vulnerabilityName": "regreSSHion",
                    "dateAdded": "2026-10-01",
                    "dueDate": "2026-10-22",
                    "requiredAction": "Patch",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                }
            ],
        }
    )

    async def fake_catalog(*_a, **_k):
        return catalog

    monkeypatch.setattr(services.settings, "offline", False)
    monkeypatch.setattr(services.kev, "load_catalog", fake_catalog)
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    first = summary["candidates"][0]
    assert first["severity"] == "high" and first["kev_cve_count"] == 1  # KEV beats critical
    assert summary["totals"]["with_kev_cve"] == 1
    assert "KEV-listed CVE first" in summary["candidate_ranking"]


async def test_kev_outage_degrades_without_fixture_substitution(services, monkeypatch):
    from riskproof.providers.base import ProviderError

    async def broken(*_a, **_k):
        raise ProviderError("feed down")

    monkeypatch.setattr(services.settings, "offline", False)
    monkeypatch.setattr(services.kev, "load_catalog", broken)
    summary = await importer.import_nessus(services, "sample_scan.nessus", min_severity="info")
    assert summary["totals"]["with_kev_cve"] is None
    assert any("KEV catalog unavailable" in w for w in summary["warnings"])
