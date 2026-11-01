"""Bulk import of scanner findings, with a triage summary for the agent.

Imports only *store and summarize* findings; they never enrich or assess. The
agent picks candidates from the summary and calls ``investigate_finding``,
which is where EPSS/KEV intel and the risk assessment happen.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

from riskproof.errors import InvalidInputError, NotFoundError
from riskproof.ingest.nessus import parse_nessus_file
from riskproof.ingest.tenable import finding_from_tenable_vuln
from riskproof.models.findings import Finding, Severity
from riskproof.providers.base import ProviderError
from riskproof.providers.tenable import TenableClient
from riskproof.services import Services

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
    Severity.UNKNOWN: 0,
}
IMPORTABLE_SEVERITIES = ("critical", "high", "medium", "low", "info")
TENABLE_STATES = ("open", "reopened", "fixed")
MAX_TOP_N = 100
MAX_WARNINGS = 20
MAX_TENABLE_FINDINGS = 50_000
_NESSUS_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.()+-]{0,200}\.nessus$")


def resolve_nessus_path(import_dir: Path, name: str, max_bytes: int) -> Path:
    """Map a bare file name to a file inside ``import_dir`` — nothing else.

    The agent controls only ``name``. Directory separators, dot-prefixes, other
    extensions, and symlinks that leave ``import_dir`` are all refused.
    """
    if not _NESSUS_NAME_RE.fullmatch(name) or ".." in name:
        raise InvalidInputError(
            "`file` must be a bare file name ending in .nessus (no directories), "
            "located in the server's import directory."
        )
    root = import_dir.expanduser().resolve()
    candidate = (root / name).resolve()
    if candidate.parent != root:
        raise InvalidInputError(
            "`file` must resolve to a file directly inside the import directory."
        )
    if not candidate.is_file():
        raise NotFoundError(
            f"No file {name!r} in the import directory {str(root)!r}. A human operator can place "
            "it there or set RISKPROOF_IMPORT_DIR."
        )
    size = candidate.stat().st_size
    if size > max_bytes:
        raise InvalidInputError(
            f"{name!r} is {size:,} bytes; the limit is {max_bytes:,} (RISKPROOF_MAX_IMPORT_BYTES)."
        )
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _clamp_top_n(top_n: int) -> int:
    return max(1, min(int(top_n), MAX_TOP_N))


def _row(f: Finding, kev: set[str] | None) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "name": f.name,
        "severity": f.severity.value,
        "host": f.asset.hostname or f.asset.ip_address or f.asset.asset_id,
        "ip": f.asset.ip_address,
        "port": f.port,
        "cve_count": len(f.cve_ids),
        "kev_cve_count": _kev_count(f, kev) if kev is not None else None,
        "vpr": f.vpr.score if f.vpr else None,
        "cvss_v3": f.cvss_v3.base_score if f.cvss_v3 else None,
    }


async def _live_kev_cves(services: Services, warnings: list[str]) -> set[str] | None:
    """CISA KEV catalog membership for ranking (one cached download; None if unavailable).

    Never substitutes SAMPLE fixtures: if the live catalog cannot be read, ranking
    simply proceeds without a KEV signal and says so.
    """
    if services.settings.offline:
        warnings.append("Offline mode: KEV signal not used for candidate ranking.")
        return None
    try:
        catalog = await services.kev.load_catalog()
    except ProviderError as exc:
        warnings.append(f"KEV catalog unavailable ({exc}); candidates ranked without KEV.")
        return None
    return set(catalog.entries)


def _kev_count(f: Finding, kev: set[str] | None) -> int:
    return sum(1 for c in f.cve_ids if c in kev) if kev else 0


def _rank_key(f: Finding, kev: set[str] | None) -> tuple:
    return (
        _kev_count(f, kev) > 0,
        SEVERITY_RANK[f.severity],
        f.vpr.score if f.vpr else -1.0,
        f.cvss_v3.base_score if f.cvss_v3 else -1.0,
        len(f.cve_ids) > 0,
    )


async def store_and_summarize(
    services: Services,
    findings: list[Finding],
    *,
    action: str,
    subject: str,
    provenance: dict[str, Any],
    min_severity: str,
    only_with_cve: bool,
    top_n: int,
    warnings: list[str],
) -> dict[str, Any]:
    """Filter, persist (one transaction), audit, and summarize imported findings."""
    if min_severity not in IMPORTABLE_SEVERITIES:
        raise InvalidInputError(f"min_severity must be one of {list(IMPORTABLE_SEVERITIES)}.")
    floor = SEVERITY_RANK[Severity(min_severity)]
    kept = [
        f
        for f in findings
        if SEVERITY_RANK[f.severity] >= floor and (f.cve_ids or not only_with_cve)
    ]
    services.findings.save_many(kept)
    kev = await _live_kev_cves(services, warnings)

    by_severity = Counter(f.severity.value for f in kept)
    crit_high = [f for f in kept if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    hosts = Counter(
        (f.asset.hostname or f.asset.ip_address or f.asset.asset_id, f.asset.ip_address)
        for f in crit_high
    )
    plugins: dict[tuple, set[str]] = {}
    for f in crit_high:
        key = (f.plugin_id, f.name, f.severity.value)
        plugins.setdefault(key, set()).add(f.asset.asset_id)

    candidates = sorted(kept, key=lambda f: _rank_key(f, kev), reverse=True)[: _clamp_top_n(top_n)]
    summary = {
        "provenance": provenance,
        "totals": {
            "parsed": len(findings),
            "imported": len(kept),
            "filtered_out": len(findings) - len(kept),
            "hosts_with_critical_or_high": len({f.asset.asset_id for f in crit_high}),
            "with_cves": sum(1 for f in kept if f.cve_ids),
            "with_kev_cve": sum(1 for f in kept if _kev_count(f, kev)) if kev is not None else None,
        },
        "filters_applied": {"min_severity": min_severity, "only_with_cve": only_with_cve},
        "imported_by_severity": dict(by_severity),
        "top_hosts_by_critical_high": [
            {"host": host, "ip": ip, "critical_high_findings": n}
            for (host, ip), n in hosts.most_common(10)
        ],
        "top_plugins_by_affected_hosts": [
            {"plugin_id": pid, "name": name, "severity": sev, "affected_hosts": len(hs)}
            for (pid, name, sev), hs in sorted(plugins.items(), key=lambda kv: -len(kv[1]))[:15]
        ],
        "candidates": [_row(f, kev) for f in candidates],
        "candidate_ranking": (
            "CISA KEV-listed CVE first (live catalog), then scanner severity, VPR, CVSS v3. "
            "KEV means the CVE is exploited somewhere, not that this asset was hit; a bundled "
            "patch finding is flagged if ANY of its CVEs is KEV-listed. EPSS is not used here."
            if kev is not None
            else "scanner severity, then VPR, then CVSS v3 (no exploitation intel available)"
        ),
        "warnings": warnings[:MAX_WARNINGS],
        "warnings_total": len(warnings),
        "next_step": (
            "Imported findings are stored but NOT yet enriched or assessed. Call "
            "investigate_finding(finding_ids=[...], up to 25 per call) on candidates to add "
            "EPSS/KEV intel and the risk assessment."
        ),
    }
    services.audit.append(
        actor=services.settings.audit_actor,
        action=action,
        subject=subject,
        outcome="ok",
        rationale=f"parsed={len(findings)} imported={len(kept)} source={provenance.get('source')}",
        details={"provenance": provenance, "filters": summary["filters_applied"]},
    )
    return summary


async def import_nessus(
    services: Services,
    file: str,
    min_severity: str = "low",
    only_with_cve: bool = False,
    top_n: int = 25,
) -> dict[str, Any]:
    settings = services.settings
    path = resolve_nessus_path(settings.effective_import_dir, file, settings.max_import_bytes)
    started = time.monotonic()
    # Parsing a large report is CPU/IO heavy: keep the server's event loop free.
    result, digest = await asyncio.gather(
        asyncio.to_thread(parse_nessus_file, path), asyncio.to_thread(_sha256, path)
    )
    provenance = {
        "source": "nessus",
        "file": file,
        "sha256": digest,
        "report_name": result.report_name,
        "hosts": result.host_count,
        "parse_seconds": round(time.monotonic() - started, 1),
    }
    return await store_and_summarize(
        services,
        result.findings,
        action="import_nessus",
        subject=file,
        provenance=provenance,
        min_severity=min_severity,
        only_with_cve=only_with_cve,
        top_n=top_n,
        warnings=result.warnings,
    )


def build_tenable_filters(
    severity: list[str] | None,
    state: list[str] | None,
    since_days: int | None,
    cidr_range: str | None,
) -> dict[str, Any]:
    severity = [s.lower() for s in (severity or ["critical", "high"])]
    state = [s.lower() for s in (state or ["open", "reopened"])]
    if not severity or any(s not in IMPORTABLE_SEVERITIES for s in severity):
        raise InvalidInputError(f"severity entries must be from {list(IMPORTABLE_SEVERITIES)}.")
    if not state or any(s not in TENABLE_STATES for s in state):
        raise InvalidInputError(f"state entries must be from {list(TENABLE_STATES)}.")
    filters: dict[str, Any] = {"severity": sorted(set(severity)), "state": sorted(set(state))}
    if since_days is not None:
        if not 1 <= since_days <= 3650:
            raise InvalidInputError("since_days must be between 1 and 3650.")
        filters["since"] = int(time.time()) - since_days * 86_400
    if cidr_range is not None:
        try:
            filters["cidr_range"] = str(ipaddress.ip_network(cidr_range.strip(), strict=False))
        except ValueError as exc:
            raise InvalidInputError(f"cidr_range is not a valid CIDR: {exc}") from exc
    return filters


async def import_tenable(
    services: Services,
    severity: list[str] | None = None,
    state: list[str] | None = None,
    since_days: int | None = None,
    cidr_range: str | None = None,
    limit: int = 5000,
    only_with_cve: bool = False,
    top_n: int = 25,
    client: TenableClient | None = None,
) -> dict[str, Any]:
    settings = services.settings
    if not 1 <= limit <= MAX_TENABLE_FINDINGS:
        raise InvalidInputError(f"limit must be between 1 and {MAX_TENABLE_FINDINGS}.")
    filters = build_tenable_filters(severity, state, since_days, cidr_range)
    client = client or TenableClient.from_env(settings)

    started = time.monotonic()
    export = await client.export_vulns(
        filters=filters,
        limit=limit,
        timeout_seconds=settings.tenable_export_timeout_seconds,
        poll_seconds=settings.tenable_poll_interval_seconds,
    )
    findings: list[Finding] = []
    warnings = list(export.warnings)
    for index, record in enumerate(export.vulns):
        try:
            findings.append(finding_from_tenable_vuln(record))
        except Exception as exc:  # one bad record must not sink the import
            warnings.append(f"Skipped export record {index}: {type(exc).__name__}: {exc}"[:300])
    if export.truncated:
        warnings.append(
            f"Import stopped at limit={limit}; more findings exist in Tenable for these filters."
        )
    provenance = {
        "source": "tenable",
        "base_url": settings.tenable_base_url,
        "export_uuid": export.export_uuid,
        "filters": filters,
        "chunks_downloaded": export.chunks_downloaded,
        "truncated": export.truncated,
        "export_seconds": round(time.monotonic() - started, 1),
    }
    return await store_and_summarize(
        services,
        findings,
        action="import_tenable",
        subject=settings.tenable_base_url,
        provenance=provenance,
        min_severity="info",
        only_with_cve=only_with_cve,
        top_n=top_n,
        warnings=warnings,
    )
