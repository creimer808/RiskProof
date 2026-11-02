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
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from riskproof.engine.investigation import MAX_BATCH_FINDINGS, investigate
from riskproof.errors import InvalidInputError, NotFoundError
from riskproof.ingest.nessus import parse_nessus_file
from riskproof.ingest.tenable import finding_from_tenable_vuln
from riskproof.models.findings import Finding, Severity
from riskproof.models.tags import validate_tag_filter
from riskproof.providers.base import ProviderError
from riskproof.providers.tenable import TenableClient
from riskproof.services import Services
from riskproof.storage.repositories import utcnow

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
    stats = services.findings.save_many(kept)
    changes = {
        "new": stats.new,
        "updated": stats.updated,
        "reopened": stats.reopened,
        "resolved": stats.resolved,
    }
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
        "changes": changes,
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
        details={
            "provenance": provenance,
            "filters": summary["filters_applied"],
            "changes": changes,
        },
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
    tags: dict[str, list[str]] | None = None,
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
    if tags:
        try:
            cleaned = validate_tag_filter(tags)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc
        # Tenable's documented form: "tag.<Category>": [values]. Values in one
        # category are OR-ed; separate categories are AND-ed.
        for category, values in cleaned.items():
            filters[f"tag.{category}"] = values
    return filters


def _tag_filter(filters: dict[str, Any]) -> dict[str, list[str]]:
    return {k[4:]: v for k, v in filters.items() if k.startswith("tag.")}


def _record_filter_tags(
    findings: list[Finding], tag_filter: dict[str, list[str]], warnings: list[str]
) -> dict[str, Any]:
    """Record the tags an export was filtered on for findings whose records lack tags.

    Tenable returned each of these assets only because it carries the filtered
    tags, so a category with a single value is known. A category with several values
    is not (the asset has one of them, unspecified), so it is left unrecorded.
    """
    known = {c: v[0] for c, v in tag_filter.items() if len(v) == 1}
    ambiguous = [c for c, v in tag_filter.items() if len(v) > 1]
    from_export = from_filter = 0
    for i, f in enumerate(findings):
        if f.asset.tags:
            from_export += 1
        elif known:
            asset = f.asset.model_copy(update={"tags": {c: [v] for c, v in known.items()}})
            raw = {**(f.raw or {}), "tags_source": "import_filter"}
            findings[i] = f.model_copy(update={"asset": asset, "raw": raw})
            from_filter += 1
    if from_filter:
        warnings.append(
            f"Tenable's export records did not include asset tags, so the tags you filtered on "
            f"were recorded for {from_filter} finding(s). Tags can drift if assets are re-tagged: "
            "a later import that does include tags replaces them."
        )
    if ambiguous and findings:
        names = ", ".join(sorted(ambiguous))
        warnings.append(
            f"Tag filter lists several values for {names}; the export does not say which one "
            "each asset has, so that category was not recorded on findings."
        )
    return {
        "filter": tag_filter,
        "recorded_from_export": from_export,
        "recorded_from_filter": from_filter,
    }


def reconcile_scope(
    filters: dict[str, Any],
    *,
    truncated: bool,
    skipped_records: int,
    imported: int,
    only_with_cve: bool,
) -> tuple[list[str] | None, str | None]:
    """Severities an export may reconcile, or the reason it may not reconcile at all.

    Absence is only meaningful when the export was a complete listing of its
    scope: not truncated, no dropped records, not empty, not narrowed by time,
    network range, CVE presence, or finding state.
    """
    if truncated:
        return None, "export was truncated at the limit; absence proves nothing"
    if skipped_records:
        return None, f"{skipped_records} export record(s) were skipped; the listing is incomplete"
    if imported == 0:
        return None, "export contained no findings (possible auth or filter problem)"
    if only_with_cve:
        return None, "only_with_cve narrows the import; not a complete listing"
    if "since" in filters:
        return None, "since_days narrows the import; not a complete listing"
    if "cidr_range" in filters:
        return None, "cidr_range narrows the import; not a complete listing"
    if _tag_filter(filters):
        return None, "a tag filter narrows the import; not a complete listing"
    states = set(filters.get("state", []))
    if not {"open", "reopened"} <= states:
        return None, "state filter must include both open and reopened to list every live finding"
    return list(filters["severity"]), None


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
    reconcile: bool = False,
    tags: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    settings = services.settings
    if not 1 <= limit <= MAX_TENABLE_FINDINGS:
        raise InvalidInputError(f"limit must be between 1 and {MAX_TENABLE_FINDINGS}.")
    filters = build_tenable_filters(severity, state, since_days, cidr_range, tags)
    tag_filter = _tag_filter(filters)
    client = client or TenableClient.from_env(settings)

    started = time.monotonic()
    import_started = utcnow()
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
    skipped_records = sum(w.startswith("Skipped export record") for w in warnings)
    tag_summary = None
    if tag_filter:
        tag_summary = _record_filter_tags(findings, tag_filter, warnings)
        if not export.vulns:
            warnings.append(
                f"No findings matched the tag filter {tag_filter}. Category and value must match "
                "Tenable exactly; list the tenant's tags with list_tenable_tags."
            )
    elif any(f.asset.tags for f in findings):
        tag_summary = {
            "filter": {},
            "recorded_from_export": sum(bool(f.asset.tags) for f in findings),
            "recorded_from_filter": 0,
        }
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
    summary = await store_and_summarize(
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
    summary["reconciliation"] = _reconcile_tenable(
        services,
        filters,
        import_started=import_started,
        truncated=export.truncated,
        skipped_records=skipped_records,
        imported=summary["totals"]["imported"],
        only_with_cve=only_with_cve,
        apply=reconcile,
    )
    if tag_summary is not None:
        summary["tags"] = tag_summary
    return summary


async def list_tenable_tags(
    services: Services, client: TenableClient | None = None
) -> dict[str, Any]:
    """The tenant's tag categories and values, for building an ``import_tenable`` tag filter."""
    client = client or TenableClient.from_env(services.settings)
    result = await client.list_tag_values()
    return {
        "categories": result.categories,
        "total_values": result.total_values,
        "truncated": result.truncated,
        "usage": (
            "Pass these exactly (spelling and case as Tenable has them) as "
            'import_tenable(tags={"<category>": ["<value>", ...]}). Values within a category '
            "are OR-ed; separate categories are AND-ed."
        ),
    }


def _reconcile_tenable(
    services: Services,
    filters: dict[str, Any],
    *,
    import_started: datetime,
    truncated: bool,
    skipped_records: int,
    imported: int,
    only_with_cve: bool,
    apply: bool,
) -> dict[str, Any]:
    """Preview (or, with ``apply``, record) findings missing from a complete export."""
    severities, reason = reconcile_scope(
        filters,
        truncated=truncated,
        skipped_records=skipped_records,
        imported=imported,
        only_with_cve=only_with_cve,
    )
    if severities is None:
        return {
            "applied": False,
            "would_mark_not_seen": 0,
            "in_scope_open": 0,
            "skipped_reason": reason,
            "sample_ids": [],
        }
    result = services.findings.reconcile_unseen(
        source="tenable",
        severities=severities,
        seen_before=import_started,
        apply=apply,
        max_fraction=services.settings.reconcile_max_missing_fraction,
    )
    if result.applied:
        services.audit.append(
            actor=services.settings.audit_actor,
            action="reconcile_not_seen",
            subject=services.settings.tenable_base_url,
            outcome="ok",
            rationale="Findings absent from a complete, in-scope Tenable export marked not_seen.",
            details={
                "count": result.candidates,
                "sample_ids": result.sample_ids,
                "severities": severities,
            },
        )
    return {
        "applied": result.applied,
        "would_mark_not_seen": result.candidates,
        "in_scope_open": result.in_scope_open,
        "skipped_reason": result.skipped_reason,
        "sample_ids": result.sample_ids,
    }


async def investigate_pending(
    services: Services,
    limit: int | None = None,
    batch_size: int = MAX_BATCH_FINDINGS,
    progress: Callable[[int, int], None] | None = None,
    refresh_greynoise: bool = False,
) -> dict[str, int]:
    """Investigate open findings that have no record yet, best candidates first.

    Candidates are ranked like an import's triage list (KEV-listed first when the
    live catalog is reachable, then severity, VPR and CVSS). Work is done in
    batches, each saved as it completes, so an interrupted or failed run keeps
    everything finished and the next run resumes with what is still pending.
    ``progress(done, planned)`` is called after each batch. With
    ``refresh_greynoise`` it also re-investigates findings whose stored intel has no
    live GreyNoise reading (e.g. investigated before a key was configured).
    """
    pending_ids = services.findings.uninvestigated_ids()
    if refresh_greynoise:
        known = set(pending_ids)
        open_ids = set(services.findings.open_ids())
        pending_ids += [
            fid
            for fid in services.investigations.ids_without_greynoise()
            if fid not in known and fid in open_ids
        ]
    findings = [services.findings.get(fid) for fid in pending_ids]
    kev = await _live_kev_cves(services, [])
    findings.sort(key=lambda f: _rank_key(f, kev), reverse=True)
    planned = findings[:limit] if limit is not None else findings
    size = max(1, min(batch_size, MAX_BATCH_FINDINGS))
    done = batches = 0
    for start in range(0, len(planned), size):
        batch = planned[start : start + size]
        await investigate(services, finding_ids=[f.finding_id for f in batch])
        done += len(batch)
        batches += 1
        if progress is not None:
            progress(done, len(planned))
    return {
        "investigated": done,
        "remaining": len(pending_ids) - done,
        "batches": batches,
        "pending_before": len(pending_ids),
    }
