"""Parse ``.nessus`` v2 XML reports into normalized findings.

Scanner output is UNTRUSTED input: parsing uses defusedxml (no entity
expansion / XXE), every value is length-limited and validated by Pydantic, and
the raw host/report attributes are preserved under ``Finding.raw`` for
traceability only — they never drive behavior.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import parse as defused_parse

from riskproof.errors import InvalidInputError
from riskproof.ingest.common import slugify as _slug
from riskproof.models.findings import (
    NESSUS_SEVERITY_MAP,
    Asset,
    CVSSV3Observation,
    Finding,
    Severity,
    VPRObservation,
)

_NESSUS_DATE = "%a %b %d %H:%M:%S %Y"


def _text(element: Any, tag: str) -> str | None:
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip()[:8000] or None


def _parse_scanned_at(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), _NESSUS_DATE)
    except ValueError:
        return None


def _build_asset(host_name: str, tags: dict[str, str]) -> Asset:
    ip = tags.get("host-ip")
    hostname = (
        tags.get("netbios-name")
        or tags.get("host-fqdn")
        or (host_name if host_name != ip else None)
    )
    return Asset(
        asset_id=_slug(hostname or ip or host_name),
        hostname=hostname,
        ip_address=ip,
        operating_system=tags.get("operating-system"),
        labels={k: v for k, v in tags.items() if k.startswith("CPE")},
    )


def _parse_report_item(item: Any, host_name: str, tags: dict[str, str]) -> Finding:
    plugin_id = item.get("pluginID") or "unknown"
    port_raw = item.get("port") or "0"
    try:
        port = int(port_raw)
    except ValueError:
        port = 0
    protocol = (item.get("protocol") or "tcp").lower()
    if protocol not in ("tcp", "udp"):
        protocol = "tcp"
    severity = NESSUS_SEVERITY_MAP.get(int(item.get("severity") or 0), Severity.UNKNOWN)

    cve_ids = [(child.text or "").strip() for child in item.findall("cve") if child.text]

    cvss_v3 = None
    base_score = _text(item, "cvss3_base_score")
    if base_score:
        try:
            cvss_v3 = CVSSV3Observation(
                base_score=float(base_score),
                vector=_text(item, "cvss3_vector"),
                source="nessus-plugin",
            )
        except ValueError:
            cvss_v3 = None

    vpr = None
    vpr_score = _text(item, "vpr_score")
    if vpr_score:
        try:
            vpr = VPRObservation(score=float(vpr_score), source="nessus-plugin")
        except ValueError:
            vpr = None

    finding_id = _slug(f"{host_name}-{plugin_id}-{port}{protocol}")
    asset = _build_asset(host_name, tags)
    raw = {
        "report_host": host_name,
        "pluginName": item.get("pluginName"),
        "pluginFamily": item.get("pluginFamily"),
        "svc_name": item.get("svc_name"),
    }
    return Finding(
        finding_id=finding_id,
        source="nessus",
        plugin_id=plugin_id,
        name=(item.get("pluginName") or "Unnamed finding")[:512],
        description=_text(item, "description"),
        severity=severity,
        cve_ids=cve_ids,
        cvss_v3=cvss_v3,
        vpr=vpr,
        asset=asset,
        port=port or None,
        protocol=protocol if port else None,
        service=item.get("svc_name") or None,
        plugin_output=_text(item, "plugin_output"),
        solution=_text(item, "solution"),
        scanned_at=_parse_scanned_at(tags.get("HOST_END")),
        raw=raw,
    )


class NessusImportResult:
    """Result of parsing one .nessus file."""

    def __init__(
        self,
        report_name: str,
        findings: list[Finding],
        host_count: int,
        warnings: list[str],
    ) -> None:
        self.report_name = report_name
        self.findings = findings
        self.host_count = host_count
        self.warnings = warnings

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"NessusImportResult(report={self.report_name!r}, hosts={self.host_count}, "
            f"findings={len(self.findings)}, warnings={len(self.warnings)})"
        )


def parse_nessus_file(path: str | Path) -> NessusImportResult:
    """Parse a .nessus file. Raises InvalidInputError for unreadable/invalid XML."""
    path = Path(path)
    if not path.is_file():
        raise InvalidInputError(f"Nessus file not found: {path}")
    try:
        tree = defused_parse(str(path))
    except Exception as exc:  # defusedxml raises several types
        raise InvalidInputError(f"Cannot parse .nessus XML: {exc}") from exc

    root = tree.getroot()
    if not root.tag.startswith("NessusClientData"):
        raise InvalidInputError(f"Not a .nessus v2 document (root <{root.tag}>)")

    warnings: list[str] = []
    findings: list[Finding] = []
    host_count = 0
    report_name = "unnamed-report"

    for report in root.iter("Report"):
        report_name = report.get("name") or report_name
        for host in report.iter("ReportHost"):
            host_count += 1
            host_name = host.get("name") or f"host-{host_count}"
            tags: dict[str, str] = {}
            props = host.find("HostProperties")
            if props is not None:
                for tag in props.findall("tag"):
                    name = tag.get("name")
                    if name and tag.text:
                        tags[name] = tag.text.strip()[:512]
            for item in host.iter("ReportItem"):
                try:
                    findings.append(_parse_report_item(item, host_name, tags))
                except Exception as exc:  # one bad item must not sink the import
                    warnings.append(f"Skipped ReportItem on {host_name}: {exc}")

    return NessusImportResult(report_name, findings, host_count, warnings)
