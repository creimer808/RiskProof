"""Normalize Tenable Vulnerability Management (Tenable.io) vuln-export records.

Export records come from a remote API and are UNTRUSTED: every field is read
defensively, length-limited by the :class:`Finding` model, and the original
record is reduced to a small ``raw`` snapshot kept for traceability only.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from riskproof.ingest.common import slugify
from riskproof.models.findings import (
    CVE_PATTERN,
    NESSUS_SEVERITY_MAP,
    Asset,
    CVSSV3Observation,
    Finding,
    Severity,
    VPRObservation,
)

_SEVERITY_NAMES = {s.value: s for s in Severity}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any, limit: int = 8000) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()[:limit]
    return text or None


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            text = _str(item)
            if text:
                return text
        return None
    return _str(value)


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_time(value: Any) -> datetime | None:
    text = _str(value, 64)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _severity(record: dict[str, Any]) -> Severity:
    severity_id = record.get("severity_id")
    if isinstance(severity_id, int) and severity_id in NESSUS_SEVERITY_MAP:
        return NESSUS_SEVERITY_MAP[severity_id]
    name = (_str(record.get("severity"), 16) or "").lower()
    return _SEVERITY_NAMES.get(name, Severity.UNKNOWN)


def finding_from_tenable_vuln(record: dict[str, Any]) -> Finding:
    """Convert one vuln-export record to a normalized :class:`Finding`.

    Raises ``ValueError``/``pydantic.ValidationError`` for records that cannot
    be normalized; the caller skips those with a warning.
    """
    asset_raw = _dict(record.get("asset"))
    plugin = _dict(record.get("plugin"))
    port_raw = _dict(record.get("port"))
    scan = _dict(record.get("scan"))

    plugin_id = _str(plugin.get("id"), 64)
    asset_uuid = _str(asset_raw.get("uuid"), 64)
    hostname = _str(asset_raw.get("hostname"), 256) or _first(asset_raw.get("fqdn"))
    ip = _first(asset_raw.get("ipv4")) or _first(asset_raw.get("ipv6"))
    asset_key = asset_uuid or hostname or ip
    if not plugin_id or not asset_key:
        raise ValueError("record has no plugin id or asset identity")

    os_names = asset_raw.get("operating_system")
    operating_system = (
        ", ".join(str(o) for o in os_names)[:256]
        if isinstance(os_names, list) and os_names
        else _str(os_names, 256)
    )
    labels = {"tenable_asset_uuid": asset_uuid} if asset_uuid else {}
    fqdn = _first(asset_raw.get("fqdn"))
    if fqdn and fqdn.lower() != (hostname or "").lower():
        labels["fqdn"] = fqdn[:256]
    asset = Asset(
        asset_id=slugify(hostname or ip or asset_key),
        hostname=hostname,
        ip_address=ip,
        operating_system=operating_system,
        labels=labels,
    )

    port = port_raw.get("port")
    port = port if isinstance(port, int) and 0 < port <= 65535 else None
    protocol = (_str(port_raw.get("protocol"), 8) or "").lower()
    protocol = protocol if port and protocol in ("tcp", "udp") else None

    raw_cves = plugin.get("cve") if isinstance(plugin.get("cve"), list) else []
    cves = [c.strip() for c in raw_cves if isinstance(c, str) and CVE_PATTERN.match(c.strip())]
    dropped = [str(c)[:40] for c in raw_cves if str(c).strip() not in cves][:10]

    cvss_v3 = None
    base_score = _float(plugin.get("cvss3_base_score"))
    if base_score is not None and 0.0 <= base_score <= 10.0:
        vector = plugin.get("cvss3_vector")
        vector = vector.get("raw") if isinstance(vector, dict) else vector
        cvss_v3 = CVSSV3Observation(
            base_score=base_score, vector=_str(vector, 200), source="tenable-plugin"
        )

    vpr = None
    vpr_score = _float(_dict(plugin.get("vpr")).get("score"))
    if vpr_score is not None and 0.0 <= vpr_score <= 10.0:
        vpr = VPRObservation(score=vpr_score, source="tenable-vpr")

    raw: dict[str, Any] = {
        "state": _str(record.get("state"), 32),
        "first_found": _str(record.get("first_found"), 64),
        "last_found": _str(record.get("last_found"), 64),
        "plugin_family": _str(plugin.get("family"), 128),
    }
    for flag in ("has_patch", "exploit_available", "exploited_by_malware"):
        if isinstance(plugin.get(flag), bool):
            raw[flag] = plugin[flag]
    if dropped:
        raw["dropped_invalid_cves"] = dropped

    return Finding(
        finding_id=slugify(f"tenable-{asset_key}-{plugin_id}-{port or 0}{protocol or ''}"),
        source="tenable",
        plugin_id=plugin_id,
        name=(_str(plugin.get("name"), 512) or "Unnamed finding"),
        description=_str(plugin.get("description")) or _str(plugin.get("synopsis")),
        severity=_severity(record),
        cve_ids=cves,
        cvss_v3=cvss_v3,
        vpr=vpr,
        asset=asset,
        port=port,
        protocol=protocol,
        service=_str(port_raw.get("service"), 64),
        plugin_output=_str(record.get("output")),
        solution=_str(plugin.get("solution")),
        scan_id=_str(scan.get("uuid"), 256),
        scanned_at=_parse_time(record.get("last_found")),
        raw={k: v for k, v in raw.items() if v is not None},
    )
