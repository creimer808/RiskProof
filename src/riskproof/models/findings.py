"""Normalized vulnerability findings and asset context.

These models are the canonical representation produced by every ingestion path
(.nessus files, normalized JSON fixtures, and later live Tenable sources).
Scanner input is untrusted: fields are validated, length-limited, and the raw
snapshot is preserved under :attr:`Finding.raw` for traceability only.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

MAX_TEXT_FIELDS = 8_000
MAX_BANNER = 2_000


def normalize_cve(value: str) -> str:
    """Normalize a CVE identifier to canonical uppercase form."""
    candidate = value.strip().upper()
    if not CVE_PATTERN.match(candidate):
        raise ValueError(f"Invalid CVE identifier: {value!r} (expected CVE-YYYY-NNNN+)")
    return candidate


def criticality_value(asset: Asset) -> str:
    """Robustly read asset criticality as a plain value.

    Accepts both the enum and its string value (``model_copy(update=...)``
    bypasses validation, so defensive normalization is warranted).
    """
    return AssetCriticality(asset.criticality).value


class Severity(StrEnum):
    """Scanner-reported severity, normalized across sources."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


#: Nessus numeric severity (ReportItem @severity) to normalized severity.
NESSUS_SEVERITY_MAP: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


class AssetCriticality(StrEnum):
    """Business criticality assigned by the organization (asset context)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNSPECIFIED = "unspecified"


class ServiceObservation(BaseModel):
    """A network service observed on an asset (from a scan or a banner)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="tcp", pattern=r"^(tcp|udp)$")
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = Field(default=None, max_length=MAX_BANNER)


class CVSSV3Observation(BaseModel):
    """CVSS v3 base score as reported by the scanner (we never recompute it)."""

    base_score: float = Field(ge=0.0, le=10.0)
    vector: str | None = Field(default=None, max_length=200)
    source: str | None = None  # e.g. "nessus-plugin"


class VPRObservation(BaseModel):
    """Tenable VPR score, when the source provides it."""

    score: float = Field(ge=0.0, le=10.0)
    source: str | None = None


class Asset(BaseModel):
    """Asset / environmental context for a finding."""

    model_config = ConfigDict(str_strip_whitespace=True)

    asset_id: str = Field(min_length=1, max_length=256)
    hostname: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)
    operating_system: str | None = Field(default=None, max_length=256)
    criticality: AssetCriticality = AssetCriticality.UNSPECIFIED
    environment: str | None = Field(default=None, max_length=64)  # prod/staging/dev/...
    internet_facing: bool | None = None
    owner: str | None = Field(default=None, max_length=256)
    services: list[ServiceObservation] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    """A normalized vulnerability finding from any source."""

    model_config = ConfigDict(str_strip_whitespace=True)

    finding_id: str = Field(min_length=1, max_length=256)
    source: str = Field(default="manual", max_length=64)  # nessus | manual | fixture | ...
    name: str = Field(min_length=1, max_length=512)
    plugin_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=MAX_TEXT_FIELDS)
    severity: Severity = Severity.UNKNOWN
    cve_ids: list[str] = Field(default_factory=list)
    cvss_v3: CVSSV3Observation | None = None
    vpr: VPRObservation | None = None
    asset: Asset
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, pattern=r"^(tcp|udp)$")
    service: str | None = Field(default=None, max_length=64)
    plugin_output: str | None = Field(default=None, max_length=MAX_TEXT_FIELDS)
    solution: str | None = Field(default=None, max_length=MAX_TEXT_FIELDS)
    scan_id: str | None = Field(default=None, max_length=256)
    scanned_at: datetime | None = None
    #: Untrusted snapshot of the original source data, kept for traceability.
    raw: dict[str, Any] | None = None

    @field_validator("cve_ids", mode="before")
    @classmethod
    def _normalize_cves(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        seen: list[str] = []
        for item in value:
            normalized = normalize_cve(str(item))
            if normalized not in seen:
                seen.append(normalized)
        return seen

    @field_validator("finding_id", "plugin_id", "scan_id", mode="before")
    @classmethod
    def _strip_disallowed(cls, value: Any) -> Any:
        # IDs are carried into audit records and SQL keys; forbid control chars.
        if isinstance(value, str) and any(ch in value for ch in "\x00\n\r\t"):
            raise ValueError("Control characters are not allowed in identifiers")
        return value
