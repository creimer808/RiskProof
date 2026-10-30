"""Threat intelligence models: FIRST EPSS and the CISA KEV catalog.

Honesty rules encoded here:

* EPSS is a statistical prediction (probability that the CVE is exploited in
  the wild within 30 days) — it never claims a specific system is exploitable.
* A KEV "sample" catalog (fixture data) is never equivalent to the live CISA
  catalog: absence from the sample does not mean "not in KEV".
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from riskproof.models.findings import normalize_cve


class EPSSObservation(BaseModel):
    """A FIRST EPSS observation for one CVE.

    ``score`` is the probability (0.0-1.0) that the vulnerability is exploited
    in the wild within the next 30 days, per FIRST's model. It is a property of
    the CVE, not of any particular system.
    """

    kind: Literal["observation"] = "observation"
    cve: str
    score: float = Field(ge=0.0, le=1.0)
    percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    date: str | None = None  # EPSS model date, e.g. "2026-01-02"
    collected_at: datetime
    source: Literal["first.org", "sample-fixture"] = "first.org"

    def model_post_init(self, __context: object) -> None:
        self.cve = normalize_cve(self.cve)


class EPSSUnavailable(BaseModel):
    """Honest record that EPSS data could not be retrieved for a CVE."""

    kind: Literal["unavailable"] = "unavailable"
    cve: str
    reason: str

    def model_post_init(self, __context: object) -> None:
        self.cve = normalize_cve(self.cve)


EPSSResult = EPSSObservation | EPSSUnavailable


class KEVEntry(BaseModel):
    """One entry from the CISA Known Exploited Vulnerabilities catalog."""

    cve: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None

    def model_post_init(self, __context: object) -> None:
        self.cve = normalize_cve(self.cve)


class KEVStatus(BaseModel):
    """Result of checking one CVE against a KEV catalog (live or sample)."""

    cve: str
    in_kev: bool
    #: "cisa-live" means the authoritative feed; "sample" means bundled demo
    #: data where absence is NOT evidence of absence.
    catalog: Literal["cisa-live", "sample"]
    entry: KEVEntry | None = None
    checked_at: datetime

    def model_post_init(self, __context: object) -> None:
        self.cve = normalize_cve(self.cve)


class KEVCatalog(BaseModel):
    """A parsed KEV catalog snapshot."""

    entries: dict[str, KEVEntry] = Field(default_factory=dict)
    catalog_version: str | None = None
    date_released: str | None = None
    catalog: Literal["cisa-live", "sample"] = "cisa-live"
    fetched_at: datetime | None = None


class ThreatIntelBundle(BaseModel):
    """Collected external intelligence for a set of CVEs."""

    cve_ids: list[str]
    epss: dict[str, EPSSResult] = Field(default_factory=dict)
    kev_status: list[KEVStatus] = Field(default_factory=list)
    collected_at: datetime
    epss_source: Literal["first.org", "sample-fixture", "unavailable"] = "unavailable"
    kev_source: Literal["cisa-live", "sample-fixture", "unavailable"] = "unavailable"
    #: True when we had to degrade (fallback to fixtures or partial failure).
    degraded: bool = False
    notices: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: object) -> None:
        self.cve_ids = [normalize_cve(c) for c in self.cve_ids]
