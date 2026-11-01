"""Operator-maintained asset inventory: business context for real scan data.

Scanners report *what* is vulnerable; only the organization knows *which assets
matter*. The inventory lets a human operator record criticality, environment,
internet exposure, and ownership, which the risk decision table needs to reach
P1 for imported Nessus/Tenable findings.

Format (JSON, path set by ``RISKPROOF_ASSET_INVENTORY``)::

    {
      "rules": [
        {"match": "10.20.0.0/24", "environment": "production", "internet_facing": false},
        {"match": ["web01", "web01.corp.example"], "criticality": "critical",
         "internet_facing": true, "owner": "platform-team"}
      ]
    }

``match`` takes hostnames / FQDNs / asset ids (exact, case-insensitive), IP
addresses, or CIDR ranges. When several rules match a finding, each field comes from the
most specific rule that sets it: a hostname or asset-id rule beats any CIDR,
and a longer prefix beats a shorter one; ties go to the earlier rule.

Security model: the inventory is operator configuration, like the validation
allowlist. No tool parameter can edit it, and its values override asset
context carried on a finding — so an agent cannot argue a finding's priority
down by asserting the asset is unimportant. SAMPLE fixture findings are never
matched against it, keeping demo data and real context separate.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from riskproof.errors import ConfigurationError
from riskproof.models.findings import AssetCriticality, Finding

MAX_INVENTORY_BYTES = 5 * 1024 * 1024
CONTEXT_FIELDS = ("criticality", "environment", "internet_facing", "owner")
_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,252}$")
_NAME_SPECIFICITY = 1_000  # above any prefix length (max 128)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class AssetRule(BaseModel):
    """One inventory rule: which assets it covers and the context it asserts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    match: list[str] = Field(min_length=1, max_length=1_000)
    criticality: AssetCriticality | None = None
    environment: str | None = Field(default=None, max_length=64)
    internet_facing: bool | None = None
    owner: str | None = Field(default=None, max_length=256)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("match", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else value

    @model_validator(mode="after")
    def _sets_something(self) -> AssetRule:
        if all(getattr(self, name) is None for name in CONTEXT_FIELDS):
            raise ValueError(f"rule {self.match} sets none of {', '.join(CONTEXT_FIELDS)}")
        return self


class _InventoryDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")  # allow "_comment"-style keys

    rules: list[AssetRule]


@dataclass(frozen=True)
class _Matcher:
    rule_index: int
    token: str
    specificity: int
    name: str | None = None
    network: Network | None = None


def _normalize_name(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _compile(rules: list[AssetRule]) -> list[_Matcher]:
    matchers: list[_Matcher] = []
    for index, rule in enumerate(rules):
        for token in rule.match:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                network = None
            if network is not None:
                matchers.append(_Matcher(index, token, network.prefixlen, network=network))
                continue
            name = _normalize_name(token)
            if "/" in token or not _NAME_RE.fullmatch(name):
                raise ConfigurationError(
                    f"Asset inventory rule {index}: {token!r} is not a valid hostname, "
                    "asset id, IP address, or CIDR range."
                )
            matchers.append(_Matcher(index, token, _NAME_SPECIFICITY, name=name))
    return matchers


class AssetInventory:
    """Parsed inventory rules, ready to apply to findings."""

    def __init__(self, rules: list[AssetRule], source: str) -> None:
        self.rules = rules
        self.source = source
        self._matchers = _compile(rules)

    @classmethod
    def parse(cls, data: Any, source: str) -> AssetInventory:
        try:
            document = _InventoryDocument.model_validate(data)
        except ValidationError as exc:
            raise ConfigurationError(f"Asset inventory {source} is invalid: {exc}") from exc
        return cls(document.rules, source)

    def apply(self, finding: Finding) -> tuple[Finding, list[str]]:
        """Return the finding with inventory context applied, plus matched rules."""
        if finding.source == "fixture":
            return finding, []
        asset = finding.asset
        candidates = (asset.asset_id, asset.hostname, asset.labels.get("fqdn"))
        names = {_normalize_name(n) for n in candidates if n}
        try:
            ip = ipaddress.ip_address(asset.ip_address) if asset.ip_address else None
        except ValueError:
            ip = None

        hits = [
            m
            for m in self._matchers
            if (m.name is not None and m.name in names)
            or (
                m.network is not None
                and ip is not None
                and ip.version == m.network.version
                and ip in m.network
            )
        ]
        if not hits:
            return finding, []
        hits.sort(key=lambda m: (-m.specificity, m.rule_index))

        update: dict[str, Any] = {}
        used: list[str] = []
        for field_name in CONTEXT_FIELDS:
            for matcher in hits:
                value = getattr(self.rules[matcher.rule_index], field_name)
                if value is not None:
                    update[field_name] = value
                    if matcher.token not in used:
                        used.append(matcher.token)
                    break
        enriched = finding.model_copy(update={"asset": asset.model_copy(update=update)})
        return enriched, used


class AssetInventorySource:
    """Loads the operator's inventory file, re-reading it only when it changes.

    A missing file means "no inventory" (findings keep unknown context and the
    investigation says so). A present but invalid file is an error: silently
    ignoring a typo would silently drop findings out of P1.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._key: tuple[int, int] | None = None
        self._cached: AssetInventory | None = None

    def current(self) -> AssetInventory | None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self._key, self._cached = None, None
            return None
        except OSError as exc:
            raise ConfigurationError(f"Cannot read asset inventory {self.path}: {exc}") from exc
        key = (stat.st_mtime_ns, stat.st_size)
        if key == self._key:
            return self._cached
        if stat.st_size > MAX_INVENTORY_BYTES:
            raise ConfigurationError(
                f"Asset inventory {self.path} is {stat.st_size:,} bytes; "
                f"the limit is {MAX_INVENTORY_BYTES:,}."
            )
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"Cannot parse asset inventory {self.path}: {exc}") from exc
        inventory = AssetInventory.parse(data, str(self.path))
        self._key, self._cached = key, inventory
        return inventory
