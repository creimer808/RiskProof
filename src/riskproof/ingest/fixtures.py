"""Load bundled / user-provided normalized fixtures.

Every fixture file is clearly labeled SAMPLE data. Findings loaded here are
marked ``source="fixture"`` so downstream evidence and reporting always state
where the data came from.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from riskproof.errors import InvalidInputError
from riskproof.models.findings import Asset, Finding


def load_findings_fixture(path: str | Path) -> list[Finding]:
    """Load findings from a normalized JSON fixture (a list of Finding objects)."""
    path = Path(path)
    if not path.is_file():
        raise InvalidInputError(f"Findings fixture not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidInputError(f"Cannot read findings fixture {path}: {exc}") from exc
    if not isinstance(data, list):
        raise InvalidInputError(f"Findings fixture {path} must be a JSON list")
    findings: list[Finding] = []
    for index, item in enumerate(data):
        try:
            finding = Finding.model_validate(item)
        except ValidationError as exc:
            raise InvalidInputError(
                f"Findings fixture {path}, entry {index} is invalid: {exc}"
            ) from exc
        findings.append(finding.model_copy(update={"source": finding.source or "fixture"}))
    return findings


def load_assets_fixture(path: str | Path) -> dict[str, Asset]:
    """Load asset context: returns assets keyed by asset_id and hostname."""
    path = Path(path)
    if not path.is_file():
        raise InvalidInputError(f"Assets fixture not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidInputError(f"Cannot read assets fixture {path}: {exc}") from exc
    items = data.get("assets") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise InvalidInputError(f"Assets fixture {path} must contain an 'assets' list")
    assets: dict[str, Asset] = {}
    for item in items:
        asset = Asset.model_validate(item)
        assets[asset.asset_id] = asset
        if asset.hostname:
            assets[asset.hostname.lower()] = asset
        if asset.ip_address:
            assets[asset.ip_address] = asset
    return assets


def attach_asset_context(findings: list[Finding], assets: dict[str, Asset]) -> list[Finding]:
    """Enrich findings' asset context from the asset catalog where available.

    Scanner-derived fields win for observed facts; the catalog contributes
    business context (criticality, environment, internet-facing, owner).
    """
    enriched: list[Finding] = []
    for finding in findings:
        asset = finding.asset
        match = assets.get(asset.asset_id)
        match = match or assets.get((asset.hostname or "").lower())
        match = match or assets.get(asset.ip_address or "")
        if match is None:
            enriched.append(finding)
            continue
        merged = asset.model_copy(
            update={
                "criticality": asset.criticality
                if asset.criticality.value != "unspecified"
                else match.criticality,
                "environment": asset.environment or match.environment,
                "internet_facing": asset.internet_facing
                if asset.internet_facing is not None
                else match.internet_facing,
                "owner": asset.owner or match.owner,
                "services": asset.services or match.services,
            }
        )
        enriched.append(finding.model_copy(update={"asset": merged}))
    return enriched
