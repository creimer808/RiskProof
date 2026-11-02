"""Pure parsing of GreyNoise API payloads (no I/O).

Everything GreyNoise returns is untrusted: shapes are validated, text is
stripped of control characters and length-capped, and malformed entries are
skipped rather than trusted.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta

from riskproof.models.findings import normalize_cve
from riskproof.models.intel import GreyNoiseResult, GreyNoiseTag
from riskproof.providers.base import ProviderError

MAX_TAG_TEXT = 120
KEPT_INTENTIONS = ("malicious", "suspicious")
NO_DATA_REASON = (
    "No GreyNoise tag maps to this CVE; that is not evidence the CVE is safe or unexploited."
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def normalize_intention(value: object) -> str | None:
    """Lowercase/strip a GreyNoise intention label (the API's casing is inconsistent)."""
    return value.strip().lower() if isinstance(value, str) else None


def _clean(value: object, limit: int = MAX_TAG_TEXT) -> str:
    return _CONTROL.sub(" ", str(value))[:limit].strip() if value is not None else ""


def parse_tag_catalog(payload: object) -> dict[str, list[GreyNoiseTag]]:
    """Map CVE -> malicious/suspicious tags from the full ``/v3/tags`` catalog."""
    if not isinstance(payload, dict) or not isinstance(payload.get("tags"), list):
        raise ProviderError("GreyNoise tag catalog missing 'tags' array")
    by_cve: dict[str, list[GreyNoiseTag]] = {}
    for item in payload["tags"]:
        if not isinstance(item, dict):
            continue
        tag_id = item.get("id")
        intention = normalize_intention(item.get("intention"))
        cves = item.get("cves")
        if (
            not isinstance(tag_id, str)
            or not tag_id.strip()
            or intention not in KEPT_INTENTIONS
            or not isinstance(cves, list)
        ):
            continue
        slug = _clean(item.get("slug"), 128)
        tag = GreyNoiseTag(
            id=tag_id.strip()[:128],
            slug=slug,
            name=_clean(item.get("name")) or slug,
            intention=intention,  # type: ignore[arg-type]
        )
        for raw_cve in cves:
            try:
                cve = normalize_cve(str(raw_cve))
            except ValueError:
                continue
            tags = by_cve.setdefault(cve, [])
            if all(t.id != tag.id for t in tags):
                tags.append(tag)
    return by_cve


def parse_activity(payload: object) -> dict[str, dict[str, int]]:
    """Intention -> {UTC day: distinct active IPs} from ``/v3/tags/{id}/activity``."""
    if not isinstance(payload, dict):
        raise ProviderError("GreyNoise tag activity payload is not an object")
    activity = payload.get("activity")
    out: dict[str, dict[str, int]] = {}
    if not isinstance(activity, dict):
        return out
    for raw_intention, buckets in activity.items():
        intention = normalize_intention(raw_intention)
        if intention not in KEPT_INTENTIONS or not isinstance(buckets, list):
            continue
        days = out.setdefault(intention, {})
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            ips = bucket.get("active_ips")
            stamp = bucket.get("timestamp")
            if isinstance(ips, bool) or not isinstance(ips, int) or ips < 0:
                continue
            try:
                day = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).date().isoformat()
            except ValueError:
                continue
            days[day] = max(days.get(day, 0), ips)
    return {k: v for k, v in out.items() if v}


def _in_window(days: dict[str, int], today: date, window_days: int) -> dict[str, int]:
    start = today - timedelta(days=window_days - 1)
    kept: dict[str, int] = {}
    for day, ips in days.items():
        try:
            parsed = date.fromisoformat(day)
        except ValueError:
            continue
        if start <= parsed <= today and ips > 0:
            kept[day] = ips
    return kept


def evaluate_cve(
    cve: str,
    tags: list[GreyNoiseTag],
    activity_by_tag: dict[str, dict[str, dict[str, int]]],
    *,
    today: date,
    window_days: int,
) -> GreyNoiseResult:
    """Decide ``observed`` / ``quiet`` / ``no_data`` for one CVE.

    Only malicious-tag activity inside the window makes a CVE ``observed``.
    Per-day counts take the maximum across tags (distinct-IP sets may overlap,
    so summing would overstate).
    """
    if not tags:
        return GreyNoiseResult(cve=cve, state="no_data", reason=NO_DATA_REASON)
    merged: dict[str, dict[str, int]] = {"malicious": {}, "suspicious": {}}
    for tag in tags:
        days = _in_window(
            activity_by_tag.get(tag.id, {}).get(tag.intention, {}), today, window_days
        )
        for day, ips in days.items():
            merged[tag.intention][day] = max(merged[tag.intention].get(day, 0), ips)
    malicious = merged["malicious"]
    return GreyNoiseResult(
        cve=cve,
        state="observed" if malicious else "quiet",
        tags=tags,
        malicious_ips_by_day=malicious,
        suspicious_ips_by_day=merged["suspicious"],
        peak_malicious_ips=max(malicious.values(), default=0),
        last_malicious_day=max(malicious) if malicious else None,
    )
