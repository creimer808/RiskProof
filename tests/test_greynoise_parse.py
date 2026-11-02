"""Pure GreyNoise payload parsing and window evaluation (no network)."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from riskproof.config import Settings
from riskproof.models.intel import GreyNoiseResult, GreyNoiseTag, ThreatIntelBundle
from riskproof.providers.base import ProviderError
from riskproof.providers.greynoise_parse import (
    evaluate_cve,
    normalize_intention,
    parse_activity,
    parse_tag_catalog,
)

TODAY = date(2026, 11, 2)
LOG4J = "CVE-2021-44228"


def tag(tag_id: str = "t1", intention: str = "malicious", cves=None, name: str = "Log4j RCE"):
    return {
        "id": tag_id,
        "slug": f"slug-{tag_id}",
        "name": name,
        "intention": intention,
        "cves": [LOG4J] if cves is None else cves,
    }


def gtag(tag_id: str = "t1", intention: str = "malicious") -> GreyNoiseTag:
    return GreyNoiseTag(id=tag_id, slug=f"slug-{tag_id}", name="n", intention=intention)


def test_normalize_intention_handles_dirty_values():
    assert normalize_intention("Suspicious") == "suspicious"
    assert normalize_intention("suspicious ") == "suspicious"
    assert normalize_intention("malicious") == "malicious"
    assert normalize_intention(None) is None
    assert normalize_intention(5) is None


def test_parse_tag_catalog_maps_cves_and_drops_noise():
    payload = {
        "tags": [
            tag("a", "malicious", [LOG4J, "CVE-2020-1472"]),
            tag("b", "benign"),
            tag("c", "unknown"),
            tag("d", "suspicious", []),
            {"slug": "no-id", "name": "x", "intention": "malicious", "cves": [LOG4J]},
            tag("e", "Suspicious ", ["not-a-cve", "CVE-2019-0708"]),
        ]
    }
    result = parse_tag_catalog(payload)
    assert set(result) == {LOG4J, "CVE-2020-1472", "CVE-2019-0708"}
    assert [t.id for t in result[LOG4J]] == ["a"]
    assert [t.id for t in result["CVE-2020-1472"]] == ["a"]
    assert result["CVE-2019-0708"][0].intention == "suspicious"


def test_parse_tag_catalog_sanitizes_names():
    result = parse_tag_catalog({"tags": [tag(name="bad\x00name\n" + "x" * 500)]})
    name = result[LOG4J][0].name
    assert "\x00" not in name and "\n" not in name
    assert len(name) <= 120


@pytest.mark.parametrize("payload", [{}, [], "x", {"tags": "nope"}, None])
def test_parse_tag_catalog_rejects_bad_payload(payload):
    with pytest.raises(ProviderError):
        parse_tag_catalog(payload)


def test_parse_activity_buckets():
    payload = {
        "activity": {
            "malicious": [
                {"timestamp": "2026-11-01T00:00:00Z", "active_ips": 11},
                {"timestamp": "2026-11-02T00:00:00Z", "active_ips": 22},
                {"timestamp": "2026-11-02T00:00:00Z", "active_ips": "x"},
                {"timestamp": "garbage", "active_ips": 5},
                {"timestamp": "2026-11-02T00:00:00Z", "active_ips": -1},
                {"timestamp": "2026-11-02T00:00:00Z", "active_ips": True},
            ],
            "Suspicious ": [{"timestamp": "2026-11-02T00:00:00Z", "active_ips": 3}],
        },
        "aggregations": {"total_ips": 25},
    }
    assert parse_activity(payload) == {
        "malicious": {"2026-11-01": 11, "2026-11-02": 22},
        "suspicious": {"2026-11-02": 3},
    }


@pytest.mark.parametrize("payload", [[], "x", None])
def test_parse_activity_rejects_non_dict(payload):
    with pytest.raises(ProviderError):
        parse_activity(payload)


def test_evaluate_observed_inside_window():
    activity = {"t1": {"malicious": {"2026-11-01": 11, "2026-11-02": 22}}}
    result = evaluate_cve(LOG4J, [gtag()], activity, today=TODAY, window_days=3)
    assert result.state == "observed"
    assert result.peak_malicious_ips == 22
    assert result.last_malicious_day == "2026-11-02"
    assert result.malicious_ips_by_day == {"2026-11-01": 11, "2026-11-02": 22}
    assert [t.id for t in result.tags] == ["t1"]


def test_evaluate_window_boundary():
    # window_days=3 -> 2026-10-31, 11-01, 11-02 count; 10-30 does not.
    inside = {"t1": {"malicious": {"2026-10-31": 4}}}
    outside = {"t1": {"malicious": {"2026-10-30": 4}}}
    assert evaluate_cve(LOG4J, [gtag()], inside, today=TODAY, window_days=3).state == "observed"
    result = evaluate_cve(LOG4J, [gtag()], outside, today=TODAY, window_days=3)
    assert result.state == "quiet"
    assert result.malicious_ips_by_day == {}


def test_evaluate_future_dated_activity_ignored():
    activity = {"t1": {"malicious": {"2026-11-09": 50}}}
    assert evaluate_cve(LOG4J, [gtag()], activity, today=TODAY, window_days=3).state == "quiet"


def test_evaluate_suspicious_only_is_quiet():
    tags = [gtag("s1", "suspicious")]
    activity = {"s1": {"suspicious": {"2026-11-02": 9}}}
    result = evaluate_cve(LOG4J, tags, activity, today=TODAY, window_days=3)
    assert result.state == "quiet"
    assert result.suspicious_ips_by_day == {"2026-11-02": 9}
    assert result.peak_malicious_ips == 0


def test_evaluate_zero_ips_is_quiet():
    activity = {"t1": {"malicious": {"2026-11-02": 0}}}
    assert evaluate_cve(LOG4J, [gtag()], activity, today=TODAY, window_days=3).state == "quiet"


def test_evaluate_no_tags_is_no_data():
    result = evaluate_cve(LOG4J, [], {}, today=TODAY, window_days=3)
    assert result.state == "no_data"
    assert "not evidence" in (result.reason or "")


def test_intel_bundle_subset_restricts_greynoise():
    bundle = ThreatIntelBundle(
        cve_ids=[LOG4J, "CVE-2020-1472"],
        collected_at=datetime.now(UTC),
        greynoise={
            LOG4J: GreyNoiseResult(cve=LOG4J, state="observed"),
            "CVE-2020-1472": GreyNoiseResult(cve="CVE-2020-1472", state="quiet"),
        },
        greynoise_source="greynoise",
    )
    subset = bundle.subset([LOG4J])
    assert set(subset.greynoise) == {LOG4J}
    assert subset.greynoise_source == "greynoise"


def test_bundle_defaults_are_backward_compatible():
    bundle = ThreatIntelBundle(cve_ids=[], collected_at=datetime.now(UTC))
    assert bundle.greynoise == {} and bundle.greynoise_source == "unavailable"


def test_greynoise_settings_defaults_and_bounds():
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.greynoise_window_days == 3
    assert s.greynoise_max_calls_per_run == 100
    assert s.greynoise_base_url == "https://api.greynoise.io"
    with pytest.raises(ValidationError):
        Settings(_env_file=None, greynoise_window_days=0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Settings(_env_file=None, greynoise_max_calls_per_run=-1)  # type: ignore[call-arg]
