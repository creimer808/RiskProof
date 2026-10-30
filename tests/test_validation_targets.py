"""Tests for the target authorizer (fail-closed allowlist enforcement)."""

from __future__ import annotations

import pytest

from riskproof.errors import AuthorizationDenied
from riskproof.validation.targets import TargetAuthorizer


def test_ip_directly_allowlisted():
    auth = TargetAuthorizer(["127.0.0.1", "10.20.0.0/24"])
    target = auth.authorize("127.0.0.1")
    assert target.matched_rule == "127.0.0.1"


def test_ip_within_cidr_allowlisted():
    auth = TargetAuthorizer(["10.20.0.0/24"])
    target = auth.authorize("10.20.0.55")
    assert target.matched_rule == "10.20.0.0/24"


def test_unlisted_ip_denied():
    auth = TargetAuthorizer(["127.0.0.1"])
    with pytest.raises(AuthorizationDenied):
        auth.authorize("10.20.0.55")


def test_empty_allowlist_denies_everything():
    auth = TargetAuthorizer([])
    with pytest.raises(AuthorizationDenied):
        auth.authorize("127.0.0.1")


def test_hostname_resolving_to_allowed_ip_is_authorized():
    auth = TargetAuthorizer(["127.0.0.1", "::1"])
    target = auth.authorize("localhost")
    assert "127.0.0.1" in target.resolved_ips or "::1" in target.resolved_ips


def test_hostname_resolving_to_disallowed_ip_denied():
    """example.com must not be validateable just because someone allows a
    different host — all resolved addresses must be on the allowlist."""
    auth = TargetAuthorizer(["127.0.0.1", "10.0.0.0/8"])
    with pytest.raises(AuthorizationDenied):
        auth.authorize("example.com")


def test_unresolvable_host_fails_closed():
    auth = TargetAuthorizer(["10.0.0.0/8"])
    with pytest.raises(AuthorizationDenied):
        auth.authorize("this-host-does-not-exist.invalid")


def test_ipv6_allowlisted():
    auth = TargetAuthorizer(["::1"])
    target = auth.authorize("::1")
    assert target.resolved_ips == ["::1"]
