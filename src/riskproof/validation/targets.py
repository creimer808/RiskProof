"""Target authorization for validation checks.

Security model (fail closed):

* Only targets on the server-side allowlist (Settings.allowed_targets) may be
  validated. The allowlist CANNOT be modified through MCP tool input.
* Allowlist entries are IPs, CIDR ranges, or exact hostnames (case-insensitive,
  no wildcards). A hostname rule authorizes that name and whatever it resolves
  to at authorization time — the operator vouched for the name.
* Any other hostname is resolved and EVERY resolved address must fall inside an
  IP/CIDR rule — this blocks an agent from dressing up an internal IP as an
  external hostname.
* The authorized address is pinned (``AuthorizedTarget.connect_ip``): checks
  connect to that IP rather than re-resolving the name, so DNS cannot change
  the destination between authorization and connection (DNS rebinding).
* Unresolvable hosts are refused.
* Attempts are recorded in the audit trail (denials included) by the caller.
"""

from __future__ import annotations

import ipaddress
import socket

from pydantic import BaseModel

from riskproof.errors import AuthorizationDenied


class AuthorizedTarget(BaseModel):
    """A target that passed authorization."""

    requested: str
    resolved_ips: list[str]
    matched_rule: str
    #: The address checks must connect to. Pinned at authorization time.
    connect_ip: str


class TargetAuthorizer:
    """Enforces the validation target allowlist. Fails closed."""

    def __init__(self, allowed: list[str]) -> None:
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self._hosts: dict[str, str] = {}
        for entry in allowed:
            entry = entry.strip()
            if not entry:
                continue
            try:
                self._networks.append((ipaddress.ip_network(entry, strict=False), entry))
            except ValueError:
                self._hosts[entry.lower().rstrip(".")] = entry

    def _ip_allowed(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, rule in self._networks:
            if addr in network:
                return rule
        return None

    def _resolve(self, host: str) -> list[str]:
        """Resolved addresses in resolver preference order, de-duplicated."""
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AuthorizationDenied(
                f"Target {host!r} could not be resolved; refusing to proceed (fail closed)."
            ) from exc
        resolved = list(dict.fromkeys(str(info[4][0]) for info in infos))
        if not resolved:
            raise AuthorizationDenied(
                f"Target {host!r} resolved to no addresses; refusing to proceed (fail closed)."
            )
        return resolved

    def authorize(self, host: str) -> AuthorizedTarget:
        """Return an AuthorizedTarget or raise AuthorizationDenied."""
        host = host.strip().rstrip(".")
        if not host:
            raise AuthorizationDenied("Empty target refused.")

        if ipaddress_value := self._as_ip(host):
            rule = self._ip_allowed(ipaddress_value)
            if rule:
                return AuthorizedTarget(
                    requested=host,
                    resolved_ips=[ipaddress_value],
                    matched_rule=rule,
                    connect_ip=ipaddress_value,
                )
            raise AuthorizationDenied(
                f"Target {host!r} is not on the RiskProof validation allowlist. "
                "Ask a human operator to add it via RISKPROOF_ALLOWED_TARGETS."
            )

        resolved = self._resolve(host)

        host_rule = self._hosts.get(host.lower())
        if host_rule is not None:
            return AuthorizedTarget(
                requested=host,
                resolved_ips=resolved,
                matched_rule=host_rule,
                connect_ip=resolved[0],
            )

        rules = [self._ip_allowed(ip) for ip in resolved]
        disallowed = [ip for ip, rule in zip(resolved, rules, strict=True) if rule is None]
        if disallowed:
            raise AuthorizationDenied(
                f"Target {host!r} resolves to {resolved}; {disallowed} "
                f"{'is' if len(disallowed) == 1 else 'are'} not on the RiskProof validation "
                "allowlist (every resolved address must be allowed). Ask a human operator to "
                "authorize this target via RISKPROOF_ALLOWED_TARGETS."
            )
        return AuthorizedTarget(
            requested=host,
            resolved_ips=resolved,
            matched_rule=str(rules[0]),
            connect_ip=resolved[0],
        )

    @staticmethod
    def _as_ip(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        return host
