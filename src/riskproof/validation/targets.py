"""Target authorization for validation checks.

Security model (fail closed):

* Only targets on the server-side allowlist (Settings.allowed_targets) may be
  validated. The allowlist CANNOT be modified through MCP tool input.
* Hostnames are resolved and EVERY resolved address must be allowed — this
  blocks an agent from dressing up an internal IP as an external hostname.
* Unresolvable hosts are refused.
* Attempts are recorded in the audit trail (denials included).
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
                self._hosts[entry.lower()] = entry

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
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise AuthorizationDenied(
                f"Target {host!r} could not be resolved; refusing to proceed (fail closed)."
            ) from exc
        return sorted({info[4][0] for info in infos})

    def authorize(self, host: str) -> AuthorizedTarget:
        """Return an AuthorizedTarget or raise AuthorizationDenied."""
        host = host.strip().rstrip(".")
        if not host:
            raise AuthorizationDenied("Empty target refused.")

        if ipaddress_value := self._as_ip(host):
            rule = self._ip_allowed(ipaddress_value)
            if rule:
                return AuthorizedTarget(
                    requested=host, resolved_ips=[ipaddress_value], matched_rule=rule
                )
            raise AuthorizationDenied(
                f"Target {host!r} is not on the RiskProof validation allowlist. "
                "Ask a human operator to add it via RISKPROOF_ALLOWED_TARGETS."
            )

        resolved = self._resolve(host)
        for ip in resolved:
            rule = self._ip_allowed(ip)
            if rule:
                return AuthorizedTarget(requested=host, resolved_ips=resolved, matched_rule=rule)
        raise AuthorizationDenied(
            f"Target {host!r} resolves to {resolved}, none of which are on the "
            "RiskProof validation allowlist. Ask a human operator to authorize "
            "this target via RISKPROOF_ALLOWED_TARGETS."
        )

    @staticmethod
    def _as_ip(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        return host
