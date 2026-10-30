"""Restricted, non-destructive validation checks.

Only the methods in ``CHECK_METHODS`` exist, and each is read-only by
construction:

* ``tcp_connect``     — open a TCP connection and close it
* ``http_banner``     — one benign ``HEAD`` request; record the status line and
                        headers (never sends exploit payloads)
* ``tls_cert_dates``  — connect with TLS and read certificate validity dates

There is no shell, no plugin execution, and no way to inject new methods at
runtime. Results NEVER claim exploitability; a closed port or missing banner is
recorded as inconclusive and must not suppress the finding.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from riskproof.errors import AuthorizationDenied
from riskproof.validation.targets import AuthorizedTarget, TargetAuthorizer

CHECK_METHODS = ("tcp_connect", "http_banner", "tls_cert_dates")
CheckMethod = Literal["tcp_connect", "http_banner", "tls_cert_dates"]

DISCLAIMER = (
    "Non-destructive connectivity/banner observation only. This check does NOT "
    "demonstrate exploitability, and an inconclusive or negative result does "
    "NOT mean the vulnerability is absent."
)
MAX_BANNER_BYTES = 4096


class ValidationResult(BaseModel):
    method: CheckMethod
    target: str
    port: int = Field(ge=0, le=65535)
    #: verified = check completed with an observation; inconclusive = check ran
    #: but could not confirm (closed/filtered/timeout); refused = authorization.
    status: Literal["verified", "inconclusive", "refused"]
    observed: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    checked_at: datetime
    audit_id: int | None = None
    disclaimer: str = DISCLAIMER

    def evidence_statement(self) -> str:
        if self.status == "verified":
            summary = ", ".join(f"{k}={v}" for k, v in list(self.observed.items())[:4])
            return (
                f"Authorized {self.method} check against {self.target}:{self.port} "
                f"succeeded ({summary})."
            )
        return (
            f"Authorized {self.method} check against {self.target}:{self.port} was "
            f"inconclusive ({'; '.join(self.notes) or 'no details'})."
        )


async def _tcp_connect(host: str, port: int, timeout: float) -> tuple[dict, list[str]]:
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (ConnectionRefusedError, OSError):
        return {}, ["connection refused or unreachable"]
    except TimeoutError:
        return {}, ["connection timed out (possibly filtered)"]
    elapsed = round(time.monotonic() - start, 3)
    writer.close()
    with contextlib.suppress(OSError):  # close races are harmless
        await writer.wait_closed()
    return {"connect_seconds": elapsed, "tcp_reachable": True}, []


async def _http_banner(host: str, port: int, timeout: float) -> tuple[dict, list[str]]:
    request = (
        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: RiskProof-validation\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (ConnectionRefusedError, OSError):
        return {}, ["connection refused or unreachable"]
    except TimeoutError:
        return {}, ["connection timed out"]
    try:
        writer.write(request.encode("utf-8", errors="replace"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=timeout)
    except (TimeoutError, OSError) as exc:
        return {}, [f"banner read failed: {type(exc).__name__}"]
    finally:
        writer.close()
        with contextlib.suppress(OSError):  # pragma: no cover
            await writer.wait_closed()
    if not data:
        return {}, ["no banner data returned"]
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()][:12]
    return {"response_lines": lines}, []


# --- Minimal DER walking for TLS certificate validity dates ------------------
# Avoids pulling in `cryptography` for one observation. Parses the standard
# Certificate -> TBSCertificate -> Validity(notBefore, notAfter) path.


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV. Returns (tag, value_bytes, next_offset)."""
    if offset + 2 > len(data):
        raise ValueError("DER truncated")
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        length, header = first, 2
    else:
        count = first & 0x7F
        header = 2 + count
        length = int.from_bytes(data[offset + 2 : header + offset], "big")
    end = offset + header + length
    if end > len(data):
        raise ValueError("DER length overruns buffer")
    return tag, data[offset + header : end], end


def _children(der: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(der):
        tag, value, offset = _read_tlv(der, offset)
        children.append((tag, value))
    return children


def _parse_asn1_time(tag: int, raw: bytes) -> str | None:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    try:
        if tag == 23:  # UTCTime YYMMDDHHMMSSZ
            year = int(text[:2])
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        elif tag == 24:  # GeneralizedTime YYYYMMDDHHMMSSZ
            year = int(text[:4])
            rest = text[4:]
        else:
            return None
        month, day = int(rest[0:2]), int(rest[2:4])
        hour, minute, second = int(rest[4:6]), int(rest[6:8]), int(rest[8:10])
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC).isoformat()
    except (ValueError, IndexError):
        return None


def _validity_from_der(der: bytes) -> dict[str, str]:
    """Extract notBefore/notAfter from a DER certificate. Raises ValueError."""
    cert_tag, cert_value, _ = _read_tlv(der, 0)
    if cert_tag != 0x30:
        raise ValueError("not a DER SEQUENCE")
    tbs_tag, tbs_value, _ = _read_tlv(cert_value, 0)
    if tbs_tag != 0x30:
        raise ValueError("no TBSCertificate")
    for tag, value in _children(tbs_value):
        if tag != 0x30:
            continue
        pair = _children(value)
        if len(pair) == 2 and pair[0][0] in (23, 24) and pair[1][0] in (23, 24):
            not_before = _parse_asn1_time(pair[0][0], pair[0][1])
            not_after = _parse_asn1_time(pair[1][0], pair[1][1])
            if not_before and not_after:
                return {"not_before": not_before, "not_after": not_after}
    raise ValueError("Validity sequence not found")


async def _tls_cert_dates(host: str, port: int, timeout: float) -> tuple[dict, list[str]]:
    loop = asyncio.get_running_loop()

    def _sync_observe() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # observing, not trusting
        ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            observed: dict[str, Any] = {"tls_version": tls.version()}
            if der:
                observed.update(_validity_from_der(der))
            return observed

    try:
        observed = await asyncio.wait_for(loop.run_in_executor(None, _sync_observe), timeout)
    except (ssl.SSLError, OSError, ValueError) as exc:
        return {}, [f"TLS observation failed: {type(exc).__name__}"]
    except TimeoutError:
        return {}, ["TLS handshake timed out"]
    return {k: v for k, v in observed.items() if v is not None}, []


async def run_check(
    method: str, target: AuthorizedTarget, port: int, timeout: float = 5.0
) -> ValidationResult:
    """Execute one approved check against an ALREADY AUTHORIZED target."""
    if method not in CHECK_METHODS:
        raise AuthorizationDenied(
            f"Validation method {method!r} does not exist. Approved methods: "
            f"{', '.join(CHECK_METHODS)}."
        )
    # Connect to the requested name (it was resolved during authorization).
    host = target.requested
    now = datetime.now(UTC)
    if method == "tcp_connect":
        observed, notes = await _tcp_connect(host, port, timeout)
    elif method == "http_banner":
        observed, notes = await _http_banner(host, port, timeout)
    else:
        observed, notes = await _tls_cert_dates(host, port, timeout)
    status: Literal["verified", "inconclusive"] = "verified" if not notes else "inconclusive"
    return ValidationResult(
        method=method,  # type: ignore[arg-type]
        target=target.requested,
        port=port,
        status=status,
        observed=observed,
        notes=notes,
        checked_at=now,
    )


async def run_authorized_check(
    method: str,
    host: str,
    port: int,
    authorizer: TargetAuthorizer,
    approved_methods: list[str],
    timeout: float = 5.0,
) -> ValidationResult:
    """Full pipeline: method approval, target authorization, then the check."""
    if method not in approved_methods:
        raise AuthorizationDenied(
            f"Validation method {method!r} is not approved by policy. Approved "
            f"methods: {', '.join(approved_methods) or '(none)'}. A human operator "
            "must approve it via RISKPROOF_APPROVED_VALIDATION_METHODS."
        )
    authorized = authorizer.authorize(host)
    return await run_check(method, authorized, port, timeout)
