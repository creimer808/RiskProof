"""Helpers shared by the ingestion adapters."""

from __future__ import annotations

import re

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def slugify(value: str) -> str:
    """Make a string safe for use inside stable finding/asset identifiers."""
    return _SLUG_RE.sub("_", value)[:120]
