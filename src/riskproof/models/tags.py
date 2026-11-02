"""Tenable asset tags: a ``category -> values`` mapping, bounded and sanitized.

Tags are operator-defined labels in Tenable (for example ``Location: DMZ`` or
``Team: Network``). They arrive from a remote API and are untrusted, so every entry
is length-limited, stripped of control characters, and capped in number.
"""

from __future__ import annotations

from typing import Any

MAX_TAG_CATEGORIES = 50
MAX_TAG_VALUES = 50
MAX_CATEGORY_CHARS = 128
MAX_VALUE_CHARS = 256

#: Categories and values accepted in an import filter (a stricter cap than storage).
MAX_FILTER_CATEGORIES = 10


def clean_text(value: Any, limit: int) -> str | None:
    """A stripped string with no control characters, cut to ``limit``; else None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    return text[:limit]


def _add(tags: dict[str, list[str]], category: Any, value: Any) -> None:
    cat = clean_text(category, MAX_CATEGORY_CHARS)
    val = clean_text(value, MAX_VALUE_CHARS)
    if cat is None or val is None:
        return
    if cat not in tags and len(tags) >= MAX_TAG_CATEGORIES:
        return
    values = tags.setdefault(cat, [])
    if val not in values and len(values) < MAX_TAG_VALUES:
        values.append(val)


def parse_asset_tags(raw: Any) -> dict[str, list[str]]:
    """Read tags from an export record leniently; anything unrecognized is dropped.

    Accepts a list of ``{key|category|category_name: ..., value: ...}`` objects or a
    ``{category: value | [values]}`` mapping.
    """
    tags: dict[str, list[str]] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            category = next(
                (item[k] for k in ("key", "category", "category_name") if k in item), None
            )
            _add(tags, category, item.get("value"))
    elif isinstance(raw, dict):
        for category, value in raw.items():
            for single in value if isinstance(value, list) else [value]:
                _add(tags, category, single)
    return {cat: vals for cat, vals in tags.items() if vals}


def check_stored_tags(tags: dict[str, list[str]]) -> dict[str, list[str]]:
    """Strict validation for the model field: reject rather than silently trim."""
    if len(tags) > MAX_TAG_CATEGORIES:
        raise ValueError(f"at most {MAX_TAG_CATEGORIES} tag categories")
    for category, values in tags.items():
        if clean_text(category, MAX_CATEGORY_CHARS) != category:
            raise ValueError(f"invalid tag category {category!r}")
        if len(values) > MAX_TAG_VALUES:
            raise ValueError(f"at most {MAX_TAG_VALUES} values per tag category")
        for value in values:
            if clean_text(value, MAX_VALUE_CHARS) != value:
                raise ValueError(f"invalid tag value {value!r} in {category!r}")
    return tags


def validate_tag_filter(tags: Any) -> dict[str, list[str]]:
    """An import filter: ``{category: [values]}``, trimmed and de-duplicated.

    Raises ``ValueError`` with a message naming the problem.
    """
    if not isinstance(tags, dict):
        raise ValueError("tags must be an object of {category: [values]}.")
    if len(tags) > MAX_FILTER_CATEGORIES:
        raise ValueError(f"tags may name at most {MAX_FILTER_CATEGORIES} categories.")
    cleaned: dict[str, list[str]] = {}
    for category, values in tags.items():
        cat = clean_text(category, MAX_CATEGORY_CHARS + 1)
        if cat is None or len(cat) > MAX_CATEGORY_CHARS:
            raise ValueError(f"tag category {str(category)[:40]!r} is empty, too long, or invalid.")
        if not isinstance(values, list) or not values:
            raise ValueError(f"tag category {cat!r} needs a non-empty list of values.")
        if len(values) > MAX_TAG_VALUES:
            raise ValueError(f"tag category {cat!r} may list at most {MAX_TAG_VALUES} values.")
        out: list[str] = []
        for value in values:
            val = clean_text(value, MAX_VALUE_CHARS + 1)
            if val is None or len(val) > MAX_VALUE_CHARS:
                raise ValueError(f"a value for tag {cat!r} is empty, too long, or invalid.")
            if val not in out:
                out.append(val)
        cleaned[cat] = out
    return cleaned
