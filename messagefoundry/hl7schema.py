"""Export HL7 v2.5.1 segment/field/component metadata (from hl7apy) as plain dicts.

Drives the IDE's HL7 field-path autocomplete: the extension ships this JSON and offers paths like
``PID-5.1`` (Family Name) with **no per-keystroke Python**. hl7apy is already a dependency (see
[parsing/validate.py](messagefoundry/parsing/validate.py)); here we walk its reference tree into a
tool-friendly shape. hl7apy's reference format is ``('sequence', (entries...))`` where each entry is
``(node_id, child, cardinality, kind)`` and ``child`` is either ``('leaf', None, datatype, name,
table, -1)`` or a nested ``('sequence', (...))`` for composite datatypes.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from hl7apy import v2_5_1 as _ref

__all__ = ["hl7_schema", "SUPPORTED_VERSION"]

SUPPORTED_VERSION = "2.5.1"


def _index(node_id: str, fallback: int) -> int:
    """HL7 1-based position from an hl7apy node id (``PID_5`` -> 5), else the walk order."""
    tail = node_id.rsplit("_", 1)[-1]
    return int(tail) if tail.isdigit() else fallback


def _describe(child: Any) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    """Return ``(name, datatype, components)`` for a field/component child node."""
    head = child[0]
    if head == "leaf":  # ('leaf', None, datatype, long_name, table, -1)
        return child[3], child[2], []
    if head == "sequence":  # composite datatype -> expand its components one level
        entries = child[1]
        components: list[dict[str, Any]] = []
        for i, entry in enumerate(entries, start=1):
            cid, cchild = entry[0], entry[1]
            cname, cdt, _ = _describe(cchild)
            components.append({"index": _index(cid, i), "name": cname, "datatype": cdt})
        datatype = entries[0][0].rsplit("_", 1)[0] if entries else None  # e.g. CX_1 -> CX
        return None, datatype, components
    return None, None, []


def _segment_fields(seg_def: Any) -> list[dict[str, Any]]:
    entries = seg_def[1]  # ('sequence', (field_entries...))
    fields: list[dict[str, Any]] = []
    for i, entry in enumerate(entries, start=1):
        fid, child = entry[0], entry[1]
        name, datatype, components = _describe(child)
        fields.append(
            {"index": _index(fid, i), "name": name, "datatype": datatype, "components": components}
        )
    return fields


@lru_cache(maxsize=None)
def hl7_schema(version: str = SUPPORTED_VERSION) -> dict[str, Any]:
    """Segment → fields → components metadata for ``version`` (only 2.5.1 today).

    Shape: ``{"version", "segments": {SEG: {"fields": [{"index", "name", "datatype",
    "components": [{"index", "name", "datatype"}]}]}}}``. Cached (immutable — treat as read-only).
    """
    if version != SUPPORTED_VERSION:
        raise ValueError(
            f"unsupported HL7 version {version!r}; only {SUPPORTED_VERSION} is available"
        )
    segments: dict[str, Any] = {}
    for seg_id, seg_def in _ref.SEGMENTS.items():
        if isinstance(seg_def, tuple) and len(seg_def) == 2 and seg_def[0] == "sequence":
            segments[seg_id] = {"fields": _segment_fields(seg_def)}
    return {"version": version, "segments": segments}
