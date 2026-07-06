# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Render a :class:`harness.reconcile.compare.ReconcileResult` as a human report + a JSON artifact."""

from __future__ import annotations

from typing import Any

from harness.reconcile.compare import ReconcileResult


def render_json(result: ReconcileResult) -> dict[str, Any]:
    """A structured artifact: per-connection counts + every mismatch's field-level differences."""
    return {
        "connection": result.connection,
        "clean": result.clean,
        "counts": {
            "matched": len(result.pairs),
            "identical": len(result.pairs) - len(result.mismatched),
            "mismatched": len(result.mismatched),
            "mefor_only": len(result.mefor_only),
            "corepoint_only": len(result.corepoint_only),
            "unkeyed_mefor": result.unkeyed_mefor,
            "unkeyed_corepoint": result.unkeyed_corepoint,
            "duplicate_keys": len(result.duplicate_keys),
        },
        "mismatches": [
            {
                "key": p.key,
                "differences": [
                    {
                        "segment": d.segment,
                        "occurrence": d.occurrence,
                        "field_no": d.field_no,
                        "left": d.left,
                        "right": d.right,
                        "kind": d.kind,
                    }
                    for d in p.differences
                ],
            }
            for p in result.mismatched
        ],
        "mefor_only": result.mefor_only,
        "corepoint_only": result.corepoint_only,
        "duplicate_keys": result.duplicate_keys,
    }


def render_text(result: ReconcileResult, *, max_diffs: int = 20) -> str:
    """A terminal summary: the per-connection counts, then up to ``max_diffs`` mismatched messages with
    their field-level differences (``left`` = MEFOR, ``right`` = Corepoint)."""
    lines = [
        f"Reconcile — connection {result.connection!r}",
        f"  matched={len(result.pairs)} "
        f"identical={len(result.pairs) - len(result.mismatched)} "
        f"mismatched={len(result.mismatched)}",
        f"  mefor_only={len(result.mefor_only)} corepoint_only={len(result.corepoint_only)} "
        f"unkeyed(mefor/corepoint)={result.unkeyed_mefor}/{result.unkeyed_corepoint} "
        f"duplicate_keys={len(result.duplicate_keys)}",
    ]
    for pair in result.mismatched[:max_diffs]:
        lines.append(f"  ✗ {pair.key}:")
        for d in pair.differences:
            lines.append(f"      {d.describe()}")
    if len(result.mismatched) > max_diffs:
        lines.append(f"  … and {len(result.mismatched) - max_diffs} more mismatched message(s)")
    if result.mefor_only:
        lines.append(f"  MEFOR-only keys: {', '.join(result.mefor_only[:20])}")
    if result.corepoint_only:
        lines.append(f"  Corepoint-only keys: {', '.join(result.corepoint_only[:20])}")
    lines.append(f"  RESULT: {'CLEAN ✓' if result.clean else 'DIFFERENCES ✗'}")
    return "\n".join(lines)
