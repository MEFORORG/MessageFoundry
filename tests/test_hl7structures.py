# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HL7 message-structure metadata for the ADR 0104 §2.3 field picker (P2 scope + P3 round-trip gate)."""

from __future__ import annotations

import messagefoundry.generators.adt as adt
from messagefoundry.hl7structures import (
    SENTINEL,
    SUPPORTED_VERSION,
    TRIGGER_TO_STRUCTURE,
    build_trigger_map,
    resolve_structure,
    structure_segments,
    to_json,
    verified_paths,
)


def test_resolve_structure_collapse_and_identity() -> None:
    # Collapsed ADT triggers all resolve to their shared structure (the whole point — a naive lookup misses).
    assert resolve_structure("ADT", "A08") == "ADT_A01"
    assert resolve_structure("ADT", "A04") == "ADT_A01"
    assert resolve_structure("ADT", "A01") == "ADT_A01"
    # Identity inversion covers the non-ADT structures without a per-generator import.
    assert resolve_structure("ORU", "R01") == "ORU_R01"
    assert resolve_structure("SIU", "S12") == "SIU_S12"
    # An unknown/partial type resolves to None (generic scope) — never a WRONG existing structure.
    assert resolve_structure("ADT", "X99") is None
    assert resolve_structure("ADT", None) is None
    assert resolve_structure(None, "A01") is None


def test_trigger_map_keyed_code_caret_trigger() -> None:
    m = build_trigger_map()
    assert m["ADT^A08"] == "ADT_A01"
    assert m["ORU^R01"] == "ORU_R01"
    assert all("^" in key for key in m), "every key is CODE^TRIGGER (not a bare trigger)"


def test_structure_segments_walk_and_dedup() -> None:
    adt_a01 = structure_segments("ADT_A01")
    assert {"MSH", "EVN", "PID", "PV1", "OBX"} <= set(adt_a01)
    assert adt_a01.count("ROL") == 1, "a segment repeated in the structure is de-duplicated"
    assert all(2 <= len(s) <= 4 and s.isalnum() for s in adt_a01), (
        "only real segment ids, no group leaks"
    )
    assert structure_segments("NOPE_X99") == []  # unknown structure -> empty (safe)


def test_single_source_map() -> None:
    # generators/adt.py imports the map from here — there must be exactly ONE (CLAUDE.md: never duplicate).
    # getattr, not attribute access, so mypy's no-implicit-reexport doesn't flag adt's imported name.
    assert getattr(adt, "TRIGGER_TO_STRUCTURE") is TRIGGER_TO_STRUCTURE


def test_verified_paths_readback_gate() -> None:
    v = verified_paths()
    # Common real paths round-trip on both backends.
    assert 3 in v["PID"]["fields"] and "3.1" in v["PID"]["components"]
    assert "5.1" in v["PID"]["components"]
    assert 9 in v["MSH"]["fields"]
    # MSH-1/MSH-2 (the encoding characters) are structurally excluded — never value targets.
    assert 1 not in v["MSH"]["fields"] and 2 not in v["MSH"]["fields"]
    # Padding-tolerant: a high field index (PID-30) round-trips even though set() pads earlier fields — this
    # guards against a byte-diff-vs-baseline gate that would flood false "unverified" badges.
    assert 30 in v["PID"]["fields"]


def test_sentinel_is_delimiter_free() -> None:
    assert SENTINEL and all(c not in SENTINEL for c in "|^~\\&\r\n")


def test_to_json_shape_and_version() -> None:
    j = to_json()
    assert j["version"] == SUPPORTED_VERSION == "2.5.1"
    assert set(j) == {"version", "sentinel", "triggerToStructure", "structureSegments", "verified"}
    assert j["sentinel"] == SENTINEL
