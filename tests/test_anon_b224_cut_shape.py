# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The check for a shape cut across fields decodes escapes too (BACKLOG #5533 item 8, cut-shape
limb).

Under a field separator of ``-``, ``ZZZ-1-123-45\\X2D\\6789`` holds a dashed SSN as two fields, the
second with its dash escaped. No one field holds the shape, as written or decoded, and the line as
written holds no dashed SSN either, so both anonymizers emitted it. The cut-shape check now also
reads the line with each field decoded, counting a cut only where two fields meet.

Every value here is synthetic: made-up numbers in the shapes the detectors match.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import leak as engine_leak
from tee.anon import leak as tee_leak
from tests.test_anon_core import _NO_SCANNER

_SALT = "b224-cut-salt-0123456789abcdef"
_DASH_HEAD = "MSH-^~\\&-A-B-C-D-20260101--ORU^R01-M1-P-2.5.1\rPID-1--1^^^H^MR--X^Y"
_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])


@_LEAKS
@pytest.mark.parametrize(
    ("line", "hit"),
    [
        ("ZZZ-1-123-45\\X2D\\6789", "SSN-shaped value across ZZZ-2 to ZZZ-3"),
        ("ZZZ-1-123\\X2D\\45-6789", "SSN-shaped value across ZZZ-2 to ZZZ-3"),
        ("ZZZ-1-555-555\\X2D\\0100", "phone-shaped value across ZZZ-2 to ZZZ-3"),
        ("ZZZ-1-\\X313233\\-45-6789", "SSN-shaped value across ZZZ-2 to ZZZ-4"),
    ],
    ids=["ssn-tail", "ssn-head", "phone", "all-hex-digits"],
)
def test_an_escaped_shape_cut_by_the_field_separator_is_a_hit(
    leak: ModuleType, line: str, hit: str
) -> None:
    hits = leak.structural_phi_hits(f"{_DASH_HEAD}\r{line}", set())
    assert any(hit in h and "cut by the field separator" in h for h in hits), hits
    assert not any("6789" in h or "0100" in h for h in hits), hits


@_LEAKS
def test_an_escaped_field_separator_inside_one_field_is_no_cut(leak: ModuleType) -> None:
    """``\\F\\`` decodes to the field separator inside one field. That field holds the shape whole,
    so the one-field detector names it, and the cut check does not call it cut."""
    hits = leak.structural_phi_hits(f"{_DASH_HEAD}\rZZZ-1-123\\F\\45\\F\\6789", set())
    assert any("SSN-shaped value in ZZZ-2" in h for h in hits), hits
    assert not any("cut by the field separator" in h for h in hits), hits


@_LEAKS
@pytest.mark.parametrize("line", ["ZZZ-1-12-45\\X2D\\6789", "ZZZ-1-123-45\\X2E\\6789"])
def test_an_escaped_near_miss_is_no_hit(leak: ModuleType, line: str) -> None:
    assert leak.structural_phi_hits(f"{_DASH_HEAD}\r{line}", {"PID-3"}) == []


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_refuses_an_escaped_cut_shape(anon: ModuleType) -> None:
    with pytest.raises(anon.LeakError, match="SSN-shaped value across ZZZ-2 to ZZZ-3") as exc:
        anon.anonymize_checked(f"{_DASH_HEAD}\rZZZ-1-123-45\\X2D\\6789", salt=_SALT)
    assert "6789" not in str(exc.value)
