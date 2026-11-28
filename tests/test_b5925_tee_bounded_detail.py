# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5925 closing step 5: the off-box audit tee's ``detail`` is bounded knowing its bound
note follows the head, as :func:`messagefoundry.redaction.safe_text` bounds it.

The tee built ``safe_text(head) + note``, so a value the 64 KiB cut left last was judged as ending
the text and printed (``a|b|mrn: 12345`` then the cut), where ``safe_text`` of the same value masks
it. Synthetic values only."""

from __future__ import annotations

import json

import pytest

from messagefoundry.redaction import safe_text, safe_text_bound
from messagefoundry.store import audit_tee

#: A value the cut leaves last, then a run the bound drops: synthetic.
_FILLER = " " + "q" * 70_000


def _shipped_detail(detail: str, monkeypatch: pytest.MonkeyPatch) -> str:
    lines: list[str] = []

    class _Capture:
        def info(self, line: str) -> None:
            lines.append(line)

    monkeypatch.setattr(audit_tee, "audit_logger", _Capture())
    monkeypatch.setattr(audit_tee, "ensure_logger_sink", lambda _logger: None)
    audit_tee.emit_audit_tee(
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash="0" * 64,
        action="auth.login_failed",
        actor="alice",
        channel_id=None,
        client=None,
        detail=detail,
    )
    (line,) = lines
    shipped = json.loads(line)["detail"]
    assert isinstance(shipped, str)
    return shipped


@pytest.mark.parametrize("value", ["a|b|mrn: 12345", "x^y^token= 4455abc", "a|b|password: 4455"])
def test_a_value_the_bound_leaves_last_is_masked_in_the_tee(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    detail = value + _FILLER
    _head, note = safe_text_bound(detail)
    assert note  # the premise: the bound cut the detail
    digits = "".join(c for c in value.rsplit(" ", 1)[-1] if c.isdigit())
    assert digits in safe_text(value)  # the premise: the value prints where it ends the text
    shipped = _shipped_detail(detail, monkeypatch)
    assert digits not in shipped, shipped
    assert shipped == safe_text(detail)
    assert shipped.endswith(note)


def test_a_scrubbed_detail_is_bounded_knowing_the_note_follows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A detail holding a C0 control takes the field scrub, then :func:`audit_tee._bounded_detail`.
    The value the cut left last does not print, whether the detail ships scrubbed or whole."""
    shipped = _shipped_detail("\x01 a|b|mrn: 12345" + _FILLER, monkeypatch)
    assert "12345" not in shipped, shipped


@pytest.mark.parametrize("kept", ["a|b|mrn: 12345", "plain words", "[redacted] x", ""])
def test_with_no_note_the_bounded_detail_is_safe_text(kept: str) -> None:
    """The no-note case is ``safe_text(kept)`` exactly, as before."""
    assert audit_tee._bounded_detail(kept, "", "") == safe_text(kept)


def test_with_a_note_the_bounded_detail_masks_the_last_value() -> None:
    note = safe_text_bound("a|b|mrn: 12345" + _FILLER)[1]
    shipped = audit_tee._bounded_detail("a|b|mrn: 12345", note, "")
    assert "12345" not in shipped and shipped.endswith(note), shipped
