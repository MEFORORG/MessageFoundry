# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The status page says how the engine process was started (vault BACKLOG #2701, #2700).

The engine's security posture carries an ``interpreter`` block: whether the interpreter runs in
isolated mode, whether its remote debugging is off, and the start-up code it found. The status
page renders three rows from it.

The states must never render alike. A posture with no reading is a dash in every row, never a
hardened launch, and an interface that is on with no guard does not read like one that is on with
its scripts refused.
"""

from __future__ import annotations

from messagefoundry.api.models import InterpreterView, StartupCodeItemView
from messagefoundry_webconsole.pages.monitoring import _interpreter_rows


def _values(interpreter: InterpreterView | None) -> list[str]:
    return [str(row[1]) for row in _interpreter_rows(interpreter)]


def _view(**overrides: object) -> InterpreterView:
    fields: dict[str, object] = {
        "isolated": True,
        "safe_path": True,
        "ignore_environment": True,
        "no_user_site": True,
        "remote_debug_enabled": False,
        "remote_debug_guard_installed": False,
    }
    return InterpreterView.model_validate({**fields, **overrides})


def test_no_reading_is_a_dash_in_every_row_and_never_a_hardened_launch() -> None:
    absent = _values(None)
    hardened = _values(_view())
    assert len(absent) == 3 and len(set(absent)) == 1
    assert hardened == [
        "yes",
        "off",
        "0 found, 0 not expected; 0 site directories writable by the engine",
    ]
    assert not set(absent) & set(hardened)


def test_a_plain_launch_reads_differently_in_both_rows() -> None:
    guarded = _values(
        _view(isolated=False, remote_debug_enabled=True, remote_debug_guard_installed=True)
    )
    assert guarded[:2] == ["no", "on, injected scripts refused"]
    # The same interface with no hook installed must not read like the guarded one.
    unguarded = _values(_view(isolated=False, remote_debug_enabled=True))
    assert unguarded[1] == "ON, NOT GUARDED"


def test_the_start_up_row_counts_what_was_found_and_what_was_not_expected() -> None:
    known = StartupCodeItemView(
        kind="pth", path="/s/known.pth", verdict="recorded", owner="pkg", expected=True
    )
    planted = StartupCodeItemView(
        kind="sitecustomize", path="/s/sitecustomize.py", verdict="unrecorded", expected=False
    )
    row = _values(_view(startup_code=[known, planted], writable_site_dirs=["/s"]))[2]
    assert row == "2 found, 1 not expected; 1 site directories writable by the engine"
    # The file names stay out of the page: they are in GET /security/posture.
    assert "sitecustomize" not in row
