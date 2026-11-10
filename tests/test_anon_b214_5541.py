# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tee's leak-check reads the token tables from its guard at each scan (BACKLOG #5541).

``tee/anon/leak.py`` copied the guard's name and estate tables once, at import, but read the
guard's liveness flag at each report. After a ``reload_tokens()`` on that guard the two disagreed:
a report could scan with the tables of import time, find nothing, and still call the denylist live.
With no guard at all, the report's reason said the check was refusing, while nothing refused
unless the caller passed ``require_live_denylist=True``. Whether that should refuse by default is
a design question this row does not change; these tests pin what the opt-in does.

The tokens are made up for these tests and loaded inline; neither is a real partner or vendor name.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import ModuleType

import pytest

import tee.anon as tee_anon
from tee.anon import leak as tee_leak

_SALT = "b214-5541-salt-0123456789abcdef"
_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
#: A sectioned token source with every floor section filled, so the guard's floor check passes.
_TOKENS = (
    "[names]\nzqsynthpartner | synthetic partner\n[estate]\nzqsynthestate\n[site_prefix]\n97\n"
)


@pytest.fixture
def reloaded_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    """The tee's own guard instance, reloaded from the made-up token source. On the way out the
    environment goes back and the guard is reloaded under it, so no other test sees these tables."""
    guard = tee_leak._GUARD
    if guard is None:
        pytest.skip("no publish guard reachable (an installed wheel has no scripts/security)")
    assert isinstance(guard, ModuleType)
    before = (tee_leak.estate_tokens(), guard.TOKENS_PRESENT)
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", _TOKENS)
    guard.reload_tokens()
    try:
        yield guard
    finally:
        monkeypatch.undo()
        guard.reload_tokens()
    # The guard is shared by the whole session, so its tables must be what they were.
    assert (tee_leak.estate_tokens(), guard.TOKENS_PRESENT) == before


def test_a_reload_of_the_guard_reaches_the_scan(reloaded_guard: ModuleType) -> None:
    report = tee_leak.leak_report(f"{_HEAD}\rZPD|1|ZQSYNTHPARTNER^zqsynthestate")
    assert tee_leak.denylist_is_live(report)
    assert "synthetic partner" in report.hits
    assert "estate token (zqsynthestate)" in report.hits


def test_no_guard_reports_structural_only_and_refuses_only_on_the_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tee_leak, "_GUARD", None)
    assert tee_leak.forbidden_names() == [] and tee_leak.estate_tokens() == ()
    clean = f"{_HEAD}\rPV2|1"
    report = tee_leak.leak_report(clean, rules=tee_anon.DEFAULT_RULES)
    assert report.token_tables_live is False
    reason = report.token_floor_reason or ""
    assert "no publish guard reachable" in reason
    # The reason says what ran. It once said "refusing", and by default nothing refuses.
    assert "refusing" not in reason and "structural-only" in reason
    assert tee_leak.denylist_is_live(report) is False
    # The documented default: a guardless run is reported, not refused.
    assert tee_anon.anonymize_checked(clean, salt=_SALT)
    # The opt-in refuses, naming the reason and no field value.
    with pytest.raises(tee_anon.LeakError, match="denylist not live: no publish guard reachable"):
        tee_anon.anonymize_checked(clean, salt=_SALT, require_live_denylist=True)
