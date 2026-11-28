# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``auth.lockable_accounts`` row hides what its store driver quotes (BACKLOG #5816).

A fail-before for the fix in engine PR 3019 that needs no overlay: this file imports only names that
exist both at that fix's parent and after it. Before the fix the row interpolated the raw exception,
whole; after it, the text goes through ``safe_exc_detail`` with the driver bound. Measured
2026-11-27: with this file run against a ``git archive`` of ``0198c09b6c`` (the parent) on
``PYTHONPATH``, every case FAILED, the first with ``AssertionError: could not read the accounts:
connection to postgresql://svc:pw-SYNTH-5816_tQ7z@db.invalid:5432/mefor failed``; on the fixed tree
every case passes. Every value here is synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.store import base as store_base
from messagefoundry.verify import checks
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.report import render_json, render_markdown

_PLANTED = "pw-SYNTH-5816_tQ7z"
#: The whole value and each run of it between its hyphens and underscore, so a redaction that stops
#: at one of them and prints the credential's head or tail is caught, not only a whole-value leak.
_FRAGMENTS = (_PLANTED, "pw-", "SYNTH", "5816", "tQ7z")


def _lockable_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> CheckResult:
    """The row, with its store open raising ``exc``; fails unless that open was actually reached."""
    db = tmp_path / "verify.db"
    db.write_bytes(b"")  # past the missing-SQLite-store SKIP, so the open is reached
    calls: list[object] = []

    async def leaky_open(*_a: object, **_k: object) -> object:
        calls.append(None)
        raise exc

    monkeypatch.setattr(store_base, "open_store", leaky_open)
    r = checks.check_lockable_accounts(StoreSettings(path=str(db)), AuthSettings())
    # Without this, a missed patch still yields an ERROR with the same prefix (the real read-only
    # open of the empty file succeeds, and the census read then fails on the missing tables), which
    # quotes nothing planted, so every absence assert below would pass vacuously.
    assert calls, "the planted store open was never called"
    assert r.status is Status.ERROR, r
    assert r.detail.startswith("could not read the accounts: "), r.detail
    return r


def _assert_absent(r: CheckResult, needles: tuple[str, ...]) -> None:
    # The rendered reports are what an operator pastes into a ticket; check them, not only the field.
    for text in (r.detail, render_json([r]), render_markdown([r])):
        for needle in needles:
            assert needle not in text, text


@pytest.mark.parametrize(
    ("leak", "witness"),
    [
        (f"connection to postgresql://svc:{_PLANTED}@db.invalid:5432/mefor failed", "db.invalid"),
        (f"Server=db.invalid;UID=svc;PWD={_PLANTED};", "UID=svc"),
        (f"password={_PLANTED}", "password="),
    ],
    ids=["dsn", "odbc", "kv"],
)
def test_a_store_open_failure_does_not_quote_the_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leak: str, witness: str
) -> None:
    r = _lockable_row(tmp_path, monkeypatch, RuntimeError(leak))
    assert witness in r.detail, r.detail  # the leak's own text reached the row
    _assert_absent(r, _FRAGMENTS)


def test_a_decode_failure_does_not_quote_the_stored_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decode error's own ``str()`` quotes the offending byte (``0xff``), a byte of the stored
    value; the fixed row names the codec, the position and the reason, and no byte of the value."""
    exc = UnicodeDecodeError("utf-8", b"PID|1||SYNTH^\xff", 13, 14, "invalid start byte")
    assert "0xff" in str(exc)  # control: the raw rendering does quote it
    r = _lockable_row(tmp_path, monkeypatch, exc)
    assert "position 13" in r.detail, r.detail
    _assert_absent(
        r, ("0xff", "\\xff", "SYNTH", "PID|1", "ÿ", "\\u00ff", "�", "\\ufffd", "\\udcff")
    )


def test_a_long_driver_failure_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A driver's multi-kilobyte trace is cut, not copied whole into the ticket-facing detail."""
    raw = "server closed the connection near statement 42; " * 400
    r = _lockable_row(tmp_path, monkeypatch, RuntimeError(raw))
    assert "server closed the connection" in r.detail, r.detail
    assert len(r.detail) < len(raw) // 4, len(r.detail)
