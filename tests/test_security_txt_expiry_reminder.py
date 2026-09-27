# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``security.txt`` renewal reminder reads the date right and goes red when it should.

BACKLOG #277, Lane 2. ``scripts/security/security_txt_expiry.py`` is run by
``.github/workflows/security-txt-renewal.yml`` on a weekly cron, and nightly-notice turns its red
into an issue. That chain only runs on ``main``, weekly, so a parsing mistake would first show as a
reminder that never fires, which looks exactly like a date that is still far away. These rows pin
the parsing and the window here instead, against planted text and a fixed "now".

The workflow wiring is pinned too, because the two ways it could go wrong are both silent: a
``pull_request`` trigger would make a date reminder red every pull request in the window, and a
watch list that dropped the workflow's name would leave the red reaching nobody.

The check that the REAL file stays readable by this script lives in
``tests/test_security_txt_rfc9116.py``, not here. This module runs in the path-gated tooling tier,
which an edit to ``.well-known/`` alone does not trip; that one runs on every pull request.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from scripts.security.security_txt_expiry import (
    LEAD_DAYS,
    ExpiresError,
    main,
    parse_expires,
    renewal_due,
    run_guarded,
)

# The workflow helpers are imported inside the two workflow rows, not here: the helper module
# skips on import when PyYAML is absent, and the parser rows below need no YAML at all.
_WORKFLOW = "security-txt-renewal.yml"

_EXPIRES = dt.datetime(2030, 6, 1, tzinfo=dt.UTC)
_PLANTED = (
    "# Expires: 1999-01-01T00:00:00Z is a comment and must be skipped\n"
    "\n"
    "Contact: mailto:a@example.com\n"
    "expires: 2030-06-01T00:00:00.000Z\n"
)


def test_it_reads_the_one_expires_and_skips_comments() -> None:
    """Positive control. The comment carries a PAST date, so a parser that read it would be caught."""
    assert parse_expires(_PLANTED) == _EXPIRES


@pytest.mark.parametrize(
    "value",
    [
        "2030-06-01T02:00:00+02:00",  # an offset other than Z is honoured
        "2030-06-01t00:00:00z",  # RFC 3339 allows lowercase; fromisoformat alone does not
        "2030-06-01T00:00:00.000Z",
    ],
)
def test_every_rfc3339_spelling_reads_as_the_same_instant(value: str) -> None:
    assert parse_expires(f"Expires: {value}\n") == _EXPIRES


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Contact: mailto:a@example.com\n", id="none"),
        pytest.param("Expires: 2030-06-01T00:00:00Z\nExpires: 2031-06-01T00:00:00Z\n", id="two"),
        pytest.param("Expires: next June\n", id="not-a-timestamp"),
        pytest.param("Expires: 2030-06-01T00:00:00\n", id="no-offset"),
        # fromisoformat accepts the next four on 3.14 and RFC 3339 does not, so a strict reader
        # would reject a renewal written this way while a lenient reminder stayed green.
        pytest.param("Expires: 2030-06-01\n", id="date-only"),
        pytest.param("Expires: 2030-06-01T00:00Z\n", id="no-seconds"),
        pytest.param("Expires: 20300601T000000Z\n", id="basic-format"),
        pytest.param("Expires: 2030-06-01T00:00:00+0200\n", id="offset-without-colon"),
        pytest.param("Expires: 2030-13-01T00:00:00Z\n", id="month-13"),
    ],
)
def test_a_file_it_cannot_read_raises_rather_than_guessing(text: str) -> None:
    with pytest.raises(ExpiresError):
        parse_expires(text)


@pytest.mark.parametrize(
    ("days_before", "due"),
    [
        (LEAD_DAYS + 1, False),
        (LEAD_DAYS, True),  # the boundary is inside the window
        (1, True),
        (0, True),
        (-10, True),  # already expired stays red
    ],
)
def test_the_window_opens_lead_days_before_and_stays_open(days_before: int, due: bool) -> None:
    now = _EXPIRES - dt.timedelta(days=days_before)
    assert renewal_due(_EXPIRES, now) is due


def _run(tmp_path: Path, text: str, now: str) -> tuple[int, str]:
    target = tmp_path / "security.txt"
    target.write_text(text, encoding="utf-8")
    summary = tmp_path / "summary.md"
    code = main(["--file", str(target), "--now", now, "--summary", str(summary)])
    return code, summary.read_text(encoding="utf-8")


def test_exit_0_when_the_date_is_far(tmp_path: Path) -> None:
    code, summary = _run(tmp_path, _PLANTED, "2029-01-01T00:00:00Z")
    assert code == 0, summary
    assert "2030-06-01" in summary


def test_exit_1_inside_the_window_names_the_owner_s_act(tmp_path: Path) -> None:
    code, summary = _run(tmp_path, _PLANTED, "2030-05-20T00:00:00Z")
    assert code == 1, summary
    assert "12 day(s)" in summary
    assert "Contact channels" in summary


def test_exit_1_once_expired(tmp_path: Path) -> None:
    code, summary = _run(tmp_path, _PLANTED, "2030-07-01T00:00:00Z")
    assert code == 1, summary
    assert "EXPIRED" in summary


def test_exit_2_when_the_date_cannot_be_read(tmp_path: Path) -> None:
    """A reminder that cannot read the date must not look like one with nothing to say."""
    code, summary = _run(tmp_path, "Contact: mailto:a@example.com\n", "2029-01-01T00:00:00Z")
    assert code == 2, summary
    assert main(["--file", str(tmp_path / "absent.txt"), "--now", "2029-01-01T00:00:00Z"]) == 2


def test_a_file_that_is_not_utf8_is_exit_2_not_renewal_due(tmp_path: Path) -> None:
    """A decode error is a ValueError; left uncaught it would exit 1 and read as "renewal due"."""
    target = tmp_path / "security.txt"
    target.write_bytes(b"# caf\xe9\nExpires: 2030-06-01T00:00:00Z\n")
    assert main(["--file", str(target), "--now", "2029-01-01T00:00:00Z"]) == 2


def test_a_non_ascii_value_is_exit_2_and_does_not_crash_the_print(tmp_path: Path) -> None:
    """A pasted U+2010 hyphen lands in the error text; on a cp1252 console that print used to raise."""
    code, summary = _run(
        tmp_path, f"Expires: 2030{chr(0x2010)}06-01T00:00:00Z\n", "2029-01-01T00:00:00Z"
    )
    assert code == 2, summary


def test_a_crash_is_exit_2_never_the_renewal_due_exit_1(tmp_path: Path) -> None:
    """An uncaught exception exits 1, which tells the reader to renew rather than to fix.

    The crash is real: a lead past ``timedelta``'s range raises OverflowError inside the window
    check, which only runs while the date is still in the future.
    """
    target = tmp_path / "security.txt"
    target.write_text(_PLANTED, encoding="utf-8")
    argv = ["--file", str(target), "--lead-days", "1000000000", "--now", "2029-01-01T00:00:00Z"]
    with pytest.raises(OverflowError):
        main(argv)
    assert run_guarded(argv) == 2


def test_the_workflow_runs_only_on_schedule_and_dispatch() -> None:
    """A pull request or queue trigger would red every merge in the renewal window."""
    from tests._workflow_contexts import triggers_of

    assert set(triggers_of(_WORKFLOW)) == {"schedule", "workflow_dispatch"}


def test_the_workflow_can_go_red_and_reaches_a_person() -> None:
    """Each link in the chain from a red run to an issue, any one of which would break it silently.

    The script must run; nothing may turn its red into a pass (``continue-on-error`` or
    ``|| true``, the obvious response to a weekly red someone finds annoying); nightly-notice must
    watch the workflow; and the job's context must stay on the never-required list, because a
    required context that never reports on a pull request wedges every one.
    """
    from tests._workflow_contexts import context_of, load_workflow, triggers_of
    from tests.test_required_contexts import _MUST_NOT_BE_REQUIRED

    doc = load_workflow(_WORKFLOW)
    jobs = doc["jobs"]
    runs = [str(step.get("run", "")) for job in jobs.values() for step in job.get("steps", [])]
    assert any("scripts/security/security_txt_expiry.py" in run for run in runs), runs
    masked = [
        key
        for key, job in jobs.items()
        if job.get("continue-on-error")
        or any(step.get("continue-on-error") for step in job.get("steps", []))
    ]
    assert not masked, f"continue-on-error on {masked} turns the reminder's red into a pass"
    assert not [run for run in runs if "|| true" in run], "`|| true` turns the red into a pass"

    watched = triggers_of("nightly-notice.yml")["workflow_run"]["workflows"]
    assert doc["name"] in watched, (
        f"nightly-notice.yml watches {watched} but not {doc['name']!r}, so the reminder's red "
        "would reach nobody."
    )
    for key, job in jobs.items():
        assert context_of(key, job) in _MUST_NOT_BE_REQUIRED, (
            f"{context_of(key, job)!r} is not in tests/test_required_contexts.py's "
            "_MUST_NOT_BE_REQUIRED, so nothing stops it being made a required context."
        )
