# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5474: guardrail #4, the release-age step, dates a release by its NEWEST file and
refuses a yanked one.

The step used to take the OLDEST file's upload time (``sort | .[0]``) and never read PyPI's yanked
flag, so a wheel added late to an old release read as old and a yanked release passed. The rows
below marked "was true" returned ``age_ok=true`` through that filter.

The real-jq rows skip where jq is absent (the maintainer's box) and run wherever bash and jq both
exist, as the guardrail file's release-age rows do. The step-running harness, the curl stub and the
age helpers are imported from that file.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

import pytest

from tests import test_dependabot_automerge_guardrails as g

_needs_jq = pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="needs bash + jq, the same runner matrix as the guardrail file's release-age rows",
)

_DEPS = '[{"dependencyName":"requests","newVersion":"2.32.3"}]'
_OLD = g._iso(24 * 30)
_OLDER = g._iso(24 * 40)
_NEW = g._iso(1)
# PyPI drops the fraction when the microseconds are zero.
_OLD_WHOLE_SECOND = (dt.datetime.now(dt.UTC) - dt.timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

# The warning each held row must print, so a row held for an unrelated reason does not pass.
_YANKED = "is yanked on PyPI"
_UNREADABLE = "no readable upload time"
_UNPARSEABLE = "unparseable upload timestamp"
_TOO_YOUNG = "h minimum"


def _payload(files: object, info: object = None) -> str:
    body: dict[str, object] = {"urls": files}
    if info is not None:
        body["info"] = info
    return json.dumps(body)


def _file(stamp: object, **extra: object) -> dict[str, object]:
    return {"upload_time_iso_8601": stamp, **extra}


def _run_age(tmp_path: Path, payload: str) -> g.StepRun:
    run = g._run_step_body(
        "age",
        {"SECURITY_TRACK": "true", "DEP_ECOSYSTEM": "uv", "DEPS_JSON": _DEPS},
        tmp_path,
        path_prepend=g._curl_stub(tmp_path, payload),
    )
    assert run.rc == 0, f"the age body aborted (rc={run.rc}){g._diagnostic(run)}"
    # The verdict counts only if the fixture answered, not live pypi.org (BACKLOG #1312).
    g._assert_the_fixture_answered(tmp_path, run, "requests/2.32.3/json")
    return run


_HELD_ROWS = [
    # (i) was true: an old release with a file uploaded an hour ago read as 30 days old.
    ("old release, new file", _payload([_file(_OLD), _file(_NEW)]), _TOO_YOUNG),
    ("new file listed first", _payload([_file(_NEW), _file(_OLD)]), _TOO_YOUNG),
    # (ii) was true: the yanked flag was never read.
    ("yanked version", _payload([_file(_OLD)], {"yanked": True, "yanked_reason": "bad"}), _YANKED),
    ("one yanked file", _payload([_file(_OLD), _file(_OLDER, yanked=True)], {}), _YANKED),
    # (iii) was true: a bad time that was not the oldest string was never read.
    (
        "unreadable time beside an old one",
        _payload([_file(_OLD), _file("not-a-date")]),
        _UNREADABLE,
    ),
    (
        "impossible date beside an old one",
        _payload([_file(_OLD), _file("2099-13-45T99:99:99Z")]),
        _UNPARSEABLE,
    ),
    ("file list not an array", _payload({"a": _file(_OLD)}), _UNREADABLE),
    ("info not an object", _payload([_file(_OLD)], "x"), _UNREADABLE),
    # Controls that already held at bd89caefe96, kept so the new filter cannot regress them.
    (
        "impossible date as the oldest",
        _payload([_file("2020-02-30T00:00:00Z"), _file(_OLD)]),
        _UNPARSEABLE,
    ),
    ("empty file list", _payload([]), _UNREADABLE),
    ("short time beside an old one", _payload([_file(_OLD), _file("1")]), _UNREADABLE),
    ("no file list", json.dumps({"info": {"yanked": False}}), _UNREADABLE),
    ("a file with no time", _payload([_file(_OLD), {"filename": "x.whl"}]), _UNREADABLE),
    ("a file with a null time", _payload([_file(_OLD), _file(None)]), _UNREADABLE),
    ("a file that is not an object", _payload([_file(_OLD), "x.whl"]), _UNREADABLE),
]


@_needs_jq
@pytest.mark.parametrize(
    ("payload", "reason"),
    [(p, r) for _, p, r in _HELD_ROWS],
    # The payloads carry collection-time timestamps, so the ids must be the stable labels or
    # xdist workers disagree on the test names (the guardrail file's release-age rows say why).
    ids=[label for label, _, _ in _HELD_ROWS],
)
def test_the_release_age_gate_holds_a_late_file_a_yank_and_an_unreadable_list(
    payload: str, reason: str, tmp_path: Path
) -> None:
    run = _run_age(tmp_path, payload)
    assert run.outputs.get("age_ok") == "false", f"{payload}{g._diagnostic(run)}"
    assert reason in run.stdout, f"held, but not for {reason!r}: {payload}{g._diagnostic(run)}"


@_needs_jq
@pytest.mark.parametrize(
    "payload",
    [
        _payload([_file(_OLDER), _file(_OLD)], {"yanked": False}),
        _payload([_file(_OLD), _file(_OLDER)], {"yanked": False, "yanked_reason": None}),
        _payload([_file(_OLD, yanked=False)]),
        _payload([_file(_OLDER), _file(_OLD_WHOLE_SECOND)], {"yanked": False}),
    ],
    ids=["two old files", "newest first, null reason", "no info block", "whole-second time"],
)
def test_a_release_whose_every_file_is_old_and_unyanked_passes_on_its_newest_file(
    payload: str, tmp_path: Path
) -> None:
    """The discriminating PASS: without it a step that denies everything satisfies the rows above.
    The age printed must be the NEWEST file's, which the shared helper derives from the payload."""
    run = _run_age(tmp_path, payload)
    assert run.outputs.get("age_ok") == "true", f"{payload}{g._diagnostic(run)}"
    g._assert_the_age_is_the_fixtures(run, payload)


def test_the_yanked_sentinel_holds_through_the_stubbed_jq(tmp_path: Path) -> None:
    """Runs where jq is absent: the step's own branch for the filter's `YANKED` answer."""
    stub_dir = g._stub_dir(tmp_path, [("requests", "2.32.3")], published="YANKED")
    run = g._run_step_body(
        "age",
        {"SECURITY_TRACK": "true", "DEP_ECOSYSTEM": "uv", "DEPS_JSON": _DEPS},
        tmp_path,
        path_prepend=stub_dir,
    )
    assert run.rc == 0, g._diagnostic(run)
    assert run.outputs.get("age_ok") == "false", g._diagnostic(run)
    assert _YANKED in run.stdout, g._diagnostic(run)
