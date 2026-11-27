# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5474: guardrail #4, the release-age step, dates a release by its NEWEST file and
refuses a yanked one.

The step used to take the OLDEST file's upload time (``sort | .[0]``) and never read PyPI's yanked
flag, so a wheel added late to an old release read as old and a yanked release passed. The rows
below marked "was true" returned ``age_ok=true`` through that filter.

These rows run the step body through REAL jq, so they skip where jq is absent (the maintainer's
box) and run on the CI legs whose images ship it, the same matrix as the guardrail file's
release-age rows. The step-running harness and the curl stub are imported from that file.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import shutil
from pathlib import Path

import pytest

from tests import test_dependabot_automerge_guardrails as g

_DEPS = '[{"dependencyName":"requests","newVersion":"2.32.3"}]'
_OLD = g._iso(24 * 30)
_OLDER = g._iso(24 * 40)
_NEW = g._iso(1)


def _payload(files: list[dict[str, object]], info: dict[str, object] | None = None) -> str:
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
    ("old release, new file", _payload([_file(_OLD), _file(_NEW)])),
    ("new file listed first", _payload([_file(_NEW), _file(_OLD)])),
    # (ii) was true: the yanked flag was never read.
    ("yanked version", _payload([_file(_OLD)], {"yanked": True, "yanked_reason": "bad"})),
    ("one yanked file", _payload([_file(_OLD), _file(_OLDER, yanked=True)], {"yanked": False})),
    # (iii) was true: an unreadable time sorted after a readable old one and was never read.
    ("unreadable time beside an old one", _payload([_file(_OLD), _file("not-a-date")])),
    # Controls that already held at bd89caefe96, kept so the new filter cannot regress them.
    ("empty file list", _payload([])),
    ("short time beside an old one", _payload([_file(_OLD), _file("1")])),
    ("no file list", json.dumps({"info": {"yanked": False}})),
    ("file list not an array", json.dumps({"urls": {"a": _file(_OLD)}})),
    ("a file with no time", _payload([_file(_OLD), {"filename": "x.whl"}])),
    ("a file with a null time", _payload([_file(_OLD), _file(None)])),
    ("a file that is not an object", json.dumps({"urls": [_file(_OLD), "x.whl"]})),
]


@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="needs bash + jq, the same runner matrix as the guardrail file's release-age rows",
)
@pytest.mark.parametrize(
    "payload",
    [p for _, p in _HELD_ROWS],
    # The payloads carry collection-time timestamps, so the ids must be the stable labels or
    # xdist workers disagree on the test names (the guardrail file's release-age rows say why).
    ids=[label for label, _ in _HELD_ROWS],
)
def test_the_release_age_gate_holds_a_late_file_a_yank_and_an_unreadable_list(
    payload: str, tmp_path: Path
) -> None:
    run = _run_age(tmp_path, payload)
    assert run.outputs.get("age_ok") == "false", f"{payload}{g._diagnostic(run)}"


_YANK_WARNING = "is yanked on PyPI"


@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="needs bash + jq, the same runner matrix as the guardrail file's release-age rows",
)
def test_a_yanked_release_is_held_for_the_yank_and_not_for_its_age(tmp_path: Path) -> None:
    """The yank alone holds it: every file is old, so no age rule could."""
    run = _run_age(tmp_path, _payload([_file(_OLD)], {"yanked": True}))
    assert run.outputs.get("age_ok") == "false", g._diagnostic(run)
    assert _YANK_WARNING in run.stdout, g._diagnostic(run)


_STAMP = re.compile(r'"upload_time_iso_8601"\s*:\s*"([^"]+)"')


@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="needs bash + jq, the same runner matrix as the guardrail file's release-age rows",
)
@pytest.mark.parametrize(
    ("files", "info"),
    [
        ([_file(_OLDER), _file(_OLD)], {"yanked": False}),
        ([_file(_OLD), _file(_OLDER)], {"yanked": False, "yanked_reason": None}),
        ([_file(_OLD, yanked=False)], None),
    ],
    ids=["two old files", "newest first, null reason", "no info block"],
)
def test_a_release_whose_every_file_is_old_and_unyanked_passes_on_its_newest_file(
    files: list[dict[str, object]], info: dict[str, object] | None, tmp_path: Path
) -> None:
    """The discriminating PASS: without it a step that denies everything satisfies the rows above.
    The age printed must be the NEWEST file's, not the oldest's."""
    payload = _payload(files, info)
    run = _run_age(tmp_path, payload)
    assert run.outputs.get("age_ok") == "true", f"{payload}{g._diagnostic(run)}"
    newest = max(_STAMP.findall(payload))
    when = dt.datetime.strptime(newest, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.UTC)
    expected = int((dt.datetime.now(dt.UTC) - when).total_seconds() // 3600)
    found = g._AGE_IN_STEP_OUTPUT.search(run.stdout)
    assert found is not None, g._diagnostic(run)
    # An hour of slack, for the reason the guardrail file's `_assert_the_age_is_the_fixtures` gives.
    assert abs(int(found.group(1) or found.group(2)) - expected) <= 1, g._diagnostic(run)


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
    assert _YANK_WARNING in run.stdout, g._diagnostic(run)
