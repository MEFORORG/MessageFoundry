# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline tests for ``scripts/connscale_harvest.py`` (BACKLOG #1415, build 1).

Every GitHub response here is fixture JSON served by a fake ``Api``, so nothing touches the network.
The fixtures are shaped on real responses read from MEFORORG/MessageFoundry on 2026-09-24: the
``test (<os>, py<ver>)`` job names, the ``connscale-readings-<os>-py<ver>`` artifact names, and an
``empty_claims.json`` payload with its ``herd_floor`` block.

The properties pinned are the three that make this a harvest rather than a sample: an artifact-less
job is counted as unknown and adverse, the two Windows legs never pool, and the two populations never
mix.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts import connscale_harvest as ch

_REPO = "MEFORORG/MessageFoundry"


def _payload(values: dict[str, float | None], *, rate_window: str | None = None) -> dict[str, Any]:
    """An ``empty_claims.json`` payload with one ``herd_floor`` reading per lane."""
    body: dict[str, Any] = {
        "schema_version": 2,
        "metric": "empty_claims_per_msg",
        "context": {"runner_os": "Windows", "cpus": "4"},
        "herd_floor": {
            "base_count": 12,
            "enforced": False,
            "readings": [{"lane": lane, "count": 12, "value": v} for lane, v in values.items()],
        },
        "readings": [],
    }
    if rate_window is not None:
        body["rate_window"] = rate_window
    return body


def _zip(payload: dict[str, Any] | None, *, raw: bytes | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if payload is not None:
            zf.writestr(ch.READINGS_FILE, json.dumps(payload))
        if raw is not None:
            zf.writestr(ch.READINGS_FILE, raw)
    return buf.getvalue()


def _job(
    job_id: int, os_name: str, conclusion: str, start: str, end: str, attempt: int = 1
) -> dict[str, Any]:
    return {
        "id": job_id,
        "name": f"test ({os_name}, py3.14)",
        "status": "completed",
        "conclusion": conclusion,
        "started_at": start,
        "completed_at": end,
        "run_attempt": attempt,
    }


def _artifact(art_id: int, os_name: str, created: str, *, expired: bool = False) -> dict[str, Any]:
    return {
        "id": art_id,
        "name": f"connscale-readings-{os_name}-py3.14",
        "created_at": created,
        "expired": expired,
    }


def _run(
    run_id: int,
    created: str,
    status: str = "completed",
    *,
    event: str = "push",
    head_branch: str = "main",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "event": event,
        "head_branch": head_branch,
        "status": status,
        "conclusion": "success" if status == "completed" else None,
        "created_at": created,
        "head_sha": f"{run_id:040d}",
        "run_attempt": 1,
    }


class FakeApi:
    """Serves fixture JSON keyed by endpoint path, honouring ``page`` so paging is exercised."""

    def __init__(
        self,
        runs: list[dict[str, Any]],
        jobs: dict[int, list[dict[str, Any]]],
        artifacts: dict[int, list[dict[str, Any]]],
        blobs: dict[int, bytes],
        failing_blobs: frozenset[int] = frozenset(),
    ) -> None:
        self.runs, self.jobs, self.artifacts = runs, jobs, artifacts
        self.blobs, self.failing_blobs = blobs, failing_blobs
        self.paths: list[str] = []

    @staticmethod
    def _page(items: list[dict[str, Any]], query: dict[str, list[str]]) -> list[dict[str, Any]]:
        per_page, page = int(query["per_page"][0]), int(query["page"][0])
        return items[(page - 1) * per_page : page * per_page]

    def get_json(self, path: str) -> Any:
        self.paths.append(path)
        split = urlsplit(path)
        query = parse_qs(split.query)
        parts = split.path.split("/")
        if parts[-1] == "runs" and "workflows" in parts:
            # The listing's own branch filter matches a run's head branch and nothing else.
            wanted = query.get("branch")
            runs = [r for r in self.runs if wanted is None or r["head_branch"] in wanted]
            return {"workflow_runs": self._page(runs, query)}
        run_id = int(parts[-2])
        if parts[-1] == "jobs":
            assert query["filter"] == ["all"], "every attempt must be listed, not only the latest"
            return {"jobs": self._page(self.jobs.get(run_id, []), query)}
        if parts[-1] == "artifacts":
            return {"artifacts": self._page(self.artifacts.get(run_id, []), query)}
        raise AssertionError(f"unexpected path {path}")

    def get_bytes(self, path: str) -> bytes:
        self.paths.append(path)
        art_id = int(path.split("/")[-2])
        if art_id in self.failing_blobs:
            raise ch.HarvestError("simulated download failure")
        return self.blobs[art_id]


_SINCE = datetime(2026, 9, 1, tzinfo=UTC)
_UNTIL = datetime(2026, 9, 30, tzinfo=UTC)


def _harvest(api: FakeApi, **kw: Any) -> ch.Harvest:
    return ch.harvest(
        api,
        repo=_REPO,
        workflow="ci.yml",
        branch=kw.pop("branch", None),
        since=kw.pop("since", _SINCE),
        until=kw.pop("until", _UNTIL),
        **kw,
    )


def _fixture() -> FakeApi:
    """One rich run after PR 729, one run before it, one still in progress.

    Run 200 (after PR 729):
      * ubuntu-latest: success, with-tail artifact.
      * windows-2022: success, post-#1420 artifact.
      * windows-2025: attempt 1 FAILED with a with-tail artifact; attempt 2 cancelled, no artifact.
    Run 100 (before PR 729): windows-2022 success, no artifact.
    Run 300: in progress.
    """
    runs = [
        _run(300, "2026-09-20T12:00:00Z", status="in_progress"),
        _run(200, "2026-09-10T10:00:00Z"),
        _run(100, "2026-09-01T09:00:00Z"),
    ]
    jobs = {
        200: [
            _job(1, "ubuntu-latest", "success", "2026-09-10T10:01:00Z", "2026-09-10T10:20:00Z"),
            _job(2, "windows-2022", "success", "2026-09-10T10:01:00Z", "2026-09-10T10:30:00Z"),
            _job(3, "windows-2025", "failure", "2026-09-10T10:01:00Z", "2026-09-10T10:30:00Z"),
            _job(4, "windows-2025", "cancelled", "2026-09-10T11:00:00Z", "2026-09-10T11:05:00Z", 2),
            {"id": 9, "name": "tooling (ubuntu-latest)", "conclusion": "success"},
        ],
        100: [_job(5, "windows-2022", "success", "2026-09-01T09:01:00Z", "2026-09-01T09:30:00Z")],
    }
    artifacts = {
        200: [
            _artifact(11, "ubuntu-latest", "2026-09-10T10:19:00Z"),
            _artifact(12, "windows-2022", "2026-09-10T10:29:00Z"),
            _artifact(13, "windows-2025", "2026-09-10T10:29:00Z"),
            {"id": 19, "name": "tooling-junit-ubuntu-latest", "created_at": "2026-09-10T10:20:00Z"},
        ],
    }
    blobs = {
        11: _zip(_payload({"fixed_aggregate": 40.0, "fixed_per_conn": 46.0})),
        12: _zip(
            _payload(
                {"fixed_aggregate": 28.0, "fixed_per_conn": 48.0},
                rate_window=ch.POST_1420_RATE_WINDOW,
            )
        ),
        13: _zip(_payload({"fixed_aggregate": 13.12, "fixed_per_conn": 34.0})),
    }
    return FakeApi(runs, jobs, artifacts, blobs)


# --- name parsing ------------------------------------------------------------------------------


def test_job_and_artifact_names_resolve_to_the_same_leg() -> None:
    for os_name in ch.EXPECTED_OS_LEGS:
        assert ch.leg_of_job(f"test ({os_name}, py3.14)") == f"{os_name} py3.14"
        assert ch.leg_of_artifact(f"connscale-readings-{os_name}-py3.14") == f"{os_name} py3.14"


def test_the_two_windows_legs_are_two_legs() -> None:
    assert ch.leg_of_job("test (windows-2022, py3.14)") != ch.leg_of_job(
        "test (windows-2025, py3.14)"
    )


def test_other_jobs_and_artifacts_are_not_legs() -> None:
    assert ch.leg_of_job("tooling (ubuntu-latest)") is None
    assert ch.leg_of_job("web console tests (ubuntu-latest, py3.14)") is None
    assert ch.leg_of_artifact("tooling-junit-ubuntu-latest") is None
    assert ch.leg_of_artifact("connscale-readings-") is None


# --- population classification -----------------------------------------------------------------

_AFTER = datetime(2026, 9, 10, tzinfo=UTC)
_BEFORE = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)


@pytest.mark.parametrize("where", ["top", "herd_floor", "context"])
def test_post_1420_is_recognised_wherever_the_field_lands(where: str) -> None:
    payload = _payload({"fixed_aggregate": 1.0})
    holder = payload if where == "top" else payload[where]
    holder["rate_window"] = ch.POST_1420_RATE_WINDOW
    assert ch.classify(payload, _AFTER)[0] == ch.POST_1420


def test_post_1420_does_not_depend_on_the_with_tail_floor() -> None:
    payload = _payload({"fixed_aggregate": 1.0}, rate_window=ch.POST_1420_RATE_WINDOW)
    assert ch.classify(payload, _BEFORE)[0] == ch.POST_1420


def test_absent_field_is_with_tail_only_after_pr_729() -> None:
    payload = _payload({"fixed_aggregate": 1.0})
    assert ch.classify(payload, _AFTER)[0] == ch.WITH_TAIL
    population, reason = ch.classify(payload, _BEFORE)
    assert population is None
    assert "PR 729" in reason
    assert ch.classify(payload, ch.WITH_TAIL_FLOOR)[0] is None


def test_an_unrecognised_rate_window_is_excluded_not_guessed() -> None:
    payload = _payload({"fixed_aggregate": 1.0}, rate_window="whole_step")
    population, reason = ch.classify(payload, _AFTER)
    assert population is None
    assert "whole_step" in reason


def test_two_different_rate_windows_in_one_payload_are_excluded() -> None:
    payload = _payload({"fixed_aggregate": 1.0}, rate_window=ch.POST_1420_RATE_WINDOW)
    payload["context"]["rate_window"] = "whole_step"
    assert ch.classify(payload, _AFTER)[0] is None


# --- the end-to-end join -----------------------------------------------------------------------


def _outcomes(result: ch.Harvest) -> dict[int, ch.JobOutcome]:
    return {j.job_id: j for j in result.jobs}


def test_every_connscale_job_is_accounted_for() -> None:
    result = _harvest(_fixture())
    assert result.runs_scanned == [200, 100]
    assert result.runs_not_completed == [300]
    assert sorted(_outcomes(result)) == [1, 2, 3, 4, 5]


def test_artifacts_join_to_their_own_job_and_population() -> None:
    by_job = _outcomes(_harvest(_fixture()))
    assert (by_job[1].status, by_job[1].population) == ("harvested", ch.WITH_TAIL)
    assert (by_job[2].status, by_job[2].population) == ("harvested", ch.POST_1420)
    # Attempt 1's artifact joins attempt 1's job by time, not attempt 2's.
    assert (by_job[3].status, by_job[3].conclusion, by_job[3].artifact_id) == (
        "harvested",
        "failure",
        13,
    )


def test_an_artifact_less_job_is_unknown_and_adverse() -> None:
    job = _outcomes(_harvest(_fixture()))[4]
    assert (job.status, job.reason, job.conclusion, job.run_attempt) == (
        "unknown_adverse",
        "no artifact",
        "cancelled",
        2,
    )


def test_an_artifact_less_job_before_pr_729_is_excluded_not_adverse() -> None:
    job = _outcomes(_harvest(_fixture()))[5]
    assert job.status == "excluded"
    assert "PR 729" in job.reason


def test_readings_carry_the_job_conclusion_from_the_jobs_api() -> None:
    readings = _harvest(_fixture()).readings
    by_leg = {(r.leg, r.lane): r for r in readings}
    assert by_leg[("windows-2025 py3.14", "fixed_aggregate")].job_conclusion == "failure"
    assert by_leg[("windows-2025 py3.14", "fixed_aggregate")].value == 13.12
    assert by_leg[("ubuntu-latest py3.14", "fixed_aggregate")].job_conclusion == "success"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("bad_zip", "artifact unreadable"),
        ("no_file", "artifact unreadable"),
        ("bad_json", "artifact unreadable"),
        ("no_herd_floor", "payload carries no usable herd_floor readings"),
        ("text_value", "payload carries no usable herd_floor readings"),
        ("empty_herd_floor", "payload carries no usable herd_floor readings"),
    ],
)
def test_every_unreadable_artifact_is_unknown_and_adverse(change: str, reason: str) -> None:
    api = _fixture()
    if change == "bad_zip":
        api.blobs[11] = b"not a zip"
    elif change == "no_file":
        api.blobs[11] = _zip(None)
    elif change == "bad_json":
        api.blobs[11] = _zip(None, raw=b"{truncated")
    elif change == "no_herd_floor":
        api.blobs[11] = _zip({"schema_version": 2, "readings": []})
    elif change == "empty_herd_floor":
        api.blobs[11] = _zip(_payload({}))
    elif change == "text_value":
        payload = _payload({"fixed_aggregate": 1.0})
        payload["herd_floor"]["readings"][0]["value"] = "fast"
        api.blobs[11] = _zip(payload)
    job = _outcomes(_harvest(api))[1]
    assert (job.status, job.reason) == ("unknown_adverse", reason)


def test_a_download_failure_is_the_readers_and_is_not_counted_adverse() -> None:
    api = _fixture()
    api.failing_blobs = frozenset({11})
    result = _harvest(api)
    job = _outcomes(result)[1]
    assert (job.status, job.reason) == (ch.READER_ERROR, "artifact download failed")
    assert "INCOMPLETE HARVEST. 1 artifact(s) exist but could not be" in ch.render_markdown(result)
    # It was retried before giving up.
    assert sum(1 for p in api.paths if p.endswith("/11/zip")) == ch._DOWNLOAD_ATTEMPTS


def test_a_scheduled_run_whose_suite_step_skipped_is_excluded_not_adverse() -> None:
    api = _fixture()
    api.jobs[200][3]["steps"] = [{"name": ch.SUITE_STEP, "conclusion": "skipped"}]
    job = _outcomes(_harvest(api))[4]
    assert job.status == "excluded"
    assert "step skipped" in job.reason


def test_a_suite_step_that_ran_leaves_a_missing_artifact_adverse() -> None:
    api = _fixture()
    api.jobs[200][3]["steps"] = [{"name": ch.SUITE_STEP, "conclusion": "cancelled"}]
    assert _outcomes(_harvest(api))[4].status == "unknown_adverse"


def test_a_schema_1_payload_is_excluded_whatever_its_timestamp() -> None:
    api = _fixture()
    api.blobs[11] = _zip({"schema_version": 1, "readings": []})
    job = _outcomes(_harvest(api))[1]
    assert (job.status, job.reason) == ("excluded", "schema 1 payload, from before PR 729")


def test_a_pre_729_run_is_excluded_the_same_way_whatever_went_missing() -> None:
    api = _fixture()
    api.artifacts[100] = [_artifact(16, "windows-2022", "2026-09-01T09:29:00Z")]
    api.blobs[16] = b"not a zip"
    job = _outcomes(_harvest(api))[5]
    assert job.status == "excluded"
    assert job.reason == "artifact unreadable, run from before PR 729"


def test_an_expired_artifact_is_an_incomplete_read_not_a_ci_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = _fixture()
    api.artifacts[200][0]["expired"] = True
    result = _harvest(api)
    job = _outcomes(result)[1]
    assert (job.status, job.reason) == (ch.READER_ERROR, "artifact expired")
    assert not ch.is_complete(result)
    monkeypatch.setattr(ch, "GhApi", lambda: api)
    out = tmp_path / "h.json"
    assert ch.main(["--since", "2026-09-01T00:00:00Z", "--quiet", "--json-out", str(out)]) == 3
    assert json.loads(out.read_text(encoding="utf-8"))["complete"] is False


def test_a_carried_over_job_copy_is_counted_once() -> None:
    api = _fixture()
    # "Re-run failed jobs": attempt 2 lists the untouched ubuntu leg again, new id, same run time.
    copy = dict(api.jobs[200][0], id=21, run_attempt=2)
    api.jobs[200].insert(0, copy)
    result = _harvest(api)
    ubuntu = [j for j in result.jobs if j.leg.startswith("ubuntu")]
    assert [(j.job_id, j.status) for j in ubuntu] == [(1, "harvested")]
    assert result.carried_over_job_copies == 1


def test_a_job_skipped_at_job_level_is_excluded_not_adverse() -> None:
    api = _fixture()
    api.jobs[200][3].update(conclusion="skipped", steps=[])
    job = _outcomes(_harvest(api))[4]
    assert (job.status, job.conclusion) == ("excluded", "skipped")


def test_a_run_from_another_head_repository_is_not_scanned() -> None:
    api = _fixture()
    fork = _run(60, "2026-09-06T00:00:00Z")
    fork["head_repository"] = {"full_name": "someone/MessageFoundry"}
    api.runs.append(fork)
    api.jobs[60] = [
        _job(61, "ubuntu-latest", "success", "2026-09-06T00:01:00Z", "2026-09-06T00:20:00Z")
    ]
    result = _harvest(api)
    assert result.runs_from_other_repos == [60]
    assert 60 not in result.runs_scanned
    assert 61 not in _outcomes(result)


def test_an_overflowing_value_is_kept_with_no_value() -> None:
    api = _fixture()
    raw = json.dumps(_payload({"fixed_aggregate": 1.0, "fixed_per_conn": 46.0}))
    api.blobs[11] = _zip(None, raw=raw.replace("1.0", "1" + "0" * 400).encode())
    result = _harvest(api)
    assert _outcomes(result)[1].status == "harvested"
    cells = {(c.leg, c.lane): c for c in ch.summarise(result)}
    assert cells[("ubuntu-latest py3.14", "fixed_aggregate")].n_no_value_passing == 1


def test_a_boolean_count_is_not_a_base_count() -> None:
    api = _fixture()
    payload = _payload({"fixed_aggregate": 40.0})
    payload["herd_floor"]["readings"][0]["count"] = True
    api.blobs[11] = _zip(payload)
    readings = [r for r in _harvest(api).readings if r.job_id == 1]
    # Not N=1, which is what True would pool with; unknown N gets a cell of its own.
    assert [r.count for r in readings] == [None]


def test_payload_text_cannot_shift_the_markdown_columns() -> None:
    api = _fixture()
    payload = _payload({"fixed_aggregate": 40.0}, rate_window=ch.POST_1420_RATE_WINDOW)
    payload["context"]["rate_window"] = "whole_step"
    api.blobs[11] = _zip(payload)
    text = ch.render_markdown(_harvest(api))
    (row,) = [line for line in text.splitlines() if "unrecognised rate_window" in line]
    assert row.replace("\\|", "").count("|") == 6


def test_a_rerun_of_a_pre_729_run_is_not_with_tail_data() -> None:
    api = _fixture()
    api.artifacts[100] = [_artifact(16, "windows-2022", "2026-09-01T09:29:00Z")]
    api.jobs[100][0]["completed_at"] = "2026-09-02T09:30:00Z"
    api.artifacts[100][0]["created_at"] = "2026-09-02T09:29:00Z"
    api.blobs[16] = _zip(_payload({"fixed_aggregate": 1.0}))
    job = _outcomes(_harvest(api))[5]
    assert (job.status, job.reason) == ("excluded", "with-tail run from before PR 729")


def test_a_quick_rerun_does_not_steal_the_previous_attempts_artifact() -> None:
    api = _fixture()
    # Attempt 2 starts 60s after attempt 1 ends, inside the join slack.
    api.jobs[200][3]["started_at"] = "2026-09-10T10:31:00Z"
    api.artifacts[200].append(_artifact(17, "windows-2025", "2026-09-10T10:34:00Z"))
    api.blobs[17] = _zip(_payload({"fixed_aggregate": 30.0, "fixed_per_conn": 40.0}))
    by_job = _outcomes(_harvest(api))
    assert (by_job[3].artifact_id, by_job[3].status) == (13, "harvested")
    assert (by_job[4].artifact_id, by_job[4].status) == (17, "harvested")


def test_with_tail_until_makes_a_missing_field_fail_closed() -> None:
    api = _fixture()
    result = _harvest(api, with_tail_until=datetime(2026, 9, 5, tzinfo=UTC))
    job = _outcomes(result)[1]
    assert (job.status, job.reason) == (
        "excluded",
        "rate_window absent, run after --with-tail-until",
    )
    assert _outcomes(result)[2].population == ch.POST_1420
    assert result.with_tail_until == "2026-09-05T00:00:00Z"


def test_a_duplicated_job_row_is_counted_once() -> None:
    api = _fixture()
    api.jobs[200].append(dict(api.jobs[200][0]))
    result = _harvest(api)
    assert [j.job_id for j in result.jobs].count(1) == 1
    assert sum(1 for r in result.readings if r.job_id == 1) == 2


def test_an_artifact_for_a_leg_with_no_job_says_so() -> None:
    api = _fixture()
    api.jobs[200] = [j for j in api.jobs[200] if "ubuntu" not in str(j["name"])]
    reasons = {a["artifact_id"]: a["reason"] for a in _harvest(api).unjoined_artifacts}
    assert reasons == {11: "no job for its leg"}


def test_an_artifact_outside_every_job_window_is_listed_not_guessed() -> None:
    api = _fixture()
    api.artifacts[200].append(_artifact(14, "windows-2022", "2026-09-10T15:00:00Z"))
    # Read before the join since BACKLOG #2013. It names no attempt, so the time join decides.
    api.blobs[14] = _zip(_payload({"fixed_aggregate": 1.0}))
    result = _harvest(api)
    assert [(a["artifact_id"], a["reason"]) for a in result.unjoined_artifacts] == [
        (14, "no job window contains it")
    ]


def test_a_second_artifact_on_one_job_keeps_the_newer_and_lists_the_older() -> None:
    api = _fixture()
    api.artifacts[200].insert(0, _artifact(15, "ubuntu-latest", "2026-09-10T10:10:00Z"))
    api.blobs[15] = _zip(_payload({"fixed_aggregate": 1.0}))
    result = _harvest(api)
    assert _outcomes(result)[1].artifact_id == 11
    assert [(a["artifact_id"], a["reason"]) for a in result.unjoined_artifacts] == [
        (15, "superseded on its job")
    ]


def test_a_run_with_no_test_job_is_listed() -> None:
    api = _fixture()
    api.runs.append(_run(50, "2026-09-05T00:00:00Z"))
    assert _harvest(api).runs_without_test_jobs == [50]


def test_a_null_reading_is_kept_and_counted() -> None:
    api = _fixture()
    api.blobs[11] = _zip(_payload({"fixed_aggregate": None, "fixed_per_conn": 46.0}))
    cells = {(c.leg, c.lane): c for c in ch.summarise(_harvest(api))}
    cell = cells[("ubuntu-latest py3.14", "fixed_aggregate")]
    assert (cell.n_no_value_passing, cell.n_passing, cell.min) == (1, 0, None)


def test_a_non_finite_reading_never_enters_the_distribution() -> None:
    api = _fixture()
    blob = json.dumps(_payload({"fixed_aggregate": 40.0, "fixed_per_conn": 46.0}))
    api.blobs[11] = _zip(None, raw=blob.replace("40.0", "NaN").encode())
    cells = {(c.leg, c.lane): c for c in ch.summarise(_harvest(api))}
    cell = cells[("ubuntu-latest py3.14", "fixed_aggregate")]
    assert (cell.n_no_value_passing, cell.n_no_value_non_passing, cell.n_passing) == (1, 0, 0)


def test_readings_at_different_base_counts_are_different_cells() -> None:
    api = _fixture()
    payload = _payload({"fixed_aggregate": 30.0})
    payload["herd_floor"]["readings"][0]["count"] = 8
    api.blobs[12] = _zip(payload)
    cells = {(c.leg, c.lane, c.count) for c in ch.summarise(_harvest(api))}
    assert ("ubuntu-latest py3.14", "fixed_aggregate", 12) in cells
    assert ("windows-2022 py3.14", "fixed_aggregate", 8) in cells


# --- window, paging and caps -------------------------------------------------------------------


def test_the_window_is_passed_to_the_api_as_given() -> None:
    api = _fixture()
    _harvest(api, since=datetime(2026, 9, 3, tzinfo=UTC), until=datetime(2026, 9, 4, tzinfo=UTC))
    query = parse_qs(urlsplit(api.paths[0]).query)
    assert query["created"] == ["2026-09-03T00:00:00Z..2026-09-04T00:00:00Z"]
    assert "branch" not in query


def _event_fixture() -> FakeApi:
    """The rich fixture, plus a pull_request run and a merge_group run that each carry a reading."""
    api = _fixture()
    api.runs += [
        _run(400, "2026-09-12T10:00:00Z", event="pull_request", head_branch="feature-x"),
        _run(
            500, "2026-09-12T11:00:00Z", event="merge_group", head_branch="gh-readonly-queue/main/x"
        ),
    ]
    for run_id, art_id, start in ((400, 41, "2026-09-12T10"), (500, 51, "2026-09-12T11")):
        api.jobs[run_id] = [
            _job(run_id, "windows-2022", "success", f"{start}:01:00Z", f"{start}:30:00Z")
        ]
        api.artifacts[run_id] = [_artifact(art_id, "windows-2022", f"{start}:29:00Z")]
        api.blobs[art_id] = _zip(_payload({"fixed_aggregate": 22.0}))
    return api


def test_the_default_harvest_reads_pull_request_and_merge_group_runs() -> None:
    # BACKLOG #1415: a `branch=main` listing keeps only pushes, since neither of these two events
    # carries `main` as its head branch. The default sends no branch filter, so both are scanned.
    result = _harvest(_event_fixture())
    assert {400, 500} <= set(result.runs_scanned)
    harvested = {j.run_id for j in result.jobs if j.status == ch.HARVESTED}
    assert {400, 500} <= harvested
    assert "branch any" in ch.render_markdown(result)


def test_an_explicit_branch_still_filters_and_says_so() -> None:
    # The control arm: the same fixture with the old filter loses both runs, so the test above
    # discriminates and is not passing on a fixture that never carried them.
    api = _event_fixture()
    result = _harvest(api, branch="main")
    assert parse_qs(urlsplit(api.paths[0]).query)["branch"] == ["main"]
    assert not {400, 500} & set(result.runs_scanned)
    assert result.runs_scanned == [200, 100]
    assert "branch main" in ch.render_markdown(result)


def test_main_sends_no_branch_unless_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    apis: list[FakeApi] = []

    def make() -> FakeApi:
        apis.append(_event_fixture())
        return apis[-1]

    monkeypatch.setattr(ch, "GhApi", make)
    window = ["--since", "2026-09-01T00:00:00Z", "--until", "2026-09-30T00:00:00Z", "--quiet"]
    ch.main(window)
    ch.main([*window, "--branch", "main"])
    first, second = (parse_qs(urlsplit(a.paths[0]).query) for a in apis)
    assert "branch" not in first
    assert second["branch"] == ["main"]


def test_max_runs_caps_completed_runs_and_never_selects_on_artifacts() -> None:
    result = _harvest(_fixture(), max_runs=1)
    assert result.runs_scanned == [200]
    assert result.runs_not_completed == [300]
    assert result.stopped_at_max_runs
    assert result.max_runs == 1
    assert not result.listing_may_be_truncated
    assert "max-runs 1, STOPPED BY IT" in ch.render_markdown(result)


def test_paging_reads_past_a_full_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_PER_PAGE", 2)
    api = _fixture()
    api.runs += [_run(40 + i, "2026-09-05T00:00:00Z") for i in range(3)]
    result = _harvest(api)
    assert len(result.runs_scanned) + len(result.runs_not_completed) == 6


def test_a_listing_at_the_api_limit_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ch, "_API_LISTING_LIMIT", 3)
    result = _harvest(_fixture())
    assert result.listing_may_be_truncated
    assert "1,000-result limit" in ch.render_markdown(result)


# --- summary: cells never pool, populations never mix ------------------------------------------


def _reading(population: str, leg: str, value: float | None, conclusion: str) -> ch.BaseReading:
    return ch.BaseReading(
        population=population,
        leg=leg,
        lane="fixed_aggregate",
        count=12,
        value=value,
        job_conclusion=conclusion,
        run_id=1,
        run_attempt=1,
        job_id=1,
        head_sha="0",
        artifact_created_at="2026-09-10T00:00:00Z",
    )


def _result_with(readings: list[ch.BaseReading]) -> ch.Harvest:
    return ch.Harvest(_REPO, "ci.yml", "main", "a", "b", readings=readings)


def test_windows_legs_and_populations_stay_separate_cells() -> None:
    result = _result_with(
        [
            _reading(ch.WITH_TAIL, "windows-2022 py3.14", 10.0, "success"),
            _reading(ch.WITH_TAIL, "windows-2025 py3.14", 20.0, "success"),
            _reading(ch.POST_1420, "windows-2022 py3.14", 30.0, "success"),
        ]
    )
    cells = {(c.population, c.leg): c.median for c in ch.summarise(result)}
    assert cells == {
        (ch.POST_1420, "windows-2022 py3.14"): 30.0,
        (ch.WITH_TAIL, "windows-2022 py3.14"): 10.0,
        (ch.WITH_TAIL, "windows-2025 py3.14"): 20.0,
    }


def test_the_distribution_is_over_passing_jobs_only() -> None:
    result = _result_with(
        [
            _reading(ch.WITH_TAIL, "ubuntu-latest py3.14", 40.0, "success"),
            _reading(ch.WITH_TAIL, "ubuntu-latest py3.14", 50.0, "success"),
            _reading(ch.WITH_TAIL, "ubuntu-latest py3.14", 1.0, "failure"),
        ]
    )
    (cell,) = ch.summarise(result)
    # median_low: a recorded reading, never an average of two.
    assert (cell.n_passing, cell.min, cell.median, cell.n_non_passing) == (2, 40.0, 40.0, 1)


def test_nearest_rank_returns_a_recorded_reading() -> None:
    values = [float(v) for v in range(1, 201)]
    assert ch.nearest_rank(values, 1) == 2.0
    assert ch.nearest_rank(values, 5) == 10.0
    assert ch.nearest_rank([7.0], 1) == 7.0


# --- rendering and CLI -------------------------------------------------------------------------


def test_the_report_states_what_it_did_not_verify_and_which_legs_are_missing() -> None:
    api = _fixture()
    api.jobs[200] = [j for j in api.jobs[200] if "ubuntu" not in str(j["name"])]
    text = ch.render_markdown(_harvest(api))
    assert "PER_LANE_WAKE pin: NOT VERIFIED" in text
    assert "no job found for expected leg(s): ubuntu-latest" in text
    assert "## Population post_1420" in text
    assert "## Population with_tail" in text


def test_main_writes_json_and_prints_markdown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ch, "GhApi", _fixture)
    out = tmp_path / "harvest.json"
    rc = ch.main(["--since", "2026-09-01T00:00:00Z", "--quiet", "--json-out", str(out)])
    assert rc == 0
    assert "connscale base-reading harvest" in capsys.readouterr().out
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["per_lane_wake_pin_verified"] is False
    assert {c["leg"] for c in written["cells"]} == {
        "ubuntu-latest py3.14",
        "windows-2022 py3.14",
        "windows-2025 py3.14",
    }


@pytest.mark.parametrize(
    "argv",
    [
        ["--since", "2026-09-10T00:00:00Z", "--until", "2026-09-01T00:00:00Z"],
        ["--since", "2026-13-01"],
        ["--since", "2026-09-01T00:00:00Z", "--max-runs", "0"],
        ["--since", "2026-09-01T00:00:00Z", "--max-runs", "-1"],
    ],
)
def test_main_refuses_bad_arguments_as_a_usage_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        ch.main(argv)
    assert exc.value.code == 2


def test_gh_failure_raises_rather_than_reading_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["gh"], 1, b"", b"HTTP 404")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ch.HarvestError, match="HTTP 404"):
        ch.GhApi().get_json("repos/x/y")


def test_a_non_json_response_is_a_harvest_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["gh"], 0, b"<html>", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ch.HarvestError, match="not JSON"):
        ch.GhApi().get_json("repos/x/y")


def test_a_response_of_the_wrong_shape_is_a_harvest_error() -> None:
    class ListBody:
        def get_json(self, path: str) -> Any:
            return []

        def get_bytes(self, path: str) -> bytes:
            return b""

    with pytest.raises(ch.HarvestError, match="list of objects"):
        _harvest(ListBody())  # type: ignore[arg-type]


def test_main_reports_an_api_failure_with_a_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Broken:
        def get_json(self, path: str) -> Any:
            raise ch.HarvestError("boom")

        def get_bytes(self, path: str) -> bytes:
            raise ch.HarvestError("boom")

    monkeypatch.setattr(ch, "GhApi", Broken)
    assert ch.main(["--since", "2026-09-01T00:00:00Z", "--quiet"]) == 2
    assert "harvest failed: boom" in capsys.readouterr().err


# --- BACKLOG #2013: the payload names its attempt and job, and records the wake pin -------------


def _with_context(
    values: dict[str, float | None], rate_window: str | None = None, **context: str
) -> bytes:
    payload = _payload(values, rate_window=rate_window)
    payload["context"].update(context)
    return _zip(payload)


def _skewed_rerun(api: FakeApi) -> None:
    """Attempt 2 of windows-2025 starts 10 s after attempt 1 ends, and attempt 1's artifact is
    stamped 20 s after that end: inside attempt 2's run time, so the time join picks attempt 2."""
    api.jobs[200][3]["started_at"] = "2026-09-10T10:30:10Z"
    api.artifacts[200][2]["created_at"] = "2026-09-10T10:30:20Z"


def test_a_payload_that_names_its_attempt_joins_that_attempts_job() -> None:
    api = _fixture()
    _skewed_rerun(api)
    api.blobs[13] = _with_context({"fixed_aggregate": 13.12}, run_attempt="1", job="test")
    by_job = _outcomes(_harvest(api))
    assert (by_job[3].artifact_id, by_job[3].status) == (13, "harvested")
    assert (by_job[4].artifact_id, by_job[4].status) == (None, "unknown_adverse")


def test_without_an_attempt_the_same_artifact_goes_to_the_wrong_job() -> None:
    # The control for the test above: the fixture is what makes the time join go wrong, and it is
    # the attempt in the payload, nothing else, that puts the artifact back on its own job.
    api = _fixture()
    _skewed_rerun(api)
    by_job = _outcomes(_harvest(api))
    assert (by_job[4].artifact_id, by_job[3].artifact_id) == (13, None)


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        ({"run_attempt": "3"}, "payload names run attempt 3; its leg has 0 jobs in it"),
        ({"run_id": "999"}, "payload names run 999, not this one"),
        ({"job": "webconsole"}, "payload names job 'webconsole', not 'test'"),
    ],
)
def test_a_payload_that_names_another_job_is_listed_not_joined(
    context: dict[str, str], reason: str
) -> None:
    api = _fixture()
    api.blobs[13] = _with_context({"fixed_aggregate": 13.12}, **context)
    result = _harvest(api)
    assert [(a["artifact_id"], a["reason"]) for a in result.unjoined_artifacts] == [(13, reason)]
    assert _outcomes(result)[3].status == "unknown_adverse"


def test_a_local_run_names_nothing_and_falls_back_to_the_time_join() -> None:
    api = _fixture()
    api.blobs[13] = _with_context({"fixed_aggregate": 13.12}, run_id="-", run_attempt="-", job="-")
    assert _outcomes(_harvest(api))[3].artifact_id == 13


def _pinned_fixture(pin_13: str) -> FakeApi:
    api = _fixture()
    api.blobs[11] = _with_context({"fixed_aggregate": 40.0}, per_lane_wake="false")
    api.blobs[12] = _with_context(
        {"fixed_aggregate": 28.0}, rate_window=ch.POST_1420_RATE_WINDOW, per_lane_wake="false"
    )
    api.blobs[13] = _with_context({"fixed_aggregate": 13.12}, per_lane_wake=pin_13)
    return api


def test_the_pin_is_verified_only_when_every_harvested_job_records_it() -> None:
    result = _harvest(_pinned_fixture("false"))
    assert ch.pin_verified(result) is True
    assert "PER_LANE_WAKE pin: VERIFIED; all 3 harvested job(s) record false" in (
        ch.render_markdown(result)
    )
    assert ch.to_json_dict(result)["per_lane_wake_pin_verified"] is True
    # One harvested job whose payload records nothing leaves the pin unproven.
    unsaid = _harvest(_pinned_fixture("-"))
    assert ch.pin_verified(unsaid) is False
    assert "NOT VERIFIED by this scan; 2 of 3 harvested job(s) record it" in (
        ch.render_markdown(unsaid)
    )


@pytest.mark.parametrize("pin", ["true", "mixed"])
def test_a_payload_from_another_engine_is_excluded_not_pooled(pin: str) -> None:
    result = _harvest(_pinned_fixture(pin))
    job = _outcomes(result)[3]
    assert (job.status, job.reason, job.per_lane_wake) == (
        "excluded",
        f"per_lane_wake {pin!r}, not the pinned 'false'",
        pin,
    )
    assert not [r for r in result.readings if r.job_id == 3]
    # The two jobs left all record the pin, so what was harvested is still verified.
    assert ch.pin_verified(result) is True


def test_a_boolean_pin_reads_the_same_as_its_text() -> None:
    payload = _payload({"fixed_aggregate": 1.0})
    payload["context"]["per_lane_wake"] = False
    assert ch.payload_per_lane_wake(payload) == "false"
    payload["context"]["per_lane_wake"] = True
    assert ch.payload_per_lane_wake(payload) == "true"


def test_an_empty_harvest_does_not_claim_it_read_a_payload() -> None:
    api = _fixture()
    api.runs = []
    text = ch.render_markdown(_harvest(api))
    assert "PER_LANE_WAKE pin: NOT VERIFIED by this scan; no job was harvested." in text


def test_the_pin_is_judged_per_population_as_well_as_overall() -> None:
    # BACKLOG #1415 fits a floor to ONE population, so the pin it needs is that population's. Here the
    # post_2024 job records false and two older with-tail/post_1420 jobs record nothing: the whole
    # scan is NOT VERIFIED, and the post_2024 population alone is VERIFIED.
    api = _fixture()
    api.blobs[12] = _with_context(
        {"fixed_aggregate": 28.0}, rate_window=ch.POST_2024_RATE_WINDOW, per_lane_wake="false"
    )
    result = _harvest(api)
    assert ch.pin_verified(result) is False
    assert ch.pin_verified(result, ch.POST_2024) is True
    assert ch.pin_verified(result, ch.WITH_TAIL) is False
    text = ch.render_markdown(result)
    assert "pin (post_2024 only): VERIFIED; all 1 harvested job(s) record false." in text
    assert "pin (with_tail only): NOT VERIFIED by this scan; 0 of 2" in text
    assert "pin (post_1420 only)" not in text  # no job in it, so no line about it
    by_population = ch.to_json_dict(result)["per_lane_wake_pin_verified_by_population"]
    assert by_population == {ch.POST_2024: True, ch.POST_1420: False, ch.WITH_TAIL: False}


def test_a_saved_harvest_re_renders_identically_without_the_api() -> None:
    result = _harvest(_pinned_fixture("false"))
    saved = json.loads(json.dumps(ch.to_json_dict(result), sort_keys=True))
    rebuilt = ch.from_json_dict(saved)
    assert ch.render_markdown(rebuilt) == ch.render_markdown(result)
    assert ch.to_json_dict(rebuilt) == saved


def test_a_hand_edited_summary_does_not_survive_a_re_render() -> None:
    saved = ch.to_json_dict(_harvest(_fixture()))
    saved["cells"] = []
    saved["per_lane_wake_pin_verified"] = True
    rebuilt = ch.to_json_dict(ch.from_json_dict(saved))
    assert rebuilt["cells"] and rebuilt["per_lane_wake_pin_verified"] is False


def test_the_csvs_carry_one_row_per_reading_job_and_unjoined_artifact(tmp_path: Path) -> None:
    result = _harvest(_fixture())
    result.unjoined_artifacts.append({"run_id": 1, "artifact_id": 2, "name": "n", "reason": "r"})
    paths = ch.write_csvs(result, tmp_path / "csv")
    rows = {p.name: list(csv.DictReader(p.open(encoding="utf-8"))) for p in paths}
    assert len(rows["readings.csv"]) == len(result.readings) > 0
    assert len(rows["jobs.csv"]) == len(result.jobs) > 0
    assert rows["unjoined.csv"] == [{"run_id": "1", "artifact_id": "2", "name": "n", "reason": "r"}]
    assert {r["value"] for r in rows["readings.csv"]} >= {"13.12", "28.0", "40.0"}


def test_an_empty_table_still_writes_its_header(tmp_path: Path) -> None:
    ch.write_csvs(_result_with([]), tmp_path)
    assert (tmp_path / "readings.csv").read_text(encoding="utf-8").startswith("population,leg,")
    assert (tmp_path / "unjoined.csv").read_text(encoding="utf-8") == (
        "run_id,artifact_id,name,reason\n"
    )


def test_main_re_renders_a_saved_harvest_and_needs_no_since(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = tmp_path / "h.json"
    saved.write_text(json.dumps(ch.to_json_dict(_harvest(_fixture()))), encoding="utf-8")

    def no_api() -> FakeApi:
        raise AssertionError("--from-json must not touch the API")

    monkeypatch.setattr(ch, "GhApi", no_api)
    rc = ch.main(["--from-json", str(saved), "--csv-dir", str(tmp_path / "csv")])
    assert rc == 0
    assert "connscale base-reading harvest" in capsys.readouterr().out
    assert (tmp_path / "csv" / "jobs.csv").is_file()


def test_main_without_since_or_a_saved_harvest_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        ch.main(["--quiet"])
    assert exc.value.code == 2


def test_main_reports_an_unreadable_saved_harvest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert ch.main(["--from-json", str(bad)]) == 2
    assert "cannot read" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flag",
    [
        ["--branch", "main"],
        ["--since", "2026-09-01T00:00:00Z"],
        ["--max-runs", "3"],
        ["--repo", "o/r"],
    ],
)
def test_a_selection_flag_cannot_narrow_a_re_render(tmp_path: Path, flag: list[str]) -> None:
    saved = tmp_path / "h.json"
    saved.write_text(json.dumps(ch.to_json_dict(_harvest(_fixture()))), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        ch.main(["--from-json", str(saved), *flag])
    assert exc.value.code == 2


def test_the_json_is_written_before_a_csv_directory_that_cannot_be(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ch, "GhApi", _fixture)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    out = tmp_path / "h.json"
    argv = ["--since", "2026-09-01T00:00:00Z", "--quiet", "--json-out", str(out)]
    rc = ch.main([*argv, "--csv-dir", str(blocker)])
    assert rc == 2
    assert "cannot write CSVs" in capsys.readouterr().err
    assert json.loads(out.read_text(encoding="utf-8"))["jobs"], "the scan must survive"


def test_payload_text_cannot_run_as_a_spreadsheet_formula(tmp_path: Path) -> None:
    result = _result_with([_reading(ch.POST_2024, "ubuntu-latest py3.14", -1.5, "success")])
    result.readings[0] = dataclasses.replace(result.readings[0], lane="   =HYPERLINK(1)")
    ch.write_csvs(result, tmp_path)
    (row,) = csv.DictReader((tmp_path / "readings.csv").open(encoding="utf-8"))
    assert row["lane"] == "'   =HYPERLINK(1)"  # a trigger behind spaces too: the canonical rule
    assert row["value"] == "-1.5", "a number is never quoted, so a negative reading stays one"


def test_a_saved_row_off_the_csv_header_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = ch.to_json_dict(_harvest(_fixture()))
    saved["unjoined_artifacts"] = [
        {"run_id": 1, "artifact_id": 2, "name": "n", "reason": "r", "x": 1}
    ]
    path = tmp_path / "h.json"
    path.write_text(json.dumps(saved), encoding="utf-8")
    assert ch.main(["--from-json", str(path), "--csv-dir", str(tmp_path / "csv")]) == 2
    assert "cannot write CSVs" in capsys.readouterr().err


def test_the_csv_writer_uses_the_canonical_rule_not_a_copy() -> None:
    # ASVS 1.2.10: tests/test_csv_formula_consistency.py records this writer as routing every cell
    # through the engine's rule. Identity, so a local copy swapped back in reds here.
    # Checked by name, not by import: this test is in the tooling tier, which imports no engine code.
    fn = ch.spreadsheet_safe
    assert (fn.__module__, fn.__qualname__) == ("messagefoundry.spreadsheet", "spreadsheet_safe")
