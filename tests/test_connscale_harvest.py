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


def _run(run_id: int, created: str, status: str = "completed") -> dict[str, Any]:
    return {
        "id": run_id,
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
            return {"workflow_runs": self._page(self.runs, query)}
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
        branch="main",
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
    assert query["branch"] == ["main"]


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
