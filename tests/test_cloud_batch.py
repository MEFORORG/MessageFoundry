# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""scripts/coord/cloud_batch.py: the REST await-start and overlap helper for cloud batches.

Each test drives the script through a fake ``gh`` and a fake clock. The fake answers from canned
JSON and pages through lists the way GitHub does. Nothing touches the network, and the deadline
tests take no real time. The fake also reads back the argv the script builds, which holds the
``gh api -X GET`` shape. Three of the last four tests start a real process, and it is this Python.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coord" / "cloud_batch.py"
OWNER = "acme"
REPO = f"{OWNER}/engine"
AUTHOR = "builder-bot"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("coord_cloud_batch", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Registered before exec, so the dataclasses can resolve their postponed annotations.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


cb = _load()


class FakeGh:
    """Answers ``gh api -X GET ENDPOINT -f k=v ...`` from canned JSON.

    A route is a JSON value, or a callable returning one. A list is filtered by the ``state`` and
    ``head`` query parameters and sliced by ``per_page`` and ``page``, as GitHub would, except for
    a parameter named in ``ignore``. Calls whose index is in ``fail`` raise GhError instead.
    """

    def __init__(
        self, routes: dict[str, Any], fail: set[int] | None = None, ignore: set[str] | None = None
    ) -> None:
        self.routes = routes
        self.fail = fail or set()
        self.ignore = ignore or set()
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, argv: list[str]) -> str:
        assert argv[:4] == ["gh", "api", "-X", "GET"], argv
        flags, pairs = argv[5::2], argv[6::2]
        assert set(flags) <= {"-f"} and len(flags) == len(pairs), argv
        endpoint = argv[4]
        params = dict(pair.split("=", 1) for pair in pairs)
        index = len(self.calls)
        self.calls.append((endpoint, params))
        if index in self.fail:
            raise cb.GhError("HTTP 502: Bad Gateway")
        data = self.routes[endpoint]
        if callable(data):
            data = data()
        if isinstance(data, list):
            if params.get("state") in ("open", "closed"):
                data = [d for d in data if d["state"] == params["state"]]
            if "head" in params and "head" not in self.ignore:
                data = [d for d in data if d["head"]["label"] == params["head"]]
            size = int(params["per_page"])
            page = 1 if "page" in self.ignore else int(params["page"])
            data = data[(page - 1) * size : page * size]
        return json.dumps(data)

    def endpoints(self) -> list[str]:
        return [endpoint for endpoint, _ in self.calls]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _pr(
    number: int = 7, *, state: str = "open", ref: str = "cloud/x", owner: str = OWNER
) -> dict[str, Any]:
    head = {"ref": ref, "label": f"{owner}:{ref}"}
    return {"number": number, "state": state, "user": {"login": AUTHOR}, "head": head}


def _await(gh: FakeGh, *args: str, repo: str = REPO) -> tuple[int, str, FakeClock]:
    clock = FakeClock()
    out = io.StringIO()
    argv = ["await-start", "--repo", repo, "--branch", "cloud/x", *args]
    code = cb.main(argv, runner=gh, clock=clock, sleep=clock.sleep, out=out)
    return code, out.getvalue(), clock


def _overlap(gh: FakeGh, *args: str) -> tuple[int, str]:
    out = io.StringIO()
    code = cb.main(["overlap", "--repo", REPO, *args], runner=gh, out=out)
    return code, out.getvalue()


PULLS = f"repos/{REPO}/pulls"
STARTED = f"STARTED pr=7 author={AUTHOR}\n"


# --- await-start -----------------------------------------------------------------------------


def test_a_found_pr_prints_started_with_its_author() -> None:
    gh = FakeGh({PULLS: [_pr()]})
    code, out, clock = _await(gh)
    assert (code, out) == (0, STARTED)
    assert gh.calls == [
        (PULLS, {"state": "open", "head": "acme:cloud/x", "per_page": "100", "page": "1"})
    ]
    assert clock.sleeps == []


def test_a_pr_that_opens_later_is_found_on_a_later_poll() -> None:
    replies = iter([[], [], [_pr()]])
    code, out, clock = _await(FakeGh({PULLS: lambda: next(replies)}))
    assert (code, out) == (0, STARTED)
    assert clock.sleeps == [120, 120]


def test_the_newest_open_pr_wins_when_a_branch_has_two() -> None:
    # GitHub allows one open PR per head and base, so two open PRs on a branch target two bases.
    pulls = [_pr(15), _pr(12)]
    assert _await(FakeGh({PULLS: pulls}))[:2] == (0, f"STARTED pr=15 author={AUTHOR}\n")


def test_a_closed_pr_left_on_a_reused_branch_does_not_count() -> None:
    gh = FakeGh({PULLS: [_pr(state="closed")]})
    assert _await(gh, "--start-deadline-min", "1")[:2] == (2, "LAPSED branch=cloud/x after=1\n")


def test_another_branchs_pr_does_not_count_when_github_ignores_the_head_filter() -> None:
    pulls = [_pr(30, ref="cloud/other"), _pr(40, owner="stranger"), _pr(), _pr(20, ref="x")]
    assert _await(FakeGh({PULLS: pulls}, ignore={"head"}))[:2] == (0, STARTED)


def test_the_owner_matches_the_head_label_in_any_case() -> None:
    # GitHub's head filter ignores the login's case; the label carries its canonical case.
    gh = FakeGh({"repos/ACME/engine/pulls": [_pr()]}, ignore={"head"})
    assert _await(gh, "--start-deadline-min", "1", repo="ACME/engine")[:2] == (0, STARTED)


def test_an_open_pr_wins_over_a_newer_closed_one_on_the_same_branch() -> None:
    pulls = [_pr(number=15, state="closed"), _pr(number=12)]
    assert _await(FakeGh({PULLS: pulls}))[:2] == (0, f"STARTED pr=12 author={AUTHOR}\n")


def test_no_pr_before_the_default_start_deadline_lapses() -> None:
    gh = FakeGh({PULLS: []})
    code, out, clock = _await(gh)
    assert (code, out) == (2, "LAPSED branch=cloud/x after=45\n")
    # A poll at the start and every 120 s after, then a short last sleep to land on 45 minutes.
    assert clock.sleeps == [120] * 22 + [60]
    assert len(gh.calls) == 24


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["await-start", "--repo", "bad", "--branch", "x"], id="bad-repo"),
        pytest.param(
            ["await-start", "--repo", REPO, "--branch", "x", "--interval-sec", "5"],
            id="interval-below-floor",
        ),
        pytest.param(
            ["await-start", "--repo", REPO, "--branch", "x", "--start-deadline-min", "inf"],
            id="infinite-deadline",
        ),
        pytest.param(
            ["await-start", "--repo", REPO, "--branch", "x", "--start-deadline-mins", "5"],
            id="misspelt-option",
        ),
        pytest.param(["overlap", "--repo", REPO, "--path", "./"], id="empty-path"),
        pytest.param(["overlap", "--repo", REPO, "--path", "."], id="dot-path"),
        pytest.param(["overlap", "--repo", REPO, "--path", "a/../b.py"], id="dot-dot-segment"),
        pytest.param(["overlap", "--repo", REPO, "--path", r"D:\repo\x.py"], id="drive-letter"),
        pytest.param(["overlap", "--repo", REPO, "--path", "scripts/*.py"], id="glob"),
        pytest.param([], id="no-subcommand"),
    ],
)
def test_a_usage_error_is_one_error_line_and_never_the_lapsed_code(argv: list[str]) -> None:
    out = io.StringIO()
    gh = FakeGh({})
    code = cb.main(argv, runner=gh, out=out)
    lines = out.getvalue().splitlines()
    assert code == 3
    assert len(lines) == 1 and lines[0].startswith("ERROR usage: "), lines
    assert gh.calls == []


def test_a_usage_error_with_json_is_a_json_error() -> None:
    out = io.StringIO()
    code = cb.main(["overlap", "--repo", "bad", "--path", "x.py", "--json"], out=out)
    assert code == 3
    assert json.loads(out.getvalue())["error"].startswith("usage: ")


def test_the_last_sleep_ends_at_the_start_deadline() -> None:
    gh = FakeGh({PULLS: []})
    code, out, clock = _await(gh, "--start-deadline-min", "5", "--interval-sec", "200")
    assert (code, out) == (2, "LAPSED branch=cloud/x after=5\n")
    assert clock.sleeps == [200, 100]


def test_after_is_rounded_to_a_tenth_of_a_minute() -> None:
    # A real poll takes time, so a real lapse lands a little past the deadline.
    clock = FakeClock()
    out = io.StringIO()
    argv = ["await-start", "--repo", REPO, "--branch", "cloud/x", "--start-deadline-min", "0.5"]

    def slow_gh(argv: list[str]) -> str:
        clock.now += 0.4
        return "[]"

    code = cb.main(argv, runner=slow_gh, clock=clock, sleep=clock.sleep, out=out)
    assert (code, out.getvalue()) == (2, "LAPSED branch=cloud/x after=0.5\n")


def test_a_fractional_deadline_is_reported_as_it_was_given() -> None:
    gh = FakeGh({PULLS: []})
    code, out, clock = _await(gh, "--start-deadline-min", "2.5", "--interval-sec", "60")
    assert (code, out) == (2, "LAPSED branch=cloud/x after=2.5\n")
    assert clock.sleeps == [60, 60, 30]


def test_a_failed_poll_never_sleeps_past_the_deadline() -> None:
    gh = FakeGh({PULLS: []}, fail={0})
    code, out, clock = _await(gh, "--interval-sec", "7200")
    assert (code, out) == (2, "LAPSED branch=cloud/x after=45\n")
    assert clock.sleeps == [2700]


def test_three_failed_polls_in_a_row_is_an_error() -> None:
    gh = FakeGh({PULLS: [_pr()]}, fail={0, 1, 2})
    code, out, _ = _await(gh)
    assert (code, out) == (3, f"ERROR gh api {PULLS}: HTTP 502: Bad Gateway\n")
    assert len(gh.calls) == 3


def test_one_failed_poll_is_retried_at_the_next_interval() -> None:
    gh = FakeGh({PULLS: [_pr()]}, fail={0})
    code, out, clock = _await(gh)
    assert (code, out) == (0, STARTED)
    assert clock.sleeps == [120]


def test_only_consecutive_failures_count() -> None:
    gh = FakeGh({PULLS: []}, fail={0, 1, 3, 4, 6, 7})
    code, out, _ = _await(gh, "--start-deadline-min", "12")
    # A failed poll cannot show there is no PR, so the deadline is judged on the next good one.
    # Past the deadline, a failed poll is retried after MIN_INTERVAL_SEC, not a full interval.
    assert (code, out) == (2, "LAPSED branch=cloud/x after=13\n")
    assert len(gh.calls) == 9


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        pytest.param(
            {"message": "Not Found"}, f"gh api {PULLS}: expected a JSON list", id="object"
        ),
        pytest.param(
            [{"number": 7, "state": "open", "head": {"ref": "cloud/x", "label": "acme:cloud/x"}}],
            "GitHub reply field 'user' is NoneType, not dict",
            id="no-author",
        ),
    ],
)
def test_a_reply_of_the_wrong_shape_is_a_failed_poll(reply: Any, error: str) -> None:
    code, out, _ = _await(FakeGh({PULLS: reply}))
    assert code == 3
    assert out.startswith(f"ERROR {error}"), out


# --- overlap ---------------------------------------------------------------------------------


def _overlap_routes(files: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    routes: dict[str, Any] = {
        f"repos/{REPO}/pulls": [_pr(n, ref=f"branch-{n}") for n in files]
        + [_pr(999, state="closed", ref="old")],
    }
    for number, entries in files.items():
        routes[f"repos/{REPO}/pulls/{number}/files"] = entries
    return routes


def _files(*names: str) -> list[dict[str, Any]]:
    return [{"filename": name} for name in names]


TWO_PRS = {
    11: _files("scripts/coord/cloud_batch.py", "docs/a.md"),
    12: _files("scripts/coord/cloud_batch.py.bak", "scripts/coord", "tests/test_x.py"),
}


def test_overlap_matches_an_exact_path() -> None:
    code, out = _overlap(FakeGh(_overlap_routes(TWO_PRS)), "--path", "scripts/coord/cloud_batch.py")
    assert code == 1
    assert out.splitlines() == [
        "OVERLAP pr=11 branch=branch-11 paths=scripts/coord/cloud_batch.py",
        "scanned 2 open PRs, 5 files",
    ]


def test_overlap_matches_a_directory_prefix() -> None:
    files = {11: _files("tests/test_a.py", "tests/sub/b.py", "testsuite/c.py", "docs/tests/d.md")}
    code, out = _overlap(FakeGh(_overlap_routes(files)), "--path", "tests/")
    assert code == 1
    assert (
        out.splitlines()[0] == "OVERLAP pr=11 branch=branch-11 paths=tests/sub/b.py,tests/test_a.py"
    )


def test_a_directory_matches_without_its_trailing_slash() -> None:
    code, out = _overlap(FakeGh(_overlap_routes(TWO_PRS)), "--path", "tests")
    assert code == 1
    assert out.splitlines()[0] == "OVERLAP pr=12 branch=branch-12 paths=tests/test_x.py"


def test_overlap_matches_a_renamed_files_old_name() -> None:
    renamed = {"filename": "new/name.py", "previous_filename": "old/name.py"}
    code, out = _overlap(FakeGh(_overlap_routes({11: [renamed]})), "--path", "old/name.py")
    assert code == 1
    assert out.splitlines()[0] == "OVERLAP pr=11 branch=branch-11 paths=old/name.py"


def test_a_file_name_cannot_forge_a_line_or_drive_the_terminal() -> None:
    files = {11: _files("tests/a\nOVERLAP pr=1 branch=x paths=y.py\x1b[2J")}
    code, out = _overlap(FakeGh(_overlap_routes(files)), "--path", "tests/")
    assert code == 1
    assert out.splitlines() == [
        "OVERLAP pr=11 branch=branch-11 paths=tests/a OVERLAP pr=1 branch=x paths=y.py [2J",
        "scanned 1 open PRs, 1 files",
    ]


@pytest.mark.parametrize(
    "path",
    [
        r".\scripts\coord\cloud_batch.py",
        "scripts//coord/cloud_batch.py ",
        "/scripts/coord/cloud_batch.py",
    ],
)
def test_a_path_is_normalised_to_githubs_form(path: str) -> None:
    code, out = _overlap(FakeGh(_overlap_routes(TWO_PRS)), "--path", path)
    assert code == 1
    assert (
        out.splitlines()[0] == "OVERLAP pr=11 branch=branch-11 paths=scripts/coord/cloud_batch.py"
    )


def test_no_overlap_exits_zero_with_the_scanned_line() -> None:
    code, out = _overlap(FakeGh(_overlap_routes(TWO_PRS)), "--path", "messagefoundry/")
    assert (code, out) == (0, "scanned 2 open PRs, 5 files\n")


def test_an_empty_scan_still_says_what_it_read() -> None:
    code, out = _overlap(FakeGh({f"repos/{REPO}/pulls": []}), "--path", "x.py")
    assert (code, out) == (0, "scanned 0 open PRs, 0 files\n")


def test_overlap_reads_every_page() -> None:
    names = [f"pkg/f{i:03}.py" for i in range(150)]
    pulls = {n: _files("other.py") for n in range(1, 102)}
    pulls[102] = _files(*names)
    gh = FakeGh(_overlap_routes(pulls))
    code, out = _overlap(gh, "--path", "pkg/f149.py")
    assert code == 1
    assert out.splitlines() == [
        "OVERLAP pr=102 branch=branch-102 paths=pkg/f149.py",
        "scanned 102 open PRs, 251 files",
    ]
    list_pages = [p["page"] for e, p in gh.calls if e == f"repos/{REPO}/pulls"]
    file_pages = [p["page"] for e, p in gh.calls if e == f"repos/{REPO}/pulls/102/files"]
    # The open-PR list is read twice; see the shifting-pages tests below.
    assert (list_pages, file_pages) == (["1", "2", "1", "2"], ["1", "2"])


def test_a_pr_at_the_file_cap_counts_as_an_overlap() -> None:
    files = {11: _files(*(f"gen/f{i:04}.py" for i in range(3050)))}
    gh = FakeGh(_overlap_routes(files))
    code, out = _overlap(gh, "--path", "gen/f3040.py")
    assert code == 1
    assert out.splitlines() == [
        "CAPPED pr=11 branch=branch-11 files=3000 :: GitHub lists at most 3000 files per pull"
        " request; the rest were not checked, so this counts as an overlap",
        "scanned 1 open PRs, 3000 files",
    ]
    assert len([e for e in gh.endpoints() if e.endswith("/files")]) == 30


def _shifting(lists: list[list[dict[str, Any]]], hot: int) -> dict[str, Any]:
    """Routes whose open-PR list is a different list on each read; PR `hot` touches hot.py."""
    replies = iter(lists)
    routes: dict[str, Any] = {PULLS: lambda: next(replies)}
    for n in range(1, 103):
        routes[f"{PULLS}/{n}/files"] = _files("hot.py" if n == hot else "other.py")
    return routes


# GitHub lists open PRs newest first, 100 to a page.
OPEN_101 = [_pr(n, ref=f"branch-{n}") for n in range(101, 0, -1)]
OPEN_102 = [_pr(102, ref="branch-102"), *OPEN_101]


def test_a_pr_repeated_across_shifting_pages_is_scanned_once() -> None:
    # PR 102 opens between the first listing's two page reads, so its page 2 repeats PR 2.
    routes = _shifting([OPEN_101, OPEN_102, OPEN_102, OPEN_102], hot=2)
    code, out = _overlap(FakeGh(routes), "--path", "hot.py")
    assert out.splitlines() == [
        "OVERLAP pr=2 branch=branch-2 paths=hot.py",
        "scanned 102 open PRs, 102 files",
    ]
    assert code == 1


def test_a_pr_hidden_by_a_close_between_pages_is_still_scanned() -> None:
    # PR 50 closes between the first listing's two page reads, so PR 2 moves up into page 1,
    # which was already read. Only the second listing sees PR 2.
    after_close = [p for p in OPEN_102 if p["number"] != 50]
    routes = _shifting([OPEN_102, after_close, after_close, after_close], hot=2)
    code, out = _overlap(FakeGh(routes), "--path", "hot.py")
    assert out.splitlines() == [
        "OVERLAP pr=2 branch=branch-2 paths=hot.py",
        "scanned 102 open PRs, 102 files",
    ]
    assert code == 1


def test_a_list_that_never_ends_is_an_error_not_a_hang() -> None:
    # A proxy that drops the page parameter returns page 1 forever.
    gh = FakeGh({PULLS: OPEN_101}, ignore={"page"})
    code, out = _overlap(gh, "--path", "x.py")
    assert (code, out) == (3, f"ERROR gh api {PULLS}: still full after 50 pages\n")
    assert len(gh.calls) == 50


def test_an_excluded_pr_is_not_scanned() -> None:
    gh = FakeGh(_overlap_routes(TWO_PRS))
    code, out = _overlap(gh, "--path", "scripts/coord/cloud_batch.py", "--exclude-pr", "11")
    assert (code, out) == (0, "scanned 1 open PRs, 3 files\n")
    assert f"repos/{REPO}/pulls/11/files" not in gh.endpoints()


def test_overlap_json() -> None:
    gh = FakeGh(_overlap_routes(TWO_PRS))
    code, out = _overlap(gh, "--path", "scripts/", "--json")
    assert code == 1
    assert json.loads(out) == {
        "overlaps": [
            {"pr": 11, "branch": "branch-11", "paths": ["scripts/coord/cloud_batch.py"]},
            {
                "pr": 12,
                "branch": "branch-12",
                "paths": ["scripts/coord", "scripts/coord/cloud_batch.py.bak"],
            },
        ],
        "capped": [],
        "scanned_prs": 2,
        "scanned_files": 5,
    }


FILES_502 = f"gh api repos/{REPO}/pulls/11/files: HTTP 502: Bad Gateway"


# Calls 0 and 1 read the open-PR list twice; call 2 reads PR 11's files.
def test_an_overlap_gh_failure_is_an_error() -> None:
    code, out = _overlap(FakeGh(_overlap_routes(TWO_PRS), fail={2}), "--path", "x.py")
    assert (code, out) == (3, f"ERROR {FILES_502}\n")


def test_an_overlap_gh_failure_is_a_json_error() -> None:
    gh = FakeGh(_overlap_routes(TWO_PRS), fail={2})
    code, out = _overlap(gh, "--path", "x.py", "--json")
    assert (code, json.loads(out)) == (3, {"error": FILES_502})


def test_a_file_entry_without_a_name_is_an_error() -> None:
    code, out = _overlap(FakeGh(_overlap_routes({11: [{"sha": "abc"}]})), "--path", "x.py")
    assert (code, out) == (3, "ERROR GitHub reply field 'filename' is NoneType, not str\n")


# --- the gh runner and the program -----------------------------------------------------------


def test_run_gh_decodes_utf8_whatever_the_locale() -> None:
    child = "import sys; sys.stdout.buffer.write('caf\\u00e9 \\u2192'.encode('utf-8'))"
    assert cb.run_gh([sys.executable, "-c", child]) == "caf\u00e9 \u2192"


def test_run_gh_raises_with_the_stderr_of_a_failed_call() -> None:
    child = "import sys; sys.stderr.write('HTTP 404:\\nNot Found'); sys.exit(4)"
    with pytest.raises(cb.GhError, match="exited 4: HTTP 404: Not Found"):
        cb.run_gh([sys.executable, "-c", child])


def test_run_gh_raises_when_the_program_is_missing() -> None:
    with pytest.raises(cb.GhError):
        cb.run_gh(["no-such-program-cloud-batch-test"])


def test_the_script_runs_as_a_program() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "await-start", "--help"],
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "--start-deadline-min" in proc.stdout
