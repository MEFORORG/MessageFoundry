# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The held-PR turn report tells the Lander whose move each PR is, so its classification matters most.

These drive the REAL ``main()`` against canned GraphQL replies through ``--input``, with no network.
The positive control is ``test_classification_keys_on_body_prefix_not_login``: every seat posts under
one GitHub login, so a classifier keyed on the author login would fail it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "coord" / "held_pr_turns.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("held_pr_turns", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


hpt = _load()

ENGINE = hpt.ENGINE_REPO
VAULT = hpt.VAULT_REPO
KORUS = hpt.KORUS_REPO
ENGINE_REQUIRED = ["CI gate", "cla"]
NOW = datetime(2026, 10, 28, 18, 0, 0, tzinfo=UTC)
LOGIN = "wshallwshall"  # every seat posts under this one login


def _sha(n: int) -> str:
    return f"{n:040x}"


def _comment(body: str, at: str, login: str = LOGIN, typename: str = "User") -> dict[str, Any]:
    return {"body": body, "createdAt": at, "author": {"__typename": typename, "login": login}}


def _hold(at: str, sha: str | None, *, still: bool = False) -> dict[str, Any]:
    word = "Still held" if still else "Held, back to the author"
    where = f", at `{sha}`" if sha else ""
    body = (
        f"Lander (session 8a04c9f3), 2026-10-28. **{word}{where}.** Finding 2 changes behaviour; "
        f"the fix commit `abcdef123` is not on the head."
    )
    return _comment(body, at)


def _runs(names: list[str], conclusion: str = "SUCCESS") -> list[dict[str, Any]]:
    return [
        {
            "__typename": "CheckRun",
            "name": n,
            "status": "COMPLETED",
            "conclusion": conclusion,
            "startedAt": "2026-10-28T10:00:00Z",
        }
        for n in names
    ]


def _pr(
    number: int,
    *,
    comments: list[dict[str, Any]] | None = None,
    reviews: list[dict[str, Any]] | None = None,
    head: str | None = None,
    committed: str = "2026-10-28T09:00:00Z",
    runs: list[dict[str, Any]] | None = None,
    draft: bool = False,
) -> dict[str, Any]:
    oid = head or _sha(number)
    return {
        "number": number,
        "title": f"pr {number}",
        "isDraft": draft,
        "baseRefName": "main",
        "headRefOid": oid,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "CLEAN",
        "commits": {
            "nodes": [
                {
                    "commit": {
                        "oid": oid,
                        "committedDate": committed,
                        "statusCheckRollup": {
                            "contexts": {
                                "pageInfo": {"hasNextPage": False},
                                "nodes": _runs(ENGINE_REQUIRED) if runs is None else runs,
                            }
                        },
                    }
                }
            ]
        },
        "comments": {"nodes": comments or []},
        "reviews": {"nodes": reviews or []},
    }


def _page(prs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "data": {
            "repository": {
                "pullRequests": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": prs,
                }
            }
        }
    }


def _run(
    tmp_path: Path,
    doc: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
    *extra: str,
    json_out: bool = True,
) -> tuple[int, Any]:
    path = tmp_path / "input.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    flags = ["--json"] if json_out else []
    code = hpt.main(["--input", str(path), *flags, *extra], now=lambda: NOW)
    out = capsys.readouterr().out
    return code, json.loads(out) if json_out else out


def _engine_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *prs: dict[str, Any]
) -> dict[int, dict[str, Any]]:
    doc = {ENGINE: {"pages": [_page(list(prs))], "required": ENGINE_REQUIRED}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert code == 0
    return {r["number"]: r for r in rows}


def test_no_lander_comment_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    row = _engine_rows(tmp_path, capsys, _pr(1))[1]
    assert (row["turn"], row["flags"]) == ("LANDER", ["no-lander-comment"])
    assert row["requiredGreen"] == "yes"


def test_hold_with_nothing_newer_is_author_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(2, comments=[_hold("2026-10-28T12:00:00Z", _sha(2)[:9])])
    row = _engine_rows(tmp_path, capsys, pr)[2]
    assert (row["turn"], row["flags"]) == ("AUTHOR", ["held"])


def test_hold_then_new_commit_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The committedDate predates the hold (a rebase keeps it), yet the SHA named in the hold differs
    # from the head, which is the stronger signal.
    pr = _pr(
        3,
        comments=[_hold("2026-10-28T12:00:00Z", "f4f4dd470")],
        committed="2026-10-28T08:00:00Z",
    )
    row = _engine_rows(tmp_path, capsys, pr)[3]
    assert (row["turn"], row["flags"]) == ("LANDER", ["new-commit"])


def test_hold_then_manager_comment_same_head_flags_no_new_commit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(
        4,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(4)),
            _comment("Manager, batch 454: ready for landing.", "2026-10-28T13:00:00Z"),
        ],
    )
    row = _engine_rows(tmp_path, capsys, pr)[4]
    assert (row["turn"], row["flags"]) == ("LANDER", ["no-new-commit"])
    assert row["age"] == "5h00m"


def test_still_held_variant_is_a_hold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pr = _pr(
        5,
        comments=[
            _hold("2026-10-28T07:00:00Z", "deadbeef0"),
            _comment("Manager: merged origin/main in.", "2026-10-28T12:00:00Z"),
            _hold("2026-10-28T16:00:00Z", _sha(5), still=True),
        ],
    )
    row = _engine_rows(tmp_path, capsys, pr)[5]
    assert (row["turn"], row["flags"]) == ("AUTHOR", ["held"])


def test_non_hold_lander_comment_latest_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(
        6,
        comments=[
            _hold("2026-10-28T07:00:00Z", _sha(6)),
            _comment("Lander (session 8a04c9f3): reviewing now.", "2026-10-28T09:00:00Z"),
        ],
    )
    row = _engine_rows(tmp_path, capsys, pr)[6]
    assert (row["turn"], row["flags"]) == ("LANDER", ["lander-not-hold"])


def test_classification_keys_on_body_prefix_not_login(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Positive control: the hold and the Manager's reply share one login, and the reply flips the
    turn. A classifier keyed on the login would see only one author and call it AUTHOR's turn. A
    'Lander handover' body is a Manager's, not a Lander comment."""
    pr = _pr(
        7,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(7)),
            _comment("Lander handover from the batch 453 Manager: fixed.", "2026-10-28T13:00:00Z"),
        ],
    )
    other = _pr(8, comments=[_comment("Lander handover: ready.", "2026-10-28T13:00:00Z")])
    rows = _engine_rows(tmp_path, capsys, pr, other)
    assert (rows[7]["turn"], rows[7]["flags"]) == ("LANDER", ["no-new-commit"])
    assert rows[8]["flags"] == ["no-lander-comment"]


def test_review_body_counts_but_bot_and_empty_reviews_do_not(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hold = _hold("2026-10-28T12:00:00Z", _sha(9))
    bot = {
        "body": "<!-- greptile-auto-approve -->",
        "submittedAt": "2026-10-28T14:00:00Z",
        "author": {"__typename": "Bot", "login": "greptile-apps"},
    }
    empty = {"body": "", "submittedAt": "2026-10-28T14:30:00Z", "author": {"__typename": "User"}}
    reply = {
        "body": "Author: fixed, see thread.",
        "submittedAt": "2026-10-28T15:00:00Z",
        "author": {"__typename": "User", "login": LOGIN},
    }
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(9, comments=[hold], reviews=[bot, empty]),
        _pr(10, comments=[_hold("2026-10-28T12:00:00Z", _sha(10))], reviews=[reply]),
    )
    assert (rows[9]["turn"], rows[9]["flags"]) == ("AUTHOR", ["held"])
    assert rows[9]["age"] == "3h30m"  # the ignored events still date the PR
    assert (rows[10]["turn"], rows[10]["flags"]) == ("LANDER", ["no-new-commit"])


def test_hold_without_sha_falls_back_to_commit_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    newer = _pr(
        11, comments=[_hold("2026-10-28T12:00:00Z", None)], committed="2026-10-28T13:00:00Z"
    )
    older = _pr(
        12, comments=[_hold("2026-10-28T12:00:00Z", None)], committed="2026-10-28T11:00:00Z"
    )
    rows = _engine_rows(tmp_path, capsys, newer, older)
    assert (rows[11]["turn"], rows[11]["flags"]) == ("LANDER", ["new-commit", "date-fallback"])
    assert (rows[12]["turn"], rows[12]["flags"]) == ("AUTHOR", ["held", "date-fallback"])


def test_hold_sha_reads_the_headline_only() -> None:
    body = "Lander (session x). **Held, at `1234567ab`.** The fix `fedcba987` is elsewhere."
    assert hpt.hold_sha(body) == "1234567ab"
    assert hpt.hold_sha("Lander (session x). **Held.** See `fedcba987`.") is None


def test_vault_pr_uses_the_vault_required_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    green = _pr(20, runs=_runs(list(hpt.VAULT_REQUIRED)))
    # The engine's contexts are green, but none of the vault's are, so it is not green.
    wrong = _pr(21, runs=_runs(ENGINE_REQUIRED))
    doc = {VAULT: {"pages": [_page([green, wrong])]}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", VAULT)
    assert code == 0
    by = {r["number"]: r for r in rows}
    assert by[20]["requiredGreen"] == "yes"
    assert by[21]["requiredGreen"] == "no"
    assert sorted(by[21]["required"]["missing"]) == sorted(hpt.VAULT_REQUIRED)


def test_required_context_missing_on_head_is_not_green(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(30, runs=_runs(["CI gate"])),
        _pr(31, runs=_runs(["CI gate"]) + _runs(["cla"], conclusion="FAILURE")),
    )
    assert rows[30]["requiredGreen"] == "no"
    assert rows[30]["required"]["missing"] == ["cla"]
    assert rows[31]["requiredGreen"] == "no"
    assert rows[31]["required"]["failing"] == ["cla"]


def test_engine_required_list_unreadable_is_unknown_not_green(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = {ENGINE: {"pages": [_page([_pr(32)])]}}
    _, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert rows[0]["requiredGreen"] == "?"
    assert "required list unreadable" in rows[0]["required"]["reason"]


def test_draft_pr_is_excluded(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows = _engine_rows(tmp_path, capsys, _pr(40, draft=True), _pr(41))
    assert list(rows) == [41]


def test_failed_repo_read_is_an_error_row_and_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = {
        ENGINE: {"error": "gh api graphql exited 1: HTTP 502"},
        VAULT: {"pages": [_page([_pr(50)])]},
        # korus is absent from the file: also an ERROR row, never silently omitted.
    }
    code, rows = _run(tmp_path, doc, capsys)
    assert code == 0
    errors = {r["repo"]: r["error"] for r in rows if r["turn"] == "ERROR"}
    assert set(errors) == {ENGINE, KORUS}
    assert "502" in errors[ENGINE]
    assert rows[0]["turn"] == "ERROR" and rows[1]["turn"] == "ERROR"
    assert [r["number"] for r in rows if r["turn"] != "ERROR"] == [50]


def test_live_gh_failure_is_an_error_row_and_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    def gh(args: list[str], stdin: str | None) -> str:
        raise hpt.pr_state.GhError("gh api exited 1: could not resolve host")

    code = hpt.main(["--repo", KORUS], gh=gh, now=lambda: NOW)
    out = capsys.readouterr().out
    assert code == 0
    assert out.splitlines()[1].startswith("ERROR")
    assert "could not resolve host" in out


def test_live_read_paginates_in_one_query_per_page(capsys: pytest.CaptureFixture[str]) -> None:
    pages = [_page([_pr(60)]), _page([_pr(61)])]
    pages[0]["data"]["repository"]["pullRequests"]["pageInfo"] = {
        "hasNextPage": True,
        "endCursor": "c1",
    }
    calls: list[dict[str, Any]] = []

    def gh(args: list[str], stdin: str | None) -> str:
        assert args == ["api", "graphql", "--input", "-"]
        calls.append(json.loads(stdin or "{}")["variables"])
        return json.dumps(pages[len(calls) - 1])

    assert hpt.main(["--repo", KORUS, "--json"], gh=gh, now=lambda: NOW) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [c["cursor"] for c in calls] == [None, "c1"]
    assert sorted(r["number"] for r in rows) == [60, 61]


def test_unreadable_input_file_is_error_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = hpt.main(["--input", str(tmp_path / "missing.json")], now=lambda: NOW)
    out = capsys.readouterr().out
    assert code == 0
    assert sum(line.startswith("ERROR") for line in out.splitlines()) == 3


def test_table_sorts_lander_first_then_oldest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    held = _pr(
        70, comments=[_hold("2026-10-28T08:00:00Z", _sha(70))], committed="2026-10-28T01:00:00Z"
    )
    fresh = _pr(71, committed="2026-10-28T17:00:00Z")
    stale = _pr(72, committed="2026-10-26T15:00:00Z")
    doc = {ENGINE: {"pages": [_page([held, fresh, stale])], "required": ENGINE_REQUIRED}}
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    lines = out.splitlines()
    assert lines[0].split()[:2] == ["TURN", "FLAGS"]
    assert [line.split()[3] for line in lines[1:]] == ["72", "71", "70"]
    assert "2d03h" in lines[1]


def test_age_text() -> None:
    assert hpt.age_text(45 * 60) == "45m"
    assert hpt.age_text(3 * 3600 + 12 * 60) == "3h12m"
    assert hpt.age_text(-5) == "0m"
