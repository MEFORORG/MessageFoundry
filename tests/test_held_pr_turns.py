# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The held-PR turn report tells the Lander whose move each PR is, so its classification matters most.

These drive the REAL ``main()`` against canned GraphQL replies through ``--input``, with no network.
The unsafe error is AUTHOR on a PR that is really the Lander's, so most cases below are shapes that
must NOT read as a hold. The positive control is ``test_classification_keys_on_body_not_login``:
every seat posts under one GitHub login, so a classifier keyed on the author login would fail it.
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
SESSION = "Lander (session 8a04c9f3), 2026-10-28. "


def _sha(n: int) -> str:
    return f"{n:040x}"


def _marker_body(sha: str, prose: str = "**Held, back to the author.** Finding 2 stands.") -> str:
    """The contract's shape, as engine PR 2608's hold comment has it."""
    return f"<!-- lander-hold head={sha} -->\n{SESSION}{prose}"


def _comment(
    body: str,
    at: str,
    login: str = LOGIN,
    typename: str = "User",
    association: str = "OWNER",
) -> dict[str, Any]:
    return {
        "body": body,
        "createdAt": at,
        "authorAssociation": association,
        "author": {"__typename": typename, "login": login},
    }


def _hold(at: str, sha: str) -> dict[str, Any]:
    return _comment(_marker_body(sha), at)


def _review(body: str, at: str, *, state: str = "COMMENTED", bot: bool = False) -> dict[str, Any]:
    return {
        "body": body,
        "state": state,
        "submittedAt": at,
        "authorAssociation": "NONE" if bot else "OWNER",
        "author": {
            "__typename": "Bot" if bot else "User",
            "login": "greptile-apps" if bot else LOGIN,
        },
    }


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


def _turn(row: dict[str, Any]) -> tuple[str, list[str]]:
    return row["turn"], row["flags"]


def _is_hold(body: str, *, trusted: bool = True, dismissed: bool = False) -> bool:
    return hpt.Event(NOW, body, bot=False, trusted=trusted, dismissed=dismissed).held_at is not None


# ---- the turn ------------------------------------------------------------------------------------


def test_no_lander_event_is_lander_turn(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    row = _engine_rows(tmp_path, capsys, _pr(1))[1]
    assert _turn(row) == ("LANDER", ["no-hold"])
    assert row["requiredGreen"] == "yes"


def test_marker_hold_with_nothing_newer_is_author_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A short marker SHA, upper-cased, still matches the head by prefix.
    full = _pr(2, comments=[_hold("2026-10-28T12:00:00Z", _sha(2))])
    short = _pr(3, comments=[_hold("2026-10-28T12:00:00Z", _sha(3)[:9].upper())])
    rows = _engine_rows(tmp_path, capsys, full, short)
    assert _turn(rows[2]) == ("AUTHOR", ["held"])
    assert _turn(rows[3]) == ("AUTHOR", ["held"])


def test_marker_hold_then_manager_comment_at_same_head_is_lander_turn(
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
    assert _turn(row) == ("LANDER", ["replied", "no-new-commit"])
    assert row["age"] == "5h00m"


def test_marker_hold_then_new_head_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The committer date predates the hold (an old local commit pushed late); only the SHA counts.
    moved = _pr(
        5, comments=[_hold("2026-10-28T12:00:00Z", "f4f4dd470")], committed="2026-10-28T08:00:00Z"
    )
    both = _pr(
        6,
        comments=[
            _hold("2026-10-28T12:00:00Z", "f4f4dd470"),
            _comment("Manager: pushed the fix.", "2026-10-28T13:00:00Z"),
        ],
    )
    rows = _engine_rows(tmp_path, capsys, moved, both)
    assert _turn(rows[5]) == ("LANDER", ["new-commit"])
    assert _turn(rows[6]) == ("LANDER", ["new-commit", "replied"])


def test_same_second_tie_goes_to_the_lander(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reply = _pr(
        7,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(7)),
            _comment("Manager: fixed.", "2026-10-28T12:00:00Z"),
        ],
    )
    rows = _engine_rows(tmp_path, capsys, reply)
    assert _turn(rows[7]) == ("LANDER", ["replied", "no-new-commit"])
    # A hold tied with a non-hold Lander comment is no hold, in either list order.
    head = _sha(8)
    hold = hpt.Event(NOW, _marker_body(head), bot=False, trusted=True)
    note = hpt.Event(NOW, SESSION + "looking now.", bot=False, trusted=True)
    assert hpt.classify(head, [hold, note]) == ("LANDER", ["no-hold"])
    assert hpt.classify(head, [note, hold]) == ("LANDER", ["no-hold"])
    # Two tied holds must both match the head.
    other = hpt.Event(NOW, _marker_body("f4f4dd470"), bot=False, trusted=True)
    assert hpt.classify(head, [hold, other]) == ("LANDER", ["new-commit"])


def test_newer_non_hold_lander_comment_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(
        9,
        comments=[
            _hold("2026-10-28T07:00:00Z", _sha(9)),
            _comment(SESSION + "reviewing now.", "2026-10-28T09:00:00Z"),
        ],
    )
    assert _turn(_engine_rows(tmp_path, capsys, pr)[9]) == ("LANDER", ["no-hold"])


def test_legacy_prose_hold_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A hold written before the marker reads as a non-hold Lander comment: LANDER, the safe side."""
    prose = SESSION + f"**Held, back to the author, at `{_sha(10)[:9]}`.** Finding 2 stands."
    pr = _pr(10, comments=[_comment(prose, "2026-10-28T12:00:00Z")])
    assert _turn(_engine_rows(tmp_path, capsys, pr)[10]) == ("LANDER", ["no-hold"])
    assert hpt.Event(NOW, prose, bot=False, trusted=True).lander


def test_classification_keys_on_body_not_login(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Positive control: the hold and the Manager's reply share one login, and the reply flips the
    turn. A classifier keyed on the login would see one author and call it AUTHOR's turn. The same
    marker hold under another login is still a hold, so the body, not the login, decides."""
    pr = _pr(
        11,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(11)),
            _comment("Lander handover from the batch 453 Manager: fixed.", "2026-10-28T13:00:00Z"),
        ],
    )
    other_login = _pr(
        12, comments=[_comment(_marker_body(_sha(12)), "2026-10-28T12:00:00Z", login="someone")]
    )
    handover = _pr(13, comments=[_comment("Lander handover: ready.", "2026-10-28T13:00:00Z")])
    rows = _engine_rows(tmp_path, capsys, pr, other_login, handover)
    assert _turn(rows[11]) == ("LANDER", ["replied", "no-new-commit"])
    assert _turn(rows[12]) == ("AUTHOR", ["held"])
    assert _turn(rows[13]) == ("LANDER", ["no-hold"])


# ---- the hold contract ---------------------------------------------------------------------------


def test_real_hold_shape_is_a_hold() -> None:
    sha = "eead80e5efa654bf063b3260ebdea1ea8f24f999"
    assert hpt.hold_head(_marker_body(sha)) == sha
    assert hpt.hold_head(_marker_body("ABCDEF1")) == "abcdef1"
    # Trailing spaces, a tab and a carriage return after the marker are stripped.
    assert hpt.hold_head(f"<!-- lander-hold head={sha} --> \t\r\n{SESSION}**Held.**") == sha


def test_marker_without_a_lander_second_line_is_not_a_hold() -> None:
    marker = "<!-- lander-hold head=abcdef1 -->"
    assert not _is_hold(marker)
    assert not _is_hold(marker + "\nManager: this is how a hold looks.")
    assert not _is_hold(marker + "\n\n" + SESSION + "**Held.**")
    assert not _is_hold(marker + "\n " + SESSION + "**Held.**")


def test_marker_indented_or_after_a_blank_line_is_not_a_hold() -> None:
    marker = "<!-- lander-hold head=abcdef1 -->"
    assert not _is_hold(" " + marker + "\n" + SESSION)
    assert not _is_hold("\t" + marker + "\n" + SESSION)
    assert not _is_hold("\n" + marker + "\n" + SESSION)
    assert not _is_hold("\r\n" + marker + "\n" + SESSION)


def test_marker_anywhere_but_line_one_is_not_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = "<!-- lander-hold head=abcdef1 -->"
    for body in (
        SESSION + "**Cleared.**\n" + marker,
        SESSION + "**Cleared.**\n\n> " + marker + "\n> " + SESSION,
        "> " + marker + "\n> " + SESSION,
        "```\n" + marker + "\n" + SESSION + "\n```",
        "`" + marker + "`\n" + SESSION,
        marker + " trailing prose\n" + SESSION,
        "<!-- lander-hold head=abcdef1 --><!-- lander-hold head=abcdef1 -->\n" + SESSION,
    ):
        assert not _is_hold(body), body
    quoted = _pr(14, comments=[_comment("> " + marker + "\n> " + SESSION, "2026-10-28T12:00:00Z")])
    assert _engine_rows(tmp_path, capsys, quoted)[14]["turn"] == "LANDER"


def test_marker_head_must_be_7_to_40_hex() -> None:
    for bad in ("abcdef", "a" * 41, "xyzxyzx", "", "abcdef1g"):
        assert hpt.hold_head(_marker_body(bad)) is None, bad
    # The contract's spacing is exact.
    assert hpt.hold_head("<!--lander-hold head=abcdef1-->\n" + SESSION) is None
    assert hpt.hold_head("<!--  lander-hold head=abcdef1 -->\n" + SESSION) is None


def test_unicode_line_breaks_in_line_one_are_not_a_hold() -> None:
    """``str.splitlines`` would split these; the contract splits on a line feed only."""
    marker = "<!-- lander-hold head=abcdef1 -->"
    for sep in ("\x0b", "\u2028", "\x1c", "\x85", "\x0c"):
        assert not _is_hold(marker + sep + SESSION + "**Held.**"), repr(sep)
        # Nor as trailing whitespace on the marker line: only space, tab and CR are stripped.
        assert not _is_hold(marker + sep + "\n" + SESSION + "**Held.**"), repr(sep)


def test_untrusted_minimized_or_dismissed_is_not_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _marker_body(_sha(15))
    assert _is_hold(body)
    assert not _is_hold(body, trusted=False)
    assert not _is_hold(body, dismissed=True)
    outsider = _pr(
        15, comments=[_comment(body, "2026-10-28T12:00:00Z", login="x", association="NONE")]
    )
    contributor = _pr(
        16,
        comments=[
            _comment(_marker_body(_sha(16)), "2026-10-28T12:00:00Z", association="CONTRIBUTOR")
        ],
    )
    dismissed = _pr(17, reviews=[_review(_marker_body(_sha(17)), "2026-10-28T12:00:00Z")])
    dismissed["reviews"]["nodes"][0]["state"] = "DISMISSED"
    hidden = _hold("2026-10-28T12:00:00Z", _sha(18))
    hidden["isMinimized"] = True
    rows = _engine_rows(
        tmp_path, capsys, outsider, contributor, dismissed, _pr(18, comments=[hidden])
    )
    for n in (15, 16, 17, 18):
        assert _turn(rows[n]) == ("LANDER", ["no-hold"]), n


def test_marker_hold_posted_as_a_review_is_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(19, reviews=[_review(_marker_body(_sha(19)), "2026-10-28T12:00:00Z")])
    assert _turn(_engine_rows(tmp_path, capsys, pr)[19]) == ("AUTHOR", ["held"])


# ---- what counts as an event ---------------------------------------------------------------------


def test_bot_review_does_not_move_the_turn_but_dates_the_pr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bot = _review("<!-- greptile-auto-approve -->", "2026-10-28T14:30:00Z", bot=True)
    pr = _pr(20, comments=[_hold("2026-10-28T12:00:00Z", _sha(20))], reviews=[bot])
    row = _engine_rows(tmp_path, capsys, pr)[20]
    assert _turn(row) == ("AUTHOR", ["held"])
    assert row["age"] == "3h30m"


def test_review_bodies_and_inline_only_reviews_count_as_replies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reply = _review("Author: fixed, see thread.", "2026-10-28T15:00:00Z")
    inline_only = _review("", "2026-10-28T15:00:00Z")
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(21, comments=[_hold("2026-10-28T12:00:00Z", _sha(21))], reviews=[reply]),
        _pr(22, comments=[_hold("2026-10-28T12:00:00Z", _sha(22))], reviews=[inline_only]),
    )
    assert _turn(rows[21]) == ("LANDER", ["replied", "no-new-commit"])
    assert _turn(rows[22]) == ("LANDER", ["replied", "no-new-commit"])


def test_pending_review_is_ignored_and_minimized_reply_still_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pending = _review("Manager: draft, not submitted.", "2026-10-28T15:00:00Z", state="PENDING")
    pr = _pr(23, comments=[_hold("2026-10-28T12:00:00Z", _sha(23))], reviews=[pending])
    hidden = _comment("Manager: answered in thread.", "2026-10-28T15:00:00Z")
    hidden["isMinimized"] = True
    replied = _pr(24, comments=[_hold("2026-10-28T12:00:00Z", _sha(24)), hidden])
    rows = _engine_rows(tmp_path, capsys, pr, replied)
    assert _turn(rows[23]) == ("AUTHOR", ["held"])
    assert _turn(rows[24]) == ("LANDER", ["replied", "no-new-commit"])


def test_reply_by_editing_an_older_comment_hands_the_turn_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = _comment("Manager: handover. Answered: finding 2 fixed.", "2026-10-28T11:00:00Z")
    edited["lastEditedAt"] = "2026-10-28T13:00:00Z"
    unedited = _comment("Manager: handover.", "2026-10-28T11:00:00Z")
    # The Lander editing its own hold is no reply.
    hold = _hold("2026-10-28T12:00:00Z", _sha(28))
    hold["lastEditedAt"] = "2026-10-28T13:00:00Z"
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(27, comments=[edited, _hold("2026-10-28T12:00:00Z", _sha(27))]),
        _pr(28, comments=[unedited, hold]),
    )
    assert _turn(rows[27]) == ("LANDER", ["replied", "no-new-commit"])
    # The age dates from the edit, the newest thing that happened.
    assert rows[27]["newestEvent"] == "2026-10-28T13:00:00Z"
    assert _turn(rows[28]) == ("AUTHOR", ["held"])


def test_unreadable_edit_time_is_an_error_row_not_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = _comment("Manager: answered.", "2026-10-28T11:00:00Z")
    edited["lastEditedAt"] = "garbage"
    pr = _pr(34, comments=[edited, _hold("2026-10-28T12:00:00Z", _sha(34))])
    row = _engine_rows(tmp_path, capsys, pr)[34]
    assert row["turn"] == "ERROR" and "lastEditedAt" in row["error"]


def test_non_object_comment_node_is_an_error_row_not_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(29, comments=[_hold("2026-10-28T12:00:00Z", _sha(29))])
    pr["comments"]["nodes"].append(None)
    row = _engine_rows(tmp_path, capsys, pr)[29]
    assert row["turn"] == "ERROR" and "PR unreadable" in row["error"]


def test_undatable_comment_is_an_error_row_not_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    undated = _pr(
        25,
        comments=[_hold("2026-10-28T12:00:00Z", _sha(25))],
        reviews=[{"body": "Manager: fixed.", "state": "COMMENTED", "authorAssociation": "OWNER"}],
    )
    rows = _engine_rows(tmp_path, capsys, undated, _pr(26))
    assert rows[25]["turn"] == "ERROR" and "PR unreadable" in rows[25]["error"]
    assert rows[26]["turn"] == "LANDER"


# ---- errors and exit codes -----------------------------------------------------------------------


def test_overflowing_stamp_is_one_error_row_and_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    crafted = _pr(30, comments=[_comment("Manager: hi.", "9999-12-31T23:59:59-14:00")])
    doc = {ENGINE: {"pages": [_page([crafted, _pr(31)])], "required": ENGINE_REQUIRED}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert code == 0
    by = {r["number"]: r for r in rows}
    assert by[30]["turn"] == "ERROR" and "OverflowError" in by[30]["error"]
    assert "report defect" in by[30]["error"]
    assert by[31]["turn"] == "LANDER"
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    assert any(line.split()[:3] == ["ERROR", "MessageFoundry", "30"] for line in out.splitlines())


def test_a_per_pr_defect_does_not_collapse_the_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = hpt._events

    def events(pr: dict[str, Any]) -> list[Any]:
        if pr.get("number") == 32:
            raise TypeError("unexpected shape")
        return real(pr)

    monkeypatch.setattr(hpt, "_events", events)
    rows = _engine_rows(tmp_path, capsys, _pr(32), _pr(33))
    assert rows[32]["turn"] == "ERROR" and "TypeError" in rows[32]["error"]
    assert "read failed" not in rows[32]["error"]
    assert rows[33]["turn"] == "LANDER"


def test_a_defect_in_the_reader_is_not_reported_as_a_read_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(doc: object, repo: str) -> Any:
        raise AttributeError("a bug, not GitHub")

    monkeypatch.setattr(hpt, "from_input", broken)
    code, rows = _run(tmp_path, {}, capsys, "--repo", KORUS)
    assert code == 0
    assert rows[0]["turn"] == "ERROR"
    assert "report defect" in rows[0]["error"] and "read failed" not in rows[0]["error"]


def test_failed_repo_read_is_an_error_row_and_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = {
        ENGINE: {"error": "gh api graphql exited 1: HTTP 502"},
        VAULT: {"pages": [_page([_pr(40)])]},
        # korus is absent from the file: also an ERROR row, never silently omitted.
    }
    code, rows = _run(tmp_path, doc, capsys)
    assert code == 0
    errors = {r["repo"]: r["error"] for r in rows if r["turn"] == "ERROR"}
    assert set(errors) == {ENGINE, KORUS}
    assert "502" in errors[ENGINE] and errors[ENGINE].startswith("read failed")
    assert rows[0]["turn"] == "ERROR" and rows[1]["turn"] == "ERROR"
    assert [r["number"] for r in rows if r["turn"] != "ERROR"] == [40]


def test_live_gh_failure_is_an_error_row_and_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    def gh(args: list[str], stdin: str | None) -> str:
        raise hpt.pr_state.GhError("gh api exited 1: could not resolve host")

    code = hpt.main(["--repo", KORUS], gh=gh, now=lambda: NOW)
    out = capsys.readouterr().out
    assert code == 0
    assert out.splitlines()[1].startswith("ERROR")
    assert "could not resolve host" in out


def test_unreadable_input_file_is_error_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = hpt.main(["--input", str(tmp_path / "missing.json")], now=lambda: NOW)
    out = capsys.readouterr().out
    assert code == 0
    assert sum(line.startswith("ERROR") for line in out.splitlines()) == 3


def test_non_object_pr_node_is_an_error_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    page = _page([_pr(41)])
    page["data"]["repository"]["pullRequests"]["nodes"].insert(0, None)
    doc = {ENGINE: {"pages": [page], "required": ENGINE_REQUIRED}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert code == 0
    assert [r["turn"] for r in rows] == ["ERROR", "LANDER"]


# ---- the green column, flags, paging and the table -----------------------------------------------


def test_vault_pr_uses_the_vault_required_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    green = _pr(50, runs=_runs(list(hpt.VAULT_REQUIRED)))
    # The engine's contexts are green, but none of the vault's are, so it is not green.
    wrong = _pr(51, runs=_runs(ENGINE_REQUIRED))
    doc = {VAULT: {"pages": [_page([green, wrong])]}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", VAULT)
    assert code == 0
    by = {r["number"]: r for r in rows}
    assert by[50]["requiredGreen"] == "yes"
    assert by[51]["requiredGreen"] == "no"
    assert sorted(by[51]["required"]["missing"]) == sorted(hpt.VAULT_REQUIRED)


def test_required_context_missing_or_failing_on_head_is_not_green(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(52, runs=_runs(["CI gate"])),
        _pr(53, runs=_runs(["CI gate"]) + _runs(["cla"], conclusion="FAILURE")),
    )
    assert rows[52]["requiredGreen"] == "no"
    assert rows[52]["required"]["missing"] == ["cla"]
    assert rows[53]["requiredGreen"] == "no"
    assert rows[53]["required"]["failing"] == ["cla"]


def test_engine_required_list_unreadable_is_unknown_and_named_in_the_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = {ENGINE: {"pages": [_page([_pr(54), _pr(55)])]}}
    _, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert rows[0]["requiredGreen"] == "?"
    assert "required list unreadable" in rows[0]["required"]["reason"]
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    assert "note: MessageFoundry GREEN ? on 2 PR(s): required list unreadable" in out


def test_listed_commit_not_the_head_names_why_green_is_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(56)
    pr["headRefOid"] = _sha(999)
    row = _engine_rows(tmp_path, capsys, pr)[56]
    assert row["requiredGreen"] == "?"
    assert "not the head" in row["required"]["reason"]
    # ...but a base other than main keeps its own reason, which a re-run cannot fix.
    other = _pr(57)
    other["headRefOid"] = _sha(998)
    other["baseRefName"] = "release/1.0"
    row = _engine_rows(tmp_path, capsys, other)[57]
    assert "release/1.0" in row["required"]["reason"]


def test_turn_reads_head_ref_oid_not_the_listed_commit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The listed commit still matches the marker, but headRefOid has moved: a new commit.
    pr = _pr(58, comments=[_hold("2026-10-28T12:00:00Z", _sha(58))])
    pr["headRefOid"] = _sha(997)
    assert _turn(_engine_rows(tmp_path, capsys, pr)[58]) == ("LANDER", ["new-commit"])


def test_queue_and_auto_merge_are_flagged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    queued = _pr(60)
    queued["mergeQueueEntry"] = {"state": "QUEUED"}
    armed = _pr(61)
    armed["autoMergeRequest"] = {"enabledAt": "2026-10-28T10:00:00Z"}
    rows = _engine_rows(tmp_path, capsys, queued, armed)
    assert rows[60]["flags"] == ["no-hold", "in-queue"]
    assert rows[61]["flags"] == ["no-hold", "auto-armed"]


def test_draft_pr_is_excluded(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows = _engine_rows(tmp_path, capsys, _pr(62, draft=True), _pr(63))
    assert list(rows) == [63]


def test_non_utc_stamp_and_odd_number_do_not_break_the_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    odd = _pr(64, committed="2026-10-28T12:00:00+02:00")
    odd["number"] = "sixty-four"
    code, rows = _run(
        tmp_path, {ENGINE: {"pages": [_page([odd])], "required": ENGINE_REQUIRED}}, capsys
    )
    assert code == 0
    row = next(r for r in rows if r["repo"] == ENGINE)
    assert row["newestEvent"] == "2026-10-28T10:00:00Z"


def test_live_read_paginates_in_one_query_per_page(capsys: pytest.CaptureFixture[str]) -> None:
    pages = [_page([_pr(70)]), _page([_pr(71)])]
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
    assert sorted(r["number"] for r in rows) == [70, 71]


def test_a_page_that_cannot_say_it_is_the_last_is_a_read_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    no_info = _page([_pr(75)])
    del no_info["data"]["repository"]["pullRequests"]["pageInfo"]
    more = _page([_pr(76)])
    more["data"]["repository"]["pullRequests"]["pageInfo"] = {"hasNextPage": True, "endCursor": "c"}
    no_nodes = _page([])
    del no_nodes["data"]["repository"]["pullRequests"]["nodes"]
    entries: list[dict[str, Any]] = [
        {"pages": [no_info]},
        {"pages": [more]},
        {"pages": [no_nodes]},
        {"pages": []},
        {"required": []},
    ]
    for entry in entries:
        code, rows = _run(tmp_path, {KORUS: entry}, capsys, "--repo", KORUS)
        assert code == 0
        assert [r["turn"] for r in rows] == ["ERROR"], entry
        assert rows[0]["error"].startswith("read failed")


def test_input_file_with_a_bom_is_read(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bom.json"
    doc = {KORUS: {"pages": [_page([_pr(78)])]}}
    path.write_text(json.dumps(doc), encoding="utf-8-sig")
    assert hpt.main(["--input", str(path), "--json", "--repo", KORUS], now=lambda: NOW) == 0
    assert [r["number"] for r in json.loads(capsys.readouterr().out)] == [78]


def test_title_control_characters_cannot_forge_a_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(77)
    pr["title"] = "x" + chr(13) + chr(10) + "AUTHOR  held" + chr(0x1B) + "[2K" + chr(0x202E) + "y"
    code, out = _run(
        tmp_path,
        {ENGINE: {"pages": [_page([pr])], "required": ENGINE_REQUIRED}},
        capsys,
        "--repo",
        ENGINE,
        json_out=False,
    )
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 2
    assert all(c.isprintable() for c in lines[1])
    # Error text from a reply is GitHub's too, and is cleaned the same way.
    forged = {KORUS: {"error": "502" + chr(10) + "AUTHOR  held  korus  999  yes"}}
    code, out = _run(tmp_path, forged, capsys, "--repo", KORUS, json_out=False)
    assert code == 0
    assert len(out.splitlines()) == 2


def test_table_sorts_lander_first_then_oldest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    held = _pr(
        72, comments=[_hold("2026-10-28T08:00:00Z", _sha(72))], committed="2026-10-28T01:00:00Z"
    )
    fresh = _pr(73, committed="2026-10-28T17:00:00Z")
    stale = _pr(74, committed="2026-10-26T15:00:00Z")
    doc = {ENGINE: {"pages": [_page([held, fresh, stale])], "required": ENGINE_REQUIRED}}
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    lines = out.splitlines()
    assert lines[0].split()[:2] == ["TURN", "FLAGS"]
    assert [line.split()[3] for line in lines[1:]] == ["74", "73", "72"]
    assert "2d03h" in lines[1]


def test_age_text() -> None:
    assert hpt.age_text(45 * 60) == "45m"
    assert hpt.age_text(3 * 3600 + 12 * 60) == "3h12m"
    assert hpt.age_text(-5) == "0m"
