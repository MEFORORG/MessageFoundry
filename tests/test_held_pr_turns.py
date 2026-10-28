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
    # The committedDate predates the hold (an old local commit pushed late), yet the SHA named in the hold differs
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


def test_bot_review_does_not_move_the_turn_but_dates_the_pr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bot = _review("<!-- greptile-auto-approve -->", "2026-10-28T14:30:00Z", bot=True)
    pr = _pr(9, comments=[_hold("2026-10-28T12:00:00Z", _sha(9))], reviews=[bot])
    row = _engine_rows(tmp_path, capsys, pr)[9]
    assert (row["turn"], row["flags"]) == ("AUTHOR", ["held"])
    assert row["age"] == "3h30m"


def test_review_bodies_and_inline_only_reviews_count_as_replies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reply = _review("Author: fixed, see thread.", "2026-10-28T15:00:00Z")
    inline_only = _review("", "2026-10-28T15:00:00Z")
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(10, comments=[_hold("2026-10-28T12:00:00Z", _sha(10))], reviews=[reply]),
        _pr(13, comments=[_hold("2026-10-28T12:00:00Z", _sha(13))], reviews=[inline_only]),
    )
    assert (rows[10]["turn"], rows[10]["flags"]) == ("LANDER", ["no-new-commit"])
    assert (rows[13]["turn"], rows[13]["flags"]) == ("LANDER", ["no-new-commit"])


def test_pending_review_and_minimized_comment_are_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pending = _review("Manager: draft, not submitted.", "2026-10-28T15:00:00Z", state="PENDING")
    hidden = _comment("Manager: ready for landing.", "2026-10-28T15:00:00Z")
    hidden["isMinimized"] = True
    pr = _pr(14, comments=[_hold("2026-10-28T12:00:00Z", _sha(14)), hidden], reviews=[pending])
    row = _engine_rows(tmp_path, capsys, pr)[14]
    assert (row["turn"], row["flags"]) == ("AUTHOR", ["held"])


def test_outside_account_cannot_post_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _comment(
        f"Lander (session x). **Held, at `{_sha(15)[:9]}`.**",
        "2026-10-28T12:00:00Z",
        login="someone",
        association="NONE",
    )
    row = _engine_rows(tmp_path, capsys, _pr(15, comments=[fake]))[15]
    assert (row["turn"], row["flags"]) == ("LANDER", ["no-lander-comment"])


def test_bold_held_quoted_in_a_non_hold_comment_is_not_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = (
        "Lander (session x). **Cleared; merging once CI is green.** The earlier **Held** is fixed."
    )
    pr = _pr(16, comments=[_comment(body, "2026-10-28T12:00:00Z")])
    row = _engine_rows(tmp_path, capsys, pr)[16]
    assert (row["turn"], row["flags"]) == ("LANDER", ["lander-not-hold"])


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


def test_hold_heads_reads_the_headline_only() -> None:
    body = "Lander (session x). **Held, at `1234567AB`.** The fix `fedcba987` is elsewhere."
    assert hpt.hold_heads(body) == ("1234567ab",)
    assert hpt.hold_heads("Lander (session x). **Held.** See `fedcba987`.") == ()
    # The SHA after "at" wins over another commit the headline names.
    lander = "Lander (session x). "
    assert hpt.hold_heads(lander + "**Held: fix `bbbbbbb` missing, at `aaaaaaa`.**") == ("aaaaaaa",)
    # A recap of an earlier hold before the bold headline is outside it.
    recap = "Lander (session x), 2026-10-28. **Still held, at `aaaaaaa`.** Earlier at `ccccccc`."
    assert hpt.hold_heads(recap) == ("aaaaaaa",)
    assert hpt.hold_heads(lander + "**Cleared.**") is None


def test_backticked_sha_without_at_is_the_held_head() -> None:
    """Regression: with no "at `sha`" form, a backticked SHA in the headline is still the head, so
    the turn never silently falls to the weaker committer date while a SHA is present."""
    lander = "Lander (session x). "
    assert hpt.hold_heads(lander + "**Held on `aaaaaaa`.**") == ("aaaaaaa",)
    assert hpt.hold_heads(lander + "**Held at head `aaaaaaa`.**") == ("aaaaaaa",)
    # Two distinct heads and no "at": ambiguous, which the classifier hands to the Lander.
    two = lander + "**Held on `aaaaaaa`: the fix `bbbbbbb` is missing.**"
    assert hpt.hold_heads(two) == ("aaaaaaa", "bbbbbbb")


def test_sha_fallback_beats_the_commit_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The committer date predates the hold, so the date fallback would call these the author's.
    moved = _pr(
        100,
        comments=[_comment("Lander (session x). **Held on `f4f4dd470`.**", "2026-10-28T12:00:00Z")],
        committed="2026-10-28T08:00:00Z",
    )
    same = _pr(
        101,
        comments=[
            _comment(
                f"Lander (session x). **Held at head `{_sha(101)[:9]}`.**", "2026-10-28T12:00:00Z"
            )
        ],
        committed="2026-10-28T08:00:00Z",
    )
    two = _pr(
        102,
        comments=[
            _comment(
                f"Lander (session x). **Held on `{_sha(102)[:9]}`, fix `abcdef1` missing.**",
                "2026-10-28T12:00:00Z",
            )
        ],
    )
    rows = _engine_rows(tmp_path, capsys, moved, same, two)
    assert (rows[100]["turn"], rows[100]["flags"]) == ("LANDER", ["new-commit"])
    assert (rows[101]["turn"], rows[101]["flags"]) == ("AUTHOR", ["held"])
    assert (rows[102]["turn"], rows[102]["flags"]) == ("LANDER", ["sha-ambiguous"])


def test_negated_or_past_tense_hold_is_not_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def hold(body: str) -> bool:
        return hpt.Event(NOW, body, bot=False, trusted=True).hold

    assert not hold("Lander (session x). No longer **held**; merging.")
    assert not hold("Lander (session x), 2026-10-28. Earlier **Held** answered.")
    assert not hold("Lander (session x). **Held** answered; merging.")
    assert not hold("Lander (session x). **Held earlier, now cleared.**")
    assert not hold("Lander (session x). **Held no longer.**")
    # A whole-sentence headline does not read the next sentence.
    assert hold("Lander (session x). **Held, at `abcdef1`.** Finding 1 is cleared; 2 stands.")
    pr = _pr(
        103, comments=[_comment("Lander (session x). No longer **held**.", "2026-10-28T12:00:00Z")]
    )
    row = _engine_rows(tmp_path, capsys, pr)[103]
    assert (row["turn"], row["flags"]) == ("LANDER", ["lander-not-hold"])


def test_same_second_reply_or_commit_goes_to_the_lander(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reply = _pr(
        104,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(104)),
            _comment("Manager: fixed.", "2026-10-28T12:00:00Z"),
        ],
    )
    commit = _pr(
        105, comments=[_hold("2026-10-28T12:00:00Z", None)], committed="2026-10-28T12:00:00Z"
    )
    rows = _engine_rows(tmp_path, capsys, reply, commit)
    assert (rows[104]["turn"], rows[104]["flags"]) == ("LANDER", ["no-new-commit"])
    assert (rows[105]["turn"], rows[105]["flags"]) == ("LANDER", ["new-commit", "date-fallback"])


def test_overflowing_stamp_is_one_error_row_and_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    crafted = _pr(106, comments=[_comment("Manager: hi.", "9999-12-31T23:59:59-14:00")])
    doc = {ENGINE: {"pages": [_page([crafted, _pr(107)])], "required": ENGINE_REQUIRED}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert code == 0
    by = {r["number"]: r for r in rows}
    assert by[106]["turn"] == "ERROR" and "OverflowError" in by[106]["error"]
    assert by[107]["turn"] == "LANDER"
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    assert any(line.split()[:3] == ["ERROR", "MessageFoundry", "106"] for line in out.splitlines())


def test_a_per_pr_defect_does_not_collapse_the_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = hpt._events

    def events(pr: dict[str, Any]) -> list[Any]:
        if pr.get("number") == 108:
            raise TypeError("unexpected shape")
        return real(pr)

    monkeypatch.setattr(hpt, "_events", events)
    rows = _engine_rows(tmp_path, capsys, _pr(108), _pr(109))
    assert rows[108]["turn"] == "ERROR" and "TypeError" in rows[108]["error"]
    assert rows[109]["turn"] == "LANDER"


def _marked(marker: str, prose: str = "**Reviewed; see below.**") -> str:
    return f"Lander (session x), 2026-10-28. {prose}\n\n{marker}"


def test_hold_marker_is_the_primary_signal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The prose is no hold, yet the marker makes it one.
    marker = f"<!-- lander-hold head={_sha(110)} -->"
    stay = _pr(110, comments=[_comment(_marked(marker), "2026-10-28T12:00:00Z")])
    # The prose names the current head; the marker names another, and wins.
    moved = _pr(
        111,
        comments=[
            _comment(
                _marked("<!-- lander-hold head=f4f4dd470 -->", f"**Held, at `{_sha(111)[:9]}`.**"),
                "2026-10-28T12:00:00Z",
            )
        ],
    )
    rows = _engine_rows(tmp_path, capsys, stay, moved)
    assert (rows[110]["turn"], rows[110]["flags"]) == ("AUTHOR", ["held"])
    assert (rows[111]["turn"], rows[111]["flags"]) == ("LANDER", ["new-commit"])


def test_marker_validation_and_release() -> None:
    heads = hpt.hold_heads

    assert heads(_marked("<!-- lander-hold head=ABCDEF1 -->")) == ("abcdef1",)
    assert heads(_marked("<!--lander-hold head=abcdef1-->")) == ("abcdef1",)
    # Anything but 7-40 hex is no marker, so the (non-hold) prose decides.
    for bad in ("abcdef", "a" * 41, "xyzxyzx", "", "abcdef1g"):
        assert heads(_marked(f"<!-- lander-hold head={bad} -->")) is None, bad
    # ...and a prose hold still counts as the fallback beside an invalid marker.
    assert heads(_marked("<!-- lander-hold head=nope -->", "**Held.**")) == ()
    # A release marker beats a hold marker and a prose hold alike.
    both = _marked("<!-- lander-hold head=abcdef1 --> <!-- lander-release -->", "**Held.**")
    assert heads(both) is None
    assert heads(_marked("<!-- lander-release -->", "**Still held.**")) is None
    # The marker is gated like the prose: an outside account or a non-Lander body is no hold.
    marker = "<!-- lander-hold head=abcdef1 -->"
    assert not hpt.Event(NOW, _marked(marker), bot=False, trusted=False).hold
    assert not hpt.Event(NOW, f"Manager: {marker}", bot=False, trusted=True).hold
    assert hpt.Event(NOW, _marked(marker), bot=False, trusted=True).hold


def test_release_comment_after_a_hold_is_lander_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(
        112,
        comments=[
            _comment(_marked(f"<!-- lander-hold head={_sha(112)} -->"), "2026-10-28T12:00:00Z"),
            _comment(_marked("<!-- lander-release -->", "**Held.**"), "2026-10-28T13:00:00Z"),
        ],
    )
    row = _engine_rows(tmp_path, capsys, pr)[112]
    assert (row["turn"], row["flags"]) == ("LANDER", ["lander-not-hold"])


def test_hold_headline_rules() -> None:
    def hold(body: str) -> bool:
        return hpt.Event(NOW, body, bot=False, trusted=True).hold

    assert hold("Lander (session x), 2026-10-28. **Held, back to the author, at `abcdef1`.**")
    assert hold("Lander (session x). **Still Held, at `abcdef1`.**")
    assert hold("Lander (session x). **HELD.**")
    assert not hold("Lander (session x). **Held-over check cleared; merging.**")
    # A bold Held far past the session marker is a mention in a triage note, not a headline.
    assert not hold(
        "Lander (session x), 2026-10-28, triage. The merge queue ejected this PR. "
        "The earlier **Held** is resolved; requeueing."
    )
    assert not hpt.Event(NOW, "Lander (session x). **Held.**", bot=False, trusted=False).hold


def test_same_second_tie_and_unknown_head_go_to_the_lander() -> None:
    hold = hpt.Event(NOW, "Lander (session x). **Held, at `abcdef1`.**", bot=False, trusted=True)
    note = hpt.Event(NOW, "Lander (session x): looking now.", bot=False, trusted=True)
    head = "abcdef1" + "0" * 33
    assert hpt.classify(head, None, [hold, note]) == ("LANDER", ["lander-not-hold"])
    assert hpt.classify(head, None, [note, hold]) == ("LANDER", ["lander-not-hold"])
    no_sha = hpt.Event(NOW, "Lander (session x). **Held.**", bot=False, trusted=True)
    assert hpt.classify(head, None, [no_sha]) == ("LANDER", ["head-unknown", "date-fallback"])


def test_queue_and_auto_merge_are_flagged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    queued = _pr(90)
    queued["mergeQueueEntry"] = {"state": "QUEUED"}
    armed = _pr(91)
    armed["autoMergeRequest"] = {"enabledAt": "2026-10-28T10:00:00Z"}
    rows = _engine_rows(tmp_path, capsys, queued, armed)
    assert rows[90]["flags"] == ["no-lander-comment", "in-queue"]
    assert rows[91]["flags"] == ["no-lander-comment", "auto-armed"]


def test_non_utc_stamp_and_odd_number_do_not_break_the_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    odd = _pr(80, committed="2026-10-28T12:00:00+02:00")
    odd["number"] = "eighty"
    code, rows = _run(
        tmp_path, {ENGINE: {"pages": [_page([odd])], "required": ENGINE_REQUIRED}}, capsys
    )
    assert code == 0
    row = next(r for r in rows if r["repo"] == ENGINE)
    assert row["newestEvent"] == "2026-10-28T10:00:00Z"


def test_table_names_the_reason_for_an_unknown_green(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = {ENGINE: {"pages": [_page([_pr(81), _pr(82)])]}}
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    assert "note: MessageFoundry GREEN ? on 2 PR(s): required list unreadable" in out


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


def test_marker_quoted_or_in_code_is_not_read() -> None:
    heads = hpt.hold_heads
    marker = "<!-- lander-hold head=abcdef1 -->"
    cleared = "Lander (session y), 2026-10-28. **Cleared; merging.**\n\n"
    # A marker quoted from an earlier hold, in a blockquote or a code block, is no hold.
    assert heads(cleared + "> Earlier hold:\n> " + marker) is None
    assert heads(cleared + "```\n" + marker + "\n```") is None
    assert heads(cleared + "~~~\n" + marker + "\n~~~") is None
    assert heads(cleared + "Mark a hold with `" + marker + "`.") is None
    # A release marker shown as an instruction does not release a real hold.
    told = "Lander (session x). **Held, at `abcdef1`.** Post `<!-- lander-release -->` when fixed."
    assert heads(told) == ("abcdef1",)
    assert heads(_marked("> <!-- lander-release -->", "**Held, at `abcdef1`.**")) == ("abcdef1",)
    # A stray backtick opens no code span, so it hides no release marker after it.
    stray = "Lander (session x). **Held.** A stray ` then <!-- lander-release -->"
    assert heads(stray) is None
    # A live marker beside a quoted one still counts.
    assert heads(cleared + "> " + marker + "\n\n<!-- lander-hold head=1234567 -->") == ("1234567",)


def test_bare_held_headline_reads_its_sentence_for_the_head_and_negation() -> None:
    heads = hpt.hold_heads
    assert heads("Lander (session x). **Held**, at `abcdef1`.") == ("abcdef1",)
    assert heads("Lander (session x). **Still held**: at `abcdef1`. Fix `1234567` next.") == (
        "abcdef1",
    )
    assert heads("Lander (session x). **Held:** at `abcdef1`.") == ("abcdef1",)
    # A label-form headline's predicate is read for negation.
    assert heads("Lander (session x). **Held:** answered, merging.") is None
    assert heads("Lander (session x). **Held;** no longer, merging once green.") is None
    # The head named after a bare headline beats the weaker commit date.
    hold = hpt.Event(NOW, "Lander (session x). **Held**, at `abcdef1`.", bot=False, trusted=True)
    old = datetime(2026, 10, 28, 9, 0, 0, tzinfo=UTC)
    assert hpt.classify("1234567" + "0" * 33, old, [hold]) == ("LANDER", ["new-commit"])


def test_same_second_holds_naming_different_heads_are_ambiguous() -> None:
    a = hpt.Event(NOW, "Lander (session x). **Held, at `abcdef1`.**", bot=False, trusted=True)
    b = hpt.Event(NOW, "Lander (session x). **Held, at `1234567`.**", bot=False, trusted=True)
    head = "abcdef1" + "0" * 33
    assert hpt.classify(head, None, [a, b]) == ("LANDER", ["sha-ambiguous"])
    assert hpt.classify(head, None, [b, a]) == ("LANDER", ["sha-ambiguous"])
    # A tied hold naming no head brings the date check in, whatever the other names.
    bare = hpt.Event(NOW, "Lander (session x). **Held.**", bot=False, trusted=True)
    assert hpt.classify(head, None, [a, bare]) == ("LANDER", ["head-unknown", "date-fallback"])
    assert hpt.classify(head, NOW, [bare, a]) == ("LANDER", ["new-commit", "date-fallback"])


def test_undatable_comment_is_an_error_row_not_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    undated = _pr(
        113,
        comments=[_hold("2026-10-28T12:00:00Z", _sha(113))],
        reviews=[{"body": "Manager: fixed.", "state": "COMMENTED", "authorAssociation": "OWNER"}],
    )
    rows = _engine_rows(tmp_path, capsys, undated, _pr(114))
    assert rows[113]["turn"] == "ERROR"
    assert rows[114]["turn"] == "LANDER"


def test_non_object_pr_node_is_an_error_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    page = _page([_pr(115)])
    page["data"]["repository"]["pullRequests"]["nodes"].insert(0, None)
    doc = {ENGINE: {"pages": [page], "required": ENGINE_REQUIRED}}
    code, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert code == 0
    assert [r["turn"] for r in rows] == ["ERROR", "LANDER"]


def test_listed_commit_not_the_head_names_why_green_is_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pr = _pr(116)
    pr["headRefOid"] = _sha(999)
    row = _engine_rows(tmp_path, capsys, pr)[116]
    assert row["requiredGreen"] == "?"
    assert "not the head" in row["required"]["reason"]
