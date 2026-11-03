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
#: The seat-id signature the Lander also writes.
SEAT = "Lander (lander-1028), 2026-10-29. "


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
        "comments": {"pageInfo": {"hasPreviousPage": False}, "nodes": comments or []},
        "reviews": {"pageInfo": {"hasPreviousPage": False}, "nodes": reviews or []},
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
    assert hpt.classify(head, [hold, note]) == ("LANDER", ["no-hold"], None)
    assert hpt.classify(head, [note, hold]) == ("LANDER", ["no-hold"], None)
    # Two tied holds must both match the head.
    other = hpt.Event(NOW, _marker_body("f4f4dd470"), bot=False, trusted=True)
    assert hpt.classify(head, [hold, other]) == ("LANDER", ["new-commit"], None)


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


def _ack_body(sha: str, prose: str = "Batch 453 Manager: hold received, fixing.") -> str:
    """The ack contract's shape: the marker line, then the author's own words."""
    return f"<!-- hold-ack head={sha} -->\n{prose}"


def _ack(at: str, sha: str) -> dict[str, Any]:
    return _comment(_ack_body(sha), at)


def _held(
    n: int,
    *extra: dict[str, Any],
    head: str | None = None,
    reviews: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """PR ``n`` with a marker hold on its own head at noon, then the ``extra`` comments."""
    return _pr(
        n, comments=[_hold("2026-10-28T12:00:00Z", _sha(n)), *extra], head=head, reviews=reviews
    )


def test_a_seat_signed_lander_comment_is_a_lander_event(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The Lander signs ``Lander (<seat id>)`` as well as ``Lander (session <id>)``. A marker
    hold so signed is a hold, and an unmarked comment so signed is a non-hold Lander event, not a
    reply."""
    signed = f"<!-- lander-hold head={_sha(101)} -->\n{SEAT}**Held, back to the author.**"
    assert hpt.hold_head(signed) == _sha(101)
    assert hpt.Event(NOW, SEAT + "looking now.", bot=False, trusted=True).lander
    hold = _pr(101, comments=[_comment(signed, "2026-10-28T12:00:00Z")])
    note = _held(102, _comment(SEAT + "**Held** pending the flake rerun.", "2026-10-28T13:00:00Z"))
    rows = _engine_rows(tmp_path, capsys, hold, note)
    assert _turn(rows[101]) == ("AUTHOR", ["held"])
    # Still the Lander's turn, but as its own newer comment, not as an author reply.
    assert _turn(rows[102]) == ("LANDER", ["no-hold"])


def test_an_author_text_starting_lander_paren_never_moves_toward_author(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A Manager addressing the Lander writes ``Lander (8a04c9f3): ...``, with a colon. It is not
    the Lander's signature, so it stays an author reply, even as the second line under a hold
    marker (an author mistaking the hold marker for the ack marker)."""
    ask = "Lander (8a04c9f3): flip #3844 on merge."
    assert not hpt.Event(NOW, ask, bot=False, trusted=True).lander
    mistaken = f"<!-- lander-hold head={_sha(106)} -->\n{ask}"
    assert hpt.hold_head(mistaken) is None
    older = _comment(ask, "2026-10-28T11:00:00Z")
    older["lastEditedAt"] = "2026-10-28T13:00:00Z"
    rows = _engine_rows(
        tmp_path,
        capsys,
        _held(103, _comment(ask, "2026-10-28T13:00:00Z")),
        _held(104, _comment(ask, "2026-10-28T12:00:00Z")),
        _pr(105, comments=[older, _hold("2026-10-28T12:00:00Z", _sha(105))]),
        _held(106, _comment(mistaken, "2026-10-28T13:00:00Z")),
        _pr(
            107, comments=[_comment(mistaken.replace(_sha(106), _sha(107)), "2026-10-28T13:00:00Z")]
        ),
    )
    for n in (103, 104, 106):
        assert _turn(rows[n]) == ("LANDER", ["replied", "no-new-commit"]), n
    assert _turn(rows[105]) == ("LANDER", ["replied", "edited", "no-new-commit"])
    assert _turn(rows[107]) == ("LANDER", ["no-hold"])


def test_only_a_lander_seat_id_signs_a_hold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``Lander (x), ...`` carries the comma but no Lander seat id, so under a hold marker it is
    an author reply, not a hold; ``Lander (lander-1028), ...`` under one is still a hold."""
    comma = "Lander (x), please re-read."
    assert not hpt.Event(NOW, comma, bot=False, trusted=True).lander
    marked = f"<!-- lander-hold head={_sha(108)} -->\n{comma}"
    assert hpt.hold_head(marked) is None
    for not_a_seat in ("Lander (lander-), ", "Lander (lander-X1), ", "Lander (lander-1028): "):
        assert hpt.hold_head(f"<!-- lander-hold head=abcdef1 -->\n{not_a_seat}x") is None
    rows = _engine_rows(
        tmp_path,
        capsys,
        _held(108, _comment(marked, "2026-10-28T13:00:00Z")),
        _held(109, _comment(comma, "2026-10-28T13:00:00Z")),
        _pr(
            110,
            comments=[
                _comment(_marker_body(_sha(110)).replace(SESSION, SEAT), "2026-10-28T12:00:00Z")
            ],
        ),
    )
    assert _turn(rows[108]) == ("LANDER", ["replied", "no-new-commit"])
    assert _turn(rows[109]) == ("LANDER", ["replied", "no-new-commit"])
    assert _turn(rows[110]) == ("AUTHOR", ["held"])


# ---- the ack contract ----------------------------------------------------------------------------


def test_a_hold_ack_naming_the_head_keeps_the_turn_the_authors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    full = _held(110, _ack("2026-10-28T17:00:00Z", _sha(110)))
    # A short, upper-cased SHA with a trailing space and CR, in the hold's own second.
    odd = f"<!-- hold-ack head={_sha(111)[:9].upper()} --> \r\nfixing"
    at = "2026-10-28T17:00:00Z"
    short = _pr(111, comments=[_hold(at, _sha(111)), _comment(odd, at)])
    rows = _engine_rows(tmp_path, capsys, full, short)
    assert _turn(rows[110]) == ("AUTHOR", ["held", "acked"])
    assert _turn(rows[111]) == ("AUTHOR", ["held", "acked"])


def test_an_ack_more_than_two_hours_old_hands_the_turn_to_the_lander(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """NOW is 18:00. An ack 2h+1s old has expired; one 1h59m old, or exactly 2h old, has not. The
    newest ack decides, and an expired ack on a cut page carries both flags."""
    rows = _engine_rows(
        tmp_path,
        capsys,
        _held(115, _ack("2026-10-28T15:59:59Z", _sha(115))),
        _held(116, _ack("2026-10-28T16:01:00Z", _sha(116))),
        _held(117, _ack("2026-10-28T16:00:00Z", _sha(117))),
        _held(
            118,
            _ack("2026-10-28T12:30:00Z", _sha(118)),
            _ack("2026-10-28T17:00:00Z", _sha(118)),
        ),
        _cut(_held(119, _ack("2026-10-28T15:00:00Z", _sha(119)))),
        # Controls: rows that would not read AUTHOR acked do not change.
        _held(114, _ack("2026-10-28T12:30:00Z", _sha(114)), _repair()),
    )
    assert _repair_row(rows[115]) == ("LANDER", ["held", "acked", "ack-expired"], None)
    assert _repair_row(rows[116]) == ("AUTHOR", ["held", "acked"], None)
    assert _repair_row(rows[117]) == ("AUTHOR", ["held", "acked"], None)
    assert _repair_row(rows[118]) == ("AUTHOR", ["held", "acked"], None)
    assert _repair_row(rows[119]) == (
        "LANDER",
        ["held", "acked", "ack-expired", "page-cut"],
        None,
    )
    assert _repair_row(rows[114]) == ("REPAIR", ["held", "acked", "repair"], OWNER_ID)


def test_anything_but_a_valid_ack_still_hands_the_turn_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prose = _comment(
        "Batch 453 Manager: hold received. Fixing the findings.", "2026-10-28T13:00:00Z"
    )
    outsider = _ack("2026-10-28T13:00:00Z", _sha(123))
    outsider["authorAssociation"] = "NONE"
    hidden = _ack("2026-10-28T13:00:00Z", _sha(124))
    hidden["isMinimized"] = True
    edited = _ack("2026-10-28T13:00:00Z", _sha(125))
    edited["lastEditedAt"] = "2026-10-28T14:00:00Z"
    dismissed = _review(_ack_body(_sha(126)), "2026-10-28T13:00:00Z", state="DISMISSED")
    # A review's inline thread comments are not read, so an ack as a review summary is a reply.
    as_review = _review(_ack_body(_sha(128)), "2026-10-28T13:00:00Z")
    rows = _engine_rows(
        tmp_path,
        capsys,
        _held(120, prose),
        _held(121, _ack("2026-10-28T13:00:00Z", "f4f4dd470")),
        _held(
            122,
            _ack("2026-10-28T13:00:00Z", _sha(122)),
            _comment("Manager: done.", "2026-10-28T14:00:00Z"),
        ),
        _held(123, outsider),
        _held(124, hidden),
        _held(125, edited),
        _held(126, reviews=[dismissed]),
        _held(127, _ack("2026-10-28T13:00:00Z", _sha(127)), head=_sha(999)),
        _held(128, reviews=[as_review]),
    )
    for n in (120, 121, 122, 123, 124, 126, 128):
        assert _turn(rows[n]) == ("LANDER", ["replied", "no-new-commit"]), n
    assert _turn(rows[125]) == ("LANDER", ["edited", "no-new-commit"])
    # The ack named the held head, but a push followed it: the Lander's turn.
    assert _turn(rows[127]) == ("LANDER", ["new-commit", "replied"])


def test_the_ack_marker_must_be_the_whole_first_line() -> None:
    marker = "<!-- hold-ack head=abcdef1 -->"
    assert hpt.ack_head(marker + "\nfixing") == "abcdef1"
    assert hpt.ack_head(" " + marker) is None
    assert hpt.ack_head("\n" + marker) is None
    assert hpt.ack_head("> " + marker) is None
    assert hpt.ack_head("Manager: " + marker) is None
    assert hpt.ack_head(marker + " ok") is None
    assert hpt.ack_head("<!-- hold-ack head=abcdef -->") is None
    assert hpt.ack_head("<!-- hold-ack head=abcdefg -->") is None
    # An ack is not a hold, and a hold is not an ack.
    assert hpt.hold_head(marker + "\n" + SESSION + "**Held.**") is None
    assert hpt.ack_head(_marker_body("abcdef1")) is None


# ---- the repair contract -------------------------------------------------------------------------

#: A made-up session id in the desktop app's shape: mixed case, an underscore, hyphens, 42 characters.
OWNER_ID = "local_Ab12cd34-0000-4000-8000-000000000000"


def _repair_body(session: str = OWNER_ID, signature: str = SESSION) -> str:
    """The shared marker contract's shape: the marker line, then the Lander-signed transfer line."""
    return (
        f"<!-- repair-owner session={session} -->\n{signature}Repair owned by the Repair Manager"
        " from 13:00Z; the original author stands down on this PR."
    )


def _repair(at: str = "2026-10-28T13:00:00Z", **kw: Any) -> dict[str, Any]:
    return _comment(_repair_body(**kw), at)


def _repair_row(row: dict[str, Any]) -> tuple[str, list[str], str | None]:
    return row["turn"], row["flags"], row["repairOwner"]


def test_a_repair_marker_after_a_standing_hold_is_the_repair_owners_turn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _engine_rows(
        tmp_path,
        capsys,
        _held(130, _repair()),
        # Seat-signed, with trailing space and CR on the marker line.
        _held(
            131,
            _comment(
                _repair_body(signature=SEAT).replace(" -->\n", " --> \r\n", 1),
                "2026-10-28T13:00:00Z",
            ),
        ),
        # An author's ack naming the head, before the transfer, is still not a reply.
        _held(132, _ack("2026-10-28T12:30:00Z", _sha(132)), _repair()),
        # A re-transfer: the newest marker names the owner.
        _held(
            133, _repair("2026-10-28T13:00:00Z", session="old-1"), _repair("2026-10-28T14:00:00Z")
        ),
    )
    assert _repair_row(rows[130]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    assert _repair_row(rows[131]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    assert _repair_row(rows[132]) == ("REPAIR", ["held", "acked", "repair"], OWNER_ID)
    assert _repair_row(rows[133]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    # A re-hold on the repair's new head, then a new marker after it: still the repair's.
    rehold = _pr(
        135,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(1)),
            _repair("2026-10-28T13:00:00Z"),
            _hold("2026-10-28T15:00:00Z", _sha(135)),
            _repair("2026-10-28T15:00:01Z"),
        ],
    )
    assert _repair_row(_engine_rows(tmp_path, capsys, rehold)[135]) == (
        "REPAIR",
        ["held", "repair"],
        OWNER_ID,
    )
    # A third line, such as a note on ASVS record content, does not stop a marker qualifying.
    third = _comment(
        _repair_body() + "\nASVS record content: the Repair Manager may take it.",
        "2026-10-28T13:00:00Z",
    )
    assert _repair_row(_engine_rows(tmp_path, capsys, _held(136, third))[136]) == (
        "REPAIR",
        ["held", "repair"],
        OWNER_ID,
    )
    # A row that is not a repair carries a null owner, never a missing key.
    assert _engine_rows(tmp_path, capsys, _held(134))[134]["repairOwner"] is None


def test_a_repair_marker_that_does_not_qualify_falls_back_to_the_lander(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Controls: each of these MUST NOT read REPAIR. A marker is never a Lander event, so one that
    does not qualify is an ordinary reply, and the turn is the Lander's, the safe direction."""
    late = _held(140, _repair(), head=_sha(999))
    outsider = _repair()
    outsider["authorAssociation"] = "CONTRIBUTOR"
    edited = _repair()
    edited["lastEditedAt"] = "2026-10-28T14:00:00Z"
    as_review = _review(_repair_body(), "2026-10-28T13:00:00Z")
    line_two = _comment(SESSION + "transfer.\n" + _repair_body(), "2026-10-28T13:00:00Z")
    quoted = _comment("> " + _repair_body().replace("\n", "\n> "), "2026-10-28T13:00:00Z")
    manager = _comment(_repair_body(signature="Lander (8a04c9f3): "), "2026-10-28T13:00:00Z")
    unsigned = _comment(_repair_body(signature="Manager: "), "2026-10-28T13:00:00Z")
    rows = _engine_rows(
        tmp_path,
        capsys,
        # A push after the hold, and so possibly after the marker: the head no longer starts with
        # the hold's SHA. Only the SHA is read, never the committer date.
        late,
        # The marker in the hold's own second is not provably after it.
        _held(141, _repair("2026-10-28T12:00:00Z")),
        _held(142, outsider),
        _held(144, edited),
        _held(145, reviews=[as_review]),
        _held(146, line_two),
        _held(147, quoted),
        _held(148, manager),
        _held(149, unsigned),
        # Any other reply after the hold still hands the turn back, marker or not.
        _held(150, _repair(), _comment("Manager: I am back, fixing.", "2026-10-28T14:00:00Z")),
        # Two sessions named in one second cannot be ordered.
        _held(151, _repair(), _repair(session="other-session")),
        # An ack after the transfer, or in its second, may be the stood-down author still working.
        _held(152, _repair(), _ack("2026-10-28T14:00:00Z", _sha(152))),
        _held(153, _repair(), _ack("2026-10-28T13:00:00Z", _sha(153))),
    )
    assert _repair_row(rows[140]) == ("LANDER", ["new-commit", "replied"], None)
    for n in (141, 142, 145, 147, 148, 149, 150, 151, 152, 153):
        assert _repair_row(rows[n]) == ("LANDER", ["replied", "no-new-commit"], None), n
    # Signed on line one, it is a newer non-hold Lander comment, so no hold stands.
    assert _repair_row(rows[146]) == ("LANDER", ["no-hold"], None)
    assert _repair_row(rows[144]) == ("LANDER", ["replied", "edited", "no-new-commit"], None)


def test_a_repair_marker_without_a_standing_hold_is_not_a_repair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _engine_rows(
        tmp_path,
        capsys,
        # No hold at all: the marker alone is not a Lander event.
        _pr(160, comments=[_repair()]),
        # A marker older than the latest hold makes no REPAIR turn. Nor does the hold park the PR
        # on its author: the hold the marker transferred may have fallen off the fetched page, so
        # it reads LANDER repair-rehold, the safe direction.
        _pr(
            161,
            comments=[_repair("2026-10-28T11:00:00Z"), _hold("2026-10-28T12:00:00Z", _sha(161))],
        ),
        # A newer non-hold Lander comment after the marker: the newest Lander event is no hold.
        _held(162, _repair(), _comment(SESSION + "reviewing the repair.", "2026-10-28T14:00:00Z")),
        # A legacy prose hold is no hold, so a marker after it is no repair.
        _pr(163, comments=[_comment(SESSION + "**Held.**", "2026-10-28T12:00:00Z"), _repair()]),
    )
    # A bot marker is not read.
    bot = _repair()
    bot["author"] = {"__typename": "Bot", "login": "some-app"}
    more = _engine_rows(tmp_path, capsys, _held(165, bot))
    assert _repair_row(more[165]) == ("AUTHOR", ["held"], None)
    assert _repair_row(rows[160]) == ("LANDER", ["no-hold"], None)
    assert _repair_row(rows[161]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[162]) == ("LANDER", ["no-hold"], None)
    assert _repair_row(rows[163]) == ("LANDER", ["no-hold"], None)


def _transferred(n: int, *after_rehold: dict[str, Any]) -> dict[str, Any]:
    """PR ``n`` held at noon on an old head, transferred at 13:00, re-held at 15:00 on its head."""
    return _pr(
        n,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(1)),
            _repair("2026-10-28T13:00:00Z"),
            _hold("2026-10-28T15:00:00Z", _sha(n)),
            *after_rehold,
        ],
    )


def test_a_rehold_on_a_transferred_pr_with_no_fresh_marker_is_the_landers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The original author was told to stand down, so a re-hold with no fresh marker must not
    park the PR on them: the Lander's move is to post a fresh marker."""
    two_owners = _pr(
        168,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(1)),
            _repair("2026-10-28T13:00:00Z"),
            _repair("2026-10-28T13:00:00Z", session="other-session"),
            _hold("2026-10-28T15:00:00Z", _sha(168)),
        ],
    )
    rows = _engine_rows(
        tmp_path,
        capsys,
        _transferred(164),
        _transferred(166, _ack("2026-10-28T15:30:00Z", _sha(166))),
        # A re-transfer before the re-hold: the newest earlier marker names the owner.
        _pr(
            167,
            comments=[
                _hold("2026-10-28T12:00:00Z", _sha(1)),
                _repair("2026-10-28T13:00:00Z", session="old-1"),
                _repair("2026-10-28T14:00:00Z"),
                _hold("2026-10-28T15:00:00Z", _sha(167)),
            ],
        ),
        two_owners,
        # Control: a fresh qualifying marker after the re-hold is a REPAIR turn for its session.
        _transferred(169, _repair("2026-10-28T15:00:01Z", session="new-owner")),
        # Control: never a marker, so the re-hold stands for the author.
        _pr(
            172,
            comments=[
                _hold("2026-10-28T12:00:00Z", _sha(1)),
                _hold("2026-10-28T15:00:00Z", _sha(172)),
            ],
        ),
    )
    assert _repair_row(rows[164]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[166]) == ("LANDER", ["held", "acked", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[167]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[168]) == ("LANDER", ["held", "repair-rehold"], None)
    assert _repair_row(rows[169]) == ("REPAIR", ["held", "repair"], "new-owner")
    assert _repair_row(rows[172]) == ("AUTHOR", ["held"], None)
    # Hiding the superseded hold does not bring back the author's turn, and a marker from an
    # outside account was never a transfer.
    hidden_hold = _transferred(173)
    hidden_hold["comments"]["nodes"][0]["isMinimized"] = True
    outsider = _transferred(175)
    outsider["comments"]["nodes"][1]["authorAssociation"] = "CONTRIBUTOR"
    hidden = _engine_rows(tmp_path, capsys, hidden_hold, outsider)
    assert _repair_row(hidden[173]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(hidden[175]) == ("AUTHOR", ["held"], None)
    doc = {ENGINE: {"pages": [_page([_transferred(164)])], "required": ENGINE_REQUIRED}}
    _, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    line = next(x for x in out.splitlines() if x.startswith("LANDER"))
    assert line.split()[:2] == ["LANDER", f"held,repair-rehold={OWNER_ID}"]


def test_a_hold_after_any_marker_is_the_landers_whatever_came_before(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Any qualifying marker before the hold, and none after, reads LANDER ``repair-rehold``,
    whether or not the hold it transferred was fetched or recognised."""
    rehold = "2026-10-28T15:00:00Z"
    dismissed = _review(_marker_body(_sha(1)), "2026-10-28T12:00:00Z", state="DISMISSED")
    # More than COMMENT_PAGE comments after the marker push the earlier hold off the page; here
    # the page simply starts at the marker.
    truncated = _pr(190, comments=[_repair(), _hold(rehold, _sha(190))])
    legacy = _pr(
        191,
        comments=[
            _comment(SESSION + "**Held.**", "2026-10-28T12:00:00Z"),
            _repair(),
            _hold(rehold, _sha(191)),
        ],
    )
    # The marker shares the earlier hold's second, so it is not provably after that hold.
    same_second = _pr(
        192,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(1)),
            _repair("2026-10-28T12:00:00Z"),
            _hold(rehold, _sha(192)),
        ],
    )
    dismissed_hold = _pr(193, comments=[_repair(), _hold(rehold, _sha(193))], reviews=[dismissed])
    # Controls: an outside account's marker was never a transfer, and a fresh marker after the
    # hold is a REPAIR turn.
    outsider = _pr(194, comments=[_repair(), _hold(rehold, _sha(194))])
    outsider["comments"]["nodes"][0]["authorAssociation"] = "CONTRIBUTOR"
    fresh = _pr(
        195, comments=[_repair(), _hold(rehold, _sha(195)), _repair("2026-10-28T15:00:01Z")]
    )
    never = _pr(196, comments=[_hold(rehold, _sha(196))])
    rows = _engine_rows(
        tmp_path, capsys, truncated, legacy, same_second, dismissed_hold, outsider, fresh, never
    )
    for n in (190, 191, 192, 193):
        assert _repair_row(rows[n]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID), n
    assert _repair_row(rows[194]) == ("AUTHOR", ["held"], None)
    assert _repair_row(rows[195]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    assert _repair_row(rows[196]) == ("AUTHOR", ["held"], None)


def _minimized(comment: dict[str, Any]) -> dict[str, Any]:
    comment["isMinimized"] = True
    return comment


def test_a_minimized_marker_is_a_cancelled_transfer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Minimizing the newest marker hands the PR back to its author: it never gives REPAIR and
    never keeps a hold on the Lander, and the PR reads as if the marker had never been posted."""
    before = _transferred(174)
    _minimized(before["comments"]["nodes"][1])
    # The newest marker before the re-hold is minimized; the older visible one still qualifies.
    re_transfer = _pr(
        176,
        comments=[
            _hold("2026-10-28T12:00:00Z", _sha(1)),
            _repair("2026-10-28T13:00:00Z", session="old-1"),
            _minimized(_repair("2026-10-28T14:00:00Z")),
            _hold("2026-10-28T15:00:00Z", _sha(176)),
        ],
    )
    outsider = _minimized(_repair())
    outsider["authorAssociation"] = "CONTRIBUTOR"
    edited = _minimized(_repair())
    edited["lastEditedAt"] = "2026-10-28T14:00:00Z"
    rows = _engine_rows(
        tmp_path,
        capsys,
        before,
        re_transfer,
        # Control: the same PR with its marker visible is the Lander's re-hold.
        _transferred(177),
        # After the hold: no REPAIR and no reply, so the hold stands for the author.
        _held(178, _minimized(_repair())),
        # A minimized marker in a visible one's second names no second session.
        _held(179, _repair(), _minimized(_repair(session="other-session"))),
        # The newest QUALIFYING marker wins: a newer minimized one does not displace it.
        _held(180, _repair(session="old-1"), _minimized(_repair("2026-10-28T14:00:00Z"))),
        # Controls: an outside account's minimized marker was never a marker, so it is a reply,
        # and an edit to a minimized marker is an edit.
        _held(181, outsider),
        _held(182, edited),
    )
    assert _repair_row(rows[174]) == ("AUTHOR", ["held"], None)
    assert _repair_row(rows[176]) == ("LANDER", ["held", "repair-rehold"], "old-1")
    assert _repair_row(rows[177]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[178]) == ("AUTHOR", ["held"], None)
    assert _repair_row(rows[179]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    assert _repair_row(rows[180]) == ("REPAIR", ["held", "repair"], "old-1")
    assert _repair_row(rows[181]) == ("LANDER", ["replied", "no-new-commit"], None)
    assert _repair_row(rows[182]) == ("LANDER", ["edited", "no-new-commit"], None)
    cancelled = hpt.Event(NOW, _repair_body(), bot=False, trusted=False, associated=True)
    assert cancelled.cancelled and cancelled.repair_by is None and not cancelled.lander
    for not_cancelled in (
        hpt.Event(NOW, _repair_body(), bot=False, trusted=True, associated=True),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=False, associated=False),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=False),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=False, associated=True, review=True),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=False, associated=True, dismissed=True),
        hpt.Event(NOW, "Manager: I am back.", bot=False, trusted=False, associated=True),
    ):
        assert not not_cancelled.cancelled


def _cut(pr: dict[str, Any], kind: str = "comments", info: object = None) -> dict[str, Any]:
    """``pr`` with its ``kind`` page cut: ``info`` replaces ``pageInfo``, or "absent" drops it."""
    if info == "absent":
        del pr[kind]["pageInfo"]
    else:
        pr[kind]["pageInfo"] = {"hasPreviousPage": True} if info is None else info
    return pr


def test_a_cut_page_never_reads_author(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A marker before the hold, or an old comment edited into a reply, may be off a cut page, so
    a row that would read AUTHOR reads LANDER ``page-cut``. So does one that would read REPAIR,
    keeping ``repair`` and its owner: an author comment or a later hold off the page could have
    ended the transfer. Nothing else changes."""
    rehold = "2026-10-28T15:00:00Z"
    rows = _engine_rows(
        tmp_path,
        capsys,
        # The transfer that told the author to stand down is off the page: only the re-hold shows.
        _cut(_pr(200, comments=[_hold(rehold, _sha(200))])),
        _cut(_held(201), "reviews"),
        _cut(_held(202, _ack("2026-10-28T17:30:00Z", _sha(202)))),
        # A pageInfo that cannot say is no proof the page is whole.
        _cut(_held(203), info="absent"),
        _cut(_held(204), info={"hasPreviousPage": None}),
        _cut(_held(205), "reviews", info="x"),
        # A transfer on a cut page: whatever ended it may be off the page.
        _cut(_held(207, _repair())),
        _cut(_held(213, _ack("2026-10-28T12:30:00Z", _sha(213)), _repair()), "reviews"),
        # Controls: an uncut page still reads AUTHOR or REPAIR, and LANDER rows do not change.
        _held(206),
        _held(214, _repair()),
        _cut(_held(208, _comment("Manager: fixed.", "2026-10-28T13:00:00Z"))),
        _cut(_transferred(209)),
        _cut(_pr(210)),
    )
    for n in (200, 201, 203, 204, 205):
        assert _repair_row(rows[n]) == ("LANDER", ["held", "page-cut"], None), n
    assert _repair_row(rows[202]) == ("LANDER", ["held", "acked", "page-cut"], None)
    assert _repair_row(rows[206]) == ("AUTHOR", ["held"], None)
    assert _repair_row(rows[207]) == ("LANDER", ["held", "repair", "page-cut"], OWNER_ID)
    assert _repair_row(rows[213]) == (
        "LANDER",
        ["held", "acked", "repair", "page-cut"],
        OWNER_ID,
    )
    assert _repair_row(rows[214]) == ("REPAIR", ["held", "repair"], OWNER_ID)
    assert _repair_row(rows[208]) == ("LANDER", ["replied", "no-new-commit"], None)
    assert _repair_row(rows[209]) == ("LANDER", ["held", "repair-rehold"], OWNER_ID)
    assert _repair_row(rows[210]) == ("LANDER", ["no-hold"], None)
    queued = _cut(_held(211))
    queued["mergeQueueEntry"] = {"state": "QUEUED"}
    assert _repair_row(_engine_rows(tmp_path, capsys, queued)[211]) == (
        "LANDER",
        ["held", "page-cut", "in-queue"],
        None,
    )
    doc = {ENGINE: {"pages": [_page([_cut(_held(212))])], "required": ENGINE_REQUIRED}}
    _, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    line = next(x for x in out.splitlines() if x.startswith("LANDER"))
    assert line.split()[:2] == ["LANDER", "held,page-cut"]


def test_the_query_asks_whether_the_comment_and_review_pages_were_cut() -> None:
    query = " ".join(hpt.QUERY.split())
    for kind, page in (("comments", hpt.COMMENT_PAGE), ("reviews", hpt.REVIEW_PAGE)):
        assert f"{kind}(last: {page}) {{ pageInfo {{ hasPreviousPage }} nodes {{" in query, kind


def test_the_repair_marker_shape_is_exact() -> None:
    assert hpt.repair_owner(_repair_body()) == OWNER_ID
    assert hpt.repair_owner(_repair_body("a" * 64)) == "a" * 64
    # As THE MARKER SHAPE says, nothing is required after ``Lander (session``, not even a space.
    assert hpt.repair_owner(_repair_body(signature="Lander (sessionless) ")) == OWNER_ID
    for bad in ("", "a" * 65, "has space", "dot.id", "slash/id", "colon:id"):
        assert hpt.repair_owner(_repair_body(bad)) is None, bad
    marker = f"<!-- repair-owner session={OWNER_ID} -->"
    for body in (
        marker,
        marker + "\n",
        " " + marker + "\n" + SESSION,
        "\n" + marker + "\n" + SESSION,
        marker + " trailing\n" + SESSION,
        marker + "\n\n" + SESSION,
        marker + "\u2028" + SESSION,
        marker + "\x0b\n" + SESSION,
        f"<!--repair-owner session={OWNER_ID}-->\n" + SESSION,
    ):
        assert hpt.repair_owner(body) is None, repr(body)
    # A repair marker is neither a hold nor an ack, and a hold is not a repair marker.
    assert hpt.hold_head(_repair_body()) is None
    assert hpt.ack_head(_repair_body()) is None
    assert hpt.repair_owner(_marker_body("abcdef1")) is None
    event = hpt.Event(NOW, _repair_body(), bot=False, trusted=True)
    assert not event.lander and event.repair_by == OWNER_ID
    for gated in (
        hpt.Event(NOW, _repair_body(), bot=False, trusted=False),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=True, dismissed=True),
        hpt.Event(NOW, _repair_body(), bot=False, trusted=True, review=True),
    ):
        assert gated.repair_by is None


def test_a_queued_or_armed_repair_is_the_landers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    queued = _held(170, _repair())
    queued["mergeQueueEntry"] = {"state": "QUEUED"}
    armed = _held(171, _repair())
    armed["autoMergeRequest"] = {"enabledAt": "2026-10-28T10:00:00Z"}
    rows = _engine_rows(tmp_path, capsys, queued, armed)
    assert _repair_row(rows[170]) == ("LANDER", ["held", "repair", "in-queue"], OWNER_ID)
    assert _repair_row(rows[171]) == ("LANDER", ["held", "repair", "auto-armed"], OWNER_ID)


def test_repair_rows_sort_between_lander_and_author_and_show_the_owner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prs = [_held(180), _held(181, _repair()), _pr(182)]
    doc = {ENGINE: {"pages": [_page(prs)], "required": ENGINE_REQUIRED}}
    _, rows = _run(tmp_path, doc, capsys, "--repo", ENGINE)
    assert [(r["turn"], r["number"]) for r in rows] == [
        ("LANDER", 182),
        ("REPAIR", 181),
        ("AUTHOR", 180),
    ]
    code, out = _run(tmp_path, doc, capsys, "--repo", ENGINE, json_out=False)
    assert code == 0
    line = next(x for x in out.splitlines() if x.startswith("REPAIR"))
    assert line.split()[:4] == ["REPAIR", f"held,repair={OWNER_ID}", "MessageFoundry", "181"]


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
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(27, comments=[edited, _hold("2026-10-28T12:00:00Z", _sha(27))]),
        _pr(28, comments=[unedited, _hold("2026-10-28T12:00:00Z", _sha(28))]),
    )
    assert _turn(rows[27]) == ("LANDER", ["replied", "edited", "no-new-commit"])
    # The age dates from the edit, the newest thing that happened.
    assert rows[27]["newestEvent"] == "2026-10-28T13:00:00Z"
    assert _turn(rows[28]) == ("AUTHOR", ["held"])


def test_any_edit_after_the_hold_hands_the_turn_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every seat posts under one login, so an edit to the hold, or to an older Lander comment, may
    # be an author answering in place. It cannot be told apart, so it is the Lander's turn.
    hold = _hold("2026-10-28T12:00:00Z", _sha(37))
    hold["lastEditedAt"] = "2026-10-28T13:00:00Z"
    older = _comment(SESSION + "Looking at it.", "2026-10-28T11:00:00Z")
    older["lastEditedAt"] = "2026-10-28T13:00:00Z"
    before = _comment(SESSION + "Looking at it.", "2026-10-28T10:00:00Z")
    before["lastEditedAt"] = "2026-10-28T11:00:00Z"
    review = _review(SESSION + "Notes.", "2026-10-28T11:00:00Z")
    review["lastEditedAt"] = "2026-10-28T12:00:00Z"
    rows = _engine_rows(
        tmp_path,
        capsys,
        _pr(37, comments=[hold]),
        _pr(38, comments=[older, _hold("2026-10-28T12:00:00Z", _sha(38))]),
        # An edit finished before the hold was posted changes nothing.
        _pr(39, comments=[before, _hold("2026-10-28T12:00:00Z", _sha(39))]),
        # An edit in the hold's own second is not provably before it.
        _pr(42, comments=[_hold("2026-10-28T12:00:00Z", _sha(42))], reviews=[review]),
    )
    assert _turn(rows[37]) == ("LANDER", ["edited", "no-new-commit"])
    assert _turn(rows[38]) == ("LANDER", ["edited", "no-new-commit"])
    assert _turn(rows[39]) == ("AUTHOR", ["held"])
    assert _turn(rows[42]) == ("LANDER", ["edited", "no-new-commit"])


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


@pytest.mark.parametrize("kind", ["comments", "reviews"])
@pytest.mark.parametrize("conn", [None, "x", [], {}, {"nodes": None}, {"nodes": {}}, "absent"])
def test_malformed_comment_or_review_connection_is_an_error_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str, conn: object
) -> None:
    # Read as zero events, a lost connection could hide the reply that ends a hold.
    pr = _pr(35, comments=[_hold("2026-10-28T12:00:00Z", _sha(35))])
    if conn == "absent":
        del pr[kind]
    else:
        pr[kind] = conn
    rows = _engine_rows(tmp_path, capsys, pr, _pr(36))
    assert rows[35]["turn"] == "ERROR" and "PR unreadable" in rows[35]["error"]
    assert kind in rows[35]["error"]
    assert rows[36]["turn"] == "LANDER"


def test_an_unreadable_submitted_at_does_not_fall_back_to_created_at(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # createdAt predates the hold, so a fall back would date this reply before it: AUTHOR, wrong.
    review = _review("Manager: fixed.", "garbage")
    review["createdAt"] = "2026-10-28T11:00:00Z"
    pr = _pr(43, comments=[_hold("2026-10-28T12:00:00Z", _sha(43))], reviews=[review])
    row = _engine_rows(tmp_path, capsys, pr)[43]
    assert row["turn"] == "ERROR" and "submittedAt" in row["error"]


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
    # Every row carries the key, an ERROR row's null, so a consumer never meets a KeyError.
    assert by[30]["repairOwner"] is None
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


def test_a_held_pr_in_the_queue_or_armed_is_the_landers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # It merges with no move from its author, so dequeuing or disarming is the Lander's move.
    queued = _pr(65, comments=[_hold("2026-10-28T12:00:00Z", _sha(65))])
    queued["mergeQueueEntry"] = {"state": "QUEUED"}
    armed = _pr(66, comments=[_hold("2026-10-28T12:00:00Z", _sha(66))])
    armed["autoMergeRequest"] = {"enabledAt": "2026-10-28T10:00:00Z"}
    rows = _engine_rows(tmp_path, capsys, queued, armed)
    assert _turn(rows[65]) == ("LANDER", ["held", "in-queue"])
    assert _turn(rows[66]) == ("LANDER", ["held", "auto-armed"])


@pytest.mark.parametrize("draft", ["false", 1, None])
def test_a_non_bool_is_draft_is_an_error_row_not_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], draft: object
) -> None:
    pr = _pr(67, comments=[_hold("2026-10-28T12:00:00Z", _sha(67))])
    pr["isDraft"] = draft
    rows = _engine_rows(tmp_path, capsys, pr, _pr(68))
    assert rows[67]["turn"] == "ERROR" and "isDraft" in rows[67]["error"]
    assert rows[68]["turn"] == "LANDER"


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


@pytest.mark.parametrize(
    "page_info",
    [{"endCursor": None}, {"hasNextPage": None}, {"hasNextPage": "false"}, {"hasNextPage": 0}],
)
def test_a_has_next_page_that_is_not_a_bool_is_a_read_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], page_info: dict[str, Any]
) -> None:
    # Reading a missing or non-bool flag as "no next page" would print a partial list as whole.
    page = _page([_pr(77)])
    page["data"]["repository"]["pullRequests"]["pageInfo"] = page_info
    code, rows = _run(tmp_path, {KORUS: {"pages": [page]}}, capsys, "--repo", KORUS)
    assert code == 0
    assert [r["turn"] for r in rows] == ["ERROR"]
    assert rows[0]["error"].startswith("read failed") and "hasNextPage" in rows[0]["error"]

    def gh(args: list[str], stdin: str | None) -> str:
        return json.dumps(page)

    assert hpt.main(["--repo", KORUS, "--json"], gh=gh, now=lambda: NOW) == 0
    live = json.loads(capsys.readouterr().out)
    assert [r["turn"] for r in live] == ["ERROR"] and "hasNextPage" in live[0]["error"]


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
