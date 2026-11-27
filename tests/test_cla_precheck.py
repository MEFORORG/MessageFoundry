# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline tests for scripts/security/cla_precheck.py (BACKLOG #5644, #5645).

Every GitHub reply comes from tests/fixtures/cla_precheck/replies.json, synthetic pages in the shape
of the GraphQL connection the script queries. No test reaches the network.
"""

from __future__ import annotations

import ast
import functools
import http.client
import io
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from scripts.security import cla_precheck
from scripts.security.cla_precheck import (
    EXIT_FAULT,
    EXIT_PASS,
    EXIT_REFUSED,
    PrecheckFault,
    attribute,
    evaluate,
    fetch_commits,
    matches_allowlist,
    parse_allowlist,
    run,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "cla_precheck" / "replies.json"
_ALLOWLIST = ["wshallwshall", "dependabot[bot]", "github-actions[bot]"]
_HEAD = "ab" * 20
_ENV = {
    "GITHUB_REPOSITORY": "MEFORORG/MessageFoundry",
    "CLA_PR_NUMBER": "7",
    "CLA_ALLOWLIST": "wshallwshall,dependabot[bot],github-actions[bot]",
}


@functools.cache
def _scenarios() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    return loaded


def _first_100_linked() -> Mapping[str, Any]:
    """The page the fixture names "first_100_linked": 100 commits by one linked account."""
    octo = {
        "name": "Octo Contributor",
        "user": {"databaseId": 90000001, "login": "octo-contributor"},
    }
    nodes = [
        {"commit": {"oid": f"{i:040x}", "author": octo, "committer": octo}} for i in range(1, 101)
    ]
    commits = {
        "totalCount": 101,
        "pageInfo": {"endCursor": "Y3Vyc29yOjEwMA==", "hasNextPage": True},
        "nodes": nodes,
    }
    return {"data": {"repository": {"pullRequest": {"headRefOid": _HEAD, "commits": commits}}}}


class _Replay:
    """Serve one scenario's pages in order, recording the variables of every call."""

    def __init__(self, scenario: str) -> None:
        self.pages: list[Mapping[str, Any]] = [
            _first_100_linked() if page == "first_100_linked" else page
            for page in _scenarios()[scenario]
        ]
        self.calls: list[dict[str, object]] = []

    def __call__(self, query: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        self.calls.append(dict(variables))
        assert self.pages, "the script asked for a page past the last one the scenario holds"
        return self.pages.pop(0)


def _no_signatures() -> frozenset[int]:
    return frozenset()


def _no_sleep(_seconds: float) -> None:
    raise AssertionError("the pre-check waited to re-read where no re-read was expected")


def _run(env: Mapping[str, str], transport: cla_precheck.Transport) -> int:
    """`run` with the network replaced: GraphQL by `transport`, the signature file by an empty one,
    and the clock by one that refuses to wait."""
    return run(env, transport, _no_signatures, _no_sleep)


def _verdict(scenario: str) -> tuple[str, ...]:
    """The refusals for one scenario."""
    read = fetch_commits(_Replay(scenario), "MEFORORG", "MessageFoundry", 7)
    return evaluate(read, _ALLOWLIST).refusals


def test_it_pages_past_the_hundredth_commit_and_refuses_the_impersonator_there() -> None:
    """BACKLOG #5645 (the 100-commit cap): upstream's action read one page, and the patched one
    pages too. The impersonating commit is the 101st, so only a reader that follows hasNextPage
    sees it."""
    replay = _Replay("impersonation_on_page_two")
    read = fetch_commits(replay, "MEFORORG", "MessageFoundry", 7)
    assert (len(read.commits), read.total, read.head) == (101, 101, _HEAD)
    assert [call["cursor"] for call in replay.calls] == [None, "Y3Vyc29yOjEwMA=="]
    refusals = evaluate(read, _ALLOWLIST).refusals
    assert len(refusals) == 1
    assert "wshallwshall" in refusals[0] and f"{101:040x}" in refusals[0]


def test_the_same_two_pages_with_a_linked_author_pass() -> None:
    """The neighbour of the test above: same size, page two linked, nothing refused."""
    assert _verdict("linked_on_page_two") == ()


@pytest.mark.parametrize(
    ("scenario", "author"),
    [
        ("unlinked_name_not_allowlisted", "Somebody Else"),
        ("name_folded_into_linked", "octo-contributor"),
        ("committer_attribution", "Unlinked Author"),
        ("actions_bot_committer", "Unlinked Author"),
    ],
)
def test_an_unlinked_author_is_refused_whatever_the_committer_or_namesake(
    scenario: str, author: str
) -> None:
    """Owner ruling 2026-11-13: the CLA binds the AUTHOR, so a commit whose author is linked to no
    account is refused, whether its committer is allowlisted, the bot, any other account, or nobody,
    and whether or not its git name matches a signed login. The refusal names the AUTHOR's git name,
    never the committer the action attributes it to."""
    refusals = _verdict(scenario)
    assert len(refusals) == 1, refusals
    assert f"git author, {author!r}," in refusals[0]
    assert "wshallwshall" not in refusals[0] or author == "wshallwshall"


def test_the_attribution_order_is_author_then_committer_then_raw_author() -> None:
    """BACKLOG #5644's subject puts the committer first; the bundle puts the author's account first.

    extractUserFromCommit is `author.user || committer.user || author || committer`.
    """
    both = {
        "oid": "a",
        "author": {"name": "A", "user": {"login": "author-acct", "databaseId": 1}},
        "committer": {"name": "C", "user": {"login": "committer-acct", "databaseId": 2}},
    }
    assert attribute(both).name == "author-acct"
    committer_only = {**both, "author": {"name": "A", "user": None}}
    who = attribute(committer_only)
    assert (who.name, who.database_id) == ("committer-acct", 2)
    neither = {**committer_only, "committer": {"name": "C", "user": None}}
    who = attribute(neither)
    assert (who.name, who.database_id, who.author_linked) == ("A", None, False)


def test_an_empty_user_object_is_chosen_as_javascript_chooses_it() -> None:
    """JavaScript's `||` passes over null and the falsy primitives but never an object, so an empty
    `{}` user is still chosen, and its name is empty, never the committer's login."""
    commit = {
        "oid": "a",
        "author": {"name": "A", "user": {}},
        "committer": {"name": "C", "user": {"login": "committer-acct", "databaseId": 2}},
    }
    who = attribute(commit)
    assert (who.name, who.author_linked) == ("", True)


def test_an_unlinked_author_under_a_signed_ordinary_committer_is_refused() -> None:
    """The case the earlier rules missed: committer octo is signed and not allowlisted, so the
    action checks octo in the author's place. The author never signed, so it refuses."""
    commit = {
        "oid": f"{5:040x}",
        "author": {"name": "Mallory", "user": None},
        "committer": {
            "name": "Octo",
            "user": {"login": "octo-contributor", "databaseId": 90000001},
        },
    }
    refusals = evaluate(fetch_commits(_serve([_page([commit], 1, False)]), "M", "N", 7), _ALLOWLIST)
    assert len(refusals.refusals) == 1 and "'Mallory'" in refusals.refusals[0]
    assert "octo-contributor" not in refusals.refusals[0]


def test_a_linked_author_wins_over_an_actions_bot_committer() -> None:
    assert _verdict("author_linked_committer_actions_bot") == ()


def _fault(scenario: str) -> str | None:
    read = fetch_commits(_Replay(scenario), "MEFORORG", "MessageFoundry", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict.refusals == (), verdict.refusals
    return verdict.fault


def test_a_read_short_of_total_count_is_a_fault_until_the_cap_is_measured() -> None:
    """Owner ruling 2026-11-13: a short read is a fault (warn and pass), not a refusal, because a
    GitHub-side cap would otherwise fail every large pull request closed."""
    fault = _fault("short_read")
    assert fault and "read 2 distinct commits where the pull request has 300" in fault


def test_a_repeated_commit_is_a_fault_too() -> None:
    fault = _fault("repeated_commit")
    assert fault and "100 distinct commits" in fault


def test_a_malformed_first_page_commit_keeps_its_slot() -> None:
    """The reviewer's case: page one is [malformed, octo], page two [new-person, unsigned]. The
    malformed commit must still count toward the first page, or new-person slides into the
    first page's keys and rule 2's refusal is lost. A null author is now refused under rule 1,
    so the malformed shape here is one GitHub never sends: this guards the slot-keeping path as
    defence in depth, and test_only_a_readable_unlinked_commit_keys_the_first_page covers it
    for a refused commit."""
    malformed = {"oid": f"{1:040x}", "author": "not-an-object", "committer": None}
    pages = [
        _page([malformed, _commit(2, "Octo", "octo-contributor", 90000001)], 3, True),
        _page([_commit(3, "New Person", "new-person", 90000003)], 3, False),
    ]
    verdict = evaluate(fetch_commits(_serve(pages), "M", "N", 7), _ALLOWLIST, _no_signatures)
    assert verdict.fault
    assert len(verdict.refusals) == 1 and "new-person" in verdict.refusals[0]


def test_an_author_first_seen_past_the_hundredth_commit_is_refused() -> None:
    """BACKLOG #5645: upstream's action never read commit 101, so it never asked that commit's new
    author to sign; rule 2 of this pre-check refused them. The patched action reads past page one
    and asks that author to sign, and rule 2 still refuses them while the signature file lacks
    their id."""
    refusals = _verdict("new_author_past_100")
    assert len(refusals) == 1 and "new-person" in refusals[0]


def test_rule_two_keys_the_first_page_however_short_it_is() -> None:
    """Rule 2 keys the first page, whatever its length. An unsigned author first seen on page two
    is refused, even though fewer than 100 commits came before it. (Upstream's action read that
    one page only; the patched action reads page two as well and asks the author to sign.)"""
    read = fetch_commits(_Replay("short_first_page"), "MEFORORG", "MessageFoundry", 7)
    assert read.first_page == 1
    refusals = evaluate(read, _ALLOWLIST).refusals
    assert (
        len(refusals) == 1
        and "new-person" in refusals[0]
        and "past the first 1 commits" in refusals[0]
    )


def test_an_author_past_the_first_page_who_signed_is_not_refused() -> None:
    """The author is first seen past page one, and the signature file the action keeps already
    holds their id, so refusing would be a false refusal of a signed contributor."""
    read = fetch_commits(_Replay("new_author_past_100"), "MEFORORG", "MessageFoundry", 7)
    calls: list[int] = []

    def signed() -> frozenset[int]:
        calls.append(1)
        return frozenset({90000003})

    assert evaluate(read, _ALLOWLIST, signed).refusals == ()
    assert len(evaluate(read, _ALLOWLIST, _no_signatures).refusals) == 1
    assert calls == [1], (
        "the signature file is read once, and only for an author first seen past the first page"
    )
    linked = fetch_commits(_Replay("linked_on_page_two"), "MEFORORG", "MessageFoundry", 7)
    evaluate(linked, _ALLOWLIST, signed)
    assert calls == [1], (
        "a pull request with no author first seen past the first page does not read the signature file"
    )


def _serve(pages: list[Mapping[str, Any]]) -> cla_precheck.Transport:
    replies = iter(pages)
    return lambda _q, _v: next(replies)


def _page(
    commits: list[Mapping[str, Any]], total: int, more: bool, head: str = _HEAD
) -> Mapping[str, Any]:
    nodes = [{"commit": c} for c in commits]
    info = {"endCursor": "Y3Vyc29yOjI=" if more else None, "hasNextPage": more}
    connection = {"totalCount": total, "pageInfo": info, "nodes": nodes}
    return {"data": {"repository": {"pullRequest": {"headRefOid": head, "commits": connection}}}}


def _commit(
    oid: int | str, name: str, login: str | None = None, db_id: int | None = None
) -> Mapping[str, Any]:
    person = {
        "name": name,
        "user": None if login is None else {"databaseId": db_id, "login": login},
    }
    return {
        "oid": oid if isinstance(oid, str) else f"{oid:040x}",
        "author": person,
        "committer": person,
    }


def test_a_linked_signed_author_does_not_cover_an_unlinked_commit_sharing_its_name() -> None:
    """Rule 1 judges an unlinked author on its own, so an unlinked 'alice' cannot have signed,
    whatever a linked alice before it did; the verdict must not depend on commit order."""
    signed = frozenset({90000004})
    for later in (
        [_commit(2, "alice", "alice", 90000004), _commit(3, "alice")],
        [_commit(3, "alice"), _commit(2, "alice", "alice", 90000004)],
    ):
        pages = [
            _page([_commit(1, "Octo", "octo-contributor", 90000001)], 3, True),
            _page(later, 3, False),
        ]
        read = fetch_commits(_serve(pages), "MEFORORG", "MessageFoundry", 7)
        refusals = evaluate(read, _ALLOWLIST, lambda: signed).refusals
        assert len(refusals) == 1 and f"{3:040x}" in refusals[0], later


def test_a_refusal_already_proven_survives_a_later_fault(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An impersonation on page one is a refusal; a signature file or page two that then faults
    must not turn it into exit 3, which the workflow passes."""

    def unreadable() -> frozenset[int]:
        raise PrecheckFault("the signature file answered HTTP 502")

    assert run(_ENV, _Replay("impersonation_on_page_two"), unreadable) == EXIT_REFUSED
    capsys.readouterr()
    pages = [
        _page([_commit(1, "wshallwshall")], 2, True),
        {"errors": [{"message": "Something went wrong"}]},
    ]
    assert run(_ENV, lambda _q, _v: pages.pop(0), _no_signatures) == EXIT_REFUSED
    out = capsys.readouterr().out
    assert "::warning title=CLA pre-check fault::" in out and "refused::" in out
    # The neighbour: the same page-two fault with nothing refused on page one stays a fault.
    pages = [_page([_commit(1, "Octo", "octo-contributor", 90000001)], 2, True), {"errors": [{}]}]
    assert run(_ENV, lambda _q, _v: pages.pop(0), _no_signatures) == EXIT_FAULT


def test_an_unreadable_signature_file_with_nothing_else_refused_is_a_fault() -> None:
    def unreadable() -> frozenset[int]:
        raise PrecheckFault("the signature file answered HTTP 502")

    assert run(_ENV, _Replay("new_author_past_100"), unreadable) == EXIT_FAULT


def test_a_linked_author_with_a_malformed_committer_is_not_a_fault() -> None:
    """The action reads no committer once the author is linked, so neither does the mirror."""
    commit = {"oid": "a", "author": {"name": "A", "user": {"login": "a", "databaseId": 1}}}
    for committer in (None, "not-an-object", {"name": "C", "user": "not-an-object"}):
        assert attribute({**commit, "committer": committer}).name == "a"


def _linked_page_one() -> Mapping[str, Any]:
    """A fresh page one by one linked account, so no test can mutate another's copy."""
    return _page([_commit(1, "Octo", "octo-contributor", 90000001)], 2, True)


_COMMITTERS = [None, "not-an-object", {"name": "C", "user": "not-an-object"}, "absent"]


@pytest.mark.parametrize("committer", _COMMITTERS)
def test_an_unlinked_author_with_a_null_or_malformed_committer_is_refused(
    committer: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5644 added item 1: rule 1 refuses an unlinked author whatever the committer, unless
    GraphQL reported an error inside the commit (owner ruling W7-R11; tested below). The
    commit sits past the first page, where rule 2 does not read it; before the fix an
    unreadable committer made this a fault (exit 3), which the workflow passes. No rule reads the
    key of a commit past that page, so its committer is not a fault either."""
    commit: dict[str, object] = {"oid": f"{2:040x}", "author": {"name": "Mallory", "user": None}}
    if committer != "absent":
        commit["committer"] = committer
    pages = [_linked_page_one(), _page([commit], 2, False)]
    assert _run(_ENV, _serve(pages)) == EXIT_REFUSED
    out = capsys.readouterr().out
    assert "refused::" in out and "'Mallory'" in out
    assert "fault::" not in out, out


@pytest.mark.parametrize("committer", _COMMITTERS)
def test_a_linked_author_with_a_null_or_malformed_committer_passes_past_page_one(
    committer: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative control for the test above: the same committers under a LINKED author, the
    account page one already holds, refuse nothing and fault nothing."""
    octo = {"name": "Octo", "user": {"databaseId": 90000001, "login": "octo-contributor"}}
    commit: dict[str, object] = {"oid": f"{2:040x}", "author": octo}
    if committer != "absent":
        commit["committer"] = committer
    assert _run(_ENV, _serve([_linked_page_one(), _page([commit], 2, False)])) == EXIT_PASS
    out = capsys.readouterr().out
    assert "refused::" not in out and "fault::" not in out, out


@pytest.mark.parametrize("page", [1, 2])
def test_a_null_author_is_refused_and_not_also_a_fault(
    page: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """A null author (schema-legal) has no account linked, so rule 1 refuses it, on the first page
    or past it, and the refusal is not also reported as a fault about a valid reply."""
    commit = {"oid": f"{2:040x}", "author": None, "committer": {"name": "C", "user": None}}
    if page == 1:
        pages = [_page([commit, _commit(3, "Octo", "octo-contributor", 90000001)], 2, False)]
    else:
        pages = [_linked_page_one(), _page([commit], 2, False)]
    assert _run(_ENV, _serve(pages)) == EXIT_REFUSED
    out = capsys.readouterr().out
    assert f"commit {2:040x} has no git author GitHub reports" in out
    assert "fault::" not in out, out


def test_an_author_with_no_user_key_is_unlinked(capsys: pytest.CaptureFixture[str]) -> None:
    commit = {"oid": f"{2:040x}", "author": {"name": "Mallory"}, "committer": None}
    assert _run(_ENV, _serve([_linked_page_one(), _page([commit], 2, False)])) == EXIT_REFUSED
    out = capsys.readouterr().out
    assert "'Mallory'" in out and "fault::" not in out, out


@pytest.mark.parametrize(
    "commit",
    [
        {"oid": f"{2:040x}", "committer": None},
        {"oid": f"{2:040x}", "author": "not-an-object", "committer": None},
        {"oid": f"{2:040x}", "author": {"name": "M", "user": ""}, "committer": None},
    ],
    ids=["absent-author-key", "author-not-an-object", "user-not-an-object"],
)
def test_a_reply_in_the_wrong_shape_is_a_fault_naming_its_commit(
    commit: Mapping[str, Any], request: pytest.FixtureRequest
) -> None:
    """The query always selects author and user, so their absence or a non-object value is a reply
    in the wrong shape: a fault (warn and pass, owner ruling 2026-11-13), never a refusal, which
    would fail every pull request if GitHub's reply changed shape."""
    read = fetch_commits(_serve([_linked_page_one(), _page([commit], 2, False)]), "M", "N", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict.refusals == ()
    reason = {
        "absent-author-key": "a commit has no author key",
        "author-not-an-object": "a commit's author is not an object",
        "user-not-an-object": "a commit's user is not an object",
    }[request.node.callspec.id]
    assert verdict.fault == f"commit {2:040x}: {reason}"


def test_a_linked_author_with_no_integer_id_past_page_one_is_a_fault() -> None:
    """Rule 2 cannot look such an author up in the signature file; a silent skip would pass."""
    author = {"name": "N", "user": {"login": "new-person", "databaseId": None}}
    commit = {"oid": f"{2:040x}", "author": author, "committer": author}
    read = fetch_commits(_serve([_linked_page_one(), _page([commit], 2, False)]), "M", "N", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict.refusals == ()
    assert verdict.fault == f"commit {2:040x}: its linked author has no integer databaseId"


def test_ten_refusals_are_all_annotated(capsys: pytest.CaptureFixture[str]) -> None:
    unlinked = [_commit(i, f"Unlinked {i}") for i in range(1, 11)]
    assert _run(_ENV, _serve([_page(unlinked, 10, False)])) == EXIT_REFUSED
    lines = capsys.readouterr().out.splitlines()
    annotated = [line for line in lines if line.startswith("::error title=CLA pre-check refused::")]
    assert len(annotated) == 10 and not any("more refusal" in line for line in annotated)


def test_both_rules_reach_the_first_annotations_and_the_rest_reach_the_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """GitHub keeps 10 error annotations a step. Twelve rule-1 refusals must not push the rule-2
    one past them, and none is dropped from the log."""
    unlinked = [_commit(i, f"Unlinked {i}") for i in range(1, 13)]
    page_one = _page([_commit(100, "Octo", "octo-contributor", 90000001), *unlinked], 14, True)
    page_two = _page([_commit(200, "New Person", "new-person", 90000003)], 14, False)
    assert _run(_ENV, _serve([page_one, page_two])) == EXIT_REFUSED
    lines = capsys.readouterr().out.splitlines()
    annotated = [line for line in lines if line.startswith("::error title=CLA pre-check refused::")]
    assert len(annotated) == 10
    assert "new-person" in annotated[1], annotated[:2]
    assert "4 more refusal(s)" in annotated[-1]
    logged = [line for line in lines if line.startswith("CLA pre-check refused: ")]
    assert len(logged) == 4


@pytest.mark.parametrize(
    ("committer", "refusals"),
    [
        ({"name": "C", "user": "not-an-object"}, 2),
        (None, 2),
        ({"name": "C", "user": None}, 1),
    ],
    ids=["unreadable-user", "null-committer", "readable"],
)
def test_only_a_readable_unlinked_commit_keys_the_first_page(
    committer: Mapping[str, Any] | None, refusals: int
) -> None:
    """A page-one unlinked commit is filed under its author name when its committer reads, as the
    action files it, and shields a linked namesake on page two from rule 2. With an unreadable
    committer its key is unknown, so it shields nobody. Either way the commit itself is refused."""
    unlinked = {
        "oid": f"{1:040x}",
        "author": {"name": "new-person", "user": None},
        "committer": committer,
    }
    pages = [
        _page([unlinked], 2, True),
        _page([_commit(2, "New Person", "new-person", 90000003)], 2, False),
    ]
    verdict = evaluate(fetch_commits(_serve(pages), "M", "N", 7), _ALLOWLIST, _no_signatures)
    assert len(verdict.refusals) == refusals, verdict.refusals
    # The unreadable committer is reported, naming its commit, beside the refusal.
    assert (verdict.fault is None) == (refusals == 1)
    assert verdict.fault is None or f"commit {1:040x}:" in verdict.fault


def test_the_signature_file_parses_as_the_action_writes_it() -> None:
    assert cla_precheck.parse_signatures({"signedContributors": []}) == frozenset()
    entry = {"name": "octo-contributor", "id": 90000001, "comment_id": 1, "pullRequestNo": 7}
    assert cla_precheck.parse_signatures({"signedContributors": [entry]}) == {90000001}
    bad_files: list[object] = [
        [],
        {"signedContributors": {}},
        {"signedContributors": [{"id": "1"}]},
    ]
    for bad in bad_files:
        with pytest.raises(PrecheckFault):
            cla_precheck.parse_signatures(bad)


def test_the_signature_file_is_read_from_the_base_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 404 is no signatures, as the action reads it; any other HTTP error is a fault."""
    seen: list[str] = []

    def answer(code: int) -> Any:
        def fake(request: urllib.request.Request, timeout: float) -> object:
            seen.append(request.full_url)
            raise urllib.error.HTTPError(
                request.full_url, code, "x", http.client.HTTPMessage(), None
            )

        return fake

    reader = cla_precheck.rest_signatures(
        "https://api.example.test",
        "synthetic-token-value",
        "MEFORORG",
        "MessageFoundry",
        "signatures/version1/cla.json",
        "cla-signatures",
    )
    monkeypatch.setattr(cla_precheck._OPENER, "open", answer(404))
    assert reader() == frozenset()
    assert seen[-1] == (
        "https://api.example.test/repos/MEFORORG/MessageFoundry/contents/"
        "signatures/version1/cla.json?ref=cla-signatures"
    )
    monkeypatch.setattr(cla_precheck._OPENER, "open", answer(500))
    with pytest.raises(PrecheckFault):
        reader()


def test_an_unexpected_exception_is_a_fault_and_exits_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bug in the script must not fail every pull request: exit 3 (fault), never 1 (refused),
    and never 2, which is the interpreter's own exit when it cannot open the script."""

    def broken(env: Mapping[str, str]) -> int:
        raise KeyError("synthetic-secret-value")

    monkeypatch.setattr(cla_precheck, "run", broken)
    assert cla_precheck.main() == EXIT_FAULT == 3
    out = capsys.readouterr().out
    assert "::warning title=CLA pre-check fault::unexpected KeyError" in out
    assert "synthetic-secret-value" not in out


def test_the_script_keeps_to_the_runners_python_3_12_grammar() -> None:
    """The step runs the runner's system python3 (3.12 on ubuntu-24.04), not this repo's 3.14."""
    source = Path(cla_precheck.__file__).read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 12))


def test_an_unlinked_author_is_refused_whichever_order_or_allowlist() -> None:
    """Under rule 1 the verdict on an unlinked author depends on neither the action's first-seen
    order nor the allowlist: it refuses with the bot on the allowlist and off it."""
    read = fetch_commits(_Replay("bot_name_before_bot_commit"), "MEFORORG", "MessageFoundry", 7)
    assert len(evaluate(read, ["wshallwshall"]).refusals) == 1
    assert len(evaluate(read, _ALLOWLIST).refusals) == 1


def test_an_unlinked_name_folded_into_the_dropped_bot_entry_is_refused() -> None:
    """The action keys both commits under github-actions[bot] and drops that id, whatever the
    allowlist says, so the fold refuses even with the bot left off the allowlist."""
    read = fetch_commits(
        _Replay("unlinked_folds_into_actions_bot"), "MEFORORG", "MessageFoundry", 7
    )
    assert len(evaluate(read, ["wshallwshall"]).refusals) == 1


@pytest.mark.parametrize(
    "scenario", ["stuck_cursor", "repeated_cursor", "graphql_error", "head_moved"]
)
def test_a_reply_that_cannot_be_trusted_is_a_fault(scenario: str) -> None:
    with pytest.raises(PrecheckFault):
        fetch_commits(_Replay(scenario), "MEFORORG", "MessageFoundry", 7)


def test_wildcard_and_empty_entries_match_as_the_action_matches() -> None:
    """Mirrored: `bot*` matches the whole name only, as the patched action anchors it (BACKLOG
    #5644 item 2); an empty entry from a doubled comma matches an empty name; and the wildcard
    stops at a carriage return, as JavaScript's `.` does."""
    assert matches_allowlist("bot-person", ["bot*"])
    assert not matches_allowlist("robot-person", ["bot*"])
    assert not matches_allowlist("evilbot-x", ["bot*"])
    assert not matches_allowlist("bot-x\n", ["bot*"])
    assert matches_allowlist("dependabot[bot]", ["*[bot]"])
    assert not matches_allowlist("aXb-1", ["a.b*"])
    assert not matches_allowlist("robot-person", ["bot"])
    assert matches_allowlist("wshallwshall", [" wshallwshall "])
    assert not matches_allowlist("wshallwshal", ["wshallwshall"])
    assert matches_allowlist("", parse_allowlist("a,,b"))
    for separator in ("\r", "\n", "\u2028", "\u2029"):
        assert not matches_allowlist(f"a{separator}b", ["a*b"])
    assert matches_allowlist("a\tb", ["a*b"])


def test_run_exit_codes_and_annotations(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(_ENV, _Replay("linked_on_page_two")) == EXIT_PASS
    assert _run(_ENV, _Replay("impersonation_on_page_two")) == EXIT_REFUSED
    assert "::error title=CLA pre-check refused::" in capsys.readouterr().out
    assert _run(_ENV, _Replay("graphql_error")) == EXIT_FAULT
    assert "::warning title=CLA pre-check fault::" in capsys.readouterr().out


def test_a_stale_head_is_a_fault(capsys: pytest.CaptureFixture[str]) -> None:
    on_head = _page([_commit(_HEAD, "Octo", "octo-contributor", 90000001)], 1, False)
    assert _run({**_ENV, "CLA_HEAD_SHA": _HEAD}, _serve([on_head])) == EXIT_PASS
    waits: list[float] = []
    # Every read reports _HEAD and would prove a refusal, which a read of another head must not
    # keep. Each read stops at its first page.
    calls: list[object] = []

    def transport(_q: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        calls.append(variables["cursor"])
        return _page([_commit(1, "wshallwshall")], 2, True)

    env = {**_ENV, "CLA_HEAD_SHA": "cd" * 20}
    assert run(env, transport, _no_signatures, waits.append) == EXIT_FAULT
    out = capsys.readouterr().out
    assert "stale" in out and "refused::" not in out
    assert waits == list(cla_precheck.HEAD_RETRY_DELAYS)
    assert calls == [None] * (len(cla_precheck.HEAD_RETRY_DELAYS) + 1)


def _node_error(index: int, *rest: str | int) -> Mapping[str, Any]:
    path = ["repository", "pullRequest", "commits", "nodes", index, *rest]
    return {"message": "Something went wrong while executing your query.", "path": path}


def test_a_partial_graphql_error_keeps_the_refusals_its_other_commits_prove(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """BACKLOG #5645 item 1: a page whose `errors` name one commit node still proves what its
    other commits prove. The errored commit reads as unlinked, because GraphQL nulled its user,
    so it must be a fault and not a second refusal."""
    nulled_user = _commit(2, "Octo Contributor")
    page = {
        **_page([_commit(1, "wshallwshall"), nulled_user], 2, False),
        "errors": [_node_error(1, "commit", "author", "user")],
    }
    assert _run(_ENV, _serve([page])) == EXIT_REFUSED
    out = capsys.readouterr().out
    refused = [line for line in out.splitlines() if "refused::" in line]
    assert len(refused) == 1 and f"{1:040x}" in refused[0]
    assert "GraphQL reported an error inside it" in out
    # The neighbour: the errored commit alone proves nothing, so the run is a fault.
    page = {**_page([nulled_user], 1, False), "errors": [_node_error(0, "commit", "author")]}
    assert _run(_ENV, _serve([page])) == EXIT_FAULT
    assert "refused::" not in capsys.readouterr().out


def test_a_partial_error_that_nulls_a_whole_node_keeps_the_others() -> None:
    page = _page([_commit(1, "wshallwshall"), _commit(2, "x")], 2, False)
    connection = page["data"]["repository"]["pullRequest"]["commits"]
    connection["nodes"][1] = None
    page = {**page, "errors": [_node_error(1, "commit", "oid")]}
    read = fetch_commits(_serve([page]), "MEFORORG", "MessageFoundry", 7)
    assert read.tainted == frozenset({1}) and len(read.commits) == 2
    verdict = evaluate(read, _ALLOWLIST)
    assert len(verdict.refusals) == 1 and f"{1:040x}" in verdict.refusals[0]
    assert verdict.fault is not None and "distinct" not in verdict.fault
    assert "the commit at position 2: GraphQL reported an error" in verdict.fault


_UNLINKED = {"name": "Anon", "user": None}
_OCTO = {"name": "Octo", "user": {"databaseId": 90000001, "login": "octo-contributor"}}


def _committer_errored(commit: Mapping[str, Any], *rest: str) -> Mapping[str, Any]:
    """`commit` as GraphQL returns it when resolving its committer failed: the committer's user,
    or with no `rest` the committer itself, is nulled. The author is intact."""
    if not rest:
        return {**commit, "committer": None}
    return {**commit, "committer": {**commit["committer"], "user": None}}


@pytest.mark.parametrize("rest", [("user",), ("user", "login"), ()])
@pytest.mark.parametrize("author", [_UNLINKED, None])
def test_a_committer_error_under_an_unlinked_author_warns_and_passes(
    rest: tuple[str, ...], author: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """Owner ruling W7-R11 (2026-11-26) on #8335 item 1 and the committer carve-out: "warn when
    unproven, refuse only when proven". With an error inside the commit's committer, an author
    that reads as unlinked, or null, may be a field the same failure nulled with only the
    committer's path reported; this read cannot rule that out, so rule 1 is unproven there: a
    fault (exit 3), which warns and passes, here past page one. Engine PR 3323 refused it."""
    unlinked = {"oid": f"{2:040x}", "author": author, "committer": _OCTO}
    page = {
        **_page([_committer_errored(unlinked, *rest)], 2, False),
        "errors": [_node_error(0, "commit", "committer", *rest)],
    }
    assert _run(_ENV, _serve([_linked_page_one(), page])) == EXIT_FAULT
    out = capsys.readouterr().out
    assert "refused::" not in out, out
    assert "error inside its committer" in out and "not refused" in out
    assert "key is missing" not in out, out  # no rule reads a key past page one


def test_a_committer_error_does_not_shield_the_proven_refusal_beside_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """W7-R11's other half: a refusal the read proves still fails. Beside a committer-errored
    unlinked author, which is a fault, an unlinked author on a commit no error names is refused,
    and only once. A commit no error names is judged as proven under the owner's delegated ruling
    of 2026-11-23 (module docstring, UNMEASURED paragraph)."""
    errored = {"oid": f"{2:040x}", "author": _UNLINKED, "committer": _OCTO}
    proven = {"oid": f"{3:040x}", "author": _UNLINKED, "committer": _OCTO}
    page_one = _page([_commit(1, "Octo", "octo-contributor", 90000001)], 3, True)
    page = {
        **_page([_committer_errored(errored, "user"), proven], 3, False),
        "errors": [_node_error(0, "commit", "committer", "user")],
    }
    assert _run(_ENV, _serve([page_one, page])) == EXIT_REFUSED
    out = capsys.readouterr().out
    refused = [line for line in out.splitlines() if "refused::" in line]
    assert len(refused) == 1 and f"{3:040x}" in refused[0], refused
    assert f"commit {2:040x}: GraphQL reported an error inside its committer" in out
    assert "not refused" in out


def test_a_committer_error_under_a_linked_author_past_page_one_is_judged() -> None:
    """The action never reads the committer of a commit whose author is linked, so a committer
    error past page one leaves nothing unjudged: rule 2 finds the author keyed on page one."""
    octo = {"oid": f"{1:040x}", "author": _OCTO, "committer": _OCTO}
    later = {**octo, "oid": f"{2:040x}"}
    page_two = {
        **_page([_committer_errored(later)], 2, False),
        "errors": [_node_error(0, "commit", "committer")],
    }
    read = fetch_commits(
        _serve([_page([octo], 2, True), page_two]), "MEFORORG", "MessageFoundry", 7
    )
    assert read.tainted == frozenset()
    assert evaluate(read, _ALLOWLIST, _no_signatures) == cla_precheck.Verdict(())


def test_a_committer_error_past_page_one_still_lets_rule_two_refuse_its_linked_author() -> None:
    """A linked author seen only past page one, whose commit has a committer error, is judged under
    rule 2 from the intact author: unsigned, they are refused, not silently dropped."""
    octo = {"oid": f"{1:040x}", "author": _OCTO, "committer": _OCTO}
    bob = {"name": "Bob", "user": {"databaseId": 90000002, "login": "bob-contributor"}}
    later = {"oid": f"{2:040x}", "author": bob, "committer": bob}
    page_two = {
        **_page([_committer_errored(later, "user")], 2, False),
        "errors": [_node_error(0, "commit", "committer", "user")],
    }
    read = fetch_commits(
        _serve([_page([octo], 2, True), page_two]), "MEFORORG", "MessageFoundry", 7
    )
    assert read.committer_tainted == frozenset({1})
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert len(verdict.refusals) == 1 and "'bob-contributor'" in verdict.refusals[0]
    assert verdict.fault is None


def test_committer_errored_commits_with_no_oid_are_unjudged_and_count_by_their_slot() -> None:
    """A committer-only error on a commit with no readable oid contradicts the carve-out's premise
    (oid is non-null and outside the committer), so, as on origin/main, the commit is unjudged with
    a fault, past page one too, and two of them count once each rather than tripping the count."""
    octo = {"oid": f"{1:040x}", "author": _OCTO, "committer": _OCTO}
    nodes: list[Mapping[str, Any]] = [
        {"author": _OCTO, "committer": None},
        {"author": _OCTO, "committer": None},
    ]
    page_two = {
        **_page(nodes, 3, False),
        "errors": [_node_error(0, "commit", "committer"), _node_error(1, "commit", "committer")],
    }
    read = fetch_commits(
        _serve([_page([octo], 3, True), page_two]), "MEFORORG", "MessageFoundry", 7
    )
    assert read.tainted == frozenset({1, 2}) and read.committer_tainted == frozenset()
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict.refusals == ()
    assert verdict.fault is not None and "distinct commits" not in verdict.fault
    assert "the commit at position 2: GraphQL reported an error inside it; not judged" in (
        verdict.fault
    )


def test_committer_errored_commits_that_share_an_oid_still_trip_the_count() -> None:
    """The negative control: committer-errored commits with a readable oid count by that oid, so a
    repeated one still shows as a short read."""
    same = {"oid": f"{1:040x}", "author": _OCTO, "committer": None}
    page = {
        **_page([same, same], 2, False),
        "errors": [_node_error(0, "commit", "committer"), _node_error(1, "commit", "committer")],
    }
    read = fetch_commits(_serve([page]), "MEFORORG", "MessageFoundry", 7)
    assert read.committer_tainted == frozenset({0, 1})
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict.fault is not None and "read 1 distinct commits" in verdict.fault


@pytest.mark.parametrize("rest", [("user",), ("user", "login"), ()])
def test_a_committer_error_under_a_linked_page_one_author_leaves_it_unkeyed(
    rest: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    """PR 3323 hold, finding 17: a page-one committer error under a linked author leaves that
    commit unkeyed with a fault, as origin/main did, so rule 2 still refuses the same author's
    unsigned later-page commit rather than the pre-check passing it."""
    octo = {"oid": f"{1:040x}", "author": _OCTO, "committer": _OCTO}
    page_one = {
        **_page([_committer_errored(octo, *rest)], 2, True),
        "errors": [_node_error(0, "commit", "committer", *rest)],
    }
    page_two = _page([{**octo, "oid": f"{2:040x}"}], 2, False)
    read = fetch_commits(_serve([page_one, page_two]), "MEFORORG", "MessageFoundry", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert len(verdict.refusals) == 1 and f"{2:040x}" in verdict.refusals[0]
    assert "'octo-contributor'" in verdict.refusals[0]
    assert verdict.fault is not None and "error inside its committer" in verdict.fault
    assert _run(_ENV, _serve([page_one, page_two])) == EXIT_REFUSED
    assert "refused::" in capsys.readouterr().out


@pytest.mark.parametrize("rest", [("user",), ("user", "login"), ()])
@pytest.mark.parametrize("author", [_UNLINKED, None])
def test_a_committer_error_under_an_unlinked_page_one_author_is_a_fault_not_a_refusal(
    rest: tuple[str, ...], author: object
) -> None:
    """W7-R11 on page one: the unlinked author is unproven, so it is a fault, not a refusal, and the
    commit keys nothing among the first page's keys (the action would key an unlinked author's
    commit under the committer, which the error hid; a null author has no key, so its fault names
    none missing). A linked page-two author whose login is the author's git name is therefore
    still judged under rule 2 and refused, not taken as keyed on page one."""
    unlinked = {"oid": f"{1:040x}", "author": author, "committer": _OCTO}
    page = {
        **_page([_committer_errored(unlinked, *rest)], 2, True),
        "errors": [_node_error(0, "commit", "committer", *rest)],
    }
    anon = {"name": "Anon", "user": {"databaseId": 90000003, "login": "Anon"}}
    page_two = _page([{"oid": f"{2:040x}", "author": anon, "committer": anon}], 2, False)
    read = fetch_commits(_serve([page, page_two]), "MEFORORG", "MessageFoundry", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert len(verdict.refusals) == 1 and f"{2:040x}" in verdict.refusals[0], verdict
    assert verdict.fault is not None
    assert "error inside its committer" in verdict.fault and "not refused" in verdict.fault
    assert ("its key is missing from the first page's keys" in verdict.fault) is (
        author is not None
    )


@pytest.mark.parametrize("node", [None, {"commit": None}, {}])
def test_a_committer_error_on_a_node_with_no_commit_keeps_the_others_judged(
    node: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round e8390625a8: a committer-only error on a node GraphQL nulled whole must leave
    that slot unjudged, as origin/main did, not fault the page and lose the refusal beside it."""
    page = _page([{"oid": f"{1:040x}", "author": _UNLINKED, "committer": _OCTO}], 2, False)
    page["data"]["repository"]["pullRequest"]["commits"]["nodes"].append(node)
    page = {**page, "errors": [_node_error(1, "commit", "committer", "user")]}
    assert _run(_ENV, _serve([page])) == EXIT_REFUSED
    assert "GraphQL reported an error inside it" in capsys.readouterr().out


@pytest.mark.parametrize(
    "path",
    [
        # Beside the committer error, one that names the author or the whole node still taints it.
        [("commit", "committer", "user"), ("commit", "author", "user")],
        [("commit", "committer"), ("commit",)],
        # A path that only starts like the committer's is not one.
        [("commit", "committerX")],
    ],
)
def test_an_error_outside_the_committer_still_leaves_the_commit_unjudged(
    path: list[tuple[str, ...]],
) -> None:
    unlinked = {"oid": f"{1:040x}", "author": _UNLINKED, "committer": _OCTO}
    page = {**_page([unlinked], 1, False), "errors": [_node_error(0, *p) for p in path]}
    read = fetch_commits(_serve([page]), "MEFORORG", "MessageFoundry", 7)
    assert read.tainted == frozenset({0})
    verdict = evaluate(read, _ALLOWLIST)
    assert verdict.refusals == () and verdict.fault is not None and "not judged" in verdict.fault


def test_an_errored_commit_that_repeats_another_still_trips_the_count() -> None:
    page = {
        **_page([_commit(1, "Octo", "octo-contributor", 90000001), _commit(1, "x")], 2, False),
        "errors": [_node_error(1, "commit", "author", "user")],
    }
    verdict = evaluate(fetch_commits(_serve([page]), "MEFORORG", "MessageFoundry", 7), _ALLOWLIST)
    assert verdict.fault is not None and "read 1 distinct commits" in verdict.fault


def test_a_partial_error_on_page_two_is_indexed_past_page_one() -> None:
    pages = [
        _page([_commit(1, "Octo", "octo-contributor", 90000001)], 3, True),
        {
            **_page([_commit(2, "x"), _commit(3, "wshallwshall")], 3, False),
            "errors": [_node_error(0, "commit", "author", "user")],
        },
    ]
    read = fetch_commits(_serve(pages), "MEFORORG", "MessageFoundry", 7)
    assert read.tainted == frozenset({1})
    refusals = evaluate(read, _ALLOWLIST).refusals
    assert len(refusals) == 1 and f"{3:040x}" in refusals[0]


@pytest.mark.parametrize(
    ("path", "fault"),
    [
        (("commit", "committer", "user"), "error inside its committer; its key is missing"),
        (("commit", "author", "user"), "error inside it; not judged"),
        (("commit",), "error inside it; not judged"),
    ],
)
def test_an_errored_first_page_commit_does_not_claim_the_author_is_absent(
    path: tuple[str, ...], fault: str
) -> None:
    """The read leaves the commit out of the first page's keys, so an unsigned author past page
    one may be that commit's author. They owe a signature either way, so the refusal stands, but
    its reason names only the first-page commits the read keyed."""
    octo = _commit(1, "Octo", "octo-contributor", 90000001)
    pages = [
        {**_page([octo], 2, True), "errors": [_node_error(0, *path)]},
        _page([_commit(2, "Octo", "octo-contributor", 90000001)], 2, False),
    ]
    read = fetch_commits(_serve(pages), "MEFORORG", "MessageFoundry", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert len(verdict.refusals) == 1
    assert (
        "none of the 0 of them this read could key carries its author's key "
        "'octo-contributor'" in verdict.refusals[0]
    )
    assert verdict.fault is not None and fault in verdict.fault
    # The neighbour: with page one readable, the same author is on it, so nothing is owed.
    pages = [_page([octo], 2, True), pages[1]]
    read = fetch_commits(_serve(pages), "MEFORORG", "MessageFoundry", 7)
    assert evaluate(read, _ALLOWLIST, _no_signatures) == cla_precheck.Verdict(())


@pytest.mark.parametrize(
    "unkeyed",
    [
        # Rule 1 cannot read the author, so no key is formed.
        {"oid": f"{1:040x}", "author": "not-an-object", "committer": _OCTO},
        # Rule 1 refuses the unlinked author, and the committer it would be keyed under is null.
        {"oid": f"{1:040x}", "author": _UNLINKED, "committer": None},
        # ... or not an object.
        {"oid": f"{1:040x}", "author": _UNLINKED, "committer": "not-an-object"},
        # A null author: the action would throw, so the commit has no key.
        {"oid": f"{1:040x}", "author": None, "committer": _OCTO},
    ],
    ids=["malformed-author", "null-committer", "malformed-committer", "null-author"],
)
def test_every_first_page_commit_without_a_key_narrows_the_rule_two_reason(
    unkeyed: Mapping[str, Any],
) -> None:
    """BACKLOG #5645: not only an errored commit leaves a first-page key unknown. The rule-2
    reason must count the commits the read could key, never claim them all; the refusal itself
    and the fault beside it are unchanged."""
    pages = [
        _page([unkeyed, _commit(2, "Bob", "bob", 90000002)], 3, True),
        _page([_commit(3, "New Person", "new-person", 90000003)], 3, False),
    ]
    verdict = evaluate(fetch_commits(_serve(pages), "M", "N", 7), _ALLOWLIST, _no_signatures)
    rule_two = [r for r in verdict.refusals if f"{3:040x}" in r]
    assert rule_two == [
        f"commit {3:040x} is past the first 2 commits of this pull request, none of the 1 of "
        "them this read could key carries its author's key 'new-person' (the login, or else the git name, "
        "the action files a commit under), and the CLA signature file holds no signature for "
        "that account"
    ]
    # A null author is refused under rule 1 and is no fault; every other shape here is one.
    assert (verdict.fault is None) == (unkeyed["author"] is None)


def test_a_fully_keyed_first_page_names_keys_not_people() -> None:
    """The author past page one is a first-page COMMITTER under a linked author, so they appear
    on the first page; only their key is absent from its keys. The reason says that, not that they
    appear nowhere."""
    bob = {"name": "Bob", "user": {"databaseId": 90000002, "login": "bob"}}
    pages = [
        _page([{"oid": f"{1:040x}", "author": _OCTO, "committer": bob}], 2, True),
        _page([_commit(2, "Bob", "bob", 90000002)], 2, False),
    ]
    read = fetch_commits(_serve(pages), "M", "N", 7)
    verdict = evaluate(read, _ALLOWLIST, _no_signatures)
    assert verdict == cla_precheck.Verdict(
        (
            f"commit {2:040x} is past the first 1 commits of this pull request, none of them "
            "carries its author's key 'bob' (the login, or else the git name, the action files a commit "
            "under), and the CLA signature file holds no signature for that account",
        )
    )
    # With no signature reader given, the reason does not claim a file was read.
    assert (
        evaluate(read, _ALLOWLIST)
        .refusals[0]
        .endswith("and no CLA signature file was given to check that account against")
    )


@pytest.mark.parametrize(
    "errors",
    [
        [{"message": "no path"}],
        [{"message": "page level", "path": ["repository", "pullRequest", "commits"]}],
        [{"message": "count", "path": ["repository", "pullRequest", "commits", "totalCount"]}],
        [_node_error(1, "commit")],  # a node the page does not hold
        [
            {
                "message": "bool index",
                "path": ["repository", "pullRequest", "commits", "nodes", True],
            }
        ],
        [_node_error(0, "commit"), {"message": "no path"}],
        {"message": "not a list"},
    ],
)
def test_an_error_that_names_no_commit_node_still_faults_the_page(errors: object) -> None:
    page = {**_page([_commit(1, "wshallwshall")], 1, False), "errors": errors}
    with pytest.raises(PrecheckFault, match="GraphQL returned an error"):
        fetch_commits(_serve([page]), "MEFORORG", "MessageFoundry", 7)


def test_a_head_that_lags_the_push_event_is_re_read(capsys: pytest.CaptureFixture[str]) -> None:
    """BACKLOG #5645 item 1: GitHub's view of the head may trail the push that started the run.
    The read is repeated until it reaches CLA_HEAD_SHA, and a refusal there stands."""
    new_head = "cd" * 20
    lagging = _page([_commit(_HEAD, "Octo", "octo-contributor", 90000001)], 1, False)
    caught_up = _page([_commit(new_head, "wshallwshall")], 1, False, head=new_head)
    replies = [lagging, lagging, caught_up]
    waits: list[float] = []
    env = {**_ENV, "CLA_HEAD_SHA": new_head}
    assert run(env, lambda _q, _v: replies.pop(0), _no_signatures, waits.append) == EXIT_REFUSED
    assert waits == list(cla_precheck.HEAD_RETRY_DELAYS) and replies == []
    assert "refused::" in capsys.readouterr().out


def test_a_commit_list_without_its_head_is_judged_with_a_fault(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """headRefOid is CLA_HEAD_SHA but the commits do not include it: judged at once, as before,
    so a refusal it proves stands, with a fault added so that a pass is not silent."""
    env = {**_ENV, "CLA_HEAD_SHA": _HEAD}
    linked = _page([_commit(1, "Octo", "octo-contributor", 90000001)], 1, False)
    assert _run(env, _serve([linked])) == EXIT_FAULT
    assert "the commits this read returned do not include CLA_HEAD_SHA" in capsys.readouterr().out
    # A complete read short of totalCount may have stopped before the head, so the fault names the
    # commits it returned, never the pull request's.
    short = _page([_commit(1, "Octo", "octo-contributor", 90000001)], 5, False)
    assert _run(env, _serve([short])) == EXIT_FAULT
    out = capsys.readouterr().out
    assert "the commits this read returned do not include CLA_HEAD_SHA" in out
    assert "the pull request's commits do not include" not in out
    assert _run(env, _serve([_page([_commit(1, "wshallwshall")], 1, False)])) == EXIT_REFUSED


def test_a_head_whose_id_graphql_nulled_is_not_said_to_be_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """BACKLOG #5645: an errored node whose oid GraphQL nulled may be CLA_HEAD_SHA itself, so the
    fault says the head is unknown rather than absent. The exit is the same fault as before."""
    env = {**_ENV, "CLA_HEAD_SHA": _HEAD}
    page = _page([_commit(1, "Octo", "octo-contributor", 90000001), _commit(2, "x")], 2, False)
    page["data"]["repository"]["pullRequest"]["commits"]["nodes"][1] = None
    page = {**page, "errors": [_node_error(1, "commit", "oid")]}
    assert _run(env, _serve([page])) == EXIT_FAULT
    out = capsys.readouterr().out
    assert "the pull request's commits do not include CLA_HEAD_SHA" not in out
    assert (
        "the commit ids this read could resolve do not include CLA_HEAD_SHA, and 1 commit(s) "
        "carry no 40-character lowercase id, so whether the pull request's commits include it "
        "is unknown" in out
    )


def test_a_lagging_first_page_with_a_pathless_error_is_re_read() -> None:
    new_head = "cd" * 20
    lagging = {**_page([_commit(1, "Octo")], 1, False), "errors": [{"message": "x"}]}
    caught_up = _page([_commit(new_head, "wshallwshall")], 1, False, head=new_head)
    replies = [lagging, caught_up]
    waits: list[float] = []
    env = {**_ENV, "CLA_HEAD_SHA": new_head}
    assert run(env, lambda _q, _v: replies.pop(0), _no_signatures, waits.append) == EXIT_REFUSED
    assert waits == [cla_precheck.HEAD_RETRY_DELAYS[0]]


def test_without_a_head_to_judge_nothing_is_re_read() -> None:
    """A comment event sets no CLA_HEAD_SHA. A head that moves partway is judged as far as the
    read got, as before this change, with no wait."""
    first = _page([_commit(1, "wshallwshall")], 2, True)
    moved = _page([_commit(2, "x")], 2, False, head="cd" * 20)
    replies = [first, moved]
    assert run(_ENV, lambda _q, _v: replies.pop(0), _no_signatures, _no_sleep) == EXIT_REFUSED


def test_a_move_away_from_the_judged_head_keeps_the_pages_of_that_head() -> None:
    """The pages read before the head moved are of CLA_HEAD_SHA, so they are judged at once, as
    before this change, with no wait."""
    first = _page([_commit(1, "wshallwshall")], 2, True)
    moved = _page([_commit(2, "x")], 2, False, head="cd" * 20)
    replies = [first, moved]
    env = {**_ENV, "CLA_HEAD_SHA": _HEAD}
    assert run(env, lambda _q, _v: replies.pop(0), _no_signatures, _no_sleep) == EXIT_REFUSED


def test_a_re_read_that_faults_outright_is_a_fault() -> None:
    env = {**_ENV, "CLA_HEAD_SHA": "cd" * 20}
    replies = [_page([_commit(1, "wshallwshall")], 1, False), {"errors": [{}]}]
    assert run(env, lambda _q, _v: replies.pop(0), _no_signatures, lambda _s: None) == EXIT_FAULT


@pytest.mark.parametrize(
    ("override", "fault"),
    [
        ({"GITHUB_REPOSITORY": "not-a-repository"}, "GITHUB_REPOSITORY"),
        ({"CLA_PR_NUMBER": "7; echo"}, "CLA_PR_NUMBER"),
        ({"CLA_PR_NUMBER": "0"}, "CLA_PR_NUMBER"),
        ({"CLA_PR_NUMBER": "9" * 5000}, "CLA_PR_NUMBER"),
        ({"CLA_ALLOWLIST": " , "}, "CLA_ALLOWLIST"),
        ({"CLA_HEAD_SHA": "abc"}, "CLA_HEAD_SHA"),
    ],
)
def test_bad_environment_is_a_fault_before_any_call(
    override: dict[str, str], fault: str, capsys: pytest.CaptureFixture[str]
) -> None:
    replay = _Replay("linked_on_page_two")
    assert _run({**_ENV, **override}, replay) == EXIT_FAULT
    assert replay.calls == []
    assert fault in capsys.readouterr().out


def test_without_a_transport_it_needs_a_token_and_https(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(_ENV) == EXIT_FAULT
    assert "GITHUB_TOKEN" in capsys.readouterr().out
    secret = "synthetic-token-value"
    env = {**_ENV, "GITHUB_TOKEN": secret, "GITHUB_GRAPHQL_URL": "http://example.test/graphql"}
    assert run(env) == EXIT_FAULT
    out = capsys.readouterr().out
    assert "https" in out and secret not in out


@pytest.mark.parametrize(
    "override",
    [
        {"GITHUB_TOKEN": "synthetic-token-é", "GITHUB_GRAPHQL_URL": ""},
        {"GITHUB_TOKEN": "synthetic token", "GITHUB_GRAPHQL_URL": ""},
        {"GITHUB_TOKEN": "synthetic-token-value", "GITHUB_GRAPHQL_URL": "https://[::1/graphql"},
        {"GITHUB_TOKEN": "synthetic-token-value", "GITHUB_GRAPHQL_URL": "https:///graphql"},
    ],
)
def test_a_malformed_token_or_url_is_a_fault_not_a_traceback(
    override: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Bad input is a fault, exit 3, never a traceback; and never 2, python3's own exit when it
    cannot open the script, which the workflow fails on."""
    assert run({**_ENV, **override}) == EXIT_FAULT
    assert "synthetic-token" not in capsys.readouterr().out


def test_a_header_urllib_cannot_encode_is_a_fault() -> None:
    transport = cla_precheck.urllib_transport("https://example.test/graphql", "synthetic-é€")
    with pytest.raises(PrecheckFault):
        transport("query", {})


def test_a_truncated_reply_is_a_fault_and_not_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """An http.client error is not an OSError; uncaught, it would exit 1, the refusal code."""

    def truncated(*_args: object, **_kwargs: object) -> object:
        raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(cla_precheck._OPENER, "open", truncated)
    transport = cla_precheck.urllib_transport(
        "https://example.test/graphql", "synthetic-token-value"
    )
    with pytest.raises(PrecheckFault):
        transport("query", {})


def test_a_redirect_is_refused_rather_than_followed_with_the_token() -> None:
    """urllib's default handler re-sends Authorization to the redirect's target."""
    installed: list[object] = getattr(cla_precheck._OPENER, "handlers")  # noqa: B009 -- untyped
    handlers = [h for h in installed if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert handlers and all(isinstance(h, cla_precheck._NoRedirect) for h in handlers)
    request = urllib.request.Request("https://example.test/graphql")
    with pytest.raises(PrecheckFault):
        handlers[0].redirect_request(
            request, io.BytesIO(), 302, "Found", http.client.HTTPMessage(), "http://other.test/"
        )


def test_a_commit_name_cannot_open_a_workflow_command_of_its_own(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every message is escaped, whatever commit text it quotes: `%`, CR and LF become `%25`, `%0D`
    and `%0A`, so the text stays one message. The oid stands in for any quoted field."""
    allowlisted = {"name": "wshallwshall", "user": None}
    page = {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefOid": _HEAD,
                    "commits": {
                        "totalCount": 1,
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                        "nodes": [
                            {
                                "commit": {
                                    "oid": "x%\n::set-output name=a::b",
                                    "author": allowlisted,
                                    "committer": allowlisted,
                                }
                            }
                        ],
                    },
                }
            }
        }
    }
    assert _run(_ENV, lambda _q, _v: page) == EXIT_REFUSED
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1 and "%25%0A::set-output" in lines[0]


def test_the_script_reads_event_data_from_the_environment_only() -> None:
    """zizmor's template-injection rule: a workflow passes event data through `env:`, never by
    templating it into the command line, so the script must not read argv at all."""
    source = Path(cla_precheck.__file__).read_text(encoding="utf-8")
    for reader in ("argv", "argparse", "getopt", "optparse", "fileinput"):
        assert reader not in source, f"cla_precheck.py names {reader!r}"
