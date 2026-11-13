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


def _run(env: Mapping[str, str], transport: cla_precheck.Transport) -> int:
    """`run` with the network replaced: GraphQL by `transport`, the signature file by an empty one."""
    return run(env, transport, _no_signatures)


def _verdict(scenario: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    verdict = evaluate(
        fetch_commits(_Replay(scenario), "MEFORORG", "MessageFoundry", 7), _ALLOWLIST
    )
    return verdict.refusals, verdict.notices


def test_it_pages_past_the_hundredth_commit_and_refuses_the_impersonator_there() -> None:
    """BACKLOG #5645 (the 100-commit cap): the action reads one page. The impersonating commit is
    the 101st, so only a reader that follows hasNextPage sees it."""
    replay = _Replay("impersonation_on_page_two")
    read = fetch_commits(replay, "MEFORORG", "MessageFoundry", 7)
    assert (len(read.commits), read.total, read.head) == (101, 101, _HEAD)
    assert [call["cursor"] for call in replay.calls] == [None, "Y3Vyc29yOjEwMA=="]
    refusals = evaluate(read, _ALLOWLIST).refusals
    assert len(refusals) == 1
    assert "wshallwshall" in refusals[0] and f"{101:040x}" in refusals[0]


def test_the_same_two_pages_with_a_linked_author_pass() -> None:
    """The neighbour of the test above: same size, page two linked, nothing refused."""
    assert _verdict("linked_on_page_two") == ((), ())


def test_an_unlinked_name_outside_the_allowlist_is_not_this_scripts_business() -> None:
    """The action itself asks that author to sign, so the pre-check stays out of the way."""
    assert _verdict("unlinked_name_not_allowlisted") == ((), ())


def test_an_unlinked_name_equal_to_a_linked_login_here_is_a_notice() -> None:
    """The action keys committers on `login || name`, so the unlinked commit folds into the linked
    account. Not ruled, so reported and passed."""
    refusals, notices = _verdict("name_folded_into_linked")
    assert refusals == ()
    assert len(notices) == 1 and "octo-contributor" in notices[0]


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
    assert (who.name, who.database_id, who.author_linked, who.committer_linked) == (
        "A",
        None,
        False,
        False,
    )


def test_an_empty_user_object_is_chosen_as_javascript_chooses_it() -> None:
    """JavaScript's `||` passes over null only, so an empty `{}` user is still chosen, and its name
    is empty, never the committer's login."""
    commit = {
        "oid": "a",
        "author": {"name": "A", "user": {}},
        "committer": {"name": "C", "user": {"login": "committer-acct", "databaseId": 2}},
    }
    who = attribute(commit)
    assert (who.name, who.author_linked) == ("", True)


def test_an_unlinked_author_under_a_linked_allowlisted_committer_is_refused() -> None:
    """Owner ruling 2026-11-13: the CLA binds the AUTHOR. The action attributes this commit to the
    allowlisted committer, whose email is trivially set, so the author is never asked to sign."""
    refusals, notices = _verdict("committer_attribution")
    assert notices == ()
    assert len(refusals) == 1 and "wshallwshall" in refusals[0]


def test_an_unlinked_author_under_the_dropped_bot_committer_is_refused() -> None:
    """41898282 is github-actions[bot]; web-flow is 19864447 (tests/fixtures/branch_main.json)."""
    refusals, notices = _verdict("actions_bot_committer")
    assert notices == ()
    assert len(refusals) == 1 and "github-actions[bot]" in refusals[0]
    assert "web-flow" not in refusals[0]


def test_a_linked_author_wins_over_an_actions_bot_committer() -> None:
    assert _verdict("author_linked_committer_actions_bot") == ((), ())


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
    action's simulated view and its refusal is lost."""
    malformed = {"oid": f"{1:040x}", "author": None, "committer": None}
    pages = [
        _page([malformed, _commit(2, "Octo", "octo-contributor", 90000001)], 3, True),
        _page([_commit(3, "New Person", "new-person", 90000003)], 3, False),
    ]
    verdict = evaluate(fetch_commits(_serve(pages), "M", "N", 7), _ALLOWLIST, _no_signatures)
    assert verdict.fault
    assert len(verdict.refusals) == 1 and "new-person" in verdict.refusals[0]


def test_an_author_first_seen_past_the_hundredth_commit_is_refused() -> None:
    """BACKLOG #5645: the action never reads commit 101, so its new author is never checked."""
    refusals, _ = _verdict("new_author_past_100")
    assert len(refusals) == 1 and "new-person" in refusals[0]


def test_the_actions_view_is_the_first_page_however_short_it_is() -> None:
    """The action reads one page, whatever its length. An author first seen on page two is never
    checked, even though fewer than 100 commits came before it."""
    read = fetch_commits(_Replay("short_first_page"), "MEFORORG", "MessageFoundry", 7)
    assert read.first_page == 1
    refusals = evaluate(read, _ALLOWLIST).refusals
    assert (
        len(refusals) == 1 and "new-person" in refusals[0] and "past the 1 commits" in refusals[0]
    )


def test_an_author_past_the_first_page_who_signed_is_not_refused() -> None:
    """The action never sees this author, but the signature file it keeps already holds their id,
    so refusing would be a false refusal of a signed contributor."""
    read = fetch_commits(_Replay("new_author_past_100"), "MEFORORG", "MessageFoundry", 7)
    calls: list[int] = []

    def signed() -> frozenset[int]:
        calls.append(1)
        return frozenset({90000003})

    assert evaluate(read, _ALLOWLIST, signed).refusals == ()
    assert len(evaluate(read, _ALLOWLIST, _no_signatures).refusals) == 1
    assert calls == [1], "the signature file is read once, and only for an unseen author"
    linked = fetch_commits(_Replay("linked_on_page_two"), "MEFORORG", "MessageFoundry", 7)
    evaluate(linked, _ALLOWLIST, signed)
    assert calls == [1], "a pull request with no unseen author never reads the signature file"


def _serve(pages: list[Mapping[str, Any]]) -> cla_precheck.Transport:
    replies = iter(pages)
    return lambda _q, _v: next(replies)


def _page(commits: list[Mapping[str, Any]], total: int, more: bool) -> Mapping[str, Any]:
    nodes = [{"commit": c} for c in commits]
    info = {"endCursor": "Y3Vyc29yOjI=" if more else None, "hasNextPage": more}
    connection = {"totalCount": total, "pageInfo": info, "nodes": nodes}
    return {"data": {"repository": {"pullRequest": {"headRefOid": _HEAD, "commits": connection}}}}


def _commit(
    oid: int, name: str, login: str | None = None, db_id: int | None = None
) -> Mapping[str, Any]:
    person = {
        "name": name,
        "user": None if login is None else {"databaseId": db_id, "login": login},
    }
    return {"oid": f"{oid:040x}", "author": person, "committer": person}


def test_a_linked_signed_author_does_not_cover_an_unlinked_commit_sharing_its_name() -> None:
    """Past the first page the action sees nothing, so an unlinked 'alice' cannot have signed,
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


def test_the_first_commit_seen_under_a_name_is_the_entry_the_action_keeps() -> None:
    """An unlinked commit named github-actions[bot] BEFORE the linked bot commit becomes the
    action's entry, with no id. With the bot off the allowlist the action asks it to sign, so
    refusing would be false; with the bot on the allowlist the action skips it, so it refuses."""
    read = fetch_commits(_Replay("bot_name_before_bot_commit"), "MEFORORG", "MessageFoundry", 7)
    assert evaluate(read, ["wshallwshall"]).refusals == ()
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
    """Mirrored, not endorsed: `bot*` matches anywhere in the name, which is why cla.yml's
    allowlist holds no glob; an empty entry from a doubled comma matches an empty name; and the
    wildcard stops at a carriage return, as JavaScript's `.` does."""
    assert matches_allowlist("robot-person", ["bot*"])
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
    assert _run({**_ENV, "CLA_HEAD_SHA": _HEAD}, _Replay("linked_on_page_two")) == EXIT_PASS
    assert _run({**_ENV, "CLA_HEAD_SHA": "cd" * 20}, _Replay("linked_on_page_two")) == EXIT_FAULT
    assert "stale" in capsys.readouterr().out


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
