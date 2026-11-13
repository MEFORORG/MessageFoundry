# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline tests for scripts/security/cla_precheck.py (BACKLOG #5644, #5645).

Every GitHub reply comes from tests/fixtures/cla_precheck/replies.json, synthetic pages in the shape
of the GraphQL connection the script queries. No test reaches the network.
"""

from __future__ import annotations

import functools
import http.client
import json
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


class _Replay:
    """Serve one scenario's pages in order, recording the variables of every call."""

    def __init__(self, scenario: str) -> None:
        self.pages: list[Mapping[str, Any]] = list(_scenarios()[scenario])
        self.calls: list[dict[str, object]] = []

    def __call__(self, query: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        self.calls.append(dict(variables))
        assert self.pages, "the script asked for a page past the last one the scenario holds"
        return self.pages.pop(0)


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


def test_an_unlinked_author_under_a_linked_allowlisted_committer_is_a_notice_not_a_refusal() -> (
    None
):
    """The action attributes this commit to the committer, as the order above says. Whether that
    should refuse is not ruled, so the script reports it and passes."""
    refusals, notices = _verdict("committer_attribution")
    assert refusals == ()
    assert len(notices) == 1 and "wshallwshall" in notices[0]


def test_the_dropped_id_is_github_actions_bot_and_the_notice_says_so() -> None:
    """41898282 is github-actions[bot]; web-flow is 19864447 (tests/fixtures/branch_main.json)."""
    refusals, notices = _verdict("actions_bot_committer")
    assert refusals == ()
    assert (
        len(notices) == 1 and "github-actions[bot]" in notices[0] and "web-flow" not in notices[0]
    )


def test_a_linked_author_wins_over_an_actions_bot_committer() -> None:
    assert _verdict("author_linked_committer_actions_bot") == ((), ())


def test_a_read_short_of_total_count_is_refused_not_excused() -> None:
    refusals, _ = _verdict("short_read")
    assert len(refusals) == 1 and "2 of the pull request's 300" in refusals[0]


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
    assert not matches_allowlist("a\rb", ["a*b"])


def test_run_exit_codes_and_annotations(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(_ENV, _Replay("linked_on_page_two")) == EXIT_PASS
    assert run(_ENV, _Replay("impersonation_on_page_two")) == EXIT_REFUSED
    assert "::error title=CLA pre-check refused::" in capsys.readouterr().out
    assert run(_ENV, _Replay("graphql_error")) == EXIT_FAULT
    assert "::error title=CLA pre-check fault::" in capsys.readouterr().out


def test_a_stale_head_is_a_fault(capsys: pytest.CaptureFixture[str]) -> None:
    assert run({**_ENV, "CLA_HEAD_SHA": _HEAD}, _Replay("linked_on_page_two")) == EXIT_PASS
    assert run({**_ENV, "CLA_HEAD_SHA": "cd" * 20}, _Replay("linked_on_page_two")) == EXIT_FAULT
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
    assert run({**_ENV, **override}, replay) == EXIT_FAULT
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


def test_a_truncated_reply_is_a_fault_and_not_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """An http.client error is not an OSError; uncaught, it would exit 1, the refusal code."""

    def truncated(*_args: object, **_kwargs: object) -> object:
        raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(urllib.request, "urlopen", truncated)
    transport = cla_precheck.urllib_transport(
        "https://example.test/graphql", "synthetic-token-value"
    )
    with pytest.raises(PrecheckFault):
        transport("query", {})


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
    assert run(_ENV, lambda _q, _v: page) == EXIT_REFUSED
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1 and "%25%0A::set-output" in lines[0]


def test_the_script_reads_event_data_from_the_environment_only() -> None:
    """zizmor's template-injection rule: a workflow passes event data through `env:`, never by
    templating it into the command line, so the script must not read argv at all."""
    source = Path(cla_precheck.__file__).read_text(encoding="utf-8")
    assert "sys.argv" not in source and "argparse" not in source
