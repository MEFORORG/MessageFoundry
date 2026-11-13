#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a pull request whose CLA verdict the vendored action would get wrong (BACKLOG #5644, #5645).

WHAT THE VENDORED ACTION DOES, read from ``.github/actions/cla-assistant-lite/dist/index.js``:

  * ``getCommitters`` asks GraphQL for ``commits(first: 100)`` ONCE, with an empty cursor, and never
    reads ``hasNextPage``, so a commit past the hundredth is never looked at.
  * ``extractUserFromCommit`` attributes each commit to ``author.user || committer.user || author ||
    committer``. A commit whose author email links to no account is therefore attributed to its
    COMMITTER's account when that one is linked, and to the raw git ``author.name`` only when
    neither is linked. (BACKLOG #5644's subject reads this order as committer-first; it is
    author-first, and the tests here pin the real order.)
  * The committer list is keyed on ``login || name`` and drops id ``41898282``, GitHub's
    ``web-flow`` account.
  * ``checkAllowList`` drops every committer whose ``name`` matches an allowlist entry, by string
    equality or, for an entry holding ``*``, an UNANCHORED regular expression. For a commit nobody
    is linked to, that name is free text the pull request's author chose.

So a commit authored and committed under unlinked emails, with the git name set to an allowlisted
login, is dropped as allowlisted and never needs a signature. This script finds that commit and
refuses. It reads EVERY commit, paging on ``hasNextPage``, and refuses when it could not read as
many commits as GitHub's ``totalCount`` reports.

WHAT IT DOES NOT DO. It is NOT WIRED INTO ANY WORKFLOW. Adding a fail-closed step to the required
``cla`` context is an owner decision, because a fault in the step would wedge every pull request,
its own revert included. It does not patch the vendored bundle either; the provenance gate forbids
that. It reports, as a NOTICE and without refusing, the two attribution shapes the owner has not
ruled on: an unlinked author attributed to a linked committer, and a commit the action drops
because that committer is ``web-flow``.

INPUT COMES ONLY FROM THE ENVIRONMENT, never from argv or a templated ``run:`` line, so a workflow
step can pass event data through ``env:`` (zizmor's template-injection rule):

  GITHUB_TOKEN        a token that can read the pull request
  GITHUB_REPOSITORY   ``owner/name``
  CLA_PR_NUMBER       the pull request number
  CLA_ALLOWLIST       the same comma-separated list cla.yml passes the action
  GITHUB_GRAPHQL_URL  optional; defaults to https://api.github.com/graphql

EXIT CODES: 0 nothing refused; 1 refused; 2 a fault (bad input, network, or a reply in the wrong
shape). The split lets a workflow choose how to treat a fault without parsing text.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

EXIT_PASS = 0
EXIT_REFUSED = 1
EXIT_FAULT = 2

# GitHub's `web-flow` account, which the action drops from its committer list.
WEB_FLOW_ID = 41898282

DEFAULT_GRAPHQL_URL = "https://api.github.com/graphql"

# The cursor is nullable: GitHub reads a null `after` as "from the start". The action's empty-string
# cursor works only because it never asks for a second page.
QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      commits(first: 100, after: $cursor) {
        totalCount
        pageInfo { endCursor hasNextPage }
        nodes {
          commit {
            oid
            author { name user { databaseId login } }
            committer { name user { databaseId login } }
          }
        }
      }
    }
  }
}
"""

Transport = Callable[[str, Mapping[str, object]], Mapping[str, Any]]


class PrecheckFault(Exception):
    """The pre-check could not reach a verdict: bad input, a failed call, or a malformed reply."""


@dataclass(frozen=True)
class Attribution:
    """Who the vendored action would say made one commit, and whether anyone is linked."""

    oid: str
    name: str
    database_id: int | None
    author_linked: bool
    committer_linked: bool


@dataclass(frozen=True)
class Verdict:
    refusals: tuple[str, ...]
    notices: tuple[str, ...]


def _person(commit: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    person = commit.get(role)
    if not isinstance(person, Mapping):
        raise PrecheckFault(f"a commit's {role} is not an object")
    return person


def _user(person: Mapping[str, Any]) -> Mapping[str, Any] | None:
    user = person.get("user")
    if user is None:
        return None
    if not isinstance(user, Mapping):
        raise PrecheckFault("a commit's user is not an object")
    return user


def attribute(commit: Mapping[str, Any]) -> Attribution:
    """Mirror ``extractUserFromCommit``: author.user, then committer.user, then the raw author."""
    author = _person(commit, "author")
    committer = _person(commit, "committer")
    author_user = _user(author)
    committer_user = _user(committer)
    chosen: Mapping[str, Any] = author_user or committer_user or author
    login = chosen.get("login")
    name = str(login) if login else str(chosen.get("name") or "")
    raw_id = chosen.get("databaseId")
    database_id = raw_id if isinstance(raw_id, int) and not isinstance(raw_id, bool) else None
    return Attribution(
        oid=str(commit.get("oid", "")),
        name=name,
        database_id=database_id,
        author_linked=author_user is not None,
        committer_linked=committer_user is not None,
    )


def matches_allowlist(name: str, patterns: Iterable[str]) -> bool:
    """Mirror ``isUserNotInAllowList``: equality, or an UNANCHORED regex for an entry with ``*``."""
    for raw in patterns:
        pattern = raw.strip()  # the action trims each entry here, so the mirror does too
        if "*" in pattern:
            if re.search(".*".join(re.escape(part) for part in pattern.split("*")), name):
                return True
        elif pattern == name:
            return True
    return False


def parse_allowlist(text: str) -> list[str]:
    return [entry.strip() for entry in text.split(",") if entry.strip()]


def fetch_commits(
    transport: Transport, owner: str, name: str, number: int
) -> tuple[list[Mapping[str, Any]], int]:
    """Every commit of the pull request, paging until ``hasNextPage`` is false, and ``totalCount``.

    A page that claims more but gives no new cursor is a fault. A list short of ``totalCount`` is
    returned as it is, for ``evaluate`` to refuse: an unreadable commit is never a fault to excuse.
    """
    commits: list[Mapping[str, Any]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        reply = transport(QUERY, {"owner": owner, "name": name, "number": number, "cursor": cursor})
        if reply.get("errors"):
            raise PrecheckFault(f"GraphQL returned {len(reply['errors'])} error(s)")
        try:
            connection = reply["data"]["repository"]["pullRequest"]["commits"]
            nodes = connection["nodes"]
            page_info = connection["pageInfo"]
        except (KeyError, TypeError) as exc:
            raise PrecheckFault(
                f"the GraphQL reply has no {exc} where the commits should be"
            ) from exc
        if not isinstance(nodes, list) or not isinstance(page_info, Mapping):
            raise PrecheckFault("the GraphQL reply's commit nodes or pageInfo have the wrong shape")
        for node in nodes:
            commit = node.get("commit") if isinstance(node, Mapping) else None
            if not isinstance(commit, Mapping):
                raise PrecheckFault("a commit node holds no commit object")
            commits.append(commit)
        if not page_info.get("hasNextPage"):
            break
        next_cursor = page_info.get("endCursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
            raise PrecheckFault("a page reports more commits but gives no new cursor to read them")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    total = connection.get("totalCount")
    if not isinstance(total, int) or isinstance(total, bool):
        raise PrecheckFault("the GraphQL reply has no integer totalCount")
    return commits, total


def evaluate(commits: Sequence[Mapping[str, Any]], total: int, allowlist: Sequence[str]) -> Verdict:
    refusals: list[str] = []
    notices: list[str] = []
    if len(commits) != total:
        refusals.append(
            f"read {len(commits)} of the pull request's {total} commits; an unread commit cannot "
            "be checked"
        )
    for commit in commits:
        who = attribute(commit)
        if who.author_linked:
            continue
        if not who.committer_linked:
            if matches_allowlist(who.name, allowlist):
                refusals.append(
                    f"commit {who.oid} is linked to no GitHub account, and its git author name "
                    f"{who.name!r} matches the CLA allowlist, so the action would skip it unsigned"
                )
        elif who.database_id == WEB_FLOW_ID:
            notices.append(
                f"commit {who.oid} has an unlinked author and is committed by web-flow, so the "
                "action drops it from the CLA check"
            )
        elif matches_allowlist(who.name, allowlist):
            notices.append(
                f"commit {who.oid} has an unlinked author and is attributed to the allowlisted "
                f"committer {who.name!r}, so its author is never asked to sign"
            )
    return Verdict(tuple(refusals), tuple(notices))


def _escape_command(text: str) -> str:
    """Escape a workflow-command message, so a commit's text cannot start a command of its own."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def urllib_transport(url: str, token: str, timeout: float = 30.0) -> Transport:
    def call(query: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        body = json.dumps({"query": query, "variables": dict(variables)}).encode("utf-8")
        request = urllib.request.Request(  # nosec B310 -- run() refuses a URL that is not https
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "messagefoundry-cla-precheck",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PrecheckFault(f"GraphQL answered HTTP {exc.code}") from exc
        except OSError as exc:  # URLError and TimeoutError included
            raise PrecheckFault(f"GraphQL call failed ({type(exc).__name__})") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrecheckFault("GraphQL replied with something that is not UTF-8 JSON") from exc
        if not isinstance(payload, Mapping):
            raise PrecheckFault("GraphQL replied with JSON that is not an object")
        return payload

    return call


_REPOSITORY = re.compile(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def run(env: Mapping[str, str], transport: Transport | None = None) -> int:
    """Read the environment, check every commit, print annotations, and return the exit code."""
    try:
        token = env.get("GITHUB_TOKEN", "")
        repository = _REPOSITORY.fullmatch(env.get("GITHUB_REPOSITORY", ""))
        number_text = env.get("CLA_PR_NUMBER", "")
        allowlist = parse_allowlist(env.get("CLA_ALLOWLIST", ""))
        url = env.get("GITHUB_GRAPHQL_URL", "") or DEFAULT_GRAPHQL_URL
        if repository is None:
            raise PrecheckFault("GITHUB_REPOSITORY is not owner/name")
        if not number_text.isdecimal() or int(number_text) <= 0:
            raise PrecheckFault("CLA_PR_NUMBER is not a positive pull request number")
        if not allowlist:
            raise PrecheckFault("CLA_ALLOWLIST is empty")
        if transport is None:
            if not token:
                raise PrecheckFault("GITHUB_TOKEN is not set")
            if not url.startswith("https://"):
                raise PrecheckFault("GITHUB_GRAPHQL_URL is not https")
            transport = urllib_transport(url, token)
        commits, total = fetch_commits(
            transport, repository.group(1), repository.group(2), int(number_text)
        )
        verdict = evaluate(commits, total, allowlist)
    except PrecheckFault as exc:
        print(f"::error title=CLA pre-check fault::{_escape_command(str(exc))}")
        return EXIT_FAULT
    for notice in verdict.notices:
        print(f"::notice title=CLA pre-check::{_escape_command(notice)}")
    for refusal in verdict.refusals:
        print(f"::error title=CLA pre-check refused::{_escape_command(refusal)}")
    if verdict.refusals:
        return EXIT_REFUSED
    print(f"CLA pre-check: {len(commits)} commit(s) read, nothing refused")
    return EXIT_PASS


def main() -> int:
    return run(os.environ)


if __name__ == "__main__":
    sys.exit(main())
