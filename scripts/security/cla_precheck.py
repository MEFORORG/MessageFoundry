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
  * The committer list is keyed on ``login || name``, keeping the first commit seen under each key,
    and drops id ``41898282``. That id is ``github-actions[bot]``, NOT ``web-flow`` (19864447,
    which ``tests/fixtures/branch_main.json`` records).
  * ``checkAllowList`` drops every committer whose ``name`` matches an allowlist entry, by string
    equality or, for an entry holding ``*``, an UNANCHORED regular expression. For a commit nobody
    is linked to, that name is free text the pull request's author chose.

So a commit authored and committed under unlinked emails, with the git name set to an allowlisted
login, is dropped as allowlisted and never needs a signature. This script finds that commit and
refuses, and so it does for any unlinked commit the action files under an entry it skips. It builds
the action's committer list as the action does, from the FIRST PAGE only, first commit seen under
each key. It reads EVERY commit, paging on ``hasNextPage``, and refuses an author the action's list
never holds, or a read with fewer distinct commits than GitHub's ``totalCount``. It faults when the
pull request's head moved while it read.

WHERE IT RUNS. ``.github/workflows/cla.yml`` runs it as a step of the required ``cla`` job, before
the CLA action, FAIL-OPEN ON A FAULT (owner ruling 2026-11-13, "Wire, fail-open on fault"): exit 2
warns and passes, so a GitHub outage or bad input cannot wedge every pull request, its own revert
included; exit 1, a refusal or an unanticipated traceback, fails the check. It does not patch the
vendored bundle; the provenance gate forbids that.

WHAT IT DOES NOT REFUSE. It reports as a NOTICE, without refusing, at least these shapes the owner
has not ruled on:

  * an unlinked author attributed to a linked, allowlisted committer;
  * an unlinked author whose commit the action drops because the committer is ``github-actions[bot]``;
  * an unlinked commit filed under a linked account's entry, which is checked in its place.

It CANNOT see a commit linked through a spoofed email. GitHub links a commit to an account by its
email alone, so an author email set to an allowlisted account's address reads as that account, here
and in the action alike. Only commit signature verification separates the two, and neither checks it.

UNMEASURED: whether GitHub caps a pull request's commit connection (its REST listing stops at 250)
and, if it does, whether ``totalCount`` reports the capped or the real count. The short-read refusal
holds only where ``totalCount`` is the real count.

INPUT COMES ONLY FROM THE ENVIRONMENT, never from the command line or a templated ``run:`` line,
so a workflow step can pass event data through ``env:`` (zizmor's template-injection rule):

  GITHUB_TOKEN        a token that can read the pull request
  GITHUB_REPOSITORY   ``owner/name``
  CLA_PR_NUMBER       the pull request number
  CLA_ALLOWLIST       the same comma-separated list cla.yml passes the action
  CLA_HEAD_SHA        optional; the head commit the run judges. A different head is a fault.
  GITHUB_GRAPHQL_URL  optional; defaults to https://api.github.com/graphql

EXIT CODES: 0 nothing refused; 1 refused; 2 a fault (bad input, network, or a reply in the wrong
shape). The split lets a workflow choose how to treat a fault without parsing text. An exception
this script does not anticipate ends in a traceback and exit 1, so a bug in it reads as a refusal.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

EXIT_PASS = 0
EXIT_REFUSED = 1
EXIT_FAULT = 2

# `github-actions[bot]`, the one id the action drops from its committer list.
ACTIONS_BOT_ID = 41898282

DEFAULT_GRAPHQL_URL = "https://api.github.com/graphql"

# The cursor is nullable: GitHub reads a null `after` as "from the start". The action's empty-string
# cursor works only because it never asks for a second page.
QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid
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

# JavaScript's `.` matches anything but these four; Python's misses only the newline.
_JS_DOT_STAR = "[^\n\r\u2028\u2029]*"
_SHA = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[\x21-\x7e]+")  # visible ASCII: what a header carries without re-encoding
_REPOSITORY = re.compile(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


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
class PullRequestRead:
    commits: list[Mapping[str, Any]]
    total: int
    head: str
    #: How many commits the first page held. The action reads that page and no other.
    first_page: int


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
    """Mirror ``extractUserFromCommit``: author.user, then committer.user, then the raw author.

    JavaScript's ``||`` passes over null only, never an empty object, so this tests ``is None``
    rather than Python truthiness.
    """
    author = _person(commit, "author")
    author_user = _user(author)
    committer_user = _user(_person(commit, "committer"))
    if author_user is not None:
        chosen = author_user
    elif committer_user is not None:
        chosen = committer_user
    else:
        chosen = author
    login = chosen.get("login")
    raw_id = chosen.get("databaseId")
    return Attribution(
        oid=str(commit.get("oid", "")),
        name=str(login) if login else str(chosen.get("name") or ""),
        database_id=raw_id if isinstance(raw_id, int) and not isinstance(raw_id, bool) else None,
        author_linked=author_user is not None,
        committer_linked=committer_user is not None,
    )


def matches_allowlist(name: str, patterns: Iterable[str]) -> bool:
    """Mirror ``isUserNotInAllowList``: equality, or an UNANCHORED regex for an entry with ``*``.

    An empty entry is kept, as the action keeps it, so a doubled comma matches an empty name.
    """
    for raw in patterns:
        pattern = raw.strip()  # the action trims each entry here, so the mirror does too
        if "*" in pattern:
            if re.search(_JS_DOT_STAR.join(re.escape(part) for part in pattern.split("*")), name):
                return True
        elif pattern == name:
            return True
    return False


def parse_allowlist(text: str) -> list[str]:
    """Split as the action does: on every comma, empty entries kept."""
    return [entry.strip() for entry in text.split(",")]


def fetch_commits(transport: Transport, owner: str, name: str, number: int) -> PullRequestRead:
    """Every commit of the pull request, paging until ``hasNextPage`` is false.

    A page that claims more but gives no new cursor is a fault, and so is a head that moves between
    pages, because the pages would then describe two different pull requests. A list short of
    ``totalCount`` is returned as it is, for ``evaluate`` to refuse.
    """
    commits: list[Mapping[str, Any]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    head: str | None = None
    first_page: int | None = None
    while True:
        reply = transport(QUERY, {"owner": owner, "name": name, "number": number, "cursor": cursor})
        if reply.get("errors"):
            raise PrecheckFault("GraphQL returned an error")
        try:
            pull_request = reply["data"]["repository"]["pullRequest"]
            page_head = pull_request["headRefOid"]
            connection = pull_request["commits"]
            nodes = connection["nodes"]
            page_info = connection["pageInfo"]
        except (KeyError, TypeError) as exc:
            raise PrecheckFault("the GraphQL reply holds no pull request commits") from exc
        if not isinstance(nodes, list) or not isinstance(page_info, Mapping):
            raise PrecheckFault("the GraphQL reply's commit nodes or pageInfo have the wrong shape")
        if not isinstance(page_head, str) or (head is not None and page_head != head):
            raise PrecheckFault("the pull request's head moved while its commits were being read")
        head = page_head
        for node in nodes:
            commit = node.get("commit") if isinstance(node, Mapping) else None
            if not isinstance(commit, Mapping):
                raise PrecheckFault("a commit node holds no commit object")
            commits.append(commit)
        if first_page is None:
            first_page = len(nodes)
        total = _total_count(connection)
        if not page_info.get("hasNextPage"):
            break
        # Bounds the loop: every page that asks for another must add commits, short of totalCount.
        if not nodes or len(commits) >= total:
            raise PrecheckFault(
                "a page asks for another although it added nothing or reached totalCount"
            )
        next_cursor = page_info.get("endCursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
            raise PrecheckFault("a page reports more commits but gives no new cursor to read them")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    return PullRequestRead(commits, total, head, first_page)


def _total_count(connection: Mapping[str, Any]) -> int:
    total = connection.get("totalCount")
    if not isinstance(total, int) or isinstance(total, bool):
        raise PrecheckFault("the GraphQL reply has no integer totalCount")
    return total


def evaluate(read: PullRequestRead, allowlist: Sequence[str]) -> Verdict:
    refusals: list[str] = []
    notices: list[str] = []
    distinct = len({str(commit.get("oid", "")) for commit in read.commits})
    if distinct != read.total:
        refusals.append(
            f"read {distinct} distinct commits where the pull request has {read.total}; a commit "
            "not read once cannot be checked"
        )
    attributions = [attribute(commit) for commit in read.commits]

    def skipped(entry: Attribution) -> bool:
        """Does the action skip this committer entry: the id it drops, or an allowlisted name?"""
        return entry.database_id == ACTIONS_BOT_ID or matches_allowlist(entry.name, allowlist)

    # The action's committer list: the FIRST page only, one entry per `login || name`, first seen.
    entries: dict[str, Attribution] = {}
    for who in attributions[: read.first_page]:
        entries.setdefault(who.name, who)
    never_checked: set[str] = set()
    for who in attributions:
        unlinked = not who.author_linked and not who.committer_linked
        entry = entries.get(who.name)
        if entry is None:
            # Past the first page, under a name the action never saw, so it checks nobody here.
            if unlinked and skipped(who):
                refusals.append(
                    f"commit {who.oid} is linked to no GitHub account, and its git author name "
                    f"{who.name!r} is one the action skips, so it would pass unsigned"
                )
            elif not skipped(who) and who.name not in never_checked:
                never_checked.add(who.name)
                refusals.append(
                    f"commit {who.oid} is past the {read.first_page} commits the action reads, and "
                    f"its author {who.name!r} appears in none of them, so the action never checks "
                    "that author"
                )
        elif unlinked and skipped(entry):
            refusals.append(
                f"commit {who.oid} is linked to no GitHub account, and the action files it under "
                f"{who.name!r}, an entry it skips, so it would pass unsigned"
            )
        elif unlinked and entry is not who and (entry.author_linked or entry.committer_linked):
            notices.append(
                f"commit {who.oid} is linked to no GitHub account, and the action files it under "
                f"the linked account {who.name!r}, which is checked in its place"
            )
        if who.author_linked or unlinked:
            continue
        if who.database_id == ACTIONS_BOT_ID:
            notices.append(
                f"commit {who.oid} has an unlinked author and is committed by github-actions[bot], "
                "so the action drops it from the CLA check"
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would re-send the Authorization header to wherever it points."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise PrecheckFault(
            "GraphQL answered with a redirect, which this pre-check does not follow"
        )


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(url: str, token: str, timeout: float = 30.0) -> Transport:
    def call(query: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        body = json.dumps({"query": query, "variables": dict(variables)}).encode("utf-8")
        try:
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
            with _OPENER.open(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PrecheckFault(f"GraphQL answered HTTP {exc.code}") from exc
        except (OSError, http.client.HTTPException) as exc:  # URLError, timeouts, truncated replies
            raise PrecheckFault(f"GraphQL call failed ({type(exc).__name__})") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrecheckFault("GraphQL replied with something that is not UTF-8 JSON") from exc
        except ValueError as exc:  # a URL or header urllib cannot form, UnicodeEncodeError included
            raise PrecheckFault(
                f"the GraphQL request could not be formed ({type(exc).__name__})"
            ) from exc
        if not isinstance(payload, Mapping):
            raise PrecheckFault("GraphQL replied with JSON that is not an object")
        return payload

    return call


def run(env: Mapping[str, str], transport: Transport | None = None) -> int:
    """Read the environment, check every commit, print annotations, and return the exit code."""
    try:
        repository = _REPOSITORY.fullmatch(env.get("GITHUB_REPOSITORY", ""))
        number_text = env.get("CLA_PR_NUMBER", "")
        allowlist = parse_allowlist(env.get("CLA_ALLOWLIST", ""))
        expected_head = env.get("CLA_HEAD_SHA", "")
        if repository is None:
            raise PrecheckFault("GITHUB_REPOSITORY is not owner/name")
        # Ten digits bounds int() well inside Python's digit limit and above any real number.
        if not (number_text.isascii() and number_text.isdigit() and len(number_text) <= 10):
            raise PrecheckFault("CLA_PR_NUMBER is not a positive pull request number")
        number = int(number_text)
        if number <= 0:
            raise PrecheckFault("CLA_PR_NUMBER is not a positive pull request number")
        if not any(allowlist):
            raise PrecheckFault("CLA_ALLOWLIST is empty")
        if expected_head and not _SHA.fullmatch(expected_head):
            raise PrecheckFault("CLA_HEAD_SHA is not a 40-character lowercase commit id")
        if transport is None:
            token = env.get("GITHUB_TOKEN", "")
            url = env.get("GITHUB_GRAPHQL_URL", "") or DEFAULT_GRAPHQL_URL
            if not _TOKEN.fullmatch(token):
                raise PrecheckFault("GITHUB_TOKEN is not set, or holds a character a header cannot")
            try:
                parts = urllib.parse.urlsplit(url)
                host = parts.hostname
            except ValueError as exc:
                raise PrecheckFault("GITHUB_GRAPHQL_URL is not a URL") from exc
            if parts.scheme != "https" or not host:
                raise PrecheckFault("GITHUB_GRAPHQL_URL is not an https URL with a host")
            transport = urllib_transport(url, token)
        read = fetch_commits(transport, repository.group(1), repository.group(2), number)
        if expected_head and read.head != expected_head:
            raise PrecheckFault("the pull request's head is not CLA_HEAD_SHA; this run is stale")
        verdict = evaluate(read, allowlist)
    except PrecheckFault as exc:
        print(f"::warning title=CLA pre-check fault::{_escape_command(str(exc))}")
        return EXIT_FAULT
    for notice in verdict.notices:
        print(f"::notice title=CLA pre-check::{_escape_command(notice)}")
    for refusal in verdict.refusals:
        print(f"::error title=CLA pre-check refused::{_escape_command(refusal)}")
    if verdict.refusals:
        return EXIT_REFUSED
    print(f"CLA pre-check: {len(read.commits)} commit(s) read, nothing refused")
    return EXIT_PASS


def main() -> int:
    # A commit name the console cannot encode must not end the run in a traceback.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")
    return run(os.environ)


if __name__ == "__main__":
    sys.exit(main())
