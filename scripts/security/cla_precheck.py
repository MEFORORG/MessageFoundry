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
never holds. It refuses an unlinked AUTHOR even when the committer is allowlisted or
``github-actions[bot]``: the CLA binds the author (owner ruling 2026-11-13). It faults when the pull
request's head moved while it read, and when it read fewer distinct commits than GitHub's
``totalCount``.

WHERE IT RUNS. ``.github/workflows/cla.yml`` runs it as a step of the required ``cla`` job, before
the CLA action: FAIL-OPEN ON A FAULT, FAIL-CLOSED ON A DETERMINATE REFUSAL (owner ruling
2026-11-13). The workflow fails the check on exit 1 only when the output carries this script's
refusal annotation; any other exit 1, such as an import-time traceback, warns and passes, as exit 3
does, so a GitHub outage, bad input or a bug in this script cannot wedge every pull request, its own
revert included. Exit 2 is NOT a fault: it is what the interpreter returns when it cannot open the
script, so a renamed or deleted script fails the check instead of switching it off. The runner runs
this with its system ``python3``, so the script keeps to Python 3.12 syntax;
tests/test_cla_precheck.py parses it at that grammar. It does not patch the vendored bundle; the
provenance gate forbids that.

AN AUTHOR THE ACTION NEVER SEES, first seen past its one page, is refused only when absent from the
signature file the action keeps (``signedContributors`` ids, read over REST from the base
repository's signature branch). A file GitHub answers 404 for holds no signatures, as the action
itself assumes; any other unreadable answer is a fault. It is read only when such an author exists.

WHAT IT DOES NOT REFUSE, at least: an unlinked commit filed under a linked account's entry, which
is reported as a NOTICE because that account is checked in its place; and an unlinked author under
a linked committer that is neither allowlisted nor ``github-actions[bot]``, which it does not report.

It CANNOT see a spoofed AUTHOR email. GitHub links a commit to an account by its email alone, so an
author email set to an allowlisted account's address reads as that account, here and in the action
alike. Only commit signature verification separates the two, and neither checks it. A spoofed
COMMITTER email under an unlinked author is refused, by the author rule above.

UNMEASURED: whether GitHub caps a pull request's commit connection (its REST listing stops at 250)
and, if it does, whether ``totalCount`` reports the capped or the real count. Until it is measured a
read short of ``totalCount`` is a FAULT (owner ruling 2026-11-13), so the commits past a cap are not
checked, and the run warns and passes.

INPUT COMES ONLY FROM THE ENVIRONMENT, never from the command line or a templated ``run:`` line,
so a workflow step can pass event data through ``env:`` (zizmor's template-injection rule):

  GITHUB_TOKEN        a token that can read the pull request
  GITHUB_REPOSITORY   ``owner/name``
  CLA_PR_NUMBER       the pull request number
  CLA_ALLOWLIST       the same comma-separated list cla.yml passes the action
  CLA_HEAD_SHA        optional; the head commit the run judges. A different head is a fault.
  GITHUB_GRAPHQL_URL  optional; defaults to https://api.github.com/graphql
  GITHUB_API_URL      optional; defaults to https://api.github.com
  CLA_SIGNATURES_PATH the action's ``path-to-signatures``
  CLA_SIGNATURES_BRANCH the action's ``branch``

EXIT CODES: 0 nothing refused; 1 refused, with a ``CLA pre-check refused`` annotation; 3 a fault
caught by this script (bad input, network, a reply in the wrong shape, a short read, or an exception
raised inside ``run``). At least one other path exits 1 with no refusal annotation: an error before
``main`` runs, such as at import. The interpreter itself exits 2 when it cannot open the script.
The workflow tells these apart by the annotation, not the code alone.
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
EXIT_FAULT = 3  # never 2: the interpreter exits 2 when it cannot open the script

# `github-actions[bot]`, the one id the action drops from its committer list.
ACTIONS_BOT_ID = 41898282

DEFAULT_GRAPHQL_URL = "https://api.github.com/graphql"
DEFAULT_API_URL = "https://api.github.com"

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
    """The pre-check could not reach a verdict: bad input, a failed call, or a malformed reply.

    ``partial`` carries the commits read before a later page failed, so a refusal they already
    prove is not thrown away with the fault.
    """

    partial: PullRequestRead | None = None


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
    #: Set when part of the verdict could not be reached. The refusals that WERE reached still stand.
    fault: str | None = None


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
    # The action never reads the committer when the author is linked, so neither does this: a
    # malformed committer there must not fault the run and drop every other commit's refusal.
    committer_user = _user(_person(commit, "committer")) if author_user is None else None
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
    state: dict[str, Any] = {"head": None, "first_page": None}
    try:
        return _fetch_pages(transport, owner, name, number, commits, state)
    except PrecheckFault as exc:
        if commits and state["head"] is not None and state["first_page"] is not None:
            exc.partial = PullRequestRead(
                list(commits), len(commits), state["head"], state["first_page"]
            )
        raise


def _fetch_pages(
    transport: Transport,
    owner: str,
    name: str,
    number: int,
    commits: list[Mapping[str, Any]],
    state: dict[str, Any],
) -> PullRequestRead:
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
        page: list[Mapping[str, Any]] = []
        for node in nodes:
            commit = node.get("commit") if isinstance(node, Mapping) else None
            if not isinstance(commit, Mapping):
                raise PrecheckFault("a commit node holds no commit object")
            page.append(commit)
        commits.extend(page)  # whole pages only, so a partial read never holds half a page
        if first_page is None:
            first_page = len(nodes)
        state["head"], state["first_page"] = head, first_page
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


Signatures = Callable[[], frozenset[int]]


def evaluate(
    read: PullRequestRead,
    allowlist: Sequence[str],
    signatures: Signatures | None = None,
    *,
    complete: bool = True,
) -> Verdict:
    """Refusals and notices for one read. ``signatures`` returns the signed account ids; it is
    called only for an author the action never sees, and with none every such author refuses.

    A fault partway (an unreadable signature file, a malformed commit) is recorded in
    ``Verdict.fault`` and the rest is still judged, so a refusal already proven stands. With
    ``complete`` false (a read cut short by a fault) the count check is skipped.
    """
    faults: list[str] = []
    signed_cache: dict[str, frozenset[int] | None] = {}

    def has_signed(who: Attribution) -> bool | None:
        """True or False, or None when the signature file could not be read."""
        if who.database_id is None or signatures is None:
            return False
        if "ids" not in signed_cache:
            try:
                signed_cache["ids"] = signatures()
            except PrecheckFault as exc:
                faults.append(str(exc))
                signed_cache["ids"] = None
        ids = signed_cache["ids"]
        return None if ids is None else who.database_id in ids

    refusals: list[str] = []
    notices: list[str] = []
    distinct = len({str(commit.get("oid", "")) for commit in read.commits})
    # A FAULT, not a refusal, until GitHub's commit cap is measured (owner ruling 2026-11-13): if
    # GitHub stops the connection short of totalCount, refusing would fail every large PR closed.
    if complete and distinct != read.total:
        faults.append(
            f"read {distinct} distinct commits where the pull request has {read.total}; the "
            "unread commits are not checked"
        )
    # One slot per commit, None for a malformed one, so the first-page slice below never shifts a
    # second-page commit into the action's view.
    slots: list[Attribution | None] = []
    for commit in read.commits:
        try:
            slots.append(attribute(commit))
        except PrecheckFault as exc:
            faults.append(str(exc))
            slots.append(None)
    attributions = [who for who in slots if who is not None]

    def skipped(entry: Attribution) -> bool:
        """Does the action skip this committer entry: the id it drops, or an allowlisted name?"""
        return entry.database_id == ACTIONS_BOT_ID or matches_allowlist(entry.name, allowlist)

    # The action's committer list: the FIRST page only, one entry per `login || name`, first seen.
    entries: dict[str, Attribution] = {}
    for slot in slots[: read.first_page]:
        if slot is not None:
            entries.setdefault(slot.name, slot)
    # Keyed on the name AND the account, so a linked author does not cover an unlinked commit that
    # merely shares its name.
    never_checked: set[tuple[str, int | None]] = set()
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
            elif not skipped(who) and (who.name, who.database_id) not in never_checked:
                never_checked.add((who.name, who.database_id))
                if has_signed(who) is False:
                    refusals.append(
                        f"commit {who.oid} is past the {read.first_page} commits the action "
                        f"reads, its author {who.name!r} appears in none of them, and the CLA "
                        "signature file holds no signature for that account"
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
        # The CLA binds the AUTHOR (owner ruling 2026-11-13). An allowlisted or bot committer does
        # not stand in for an unlinked author, and a committer email is trivially set.
        if who.database_id == ACTIONS_BOT_ID:
            refusals.append(
                f"commit {who.oid} has an author linked to no GitHub account and is committed by "
                "github-actions[bot], so the action drops it and its author is never checked"
            )
        elif matches_allowlist(who.name, allowlist):
            refusals.append(
                f"commit {who.oid} has an author linked to no GitHub account and is attributed to "
                f"the allowlisted committer {who.name!r}, so its author is never asked to sign"
            )
    return Verdict(tuple(refusals), tuple(notices), "; ".join(faults) or None)


def _escape_command(text: str) -> str:
    """Escape a workflow-command message, so a commit's text cannot start a command of its own."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would re-send the Authorization header to wherever it points."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise PrecheckFault("GitHub answered with a redirect, which this pre-check does not follow")


_OPENER = urllib.request.build_opener(_NoRedirect)


class _NotFound(Exception):
    """GitHub answered 404."""


def _fetch_json(
    url: str, token: str, what: str, *, body: bytes | None = None, accept: str, timeout: float
) -> object:
    """One authenticated request to GitHub, its reply parsed as JSON; every failure is a fault."""
    headers = {"Authorization": f"Bearer {token}", "Accept": accept}
    headers["User-Agent"] = "messagefoundry-cla-precheck"
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        request = urllib.request.Request(  # nosec B310 -- run() refuses a URL that is not https
            url, data=body, headers=headers, method="GET" if body is None else "POST"
        )
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _NotFound from exc
        raise PrecheckFault(f"{what} answered HTTP {exc.code}") from exc
    except (OSError, http.client.HTTPException) as exc:  # URLError, timeouts, truncated replies
        raise PrecheckFault(f"{what} call failed ({type(exc).__name__})") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrecheckFault(f"{what} replied with something that is not UTF-8 JSON") from exc
    except ValueError as exc:  # a URL or header urllib cannot form, UnicodeEncodeError included
        raise PrecheckFault(
            f"the {what} request could not be formed ({type(exc).__name__})"
        ) from exc


def urllib_transport(url: str, token: str, timeout: float = 30.0) -> Transport:
    def call(query: str, variables: Mapping[str, object]) -> Mapping[str, Any]:
        body = json.dumps({"query": query, "variables": dict(variables)}).encode("utf-8")
        try:
            payload = _fetch_json(
                url, token, "GraphQL", body=body, accept="application/json", timeout=timeout
            )
        except _NotFound as exc:
            raise PrecheckFault("GraphQL answered HTTP 404") from exc
        if not isinstance(payload, Mapping):
            raise PrecheckFault("GraphQL replied with JSON that is not an object")
        return payload

    return call


def parse_signatures(payload: object) -> frozenset[int]:
    """The account ids in the action's ``{"signedContributors": [{"id": ...}, ...]}`` file."""
    contributors = payload.get("signedContributors") if isinstance(payload, Mapping) else None
    if not isinstance(contributors, list):
        raise PrecheckFault("the CLA signature file holds no signedContributors list")
    ids: set[int] = set()
    for entry in contributors:
        raw = entry.get("id") if isinstance(entry, Mapping) else None
        if not isinstance(raw, int) or isinstance(raw, bool):
            raise PrecheckFault("a CLA signature entry holds no integer id")
        ids.add(raw)
    return frozenset(ids)


def rest_signatures(
    api_url: str, token: str, owner: str, name: str, path: str, branch: str, timeout: float = 30.0
) -> Signatures:
    """Read the signature file the action keeps, from the base repository, over REST.

    A 404 means the file does not exist yet, which the action itself reads as no signatures.
    """
    url = (
        f"{api_url.rstrip('/')}/repos/{owner}/{name}/contents/"
        f"{urllib.parse.quote(path)}?ref={urllib.parse.quote(branch, safe='')}"
    )

    def read() -> frozenset[int]:
        try:
            payload = _fetch_json(
                url,
                token,
                "the signature file",
                accept="application/vnd.github.raw+json",
                timeout=timeout,
            )
        except _NotFound:
            return frozenset()
        return parse_signatures(payload)

    return read


def _https_url(env: Mapping[str, str], key: str, default: str) -> str:
    url = env.get(key, "") or default
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError as exc:
        raise PrecheckFault(f"{key} is not a URL") from exc
    if parts.scheme != "https" or not host:
        raise PrecheckFault(f"{key} is not an https URL with a host")
    return url


def run(
    env: Mapping[str, str],
    transport: Transport | None = None,
    signatures: Signatures | None = None,
) -> int:
    """Read the environment, check every commit, print annotations, and return the exit code.

    ``transport`` and ``signatures`` replace the network for tests; both default to GitHub.
    """
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
        owner, name = repository.group(1), repository.group(2)
        if transport is None or signatures is None:
            token = env.get("GITHUB_TOKEN", "")
            if not _TOKEN.fullmatch(token):
                raise PrecheckFault("GITHUB_TOKEN is not set, or holds a character a header cannot")
            if transport is None:
                transport = urllib_transport(
                    _https_url(env, "GITHUB_GRAPHQL_URL", DEFAULT_GRAPHQL_URL), token
                )
            if signatures is None:
                path = env.get("CLA_SIGNATURES_PATH", "")
                branch = env.get("CLA_SIGNATURES_BRANCH", "")
                if not path or not branch:
                    raise PrecheckFault("CLA_SIGNATURES_PATH or CLA_SIGNATURES_BRANCH is not set")
                api = _https_url(env, "GITHUB_API_URL", DEFAULT_API_URL)
                signatures = rest_signatures(api, token, owner, name, path, branch)
        try:
            read = fetch_commits(transport, owner, name, number)
            complete, read_fault = True, None
        except PrecheckFault as exc:
            # A later page failed. The pages already read still prove what they prove.
            if exc.partial is None:
                raise
            read, complete, read_fault = exc.partial, False, str(exc)
        if expected_head and read.head != expected_head:
            raise PrecheckFault("the pull request's head is not CLA_HEAD_SHA; this run is stale")
        verdict = evaluate(read, allowlist, signatures, complete=complete)
    except PrecheckFault as exc:
        print(f"::warning title=CLA pre-check fault::{_escape_command(str(exc))}")
        return EXIT_FAULT
    for notice in verdict.notices:
        print(f"::notice title=CLA pre-check::{_escape_command(notice)}")
    fault = "; ".join(f for f in (read_fault, verdict.fault) if f)
    if fault:
        print(f"::warning title=CLA pre-check fault::{_escape_command(fault)}")
    for refusal in verdict.refusals:
        print(f"::error title=CLA pre-check refused::{_escape_command(refusal)}")
    if verdict.refusals:
        return EXIT_REFUSED  # a refusal the read proved stands, whatever else faulted
    if fault:
        return EXIT_FAULT
    print(f"CLA pre-check: {len(read.commits)} commit(s) read, nothing refused")
    return EXIT_PASS


def main() -> int:
    # A commit name the console cannot encode must not end the run in a traceback.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        return run(os.environ)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad, see below
        # A bug in this script is a FAULT, not a refusal (owner ruling 2026-11-13, fail-open on a
        # fault): a traceback would exit 1 and fail every pull request, its own revert included.
        # Only the type is printed; the message could quote commit data.
        print(f"::warning title=CLA pre-check fault::unexpected {type(exc).__name__}")
        return EXIT_FAULT


if __name__ == "__main__":
    sys.exit(main())
