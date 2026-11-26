#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a pull request whose CLA verdict the vendored action would get wrong (BACKLOG #5644, #5645).

WHAT THE VENDORED ACTION DOES, read from ``.github/actions/cla-assistant-lite/dist/index.js``. That
bundle is a PATCHED FORK of upstream v2.6.1 since 2026-11-23 (owner ruling "Fork, patch,
re-provenance"; BACKLOG #5644 item 2, #5645 item 2). The action's README lists the patches; the two bullets marked PATCHED
below are them, and the other two describe upstream behaviour the fork keeps:

  * ``getCommitters`` asks GraphQL for ``commits(first: 100)`` and, PATCHED, follows ``hasNextPage``
    to the end of the list. Upstream read one page with an empty cursor and never followed it.
    GitHub's list stops at 250 commits (see the measurement below), so neither the action nor this
    script checks an author first seen past commit 250.
  * ``extractUserFromCommit`` attributes each commit to ``author.user || committer.user || author ||
    committer``. A commit whose author email links to no account is therefore attributed to its
    COMMITTER's account when that one is linked, and to the raw git ``author.name`` only when
    neither is linked. (BACKLOG #5644's subject reads this order as committer-first; it is
    author-first, and the tests here pin the real order.)
  * The committer list is keyed on ``login || name``, keeping the first commit seen under each key,
    and drops id ``41898282``. That id is ``github-actions[bot]``, NOT ``web-flow`` (19864447,
    which ``tests/fixtures/branch_main.json`` records).
  * ``checkAllowList`` drops every committer whose ``name`` matches an allowlist entry, by string
    equality or, for an entry holding ``*``, a regular expression that is, PATCHED, anchored to the
    whole name (upstream's was unanchored, so ``bot*`` matched ``evilbot-x``). For a commit nobody
    is linked to, that name is free text the pull request's author chose.

So a commit authored and committed under unlinked emails, with the git name set to an allowlisted
login, is dropped as allowlisted and never needs a signature. This script applies two rules to
EVERY commit it can read, paging on ``hasNextPage``:

  1. A commit whose AUTHOR is linked to no GitHub account is refused, whatever its committer or
     git name. The CLA binds the author, and an unlinked author can never be shown to have signed
     (owner ruling 2026-11-13). Measured before the ruling: every commit on merged PRs 2909 and
     2432 has a linked author, so the rule refuses nothing in current flows. A null author, and an
     author whose ``user`` is null or absent, are refused; an absent ``author`` key, or a value of
     either that is neither null nor an object, is a reply in the wrong shape and a fault.
  2. A linked author first seen past the first page (as many commits as GitHub returned
     first, at most 100) is refused only when
     absent from the signature file the action keeps (below). The first page's keys are built as
     the action builds its list, first commit seen under each key. Rule 2 was written for the
     upstream action, which read that page only. The patched action now lists such an author
     itself and asks them to sign, so rule 2 duplicates the action's own demand there rather than
     adding to it; it is kept. It clears once the signature file holds the author's id. This
     pre-check runs before the action step that writes that id, so the run on which the author
     signs still refuses, and a later run (a recheck comment or a push) clears.

It faults in at least these cases: the pull request's head moved while it read, it read fewer
distinct commits than GitHub's ``totalCount``, or a commit's author or committer it needs could
not be read.

TWO CASES BACKLOG #5645 item 1 names:

  * A GraphQL reply carrying ``errors`` beside its ``data`` (a partial error). An error whose
    ``path`` points inside one commit node leaves that commit unjudged, a fault, because GraphQL
    nulls the field it could not resolve and a nulled ``author.user`` would read as an unlinked
    author. One whose path stays inside that commit's ``committer`` leaves only the committer
    unread: the nullable committer stops null propagation there, so rule 1 still judges the
    author (BACKLOG #5644 added item 1). On the first page, such a commit with a git author is
    still left out of the first page's keys, with a fault, whether that author is linked or not,
    as before that item; an unlinked one is also refused under rule 1. On any page, a commit
    with a committer-only error that came back with no commit object, or with no readable
    ``oid``, contradicts the premise and is unjudged whole. The other commits on the page are judged, so a refusal they prove stands. An error with
    no such path still faults the whole page, keeping the pages read before it.
  * A head that lags the push event. When ``CLA_HEAD_SHA`` is set and the first page's
    ``headRefOid`` is another commit, the read stops there and is repeated after each wait in
    ``HEAD_RETRY_DELAYS``. If every first page shows another head, the run is a fault and nothing
    is judged: a read of another head proves nothing about this one. Only that case is re-read. A
    read whose ``headRefOid`` is ``CLA_HEAD_SHA`` is judged; if it is complete and its commits do
    not include that head, or cannot show that they do, a fault is added beside the verdict, so a
    pass is not silent. A read cut short carries its own fault and is not checked for the head. A
    head that moves after the first page is not re-read: the pages before the move, which are of
    ``CLA_HEAD_SHA``, are judged, with a fault. Without ``CLA_HEAD_SHA`` (a comment event) nothing
    is re-read.

WHERE IT RUNS. ``.github/workflows/cla.yml`` runs it as a step of the required ``cla`` job, before
the CLA action: FAIL-OPEN ON A FAULT, FAIL-CLOSED ON A DETERMINATE REFUSAL (owner ruling
2026-11-13). The workflow fails the check on exit 1 only when the output carries this script's
refusal annotation; any other exit 1, such as an import-time traceback, warns and passes, as exit 3
does, so a GitHub outage, bad input or a bug in this script cannot wedge every pull request, its own
revert included. Exit 2 is NOT a fault: it is what the interpreter returns when it cannot open the
script, so a renamed or deleted script fails the check instead of switching it off. The runner runs
this with its system ``python3``, so the script keeps to Python 3.12 syntax;
tests/test_cla_precheck.py parses it at that grammar. It does not itself change the vendored
bundle. The bundle's patches are recorded in ``scripts/security/build_cla_action_provenance.py``,
whose gate refuses any change to the bundle outside them.

THE SIGNATURE FILE (rule 2) holds ``signedContributors`` ids, read over REST from the base
repository's signature branch. A file GitHub answers 404 for holds no signatures, as the action
itself assumes; any other unreadable answer is a fault. It is read only when rule 2 needs it.

It CANNOT see a spoofed AUTHOR email. GitHub links a commit to an account by its email alone, so an
author email set to an allowlisted account's address reads as that account, here and in the action
alike. Only commit signature verification separates the two, and neither checks it.

MEASURED 2026-11-23 (first by the patched-fork change's code review, then repeated by its Builder), with ``gh api graphql`` against a
public pull request of 4096 commits (home-assistant/core 189294): the GraphQL commit connection
returned 100, 100 and 50 commits, then ``hasNextPage`` false, while ``totalCount`` reported 4096 on
every page. So GitHub stops the list at 250 and ``totalCount`` reports the real count. One pull
request was read, so this is a reading, not a documented contract. A read short of ``totalCount``
stays a FAULT that warns and passes (owner rulings 2026-11-13, "Wire, fail-open on fault", and
2026-11-23 on BACKLOG #5645 item 1, "Warn and pass"). SO AN AUTHOR FIRST SEEN PAST COMMIT 250 IS NOT
CHECKED, by this script or by the action: on such a pull request the ``cla`` check warns and can
pass for an author who never signed.

UNMEASURED: whether GitHub's GraphQL ``headRefOid`` or commit list trails the push event, and by
how long. The waits in ``HEAD_RETRY_DELAYS`` are a guess. A ``headRefOid`` that still shows another
head after them leaves the run a fault that warns and passes. A commit list that trails a current
``headRefOid`` is not waited for: it is judged, so after a force-push it can
refuse a commit the pull request no longer holds.

UNMEASURED: that every field a partial error nulled lies on the ``path`` of an error naming its
commit node. The GraphQL specification implies it: an error's path names the field that raised it,
and null propagation reaches only that field's ancestors. A nulled ``author.user`` that no error
path reaches reads as an unlinked author and is refused. That includes a commit whose only error
path is inside its ``committer``: if one failure nulled ``author.user`` too but GitHub reported
only the committer's path, its author is refused under rule 1, where before BACKLOG #5644 added
item 1 the commit was a fault that passes.

INPUT COMES ONLY FROM THE ENVIRONMENT, never from the command line or a templated ``run:`` line,
so a workflow step can pass event data through ``env:`` (zizmor's template-injection rule):

  GITHUB_TOKEN        a token that can read the pull request
  GITHUB_REPOSITORY   ``owner/name``
  CLA_PR_NUMBER       the pull request number
  CLA_ALLOWLIST       the same comma-separated list cla.yml passes the action
  CLA_HEAD_SHA        optional; the head commit the run judges. A first page showing another
                      head is re-read, then a fault; a head that moves on a later page is not
                      re-read.
  GITHUB_GRAPHQL_URL  optional; defaults to https://api.github.com/graphql
  GITHUB_API_URL      optional; defaults to https://api.github.com
  CLA_SIGNATURES_PATH the action's ``path-to-signatures``
  CLA_SIGNATURES_BRANCH the action's ``branch``

EXIT CODES: 0 nothing refused and no fault; 1 refused, with a ``CLA pre-check refused``
annotation, whatever fault is reported beside it; 3 a fault caught by this script with nothing
refused, at least: bad input, network, a reply in the wrong shape, a short read, a head still
stale after the re-reads, a commit list that does not include ``CLA_HEAD_SHA`` or cannot show that
it does, a commit with a GraphQL error inside it (for one inside its ``committer`` alone, the
partial-error case above says which are faults), or an exception raised inside ``run``. At least
one other path exits 1 with no refusal annotation: an error before ``main`` runs, such as at
import. The interpreter itself exits 2 when it cannot open the script. The workflow tells these
apart by the annotation, not the code alone.
"""

from __future__ import annotations

import http.client
import io
import itertools
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

EXIT_PASS = 0
EXIT_REFUSED = 1
EXIT_FAULT = 3  # never 2: the interpreter exits 2 when it cannot open the script

# Refusals printed as annotations before the rest go to the log; one more annotation counts them.
_ANNOTATED_REFUSALS = 9

# `github-actions[bot]`, the one id the action drops from its committer list.
ACTIONS_BOT_ID = 41898282

DEFAULT_GRAPHQL_URL = "https://api.github.com/graphql"
DEFAULT_API_URL = "https://api.github.com"

# Seconds to wait before each re-read when the head read is not the head the run judges. That
# GitHub's GraphQL view trails the push event, and by how much, is unmeasured (module docstring).
HEAD_RETRY_DELAYS = (5.0, 10.0)

# Where a commit node sits in the reply, as a GraphQL error ``path`` names it.
_NODES_PATH = ("repository", "pullRequest", "commits", "nodes")

# The cursor is nullable: GitHub reads a null `after` as "from the start". The action declares its
# cursor non-null and passes an empty string for the first page, which GitHub also reads as the
# start (the 2026-11-23 measurement in the module docstring used that form).
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


class _StaleHead(PrecheckFault):
    """The first page's head is not the head the run judges, so the read stopped there."""


@dataclass(frozen=True)
class Attribution:
    """Who the vendored action would say made one commit, and whether anyone is linked."""

    oid: str
    name: str
    database_id: int | None
    author_linked: bool


@dataclass(frozen=True)
class PullRequestRead:
    commits: list[Mapping[str, Any]]
    total: int
    head: str
    #: How many commits the first page held. Rule 2 keys that page, first commit seen per key.
    first_page: int
    #: Indexes into ``commits`` that a GraphQL error points inside, other than those in
    #: ``committer_tainted``. They are not judged.
    tainted: frozenset[int] = frozenset()
    #: Indexes, none in ``tainted``, whose errors all point inside the commit's ``committer`` and
    #: whose commit came back with a readable 40-hex ``oid``; ``evaluate`` relies on that oid.
    #: Their author is judged; their committer is not read.
    committer_tainted: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Verdict:
    refusals: tuple[str, ...]
    #: Set when part of the verdict could not be reached. The refusals that WERE reached still stand.
    fault: str | None = None


def _person(commit: Mapping[str, Any], role: str) -> Mapping[str, Any] | None:
    """The commit's ``author`` or ``committer``: None for a null one, which the schema allows. An
    absent key, or any value that is not an object, is a reply in the wrong shape: a fault."""
    if role not in commit:
        raise PrecheckFault(f"a commit has no {role} key")
    person = commit[role]
    if person is None:
        return None
    if not isinstance(person, Mapping):
        raise PrecheckFault(f"a commit's {role} is not an object")
    return person


def _user(person: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """A person's linked account, or None when none is linked (a null or absent ``user``). Any
    other value that is not an object is a fault."""
    user = person.get("user")
    if user is None:
        return None
    if not isinstance(user, Mapping):
        raise PrecheckFault("a commit's user is not an object")
    return user


def attribute(commit: Mapping[str, Any]) -> Attribution:
    """Mirror ``extractUserFromCommit``: ``author.user || committer.user || author || committer``.

    A null is passed over, as ``||`` passes it; an empty ``{}`` user is still chosen, as ``||``
    chooses it. The bundle reads ``author.user``, and ``committer.user`` when that is null, so a
    null person there would throw in the action. A null committer there is a fault here; the commit
    keys nothing among the first page's keys. ``evaluate`` never calls this for a null author:
    rule 1 refuses that commit first, and it is not also a fault.
    """
    author = _person(commit, "author")
    if author is None:
        raise PrecheckFault("a commit's author is null, so the action has no key for it")
    author_user = _user(author)
    committer: Mapping[str, Any] | None = None
    # The action never reads the committer when the author is linked, so neither does this: a
    # malformed committer there must not fault that commit.
    if author_user is None:
        committer = _person(commit, "committer")
        if committer is None:
            raise PrecheckFault("a commit's committer is null, so the action has no key for it")
    committer_user = None if committer is None else _user(committer)
    # Each is None or an object, and `is not None` rather than Python truthiness keeps an empty {}.
    chosen = next(c for c in (author_user, committer_user, author) if c is not None)
    login = chosen.get("login")
    raw_id = chosen.get("databaseId")
    return Attribution(
        oid=str(commit.get("oid", "")),
        name=str(login) if login else str(chosen.get("name") or ""),
        database_id=raw_id if isinstance(raw_id, int) and not isinstance(raw_id, bool) else None,
        author_linked=author_user is not None,
    )


def _rule_one(commit: Mapping[str, Any]) -> str | None:
    """Rule 1's refusal for one commit, judged from its author alone, or None when it owes none.

    Uses the same ``_person``/``_user`` reading as :func:`attribute`, so the two cannot disagree on
    whether an author is linked. A malformed author raises; the caller records the fault.
    """
    oid = commit.get("oid", "")
    author = _person(commit, "author")
    if author is None:
        return (
            f"commit {oid} has no git author GitHub reports, so no author can be shown to have "
            "signed the CLA; re-author the commit"
        )
    if _user(author) is not None:
        return None
    # The CLA binds the AUTHOR, and an unlinked author cannot have signed.
    return (
        f"commit {oid} has a git author, {str(author.get('name') or '')!r}, linked to no GitHub "
        "account, so that author cannot be shown to have signed the CLA; link the author's email "
        "to an account, or re-author the commit"
    )


def matches_allowlist(name: str, patterns: Iterable[str]) -> bool:
    """Mirror ``isUserNotInAllowList``: equality, or for an entry with ``*`` a regex anchored to the
    whole name, as the patched action anchors it (BACKLOG #5644 item 2).

    An empty entry is kept, as the action keeps it, so a doubled comma matches an empty name.
    ``fullmatch`` stands for JavaScript's ``^...$`` without the ``m`` flag: neither lets a match
    end before a trailing newline, which Python's ``$`` alone would.
    """
    for raw in patterns:
        pattern = raw.strip()  # the action trims each entry here, so the mirror does too
        if "*" in pattern:
            if re.fullmatch(
                _JS_DOT_STAR.join(re.escape(part) for part in pattern.split("*")), name
            ):
                return True
        elif pattern == name:
            return True
    return False


def parse_allowlist(text: str) -> list[str]:
    """Split as the action does: on every comma, empty entries kept."""
    return [entry.strip() for entry in text.split(",")]


def fetch_commits(
    transport: Transport, owner: str, name: str, number: int, expected_head: str = ""
) -> PullRequestRead:
    """Every commit of the pull request, paging until ``hasNextPage`` is false.

    A page that claims more but gives no new cursor is a fault, and so is a head that moves between
    pages, because the pages would then describe two different pull requests. A list short of
    ``totalCount`` is returned as it is, for ``evaluate`` to record as a fault. With
    ``expected_head`` set, a first page of another head raises :class:`_StaleHead` at once.
    """
    commits: list[Mapping[str, Any]] = []
    state: dict[str, Any] = {
        "head": None,
        "first_page": None,
        "tainted": set(),
        "committer_tainted": set(),
    }
    try:
        return _fetch_pages(transport, owner, name, number, expected_head, commits, state)
    except PrecheckFault as exc:
        if commits and state["head"] is not None and state["first_page"] is not None:
            exc.partial = _snapshot(list(commits), len(commits), state)
        raise


def _snapshot(
    commits: list[Mapping[str, Any]], total: int, state: Mapping[str, Any]
) -> PullRequestRead:
    tainted = frozenset(state["tainted"])
    return PullRequestRead(
        commits,
        total,
        state["head"],
        state["first_page"],
        tainted,
        frozenset(state["committer_tainted"]) - tainted,
    )


def _errored_nodes(errors: object) -> tuple[set[int], set[int]]:
    """The commit-node indexes a GraphQL ``errors`` list points inside: those an error may have
    nulled anything in, and those an error points inside the ``committer`` of. An index can be in
    both; the first set wins.

    An error that does not name one node by its ``path`` could have touched anything on the page,
    so it faults the page instead.
    """
    if not isinstance(errors, list):
        raise PrecheckFault("GraphQL returned an error")
    indexes: set[int] = set()
    committer_only: set[int] = set()
    for error in errors:
        path = error.get("path") if isinstance(error, Mapping) else None
        if not isinstance(path, list) or len(path) < 5 or tuple(path[:4]) != _NODES_PATH:
            raise PrecheckFault("GraphQL returned an error")
        index = path[4]
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise PrecheckFault("GraphQL returned an error")
        # `committer` is nullable, so null propagation from inside it stops there (BACKLOG #5644
        # added item 1), on the same unmeasured premise as every partial error (module docstring).
        (committer_only if tuple(path[5:7]) == ("commit", "committer") else indexes).add(index)
    return indexes, committer_only


def _fetch_pages(
    transport: Transport,
    owner: str,
    name: str,
    number: int,
    expected_head: str,
    commits: list[Mapping[str, Any]],
    state: dict[str, Any],
) -> PullRequestRead:
    cursor: str | None = None
    seen_cursors: set[str] = set()
    head: str | None = None
    first_page: int | None = None
    while True:
        reply = transport(QUERY, {"owner": owner, "name": name, "number": number, "cursor": cursor})
        if head is None and expected_head:
            # Before the errors list, so a lagging first page is re-read whatever else it holds.
            first_head = _dig(reply, "data", "repository", "pullRequest", "headRefOid")
            if isinstance(first_head, str) and first_head != expected_head:
                raise _StaleHead("the pull request's head is not CLA_HEAD_SHA")
        errors = reply.get("errors")
        # A partial error: the data beside it still holds the commits no error points inside.
        errored, committer_errored = _errored_nodes(errors) if errors else (set(), set())
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
        if not isinstance(page_head, str):
            raise PrecheckFault("the GraphQL reply holds no pull request head")
        if head is not None and page_head != head:
            raise PrecheckFault("the pull request's head moved while its commits were being read")
        head = page_head
        if any(index >= len(nodes) for index in errored | committer_errored):
            raise PrecheckFault(
                "GraphQL returned an error for a commit node the page does not hold"
            )
        # A committer-only error on a node that came back with no commit object, or with no
        # readable oid (non-null, and outside the committer), contradicts the premise the carve-out
        # rests on, so that node is unjudged whole, as before the carve-out, and its siblings are
        # still judged.
        for index in list(committer_errored):
            node = nodes[index]
            commit = node.get("commit") if isinstance(node, Mapping) else None
            if not isinstance(commit, Mapping) or not _SHA.fullmatch(str(commit.get("oid", ""))):
                committer_errored.discard(index)
                errored.add(index)
        page: list[Mapping[str, Any]] = []
        for index, node in enumerate(nodes):
            commit = node.get("commit") if isinstance(node, Mapping) else None
            if index in errored:
                # GraphQL nulls what it could not resolve, up to the node itself: keep the slot,
                # unjudged, so the first page's length and the other commits stay as read.
                page.append(commit if isinstance(commit, Mapping) else {})
                continue
            if not isinstance(commit, Mapping):
                raise PrecheckFault("a commit node holds no commit object")
            page.append(commit)
        state["tainted"].update(len(commits) + index for index in errored)
        state["committer_tainted"].update(len(commits) + index for index in committer_errored)
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
    return _snapshot(commits, total, state)


def _dig(value: object, *keys: str) -> object:
    """``value[k1][k2]...``, or None where a step is missing or not an object."""
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


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
    """Refusals for one read, by the two rules in the module docstring. ``signatures`` returns the
    signed account ids; it is called only under rule 2, and with none every such author refuses.

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

    rule_one: list[str] = []
    rule_two: list[str] = []
    # An unjudged commit's oid may be the field GraphQL nulled: one that still reads as a commit
    # id counts as itself, and any other counts once by its slot.
    oids: set[str] = set()
    for index, commit in enumerate(read.commits):
        oid = str(commit.get("oid", ""))
        oids.add(f"slot {index}" if index in read.tainted and not _SHA.fullmatch(oid) else oid)
    distinct = len(oids)
    # A FAULT, not a refusal (owner rulings 2026-11-13 and 2026-11-23): GitHub stops the connection
    # at 250 commits while totalCount reports them all (measured; module docstring), so refusing
    # would fail every larger PR closed. The commits past the stop are not checked.
    if complete and distinct != read.total:
        faults.append(
            f"read {distinct} distinct commits where the pull request has {read.total}; the "
            "unread commits are not checked"
        )
    # One slot per commit, None for a malformed one, so the first-page slice below never shifts a
    # second-page commit among the first page's keys.
    slots: list[Attribution | None] = []
    for index, commit in enumerate(read.commits):
        oid = commit.get("oid", "")
        if index in read.tainted:
            # GraphQL could not resolve part of it, and a nulled user reads as an unlinked author.
            where = f"commit {oid}" if oid else f"the commit at position {index + 1}"
            faults.append(f"{where}: GraphQL reported an error inside it; not judged")
            slots.append(None)
            continue
        try:
            refusal = _rule_one(commit)
        except PrecheckFault as exc:
            faults.append(f"commit {oid}: {exc}")
            slots.append(None)
            continue
        if refusal is not None:
            # Judged before the key below, so a commit whose committer cannot be read is refused.
            rule_one.append(refusal)
            # Past the first page, rule 2 judges linked authors only, so no rule reads this
            # commit's key, and an unreadable committer here is not a fault. A null author, which
            # the schema allows, has no key anywhere: the action would throw on it.
            if index >= read.first_page or commit["author"] is None:
                slots.append(None)
                continue
        if index < read.first_page and index in read.committer_tainted:
            # Left unkeyed with a fault for a linked author too (PR 3323 hold). An unlinked
            # author's commit is keyed under its committer's account, which the error may have
            # hidden. A linked author's key, its login, is not hidden by it; the commit is left
            # unkeyed so rule 2 judges that author's later-page commits as it did before BACKLOG
            # #5644 added item 1, when such a commit was unjudged whole.
            faults.append(
                f"commit {oid}: GraphQL reported an error inside its committer; its key is "
                "missing from the first page's keys"
            )
            slots.append(None)
            continue
        try:
            slots.append(attribute(commit))
        except PrecheckFault as exc:
            # Only an unlinked author on the first page gets here, so its key, the committer's
            # account the action would file it under, is then missing from the first page's keys.
            faults.append(f"commit {oid}: {exc}; its key is missing from the first page's keys")
            slots.append(None)
    # The first page's keys this read could form, one per `login || name`. A linked
    # author is attributed to their own account, so only the key set matters for rule 2.
    first_slots = slots[: read.first_page]
    first_page_keys = {slot.name for slot in first_slots if slot is not None}
    # A first-page commit this read could not key (an error inside it, a malformed author or
    # committer) has an unknown key, and a null-author one, on which the action throws, has
    # none. A refusal below still holds, since an unsigned author owes a signature wherever the
    # action sees them, but its reason counts only the commits keyed. It names keys, not people:
    # an author may be a first-page committer, or carry another key there, and still be absent
    # under this key.
    keyed = sum(1 for slot in first_slots if slot is not None)
    if keyed == len(first_slots):
        where = "none of them carries"
    else:
        where = f"none of the {keyed} of them this read could key carries"
    unsigned = (
        "the CLA signature file holds no signature for that account"
        if signatures is not None
        else "no CLA signature file was given to check that account against"
    )
    checked: set[int] = set()  # linked accounts already judged under rule 2
    for who in (slot for slot in slots if slot is not None):
        if not who.author_linked:
            continue  # rule 1 judged it above
        if who.name in first_page_keys or who.database_id in checked:
            continue
        if who.database_id is None:
            # Linked, but with no integer id: the signature file cannot be checked for it, so
            # rule 2 cannot be judged, and skipping it in silence would read as a pass.
            faults.append(f"commit {who.oid}: its linked author has no integer databaseId")
            continue
        # Rule 2: a linked author first seen past the first page, unless the action would skip
        # them anyway.
        checked.add(who.database_id)
        skipped = who.database_id == ACTIONS_BOT_ID or matches_allowlist(who.name, allowlist)
        if not skipped and has_signed(who) is False:
            rule_two.append(
                f"commit {who.oid} is past the first {read.first_page} commits of this pull "
                f"request, {where} its author's key {who.name!r} (the login, or else the git name, "
                f"the action files a commit under), and {unsigned}"
            )
    # Interleaved, so the first annotations GitHub shows carry both rules' reasons, not one rule's.
    refusals = [
        r for pair in itertools.zip_longest(rule_one, rule_two) for r in pair if r is not None
    ]
    return Verdict(tuple(refusals), "; ".join(faults) or None)


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


def read_judged_head(
    transport: Transport,
    owner: str,
    name: str,
    number: int,
    expected_head: str,
    sleep: Callable[[float], None],
) -> tuple[PullRequestRead, bool, str | None]:
    """Read the pull request, re-reading while its first page shows another head.

    Returns the read, whether it is complete, and a fault to report beside its verdict, if any.
    With ``expected_head`` set, a first page of another head is read again after each wait in
    ``HEAD_RETRY_DELAYS``, and is a fault that judges nothing once the waits run out. A complete
    read of that head whose commits do not include it is judged, with a fault.
    """
    delays = iter(HEAD_RETRY_DELAYS)
    while True:
        try:
            read = fetch_commits(transport, owner, name, number, expected_head)
        except _StaleHead as exc:
            delay = next(delays, None)
            if delay is None:
                raise PrecheckFault(
                    f"{exc} after {len(HEAD_RETRY_DELAYS)} re-reads; this run is stale"
                ) from exc
            sleep(delay)
            continue
        except PrecheckFault as exc:
            # A page failed after whole pages were kept. Those pages still prove what they prove.
            if exc.partial is None:
                raise
            return exc.partial, False, str(exc)
        if expected_head and not any(c.get("oid") == expected_head for c in read.commits):
            # A commit whose id GraphQL nulled, or that came back in another form, may be the head.
            unreadable = sum(1 for c in read.commits if not _SHA.fullmatch(str(c.get("oid") or "")))
            if unreadable:
                return (
                    read,
                    True,
                    (
                        "the commit ids this read could resolve do not include CLA_HEAD_SHA, and "
                        f"{unreadable} commit(s) carry no 40-character lowercase id, so whether the "
                        "pull request's commits include it is unknown"
                    ),
                )
            # The read may have stopped short of the head, so this names what it returned.
            return read, True, "the commits this read returned do not include CLA_HEAD_SHA"
        return read, True, None


def run(
    env: Mapping[str, str],
    transport: Transport | None = None,
    signatures: Signatures | None = None,
    sleep: Callable[[float], None] | None = None,
) -> int:
    """Read the environment, check every commit, print annotations, and return the exit code.

    ``transport``, ``signatures`` and ``sleep`` replace the network and the clock for tests; they
    default to GitHub and ``time.sleep``, looked up at call time.
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
        read, complete, read_fault = read_judged_head(
            transport, owner, name, number, expected_head, sleep or time.sleep
        )
        verdict = evaluate(read, allowlist, signatures, complete=complete)
    except PrecheckFault as exc:
        print(f"::warning title=CLA pre-check fault::{_escape_command(str(exc))}")
        return EXIT_FAULT
    fault = "; ".join(f for f in (read_fault, verdict.fault) if f)
    if fault:
        print(f"::warning title=CLA pre-check fault::{_escape_command(fault)}")
    # GitHub keeps at most 10 error annotations per step. Up to 10 refusals are all annotated; past
    # that, 9 are, one annotation counts the rest, and they go to the log as plain lines.
    limit = len(verdict.refusals) if len(verdict.refusals) <= 10 else _ANNOTATED_REFUSALS
    shown = verdict.refusals[:limit]
    for refusal in shown:
        print(f"::error title=CLA pre-check refused::{_escape_command(refusal)}")
    rest = verdict.refusals[len(shown) :]
    if rest:
        print(
            f"::error title=CLA pre-check refused::{len(rest)} more refusal(s), printed below as "
            "plain log lines"
        )
        for refusal in rest:
            print(f"CLA pre-check refused: {_escape_command(refusal)}")
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
