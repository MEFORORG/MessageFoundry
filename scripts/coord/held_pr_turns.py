#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whose move is each open pull request: the Lander's or its author's, from GitHub state alone.

WHY THIS EXISTS. The Lander holds dozens of PRs across three repositories. Tracking holds from
memory failed after a context compaction: PRs kept reading as held with their authors hours after
the authors had replied, and green PRs sat unmerged. This report re-derives the answer every pass
from the PR's own comments, reviews and head, so nothing depends on what a session remembers.

READ-ONLY, AND EXIT 0 ON A FAILED READ. It is a report, not a gate. A repository whose read fails
prints as an ERROR row naming the reason; it is never omitted, and never printed as an empty list,
because "no PRs" and "could not read" must not look alike. A PR this script could not turn into a
row is one ERROR row for that PR, and its siblings still print: ``PR unreadable`` where the reply
itself is (an event with no time), and ``a report defect`` where this script failed on a shape it
did not foresee (a missing field, a crafted stamp whose offset overflows the date range), so a bug
here is never chased as a GitHub outage. A bad command line still exits 2, argparse's usage error.

THE UNSAFE DIRECTION. Marking a PR AUTHOR's turn when it is really the Lander's is the failure this
script exists to prevent. So AUTHOR needs a positive, machine-readable hold, and everything else,
including every case this script cannot read, is LANDER's.

WHY PYTHON, AND WHAT IT REUSES. ``pr_state.py`` beside it says why coord tooling reading GitHub is
Python. This script loads ``pr_state.py`` by path and reuses its gh runner, GraphQL wrapper,
``fetch_required`` (branch protection plus rulesets, parsed by ``scripts/ci/required_contexts.py``)
and ``required_verdict`` (per-context verdicts through ``scripts/ci/_pr_checks.py``), so there is no
second check-run classifier here to drift. It is fed less than ``pr_state`` feeds it: GitHub's
per-run ``isRequired`` needs a PR number argument, which a paginated PR list cannot pass, so here a
same-named run from an app the rule does not count is read as speaking for the context, and a
context GitHub requires but the list omits is not surfaced. GREEN is advisory: before arming a
merge the Lander still reads the live list, as CLAUDE.md section 5 requires. The vault's and
korus's lists are hard-coded below, by the commissioning brief's choice, so they too can lag the
server. A required context whose newest run concluded NEUTRAL or SKIPPED counts as green, as
``_pr_checks.PASSING`` and branch protection both read it. A required context with no result on the
head yet is NOT green.

ONE GRAPHQL QUERY PER REPOSITORY, paginated. Never one ``gh pr view`` per PR. The page is
``PR_PAGE`` PRs, below GitHub's 100, because each PR carries its head's contexts, comments and
reviews, and ``pr_state.py`` records a full-rollup query over 67 PRs failing with 502/504. The
engine's required list costs two REST calls more, through ``fetch_required``.

THE HOLD CONTRACT. A hold is recognised ONLY by this shape, which the Lander writes::

    <!-- lander-hold head=<7 to 40 hex characters> -->
    Lander (<session or seat id>), <date>. **Held, ...**

* The body's FIRST line, with only trailing spaces, tabs and carriage returns stripped and nothing
  stripped from its start, fully matches the marker. Nothing can precede the first line, so no
  blockquote, fence or code span can wrap it: a quoted or shown marker is never line 1. That is why
  the marker goes first, and why no Markdown is parsed here.
* The SECOND line starts with ``Lander (``. The Lander signs ``Lander (session <id>)`` or
  ``Lander (<seat id>)``, as in ``Lander (lander-1028)``; both are its signature.
* The author's ``authorAssociation`` is OWNER, MEMBER or COLLABORATOR, and the comment is not
  minimized. This is not a seat check (every seat posts under one GitHub login, so classification
  keys on the body, never the login): it only stops an outside account on a public repository from
  posting a fake hold that would park a PR on its author.
* A DISMISSED review is never a hold.

Lines split on a line feed only. ``str.splitlines`` also breaks on a vertical tab, U+2028 and
others, which would let a body whose first line-feed line is not the marker read as a hold.

A LANDER EVENT is a marker hold, or a body starting with ``Lander (`` (a non-hold Lander
comment), under the same association gate. Anything else is a non-Lander event. A prose hold
written before the marker existed (``**Held, ...**`` with no marker line) is therefore a non-hold
Lander comment, and its PR reads as LANDER's. That is intended, and in the safe direction: the
Lander looks again and re-posts the hold with a marker.

WHY ``Lander (`` IS WIDE ENOUGH AND NO WIDER. An author's comment can start with it too: a Manager
addressing the Lander writes ``Lander (8a04c9f3): ...``. Read as a Lander event, such a reply at or
after the hold is a non-hold Lander event, so it is the newest Lander event (or ties with the hold)
and the PR reads ``no-hold``, LANDER's; an older one edited after the hold is caught as
``edited``. So the widening can only move a PR toward LANDER. Only the marker moves one toward
AUTHOR, and a body that merely starts with ``Lander (`` carries no marker.

THE ACK CONTRACT. An author who has read a hold and is still working on it, with nothing pushed
yet, may say so without handing the turn back, ONLY by this shape::

    <!-- hold-ack head=<7 to 40 hex characters> -->
    Batch 453 Manager: hold received. The original Builder is fixing the named findings.

The first line is read exactly as the hold marker's is (a full match, only trailing spaces, tabs
and carriage returns stripped, and the same association, minimized and dismissed gates), and the
PR's ``headRefOid`` must start with its SHA, ignoring case. A Lander event is never an ack. Such an
ack at or after the hold is not a reply, so the PR stays AUTHOR's, flagged ``held`` and
``acked``. Everything else still hands the turn back: a push (``new-commit``), any other comment
or review after the hold (``replied``), an ack naming another SHA (a reply), and an edit to the
ack or to anything else (``edited``). A plain-prose acknowledgement, with no marker, is a reply
and the Lander's turn. The ack line says only "still my move"; anything the Lander must read or
answer goes in a comment WITHOUT the marker, which hands the turn back.

AUTHOR's turn only when ALL of these hold: the newest Lander event is a marker hold (a same-second
tie with a non-hold Lander event is no hold); the PR's ``headRefOid`` starts with the marker's SHA,
ignoring case; no non-Lander event other than an ack (THE ACK CONTRACT) is at or after the hold's
second (a tie is a reply); and no comment or review, Lander or not and the hold itself included,
was edited at or after the hold's second. Otherwise LANDER's.

WHAT COUNTS AS AN EVENT. Issue comments and submitted PR reviews. A review with an empty body is a
non-Lander event, because an inline-only review is how an author answers a finding in its thread;
the Lander's own inline-only review after its hold hands the turn back to it too, the safe
direction. Skipped entirely: a PENDING review (every seat shares one login, so each sees the
others' unsubmitted drafts, which the author cannot). A minimized comment still counts, but never
as a Lander event: hiding a reply must not bring back the hold before it. Skipped for the TURN,
though still counted toward the newest-event age: anything authored by a GitHub App or bot
(GraphQL ``author.__typename == "Bot"``), such as the auto-approve review a push triggers; the push
itself is caught as a new head. A non-Lander event dates from its latest edit
(``lastEditedAt``), so editing an older comment to answer a hold is a reply. An edit to a Lander
event at or after the hold, the hold's own included, also hands the turn back: every seat posts
under one login, so an edit cannot be told apart from an author answering in place. An event with no
readable time, or a node that is not an object, is an ERROR row, never dropped, since dropping a
reply could park the PR on its author. So is a stamp that is present but unreadable, rather than
a fall back to the next stamp, and a ``comments`` or ``reviews`` connection that is null, not an
object, or has no ``nodes`` list: it is never read as zero events. A PR whose ``isDraft`` is not a
bool is an ERROR row too, never skipped as a draft. Inline review-thread comment bodies are not
read. Only the latest ``COMMENT_PAGE`` issue comments and ``REVIEW_PAGE`` reviews are fetched.

A HOLD ON A QUEUED OR ARMED PR IS THE LANDER'S. A PR in the merge queue, or with auto-merge armed,
merges without its author moving, so a hold on it reads LANDER with ``held`` kept beside the
``in-queue`` or ``auto-armed`` flag: dequeuing or disarming it is the Lander's move.

FLAGS. ``held`` (a hold stands: AUTHOR's turn, unless the PR is queued or armed); ``no-hold`` (no Lander event, or the newest is not a marker
hold); ``new-commit`` (the head does not start with the marker's SHA); ``replied`` (a non-Lander
event at or after the hold); ``edited`` (a comment or review, of any author, the hold included,
edited at or after the hold); ``acked`` (beside ``held``: an author's ack kept the turn the
author's); ``no-new-commit`` (replied or edited, but the head still matches the marker: the Lander
must read the reply or edit, but can bounce it fast); ``in-queue`` / ``auto-armed`` (the PR is
already in the merge queue or has auto-merge armed).

Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path
from types import ModuleType
from typing import Any

ENGINE_REPO = "MEFORORG/MessageFoundry"
VAULT_REPO = "MEFORORG/MessageFoundry-vault"
KORUS_REPO = "MEFORORG/korus"
REPOS = (ENGINE_REPO, VAULT_REPO, KORUS_REPO)

#: The vault's required contexts on main. Hard-coded from the Lander brief that commissioned this
#: script (2026-10-28), which read them from the vault's branch protection. The engine's list is
#: read live instead, because it moves often; these two have not.
VAULT_REQUIRED = ("ledger structure", "publish leak gate", "register cell lists match the record")
#: korus's required contexts on main, from the same brief.
KORUS_REQUIRED = ("gates (ubuntu-latest)", "gates (windows-latest)")
STATIC_REQUIRED: dict[str, tuple[str, ...]] = {
    VAULT_REPO: VAULT_REQUIRED,
    KORUS_REPO: KORUS_REQUIRED,
}

PR_PAGE = 25
MAX_PAGES = 40
CONTEXT_PAGE = 100
COMMENT_PAGE = 100
REVIEW_PAGE = 50
TITLE_WIDTH = 50

#: How every Lander comment begins: ``Lander (session <id>)`` or ``Lander (<seat id>)``. The module
#: docstring says why an author's text starting with it cannot move a PR toward AUTHOR.
LANDER_PREFIX = "Lander ("
#: Associations whose comments may be Lander events: accounts with standing on the repository.
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
#: The hold marker, matched against the whole first line. Literal with one bounded repeat, so it
#: cannot backtrack catastrophically.
_HOLD_MARKER = re.compile(r"<!-- lander-hold head=([0-9a-fA-F]{7,40}) -->")
#: An author's hold acknowledgement, matched the same way as the hold marker.
_ACK_MARKER = re.compile(r"<!-- hold-ack head=([0-9a-fA-F]{7,40}) -->")
#: What may trail the marker on its line. Only these: a Unicode space is not stripped.
_TRAILING = " \t\r"

LANDER = "LANDER"
AUTHOR = "AUTHOR"
ERROR = "ERROR"

QUERY = (
    """
query($owner: String!, $name: String!, $cursor: String) {
  rateLimit { cost remaining resetAt limit }
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: %PR_PAGE%, after: $cursor,
                 orderBy: {field: CREATED_AT, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title isDraft baseRefName headRefOid mergeable mergeStateStatus
        mergeQueueEntry { state } autoMergeRequest { enabledAt }
        commits(last: 1) { nodes { commit { oid committedDate statusCheckRollup {
          contexts(first: %CONTEXT_PAGE%) {
            pageInfo { hasNextPage }
            nodes {
              __typename
              ... on CheckRun { name status conclusion startedAt }
              ... on StatusContext { context state createdAt }
            }
          }
        } } } }
        comments(last: %COMMENT_PAGE%) {
          nodes {
            body createdAt lastEditedAt authorAssociation isMinimized
            author { __typename login }
          }
        }
        reviews(last: %REVIEW_PAGE%) {
          nodes {
            body state createdAt submittedAt lastEditedAt authorAssociation isMinimized
            author { __typename login }
          }
        }
      }
    }
  }
}
""".replace("%PR_PAGE%", str(PR_PAGE))
    .replace("%CONTEXT_PAGE%", str(CONTEXT_PAGE))
    .replace("%COMMENT_PAGE%", str(COMMENT_PAGE))
    .replace("%REVIEW_PAGE%", str(REVIEW_PAGE))
)

_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


pr_state = _load("_held_pr_turns_pr_state", _HERE / "pr_state.py")

#: ``gh(args, stdin) -> stdout``, pr_state's Gh restated: a by-path module is Any to mypy.
Gh = Callable[[list[str], str | None], str]


class ReadError(RuntimeError):
    """A repository's reply, or its ``--input`` entry, could not be read as a PR list."""


#: What building a row can raise on a reply this script did not foresee: a report defect, not a
#: read failure. A crafted stamp raises OverflowError, an ArithmeticError, when its offset pushes
#: it past year 1 or 9999.
_ROW_ERRORS = (TypeError, LookupError, AttributeError, ValueError, ArithmeticError)
#: What reading one repository can raise; each becomes that repository's "read failed" row.
_READ_ERRORS = (pr_state.PollError, pr_state.GhError, OSError, ReadError)


@dataclass
class RepoRead:
    prs: list[dict[str, Any]] = field(default_factory=list)
    required: list[str] | None = None
    required_error: str | None = None


def _first_line_sha(pattern: re.Pattern[str], first_line: str) -> str | None:
    """The SHA ``pattern`` captures from the whole of ``first_line``, lower-cased, else ``None``."""
    marker = pattern.fullmatch(first_line.rstrip(_TRAILING))
    return marker.group(1).lower() if marker else None


def hold_head(body: str) -> str | None:
    """The SHA a marker hold names, lower-cased; ``None`` when ``body`` has no hold's shape.

    The shape only. The association, minimized and dismissed gates are ``Event``'s.
    """
    lines = body.split("\n", 2)
    if len(lines) < 2 or not lines[1].startswith(LANDER_PREFIX):
        return None
    return _first_line_sha(_HOLD_MARKER, lines[0])


def ack_head(body: str) -> str | None:
    """The SHA an author's hold-ack names, lower-cased; ``None`` when ``body`` is not one.

    The shape only, as ``hold_head``. The gates are ``Event``'s.
    """
    return _first_line_sha(_ACK_MARKER, body.split("\n", 1)[0])


@dataclass(frozen=True)
class Event:
    when: datetime
    body: str
    bot: bool
    #: Trusted association and not minimized: allowed to be a Lander event at all.
    trusted: bool
    dismissed: bool = False
    #: ``lastEditedAt``: an edit is a reply too, so a non-Lander event dates from its latest edit,
    #: and any edit at or after the hold, a Lander event's included, hands the turn back.
    edited: datetime | None = None

    @property
    def latest(self) -> datetime:
        return max(self.when, self.edited) if self.edited else self.when

    @cached_property
    def _marker(self) -> str | None:
        return hold_head(self.body)

    @property
    def lander(self) -> bool:
        return self.trusted and (self.body.startswith(LANDER_PREFIX) or self._marker is not None)

    @property
    def held_at(self) -> str | None:
        """The marker's SHA when this event is a hold, else ``None``."""
        return None if not self.trusted or self.dismissed else self._marker

    @property
    def acked_at(self) -> str | None:
        """The ack's SHA when this event is an author's hold-ack, else ``None``."""
        return None if not self.trusted or self.dismissed else ack_head(self.body)


_nodes = pr_state._nodes


def _events(pr: dict[str, Any]) -> list[Event]:
    out: list[Event] = []
    for kind, stamp_keys in (
        ("comments", ("createdAt",)),
        ("reviews", ("submittedAt", "createdAt")),
    ):
        conn = pr.get(kind)
        if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
            # Reading it as no events could hide a reply and park the PR on its author.
            raise ReadError(f"the {kind} connection is missing or has no nodes list")
        for node in conn["nodes"]:
            if not isinstance(node, dict):
                # Skipping it could drop a reply after the hold and park the PR on its author.
                raise ReadError(f"a {kind[:-1]} node is not an object")
            if node.get("state") == "PENDING":
                continue
            when = None
            for key in stamp_keys:
                if node.get(key) is None:
                    continue
                when = pr_state.parse_iso(node.get(key))
                if when is None:
                    # Falling back to an older stamp could date a reply before the hold.
                    raise ReadError(f"a {kind[:-1]} has an unreadable {key}")
                break
            if when is None:
                # Dropping it could hide a reply after the hold and park the PR on its author.
                raise ReadError(f"a {kind[:-1]} has no readable timestamp")
            edited = pr_state.parse_iso(node.get("lastEditedAt"))
            if edited is None and node.get("lastEditedAt") is not None:
                # An unreadable edit time could hide a reply-by-edit, so it is no silent None.
                raise ReadError(f"a {kind[:-1]} has an unreadable lastEditedAt")
            author = node.get("author")
            out.append(
                Event(
                    when,
                    str(node.get("body") or ""),
                    bot=isinstance(author, dict) and author.get("__typename") == "Bot",
                    trusted=not node.get("isMinimized")
                    and node.get("authorAssociation") in TRUSTED_ASSOCIATIONS,
                    dismissed=node.get("state") == "DISMISSED",
                    edited=edited,
                )
            )
    return out


def classify(head_oid: str, events: Iterable[Event]) -> tuple[str, list[str]]:
    """``(turn, flags)`` for one PR. Pure; the module docstring states the rules."""
    turn_events = [e for e in events if not e.bot]
    landers = [e for e in turn_events if e.lander]
    if not landers:
        return LANDER, ["no-hold"]
    # Every Lander event in the newest second is read together, so list order never decides.
    when = max(e.when for e in landers)
    tied = [e.held_at for e in landers if e.when == when]
    heads = [h for h in tied if h is not None]
    if len(heads) < len(tied):
        return LANDER, ["no-hold"]
    head = head_oid.lower()
    new_commit = not all(head.startswith(h) for h in heads)
    after = [e for e in turn_events if e.latest >= when and not e.lander]
    # An ack naming the head says "still my move", not a reply; any other event after it is one.
    acks = [e for e in after if (a := e.acked_at) is not None and head.startswith(a)]
    replied = len(acks) < len(after)
    # Every seat posts under one login, so who edited cannot be told: any edit from the hold's
    # second on, of the hold itself or of an older Lander comment too, hands the turn back.
    edited = any(e.edited is not None and e.edited >= when for e in turn_events)
    if not new_commit and not replied and not edited:
        return AUTHOR, ["held", "acked"] if acks else ["held"]
    flags = ["new-commit"] if new_commit else []
    if replied:
        flags.append("replied")
    if edited:
        flags.append("edited")
    if not new_commit:
        flags.append("no-new-commit")
    return LANDER, flags


def age_text(seconds: float) -> str:
    """``3h12m``, ``2d05h`` or ``45m``. A negative age (clock skew) reads as ``0m``."""
    minutes = max(int(seconds // 60), 0)
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        return f"{days}d{hours:02d}h"
    if hours:
        return f"{hours}h{mins:02d}m"
    return f"{mins}m"


def _required_green(
    pr: dict[str, Any], head: dict[str, Any], read: RepoRead
) -> tuple[str, dict[str, Any]]:
    """``("yes" | "no" | "?", verdict)``. pr_state.required_verdict does the judging."""
    head_oid = str(pr.get("headRefOid") or "")
    contexts: dict[str, Any] | None = None
    if head.get("oid") == head_oid:
        rollup = head.get("statusCheckRollup")
        conn = rollup.get("contexts") if isinstance(rollup, dict) else None
        page = conn.get("pageInfo") if isinstance(conn, dict) else None
        contexts = {
            "nodes": _nodes(conn),
            "hasNextPage": bool(isinstance(page, dict) and page.get("hasNextPage")),
        }
    verdict: dict[str, Any] = pr_state.required_verdict(
        read.required, contexts, head_oid, base=pr.get("baseRefName")
    )
    if read.required_error and verdict.get("reason") == "no required-context list":
        verdict["reason"] = read.required_error
    elif (
        head.get("oid")
        and contexts is None
        and str(verdict.get("reason")).startswith("required-context query returned nothing")
    ):
        verdict["reason"] = "the commit listed is not the head (a push during the read?); re-run"
    state = verdict.get("state")
    return (
        "yes" if state == "SUCCESS" else "no" if state in ("FAILURE", "PENDING") else "?"
    ), verdict


def _row(repo: str, pr: dict[str, Any], read: RepoRead, now: datetime) -> dict[str, Any]:
    head = pr_state._head_commit(pr)
    head_oid = str(pr.get("headRefOid") or "")
    # commits(last: 1) only dates the age column, and only when it is the head; the turn reads
    # headRefOid alone.
    on_head = head.get("oid") == head_oid
    committed = pr_state.parse_iso(head.get("committedDate")) if on_head else None
    events = _events(pr)
    turn, flags = classify(head_oid, events)
    if pr.get("mergeQueueEntry"):
        flags.append("in-queue")
    if pr.get("autoMergeRequest"):
        flags.append("auto-armed")
    if turn == AUTHOR and ("in-queue" in flags or "auto-armed" in flags):
        # Queued or armed, a held PR merges with no move from its author.
        turn = LANDER
    green, verdict = _required_green(pr, head, read)
    stamps = [e.latest for e in events] + ([committed] if committed else [])
    newest = max(stamps) if stamps else None
    age = int((now - newest).total_seconds()) if newest else None
    return {
        "repo": repo,
        "number": pr.get("number"),
        "title": str(pr.get("title") or ""),
        "head": head_oid[:9],
        "mergeable": pr.get("mergeable"),
        "mergeStateStatus": pr.get("mergeStateStatus"),
        "requiredGreen": green,
        "required": {
            k: verdict.get(k)
            for k in ("state", "failing", "pending", "missing", "unknown", "reason")
        },
        "turn": turn,
        "flags": flags,
        "newestEvent": pr_state.iso(newest) if newest else None,
        "age": age_text(age) if age is not None else "?",
        "ageSeconds": age,
    }


def build_rows(repo: str, read: RepoRead, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pr in read.prs:
        if not isinstance(pr, dict):
            rows.append(error_row(repo, f"a PR node is not an object: {type(pr).__name__}"))
            continue
        try:
            draft = pr.get("isDraft")
            if draft is True:
                continue
            if draft is not False:
                # Skipping it as a draft would drop the PR from the report unseen.
                raise ReadError(f"isDraft is not a bool: {draft!r}"[:100])
            rows.append(_row(repo, pr, read, now))
        # One bad PR is one ERROR row; its siblings still print.
        except ReadError as exc:
            rows.append(error_row(repo, f"PR unreadable: {exc}"[:300], pr.get("number")))
        except _ROW_ERRORS as exc:
            rows.append(error_row(repo, _defect(exc), pr.get("number")))
    return rows


def sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ERROR rows first (never missed), then LANDER, then AUTHOR; oldest newest-event first."""
    order = {ERROR: 0, LANDER: 1, AUTHOR: 2}

    def key(row: dict[str, Any]) -> tuple[int, int, str, int]:
        age = row.get("ageSeconds")
        return (
            order.get(row["turn"], 3),
            # An undatable PR may be the stalest, so it sorts first in its group, not last.
            -(age if isinstance(age, int) else sys.maxsize),
            row["repo"],
            number if isinstance(number := row.get("number"), int) else 0,
        )

    return sorted(rows, key=key)


def fetch_live(gh: Gh, repo: str) -> RepoRead:
    owner, name = repo.split("/", 1)
    read = RepoRead()
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        repository, _rate = pr_state.graphql(
            gh, QUERY, {"owner": owner, "name": name, "cursor": cursor}, part="pulls"
        )
        cursor = _take_page(read, repository.get("pullRequests"))
        if cursor is None:
            break
    else:
        raise ReadError(f"more than {MAX_PAGES * PR_PAGE} open PRs; refusing a partial list")
    _set_required(read, repo, lambda: list(pr_state.fetch_required(gh, repo)))
    return read


def _take_page(read: RepoRead, conn: object) -> str | None:
    """Add one page's PRs to ``read``; the next page's cursor, or ``None`` on the last page.

    A page that cannot say whether more follow is a ReadError: a partial list must not print as
    the whole one.
    """
    if not (
        isinstance(conn, dict)
        and isinstance(page := conn.get("pageInfo"), dict)
        and isinstance(conn.get("nodes"), list)
    ):
        raise ReadError("a page has no pullRequests connection with pageInfo and nodes")
    has_next = page.get("hasNextPage")
    if not isinstance(has_next, bool):
        # A missing or non-bool flag is no proof that this is the last page.
        raise ReadError(f"pageInfo.hasNextPage is not a bool: {has_next!r}"[:200])
    read.prs.extend(conn["nodes"])
    if not has_next:
        return None
    cursor = page.get("endCursor")
    if not cursor:
        raise ReadError("hasNextPage with no endCursor")
    return str(cursor)


def _set_required(read: RepoRead, repo: str, live: Callable[[], list[str]]) -> None:
    if repo in STATIC_REQUIRED:
        read.required = list(STATIC_REQUIRED[repo])
        return
    try:
        read.required = live()
    except _READ_ERRORS as exc:
        # The turns are still worth printing; only the green column goes to "?".
        read.required_error = f"required list unreadable: {exc}"


def from_input(doc: object, repo: str) -> RepoRead:
    """One repository's canned reply from ``--input``.

    Shape: ``{"<owner/name>": {"pages": [<gh api graphql reply>, ...], "required": [...]}}``, or
    ``{"<owner/name>": {"error": "<reason>"}}`` to stand for a failed read. ``required`` is read
    only for a repository with no hard-coded list; leaving it out reads as an unreadable list.
    """
    if not isinstance(doc, dict) or repo not in doc:
        raise ReadError(f"{repo} is not in the input file")
    entry = doc[repo]
    if not isinstance(entry, dict):
        raise ReadError(f"the input entry for {repo} is not an object")
    if entry.get("error"):
        raise ReadError(str(entry["error"]))
    pages = entry.get("pages")
    if not isinstance(pages, list) or not pages:
        # A live read always has at least one page, so none is no read, not zero PRs.
        raise ReadError(f"the input entry for {repo} has no pages")
    read = RepoRead()
    cursor: str | None = None
    for page in pages:
        try:
            conn = page["data"]["repository"]["pullRequests"]
        except (KeyError, TypeError) as exc:
            raise ReadError(f"an input page has no data.repository.pullRequests: {exc!r}") from exc
        cursor = _take_page(read, conn)
    if cursor is not None:
        raise ReadError("the last input page says more pages follow; refusing a partial list")

    def canned() -> list[str]:
        required = entry.get("required")
        if not isinstance(required, list):
            raise ReadError("no required list in the input file")
        return [str(c) for c in required]

    _set_required(read, repo, canned)
    return read


def error_row(repo: str, reason: str, number: object = None) -> dict[str, Any]:
    return {
        "repo": repo,
        "number": number,
        "turn": ERROR,
        "error": reason,
        "flags": [],
        "ageSeconds": None,
    }


def _defect(exc: Exception) -> str:
    # Not a GitHub failure: say so, so a defect here is not chased as an outage.
    return f"rows not built, a report defect: {type(exc).__name__}: {exc}"[:300]


def render(rows: list[dict[str, Any]]) -> str:
    header = ("TURN", "FLAGS", "REPO", "PR", "GREEN", "MERGEABLE", "STATE", "HEAD", "AGE", "TITLE")
    table: list[tuple[str, ...]] = [header]
    for row in rows:
        short = row["repo"].split("/", 1)[-1]
        if row["turn"] == ERROR:
            number = row.get("number")
            pr = "" if number is None else str(number)
            table.append((ERROR, "", short, pr, "", "", "", "", "", row["error"]))
            continue
        title = row["title"]
        if len(title) > TITLE_WIDTH:
            title = title[: TITLE_WIDTH - 3] + "..."
        table.append(
            (
                row["turn"],
                ",".join(row["flags"]),
                short,
                str(row["number"]),
                row["requiredGreen"],
                str(row["mergeable"]),
                str(row["mergeStateStatus"]),
                row["head"],
                row["age"],
                title,
            )
        )
    widths = [max(len(r[i]) for r in table) for i in range(len(header) - 1)]
    lines = [
        "  ".join([*(cell.ljust(w) for cell, w in zip(r[:-1], widths, strict=True)), r[-1]])
        for r in table
    ]
    # A "?" carries its reason only in the JSON; name each distinct one here, so the table does
    # not hide why a column could not be read.
    unknown: dict[tuple[str, str], int] = {}
    for row in rows:
        if row["turn"] != ERROR and row["requiredGreen"] == "?":
            why = (row["repo"].split("/", 1)[-1], str(row["required"].get("reason")))
            unknown[why] = unknown.get(why, 0) + 1
    lines += [f"note: {repo} GREEN ? on {n} PR(s): {why}" for (repo, why), n in unknown.items()]
    # Titles and error text come from GitHub, and anyone can title a PR on a public repository:
    # a control or bidi character must not rewrite or forge a row on the Lander's terminal. One
    # character for one keeps the columns aligned.
    return "\n".join(
        "".join(c if c.isprintable() else "?" for c in line).rstrip() for line in lines
    )


def collect(
    repos: Iterable[str], reader: Callable[[str], RepoRead], now: datetime
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for repo in repos:
        try:
            rows.extend(build_rows(repo, reader(repo), now))
        except _READ_ERRORS as exc:
            rows.append(error_row(repo, f"read failed: {type(exc).__name__}: {exc}"[:300]))
        # build_rows contains each PR's own defect; this catches one in the reader or the list.
        except _ROW_ERRORS as exc:
            rows.append(error_row(repo, _defect(exc)))
    return sort_rows(rows)


def main(
    argv: list[str] | None = None,
    *,
    gh: Gh = pr_state.run_gh,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    ap = argparse.ArgumentParser(
        description="Whose move is each open, non-draft PR: the Lander's or its author's."
    )
    ap.add_argument("--repo", choices=REPOS, help="restrict to one repository")
    ap.add_argument("--json", action="store_true", help="emit a JSON list of objects")
    ap.add_argument("--input", type=Path, help="canned GraphQL replies per repo (offline, tests)")
    args = ap.parse_args(argv)
    repos = [args.repo] if args.repo else list(REPOS)

    doc: object = None
    unreadable: str | None = None
    if args.input is not None:
        try:
            # utf-8-sig: Windows PowerShell 5's Out-File writes a BOM.
            doc = json.loads(args.input.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            unreadable = f"input file unreadable: {exc}"

    def reader(repo: str) -> RepoRead:
        if unreadable:
            raise ReadError(unreadable)
        return from_input(doc, repo) if args.input is not None else fetch_live(gh, repo)

    rows = collect(repos, reader, now())
    if hasattr(sys.stdout, "reconfigure"):
        # A PR title can carry characters a cp1252 console cannot encode; a report must not crash.
        sys.stdout.reconfigure(errors="replace")
    print(json.dumps(rows, indent=2) if args.json else render(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
