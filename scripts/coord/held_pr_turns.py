#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whose move is each open pull request: the Lander's, its author's or its repair owner's.

All from GitHub state alone.

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

THE UNSAFE DIRECTION. Marking a PR AUTHOR's or REPAIR's turn when it is really the Lander's is the
failure this script exists to prevent. So AUTHOR needs a positive, machine-readable hold, REPAIR
needs that hold AND a positive, machine-readable repair-owner marker after it, and everything else,
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
* The SECOND line starts with the Lander's signature: ``Lander (session`` (the form this script
  first read), or a Lander seat id then a comma, ``Lander (lander-<id>), `` as in
  ``Lander (lander-1028), ``.
* The author's ``authorAssociation`` is OWNER, MEMBER or COLLABORATOR, and the comment is not
  minimized. This is not a seat check (every seat posts under one GitHub login, so classification
  keys on the body, never the login): it only stops an outside account on a public repository from
  posting a fake hold that would park a PR on its author.
* A DISMISSED review is never a hold.

Lines split on a line feed only. ``str.splitlines`` also breaks on a vertical tab, U+2028 and
others, which would let a body whose first line-feed line is not the marker read as a hold.

A LANDER EVENT is a marker hold, or a body starting with the Lander's signature (a non-hold Lander
comment), under the same association gate. Anything else is a non-Lander event. A prose hold
written before the marker existed (``**Held, ...**`` with no marker line) is therefore a non-hold
Lander comment, and its PR reads as LANDER's. That is intended, and in the safe direction: the
Lander looks again and re-posts the hold with a marker.

WHY THE SIGNATURE IS NARROW. A Manager addressing the Lander writes ``Lander (8a04c9f3): ...`` or
``Lander (x), please re-read``. A bare ``Lander (`` prefix would read either as the Lander's own: as
an unmarked comment it would show ``no-hold`` rather than ``replied``, hiding that the author
answered, and as the second line under a hold marker (an author mistaking the hold marker for the
ack marker) it would read as a hold and park the PR on its author, the unsafe direction. So the new
form counts only as ``lander-`` plus 1 to 40 of ``[0-9a-z-]``, then ``), ``. The ``Lander
(session`` form reads exactly as it did before seat ids, so an author writing it under a hold
marker still makes a hold, as it always did.

THE ACK CONTRACT. An author who has read a hold and is still working on it, with nothing pushed
yet, may say so without handing the turn back, ONLY by this shape::

    <!-- hold-ack head=<7 to 40 hex characters> -->
    Batch 453 Manager: hold received. The original Builder is fixing the named findings.

The first line is read exactly as the hold marker's is (a full match, only trailing spaces, tabs
and carriage returns stripped, and the same association, minimized and dismissed gates), and the
PR's ``headRefOid`` must start with its SHA, ignoring case. It must be an issue comment: a review
carries inline thread comments this script does not read, so a review is never an ack. A Lander
event is never an ack. Such an ack at or after the hold is not a reply, so the PR stays AUTHOR's,
flagged ``held`` and ``acked``. At least these still hand the turn back: a push (``new-commit``),
any other counted comment or review after the hold (``replied``), an ack naming another SHA or
posted as a review (a reply), and an edit to the ack or to anything else (``edited``). A
plain-prose acknowledgement, with no marker, is a reply and the Lander's turn. The ack line says
only "still my move"; anything the Lander must read or answer goes in a comment WITHOUT the
marker, which hands the turn back.

AUTHOR's turn only when ALL of these hold: the newest Lander event is a marker hold (a same-second
tie with a non-hold Lander event is no hold); the PR's ``headRefOid`` starts with the marker's SHA,
ignoring case; no non-Lander event other than an ack (THE ACK CONTRACT) is at or after the hold's
second (a tie is a reply, but a tied ack is not); and no comment or review, Lander or not and
the hold itself included, was edited at or after the hold's second. Otherwise LANDER's. THE REPAIR
CONTRACT says when a PR that meets these reads REPAIR's, or LANDER's ``repair-rehold``, instead.

THE REPAIR CONTRACT. When a held author does not answer, the Lander may hand the repair to a Repair
Manager session by posting, as an issue comment, ONLY this shape::

    <!-- repair-owner session=<session id> -->
    Lander (<session or seat id>), <date>. Repair owned by the Repair Manager from <time>; ...

THE MARKER SHAPE, the one every reader of a marker applies (this script reads it only through
``repair_owner`` and ``Event.repair_by``). A comment is a QUALIFYING MARKER only when ALL of these
hold, and the newest qualifying marker wins:

* the body splits on a line feed only, and its FIRST line, with only trailing spaces, tabs and
  carriage returns stripped and nothing stripped from its start, fully matches
  ``<!-- repair-owner session=<id> -->``, where ``<id>`` is 1 to 64 of ``[0-9A-Za-z_-]``, kept in
  its own case (the regular expression ``<!-- repair-owner session=([0-9A-Za-z_-]{1,64}) -->``);
* its SECOND line starts with the Lander's signature, matched from the line's start by the regular
  expression ``Lander \\((?:session|lander-[0-9a-z-]{1,40}\\), )`` (``_LANDER_SIGNATURE``): the
  text ``Lander (session`` with nothing required after it, not even a space, or
  ``Lander (lander-``, 1 to 40 of ``[0-9a-z-]``, then ``), `` (WHY THE SIGNATURE IS NARROW);
* its ``authorAssociation`` is OWNER, MEMBER or COLLABORATOR;
* it is an issue comment, never a review (as an ack is never a review), and not a bot's;
* it is NOT minimized.

A MINIMIZED MARKER IS A CANCELLED TRANSFER. A comment meeting every condition but the last is set
aside entirely: it is no transfer, no reply and no Lander event, so it never gives REPAIR and never
keeps a hold on the Lander (``repair-rehold``). The PR reads as if it had never been posted.
MINIMIZING THE NEWEST MARKER IS THE HAND-BACK TO THE ORIGINAL AUTHOR, but only once it leaves no
qualifying marker on the PR: a hold that stands then reads AUTHOR again. While an older marker is
still visible, that one is the newest qualifying marker and is read instead (REPAIR or
``repair-rehold`` naming its session), so a full hand-back minimizes every marker. Hiding a
superseded marker therefore can bring back the author's turn; that is intended, because a minimized
marker is the hand-back, so a marker the Lander means to keep as a transfer is left visible. An edit
to a minimized marker at or after the hold still hands the turn back, as any edit does.

The PR is REPAIR's turn, its row naming the marker's session as ``repairOwner``, ONLY when ALL of
these hold:

* every AUTHOR condition above holds, reading every qualifying marker as neither a reply nor a Lander
  event, so REPAIR is never reached from a state that fails an AUTHOR condition (a marker before
  the hold, which would make it ``repair-rehold``, does not stop a fresh one making it REPAIR's);
* at least one qualifying marker was posted strictly after the hold's second (a same-second marker
  is not provably after the hold, so it does not qualify);
* the qualifying markers in the newest marker second all name one session;
* no ack is at or after that newest marker's second. An ack after the transfer is most likely the
  stood-down author saying "still my move", so two seats may be working one fix: the Lander's to
  sort out. An ack before the marker is history the transfer overrode, and is kept as ``acked``.

Otherwise the PR is classified as it was before this contract, with every marker but a cancelled one
an ordinary event, except at least that a hold with a marker before it reads LANDER rather than
AUTHOR (below), and that a cut page does too (A CUT PAGE IS THE LANDER'S). Under that
reading a marker body starts with ``<!--``, not the signature, so it is not a Lander event, and one
after the hold is a reply: the PR reads LANDER ``replied``, even when the marker is the only thing
after the hold, so ``replied`` beside a marker can be the Lander's own transfer comment. So at least
these fall back to the Lander: a marker on a PR whose newest Lander event is not a marker hold
(``no-hold``: a marker is never a Lander event, so it cannot make one), a push after the marker
(``new-commit``: the head no longer starts with the hold's SHA, which is how "no commit after the
marker" is read, and is stricter, since it also catches a push between the hold and the marker), any
other reply or any edit after the hold, an edit to the marker itself, an ack after the marker, and a
newer non-hold Lander comment (``no-hold``).

A MARKER OLDER THAN THE LATEST HOLD DOES NOT MAKE A REPAIR TURN. Each hold re-opens the turn, so a
transfer that should outlive a new hold needs a new marker posted after it, in a later second, since
one comment cannot be both; that new marker makes the PR REPAIR's, naming its session. A HOLD WITH
ANY MARKER BEFORE IT AND NONE AFTER IT IS THE LANDER'S: when the hold would otherwise read AUTHOR,
and any marker was posted before the hold's second, the PR reads LANDER, flagged ``held`` and
``repair-rehold`` (and ``acked`` when an ack stands). No earlier hold is needed, and none is read:
one may have fallen out of the fetched page, been a prose hold, been dismissed, or shared the
marker's second. A marker means some author was told to stand down, so parking the PR on an author
is the unsafe direction, and the Lander's move is to post a fresh marker. ``repairOwner`` names the
session of the newest such marker, or is ``null`` when two sessions were named in that marker's
second. These are qualifying markers (THE MARKER SHAPE), so a minimized one is not read.

A CUT PAGE IS THE LANDER'S. Only the latest ``COMMENT_PAGE`` comments and ``REVIEW_PAGE`` reviews
are fetched, so a marker before the hold, or an old comment edited into a reply, may be off the
page.
When either connection's ``pageInfo.hasPreviousPage`` is true, or its ``pageInfo`` cannot say, a row
that would read AUTHOR reads LANDER instead, ``page-cut`` following its ``held`` (and ``acked``)
flags and preceding ``in-queue`` or ``auto-armed``. No other
row changes: REPAIR, and every LANDER row, read as they would on an uncut page.

A marker posted by a GitHub App or bot is not read, as no bot event is (WHAT COUNTS AS AN EVENT).

WHY A MARKER IS NOT A LANDER EVENT. It is Lander-signed, but it is not the Lander answering: read as
a Lander event it would become the newest one, which is no hold, and so erase the hold that the
REPAIR turn rests on. Read as a reply it would hand the turn back to the Lander, which is what the
marker means to prevent. So a qualifying marker is set aside while the hold is judged, and is then
the one thing that turns AUTHOR into REPAIR. A marker that fails any condition but the minimized one
is not set aside at all: it is an ordinary reply, so it hands the turn to the Lander. A minimized
one is a cancelled transfer, set aside entirely.
A Repair Manager pushing its fix moves the head, which hands the turn to the Lander to review, as
any author's push does.

WHAT COUNTS AS AN EVENT. Issue comments and submitted PR reviews. A review with an empty body is a
non-Lander event, because an inline-only review is how an author answers a finding in its thread;
the Lander's own inline-only review after its hold hands the turn back to it too, the safe
direction. Skipped entirely: a PENDING review (every seat shares one login, so each sees the
others' unsubmitted drafts, which the author cannot). A minimized comment still counts, but never
as a Lander event: hiding a reply must not bring back the hold before it. The one exception is a
minimized marker, a cancelled transfer (THE REPAIR CONTRACT). Skipped for the TURN,
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
read. Only the latest ``COMMENT_PAGE`` issue comments and ``REVIEW_PAGE`` reviews are fetched;
A CUT PAGE IS THE LANDER'S (THE REPAIR CONTRACT) says what a cut page does.

A HOLD ON A QUEUED OR ARMED PR IS THE LANDER'S. A PR in the merge queue, or with auto-merge armed,
merges without its author moving, so a hold on it reads LANDER with ``held`` kept beside the
``in-queue`` or ``auto-armed`` flag: dequeuing or disarming it is the Lander's move. A REPAIR turn
on such a PR reads LANDER the same way, keeping ``repair`` and ``repairOwner``.

SORTING. ERROR rows first, then LANDER, then REPAIR, then AUTHOR, each group oldest newest-event
first. REPAIR sits after LANDER because it is not the Lander's move. It sits before AUTHOR only as a
reading order: this script does not check that the repair owner's session is alive or working, so a
REPAIR row says only that a transfer stands. The table's FLAGS cell shows ``repair=<session id>``
for the ``repair`` flag, and ``repair-rehold=<session id>`` for ``repair-rehold`` when an owner is
named; the JSON carries the id as ``repairOwner``, ``null`` on any row with neither flag.

FLAGS. ``held`` (a hold stands: AUTHOR's turn, or REPAIR's beside ``repair``, unless the PR is
queued or armed, or LANDER's beside at least ``repair-rehold`` or ``page-cut``); ``repair``
(beside ``held``: a repair-owner marker after the hold made it REPAIR's turn, so ``held`` alone
never means the author owns a ``repair`` row); ``repair-rehold`` (beside ``held``: a hold with a
marker before it and none after it, so the Lander's move is to post one; THE REPAIR CONTRACT);
``no-hold`` (no Lander event, or the newest is not a marker hold); ``new-commit`` (the head does
not start with the marker's SHA); ``replied`` (a non-Lander event at or after the hold, other than an ack naming the
head); ``edited`` (a comment or review, of any author, the hold included,
edited at or after the hold); ``acked`` (beside ``held``: an author's ack naming the head stands
after the hold; alone, it kept the turn the author's; beside ``repair``, it came before the
transfer; beside ``repair-rehold``, it did not keep the turn, which is still the Lander's);
``no-new-commit`` (replied or edited, but the head still matches the marker: the Lander must read
the reply or edit, but can bounce it fast); ``page-cut`` (beside ``held``: the row would read
AUTHOR, but a comment or review page was cut, so it is the Lander's; THE REPAIR CONTRACT);
``in-queue`` / ``auto-armed`` (the PR is already in the merge queue or has auto-merge armed).

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

#: How every Lander comment begins: ``Lander (session <id>)``, or ``Lander (lander-<id>), ``. A
#: Manager's ``Lander (<id>): ...`` matches neither; WHY THE SIGNATURE IS NARROW says why. Bounded,
#: with no nested repeat, so it cannot backtrack catastrophically.
_LANDER_SIGNATURE = re.compile(r"Lander \((?:session|lander-[0-9a-z-]{1,40}\), )")
#: Associations whose comments may be Lander events: accounts with standing on the repository.
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
#: The hold marker, matched against the whole first line. Literal with one bounded repeat, so it
#: cannot backtrack catastrophically.
_HOLD_MARKER = re.compile(r"<!-- lander-hold head=([0-9a-fA-F]{7,40}) -->")
#: An author's hold acknowledgement, matched the same way as the hold marker.
_ACK_MARKER = re.compile(r"<!-- hold-ack head=([0-9a-fA-F]{7,40}) -->")
#: The Lander's repair-owner marker, matched the same way as the hold marker. The session id keeps
#: its case; one bounded repeat, so it cannot backtrack catastrophically.
_REPAIR_MARKER = re.compile(r"<!-- repair-owner session=([0-9A-Za-z_-]{1,64}) -->")
#: What may trail the marker on its line. Only these: a Unicode space is not stripped.
_TRAILING = " \t\r"

LANDER = "LANDER"
REPAIR = "REPAIR"
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
          pageInfo { hasPreviousPage }
          nodes {
            body createdAt lastEditedAt authorAssociation isMinimized
            author { __typename login }
          }
        }
        reviews(last: %REVIEW_PAGE%) {
          pageInfo { hasPreviousPage }
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


def _signed_marker(pattern: re.Pattern[str], body: str) -> re.Match[str] | None:
    """``pattern`` matched against the whole first line, when the second carries the signature."""
    lines = body.split("\n", 2)
    if len(lines) < 2 or not _LANDER_SIGNATURE.match(lines[1]):
        return None
    return pattern.fullmatch(lines[0].rstrip(_TRAILING))


def hold_head(body: str) -> str | None:
    """The SHA a marker hold names, lower-cased; ``None`` when ``body`` has no hold's shape.

    The shape only. The association, minimized and dismissed gates are ``Event``'s.
    """
    marker = _signed_marker(_HOLD_MARKER, body)
    return marker.group(1).lower() if marker else None


def ack_head(body: str) -> str | None:
    """The SHA an author's hold-ack names, lower-cased; ``None`` when ``body`` is not one.

    The shape only, as ``hold_head``. The gates are ``Event``'s.
    """
    return _first_line_sha(_ACK_MARKER, body.split("\n", 1)[0])


def repair_owner(body: str) -> str | None:
    """The session a Lander repair-owner marker names; ``None`` when ``body`` is not one.

    The shape only, as ``hold_head``: the marker's first line, then the Lander's signature on the
    second. The gates are ``Event``'s.
    """
    marker = _signed_marker(_REPAIR_MARKER, body)
    return marker.group(1) if marker else None


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
    #: A PR review, not an issue comment. A review is never an ack: its inline thread comments,
    #: which this script does not read, may hold the reply.
    review: bool = False
    #: A trusted association, minimized or not; ``None`` reads as ``trusted``. Only a cancelled
    #: transfer is read through it (``cancelled``).
    associated: bool | None = None

    @property
    def cancelled(self) -> bool:
        """A repair-owner marker comment in every way but that it is minimized: a cancelled
        transfer, set aside entirely (THE REPAIR CONTRACT). The shape is ``repair_owner``'s."""
        associated = self.trusted if self.associated is None else self.associated
        if self.trusted or not associated or self.dismissed or self.review:
            return False
        return repair_owner(self.body) is not None

    @property
    def latest(self) -> datetime:
        return max(self.when, self.edited) if self.edited else self.when

    @cached_property
    def _marker(self) -> str | None:
        return hold_head(self.body)

    @property
    def lander(self) -> bool:
        return self.trusted and (
            _LANDER_SIGNATURE.match(self.body) is not None or self._marker is not None
        )

    @property
    def held_at(self) -> str | None:
        """The marker's SHA when this event is a hold, else ``None``."""
        return None if not self.trusted or self.dismissed else self._marker

    @property
    def acked_at(self) -> str | None:
        """The ack's SHA when this event is an author's hold-ack comment, else ``None``."""
        if not self.trusted or self.dismissed or self.review:
            return None
        return ack_head(self.body)

    @cached_property
    def repair_by(self) -> str | None:
        """The session a repair-owner marker comment names, else ``None``. Never a review."""
        if not self.trusted or self.dismissed or self.review:
            return None
        return repair_owner(self.body)


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
                    review=kind == "reviews",
                    associated=node.get("authorAssociation") in TRUSTED_ASSOCIATIONS,
                )
            )
    return out


def page_cut(pr: dict[str, Any]) -> bool:
    """Whether the fetched ``comments`` or ``reviews`` page may have left older ones out.

    ``hasPreviousPage`` true, or a ``pageInfo`` that cannot say, both read as cut: a marker or a
    hold off the page must not leave a row reading AUTHOR. Call after ``_events`` has checked that
    both connections are objects.
    """
    for kind in ("comments", "reviews"):
        info = pr[kind].get("pageInfo")
        if not isinstance(info, dict) or info.get("hasPreviousPage") is not False:
            return True
    return False


def _earlier_transfer(turn_events: list[Event], hold: datetime) -> tuple[str | None] | None:
    """``(owner,)`` when any repair-owner marker came before ``hold``'s second, else ``None``.

    No earlier hold is required: one may have fallen off the fetched page, been a prose hold, or
    been dismissed. A minimized marker is a cancelled transfer and is not read. The owner is the
    session the newest such marker names, or ``None`` when two sessions were named in that second
    and so neither can be ordered.
    """
    markers = [e for e in turn_events if e.repair_by is not None and e.when < hold]
    if not markers:
        return None
    newest = max(e.when for e in markers)
    owners = {e.repair_by for e in markers if e.when == newest}
    return (owners.pop() if len(owners) == 1 else None,)


def _repair_turn(
    after: list[Event], acks: list[Event], hold: datetime
) -> tuple[str, list[str], str] | None:
    """The REPAIR row when THE REPAIR CONTRACT's marker conditions hold, else ``None``.

    The caller has already checked the head and the edits. A marker strictly after the hold is set
    aside as a reply only to ask whether the hold would otherwise stand.
    """
    repairs = [e for e in after if e.when > hold and e.repair_by is not None]
    # A marker's first line is never an ack's, so the two lists are disjoint and their lengths
    # add up to ``after``'s exactly when nothing else came after the hold.
    if not repairs or len(acks) + len(repairs) != len(after):
        return None
    newest = max(e.when for e in repairs)
    owners = {e.repair_by for e in repairs if e.when == newest}
    # Two sessions named in one second cannot be ordered, so neither owns the repair; an ack from
    # the transfer's second on may be the stood-down author still working.
    owner = owners.pop() if len(owners) == 1 else None
    if owner is None or any(e.latest >= newest for e in acks):
        return None
    return REPAIR, ["held", "acked", "repair"] if acks else ["held", "repair"], owner


def classify(head_oid: str, events: Iterable[Event]) -> tuple[str, list[str], str | None]:
    """``(turn, flags, repair owner)`` for one PR; the owner is ``None`` without a ``repair`` or
    ``repair-rehold`` flag, and may be ``None`` beside ``repair-rehold`` (``_earlier_transfer``).

    Pure; the module docstring states the rules. ``page-cut`` is ``_row``'s, not this one's.
    """
    turn_events = [e for e in events if not e.bot]
    landers = [e for e in turn_events if e.lander]
    if not landers:
        return LANDER, ["no-hold"], None
    # Every Lander event in the newest second is read together, so list order never decides.
    when = max(e.when for e in landers)
    tied = [e.held_at for e in landers if e.when == when]
    heads = [h for h in tied if h is not None]
    if len(heads) < len(tied):
        return LANDER, ["no-hold"], None
    head = head_oid.lower()
    new_commit = not all(head.startswith(h) for h in heads)
    # A cancelled (minimized) marker is set aside entirely: neither a reply nor a transfer.
    after = [e for e in turn_events if e.latest >= when and not e.lander and not e.cancelled]
    # An ack naming the head says "still my move", not a reply; any other event after it is one.
    acks = [e for e in after if (a := e.acked_at) is not None and head.startswith(a)]
    replied = len(acks) < len(after)
    # Every seat posts under one login, so who edited cannot be told: any edit from the hold's
    # second on, of the hold itself or of an older Lander comment too, hands the turn back.
    edited = any(e.edited is not None and e.edited >= when for e in turn_events)
    if not new_commit and not edited:
        repair = _repair_turn(after, acks, when)
        if repair is not None:
            return repair
        if not replied:
            flags = ["held", "acked"] if acks else ["held"]
            transferred = _earlier_transfer(turn_events, when)
            if transferred is not None:
                # A marker before this hold and none after it: an author was told to stand down,
                # so parking it on them is the unsafe direction. The Lander re-posts a marker.
                return LANDER, [*flags, "repair-rehold"], transferred[0]
            return AUTHOR, flags, None
    flags = ["new-commit"] if new_commit else []
    if replied:
        flags.append("replied")
    if edited:
        flags.append("edited")
    if not new_commit:
        flags.append("no-new-commit")
    return LANDER, flags, None


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
    turn, flags, owner = classify(head_oid, events)
    if turn == AUTHOR and page_cut(pr):
        # A marker before the hold, or a reply by editing an old comment, may be off the page.
        turn = LANDER
        flags.append("page-cut")
    if pr.get("mergeQueueEntry"):
        flags.append("in-queue")
    if pr.get("autoMergeRequest"):
        flags.append("auto-armed")
    if turn in (AUTHOR, REPAIR) and ("in-queue" in flags or "auto-armed" in flags):
        # Queued or armed, a held PR merges with no move from its author or its repair owner.
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
        "repairOwner": owner,
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
    """ERROR rows first (never missed), then LANDER, REPAIR, AUTHOR; oldest newest-event first."""
    order = {ERROR: 0, LANDER: 1, REPAIR: 2, AUTHOR: 3}

    def key(row: dict[str, Any]) -> tuple[int, int, str, int]:
        age = row.get("ageSeconds")
        return (
            order.get(row["turn"], 4),
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
    Each PR's ``comments`` and ``reviews`` need ``pageInfo.hasPreviousPage`` as ``QUERY`` fetches
    it: a reply captured without it reads as a cut page, so a row that would read AUTHOR reads
    LANDER ``page-cut``.
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
        "repairOwner": None,
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
        owner = row.get("repairOwner")
        flags = [
            f"{f}={owner}" if f in ("repair", "repair-rehold") and owner else f
            for f in row["flags"]
        ]
        table.append(
            (
                row["turn"],
                ",".join(flags),
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
        description=(
            "Whose move is each open, non-draft PR: the Lander's, its author's or its repair owner's."
        )
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
