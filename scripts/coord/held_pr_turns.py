#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whose move is each open pull request: the Lander's or its author's, from GitHub state alone.

WHY THIS EXISTS. The Lander holds dozens of PRs across three repositories. Tracking holds from
memory failed after a context compaction: PRs kept reading as held with their authors hours after
the authors had replied, and green PRs sat unmerged. This report re-derives the answer every pass
from the PR's own comments and commits, so nothing depends on what a session remembers.

READ-ONLY, AND EXIT 0 ALWAYS. It is a report, not a gate. A repository whose read fails prints as
an ERROR row naming the reason; it is never omitted, and never printed as an empty list, because
"no PRs" and "could not read" must not look alike.

WHY PYTHON, AND WHAT IT REUSES. ``pr_state.py`` beside it says why coord tooling reading GitHub is
Python. This script loads ``pr_state.py`` by path and reuses its gh runner, GraphQL wrapper,
``fetch_required`` (branch protection plus rulesets, parsed by ``scripts/ci/required_contexts.py``)
and ``required_verdict`` (per-context verdicts through ``scripts/ci/_pr_checks.py``), so there is no
second check-run classifier here to drift. One consequence: a required context whose newest run
concluded NEUTRAL or SKIPPED counts as green, as ``_pr_checks.PASSING`` and branch protection both
read it. A required context with no result on the head yet is NOT green.

ONE GRAPHQL QUERY PER REPOSITORY, paginated. Never one ``gh pr view`` per PR. The page is
``PR_PAGE`` PRs, below GitHub's 100, because each PR carries its head's contexts, comments and
reviews, and ``pr_state.py`` records a full-rollup query over 67 PRs failing with 502/504. The
engine's required list costs two REST calls more, through ``fetch_required``.

CLASSIFICATION -- BY BODY PREFIX, NEVER BY AUTHOR LOGIN. Every seat posts under the same GitHub
login, so the login says nothing about which seat wrote a comment.

* A Lander comment is one whose body, after leading whitespace, starts with ``Lander (session``.
  ("Lander handover from the batch 453 Manager" is a Manager's comment, and is not one.)
* A hold is a Lander comment containing ``**Held`` or ``**Still held``.
* LANDER's turn: there is no Lander comment; or the latest Lander comment is not a hold; or there is
  a commit newer than the latest hold; or a non-Lander comment newer than it.
* AUTHOR's turn: the latest Lander comment is a hold and nothing is newer.

"A commit newer than the hold". A hold names the head it held at in backticks, e.g.
``**Held, back to the author, at `f4f4dd470`.**``. That is the preferred signal: if the hold names a
SHA and the current head does not start with it, there is a new commit. Only when the hold names no
SHA does this fall back to the head commit's ``committedDate`` against the hold's ``createdAt``. That
is the weaker signal: ``committedDate`` is when the commit was made, not pushed, so a rebase or an
old local commit pushed after the hold can predate it. Rows decided that way carry ``date-fallback``.

WHAT COUNTS AS A COMMENT (the choice made here). Issue comments and PR review bodies both count, and
both are classified by the same body prefix, so a Lander verdict posted as a review body is a Lander
comment. Two things are skipped for the TURN, though both still count toward the newest-event age:

* a review with an empty body (inline-only or a bare approval): there is no text to read as a move;
* anything authored by a GitHub App or bot (GraphQL ``author.__typename == "Bot"``), such as the
  greptile auto-approve review a push triggers. A bot reacting to a push is not the author moving;
  the push itself is the move, and it is caught as a new commit. This keys on the author's TYPE,
  not its login, so it never separates two seats.

Inline review-thread comments are not read. Only the latest ``COMMENT_PAGE`` issue comments and
``REVIEW_PAGE`` reviews are fetched, enough to hold the newest Lander comment on any PR seen so far.

FLAGS. ``no-lander-comment``, ``lander-not-hold``, ``new-commit``, ``no-new-commit`` (LANDER's turn
caused only by a newer non-Lander comment, with no new commit since the hold: the Lander must still
read it, but can bounce it fast), ``held`` (AUTHOR's turn) and ``date-fallback``.

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

LANDER_PREFIX = "Lander (session"
HOLD_MARKERS = ("**Held", "**Still held")
#: A SHA named in backticks. Bounded and literal, so the ReDoS scanner resolves it statically.
_SHA_IN_BACKTICKS = re.compile(r"`([0-9a-fA-F]{7,40})`")

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
        comments(last: %COMMENT_PAGE%) { nodes { body createdAt author { __typename login } } }
        reviews(last: %REVIEW_PAGE%) {
          nodes { body createdAt submittedAt author { __typename login } }
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

#: The failures one repository's read can raise; any of them becomes that repository's ERROR row.
_READ_ERRORS = (
    pr_state.PollError,
    pr_state.GhError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    OSError,
)


@dataclass
class RepoRead:
    prs: list[dict[str, Any]] = field(default_factory=list)
    required: list[str] | None = None
    required_error: str | None = None


@dataclass(frozen=True)
class Event:
    when: datetime
    body: str
    bot: bool

    @property
    def lander(self) -> bool:
        return self.body.lstrip().startswith(LANDER_PREFIX)

    @property
    def hold(self) -> bool:
        return self.lander and any(m in self.body for m in HOLD_MARKERS)

    @property
    def counts_for_turn(self) -> bool:
        return not self.bot and bool(self.body.strip())


_nodes = pr_state._nodes


def _events(pr: dict[str, Any]) -> list[Event]:
    out: list[Event] = []
    for kind, stamp_keys in (
        ("comments", ("createdAt",)),
        ("reviews", ("submittedAt", "createdAt")),
    ):
        for node in _nodes(pr.get(kind)):
            if not isinstance(node, dict):
                continue
            when = next(
                (w for k in stamp_keys if (w := pr_state.parse_iso(node.get(k))) is not None), None
            )
            if when is None:
                continue
            author = node.get("author")
            bot = isinstance(author, dict) and author.get("__typename") == "Bot"
            out.append(Event(when, str(node.get("body") or ""), bot))
    return out


def hold_sha(body: str) -> str | None:
    """The SHA a hold names in backticks inside its bold headline, lower-cased, or None.

    Only the bold run that opens at the hold marker is searched, so a SHA quoted later in the body
    (a fix commit, a parent) is never mistaken for the held head.
    """
    starts = [i for m in HOLD_MARKERS if (i := body.find(m)) >= 0]
    if not starts:
        return None
    start = min(starts)
    end = body.find("**", start + 2)
    headline = body[start : end if end >= 0 else len(body)]
    match = _SHA_IN_BACKTICKS.search(headline)
    return match.group(1).lower() if match else None


def classify(
    head_oid: str, committed: datetime | None, events: Iterable[Event]
) -> tuple[str, list[str]]:
    """``(turn, flags)`` for one PR. Pure; the module docstring states the rules."""
    turn_events = [e for e in events if e.counts_for_turn]
    landers = [e for e in turn_events if e.lander]
    if not landers:
        return LANDER, ["no-lander-comment"]
    latest = max(landers, key=lambda e: e.when)
    if not latest.hold:
        return LANDER, ["lander-not-hold"]
    flags: list[str] = []
    sha = hold_sha(latest.body)
    if sha is not None:
        new_commit = not head_oid.lower().startswith(sha)
    else:
        flags.append("date-fallback")
        new_commit = committed is not None and committed > latest.when
    newer_comment = any(e.when > latest.when and not e.lander for e in turn_events)
    if new_commit:
        return LANDER, ["new-commit", *flags]
    if newer_comment:
        return LANDER, ["no-new-commit", *flags]
    return AUTHOR, ["held", *flags]


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
        # commits(last: 1) is not guaranteed to be the head; a verdict on another commit is none.
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
    if read.required_error:
        verdict["reason"] = read.required_error
    state = verdict.get("state")
    return (
        "yes" if state == "SUCCESS" else "no" if state in ("FAILURE", "PENDING") else "?"
    ), verdict


def build_rows(repo: str, read: RepoRead, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pr in read.prs:
        if not isinstance(pr, dict) or pr.get("isDraft"):
            continue
        head = pr_state._head_commit(pr)
        head_oid = str(pr.get("headRefOid") or "")
        committed = pr_state.parse_iso(head.get("committedDate"))
        events = _events(pr)
        turn, flags = classify(head_oid, committed, events)
        green, verdict = _required_green(pr, head, read)
        stamps = [e.when for e in events] + ([committed] if committed else [])
        newest = max(stamps) if stamps else None
        age = int((now - newest).total_seconds()) if newest else None
        rows.append(
            {
                "repo": repo,
                "number": pr.get("number"),
                "title": str(pr.get("title") or ""),
                "head": head_oid[:9],
                "mergeable": pr.get("mergeable"),
                "mergeStateStatus": pr.get("mergeStateStatus"),
                "requiredGreen": green,
                "required": {
                    k: verdict.get(k) for k in ("state", "failing", "pending", "missing", "reason")
                },
                "turn": turn,
                "flags": flags,
                "newestEvent": newest.strftime("%Y-%m-%dT%H:%M:%SZ") if newest else None,
                "age": age_text(age) if age is not None else "?",
                "ageSeconds": age,
            }
        )
    return rows


def sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ERROR rows first (never missed), then LANDER, then AUTHOR; oldest newest-event first."""
    order = {ERROR: 0, LANDER: 1, AUTHOR: 2}

    def key(row: dict[str, Any]) -> tuple[int, int, str, int]:
        age = row.get("ageSeconds")
        return (
            order.get(row["turn"], 3),
            -(age if isinstance(age, int) else -1),
            row["repo"],
            int(row.get("number") or 0),
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
        conn = repository.get("pullRequests")
        if not isinstance(conn, dict):
            raise ValueError("reply has no pullRequests connection")
        read.prs.extend(_nodes(conn))
        page = conn.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
        if not cursor:
            raise ValueError("hasNextPage with no endCursor")
    else:
        raise ValueError(f"more than {MAX_PAGES * PR_PAGE} open PRs; refusing a partial list")
    _set_required(read, repo, lambda: list(pr_state.fetch_required(gh, repo)))
    return read


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
        raise ValueError(f"{repo} is not in the input file")
    entry = doc[repo]
    if not isinstance(entry, dict):
        raise ValueError(f"the input entry for {repo} is not an object")
    if entry.get("error"):
        raise ValueError(str(entry["error"]))
    read = RepoRead()
    for page in entry.get("pages") or []:
        conn = page["data"]["repository"]["pullRequests"]
        read.prs.extend(_nodes(conn))

    def canned() -> list[str]:
        required = entry.get("required")
        if not isinstance(required, list):
            raise ValueError("no required list in the input file")
        return [str(c) for c in required]

    _set_required(read, repo, canned)
    return read


def error_row(repo: str, reason: str) -> dict[str, Any]:
    return {"repo": repo, "turn": ERROR, "error": reason, "flags": [], "ageSeconds": None}


def render(rows: list[dict[str, Any]]) -> str:
    header = ("TURN", "FLAGS", "REPO", "PR", "GREEN", "MERGEABLE", "STATE", "HEAD", "AGE", "TITLE")
    table: list[tuple[str, ...]] = [header]
    for row in rows:
        short = row["repo"].split("/", 1)[-1]
        if row["turn"] == ERROR:
            table.append((ERROR, "", short, "", "", "", "", "", "", row["error"]))
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
    return "\n".join(line.rstrip() for line in lines)


def collect(
    repos: Iterable[str], reader: Callable[[str], RepoRead], now: datetime
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for repo in repos:
        try:
            rows.extend(build_rows(repo, reader(repo), now))
        except _READ_ERRORS as exc:
            rows.append(error_row(repo, f"{type(exc).__name__}: {exc}"[:300]))
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
            doc = json.loads(args.input.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            unreadable = f"input file unreadable: {exc}"

    def reader(repo: str) -> RepoRead:
        if unreadable:
            raise ValueError(unreadable)
        return from_input(doc, repo) if args.input is not None else fetch_live(gh, repo)

    rows = collect(repos, reader, now())
    if hasattr(sys.stdout, "reconfigure"):
        # A PR title can carry characters a cp1252 console cannot encode; a report must not crash.
        sys.stdout.reconfigure(errors="replace")
    print(json.dumps(rows, indent=2) if args.json else render(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
