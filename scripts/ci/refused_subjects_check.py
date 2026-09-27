# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a pull request that carries a commit its own author marked as not to land (BACKLOG #1775).

THE DEFECT. Authors in this project record a refusal in the commit SUBJECT -- the vocabulary is
``DO NOT LAND`` and ``NOT LANDABLE`` -- and keep the commit alive as evidence rather than delete it. One
such commit is a recorded NEGATIVE verdict on a candidate security fix: the work looks finished because
it is finished, and a reader looking at a diff and a green check cannot tell it from a fix ready to
land. Nothing that opens a pull request reads a subject line, and no script in this repository opens
pull requests -- sessions do. So the refusal lives where no machine looks.

THE FIX IS TO PUT IT WHERE EVERY OPENER AND EVERY MERGE MUST PASS: the required ``test
(ubuntu-latest, py3.14)`` context. On a ``pull_request`` event ci.yml calls this script with the pull
request's base and head SHAs; it lists every commit in ``base..head`` and exits non-zero when any
SUBJECT matches the vocabulary. Whoever opened the pull request, by hand or by a mechanical pass over
refs, the merge is blocked until the refused commits are gone from the branch.

IT NEVER SKIPS SILENTLY. A refusal prints the count and each SHA and subject. A clean run prints how
many commits it scanned, the range, and the merge base, so a zero is attributable to a real range and
not to an empty one. A range it cannot establish is exit 2 with the reason, never a pass.

THE RANGE MUST BE WHOLE, AND A SHALLOW CHECKOUT CAN HIDE PART OF IT. The CI checkout is one commit
deep. Two independent checks decide whether the range is whole:

* NOTHING MISSING. No commit in the range may sit on the shallow boundary (``.git/shallow``). Such a
  commit has its parents hidden, so older commits of the branch may be absent even when a merge base
  was found. This check needs nothing from outside git.
* NOTHING EXTRA. With ``--expected-count`` (ci.yml passes the event's ``pull_request.commits``), the
  range must hold exactly that many commits. A truncated base side can make main's own commits look
  like the branch's; only a count from outside git says so.

With ``--fetch-remote`` the script fetches the two SHAs and deepens until both checks pass. It deepens
with ``--deepen``, which only ever adds history. It never uses ``--depth``: measured 2026-09-26,
``--depth=2`` into a clone 15 commits deep cut it to 2, which on a developer's machine is destructive.
A full clone gets one plain fetch and nothing else.

THE SUBJECT IS GIT'S SUBJECT: the first PARAGRAPH, joined into one line, as the item's own census read
it with ``%(subject)``. A refusal wrapped onto a second line with no blank line between is still read.
So a quotation belongs in the body, after a blank line.

KNOWN FALSE POSITIVE, KEPT ON PURPOSE. A subject that merely QUOTES the phrase -- a commit about this
very gate, or one explaining why some other branch was refused -- is refused too. There is no escape
hatch: an override flag is one more field a mechanical reader treats as decoration, which is the defect
this exists to fix.

WHY ``merge_group`` IS NOT SCANNED. Its range holds the queue's own commits for every entry ahead of
this one, so scanning it would red the whole queue on another entry's title. The pull request's own
run scans this head, and that run is required before the pull request can enter the queue.

WHAT THIS DOES NOT COVER. The pull request TITLE: the queue squashes, and a multi-commit pull
request's squash subject is its title, so a refusal written only there would still reach ``main``.
And a changed BASE: retargeting a pull request fires ``edited``, which ci.yml does not trigger on, so
a range that grows by a retarget is not re-scanned until the next push. Both need a trigger change
this script cannot make.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

# The words are fixed; the separator is not. Space, hyphen or underscore between the words, and no
# letter or digit on either side, so "do-not-land" and "wip_DO NOT LAND" match while "do not
# landscape" does not. Case-insensitive, as the item's own census grep was. Measured 2026-09-26 over
# one clone's whole history (2,694 `fix(` control hits): every refusal is upper-case and no lower-case
# use of either phrase exists, so the wider match costs nothing observed. Lower-case prose is the
# false positive it would buy.
REFUSAL = re.compile(
    r"(?<![A-Za-z0-9])(?:DO[\s_-]+NOT[\s_-]+LAND|NOT[\s_-]+LANDABLE)(?![A-Za-z0-9])", re.IGNORECASE
)

# Deepening schedule for a shallow checkout, then a full unshallow as the last resort.
_DEPTHS: tuple[int, ...] = (64, 512, 4096)

# Seconds. One budget for the whole run, so a slow fetch fails THIS script by name, inside the
# workflow step's own `timeout-minutes`, rather than being killed by the runner with no reason given.
DEFAULT_BUDGET = 240

EXIT_CLEAN = 0
EXIT_REFUSED = 1
EXIT_UNRESOLVED = 2

_FIELD = "\x1f"
_RECORD = "\x00"


class GitError(RuntimeError):
    """A git command failed, or the run's time budget ran out; the message says which."""


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str


class _Clock:
    """The run's deadline. ``None`` means unbounded, which only direct library callers get."""

    deadline: float | None = None

    @classmethod
    def remaining(cls) -> float | None:
        return None if cls.deadline is None else cls.deadline - time.monotonic()


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    remaining = _Clock.remaining()
    if remaining is not None and remaining <= 0:
        raise GitError(f"the time budget ran out before git {' '.join(args)}")
    try:
        # Fixed argv, no shell; git is resolved on PATH, as every script here runs it.
        proc = subprocess.run(  # noqa: S603  # nosec B603 B607
            ["git", "-c", "log.showSignature=false", *args],  # noqa: S607
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=remaining,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args)} did not finish inside the time budget") from exc
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
    return proc


def is_refused(subject: str) -> bool:
    return REFUSAL.search(subject) is not None


def _present(repo: Path, rev: str) -> bool:
    return _git(repo, "cat-file", "-e", f"{rev}^{{commit}}", check=False).returncode == 0


def _merge_base(repo: Path, base: str, head: str) -> str | None:
    proc = _git(repo, "merge-base", base, head, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _is_shallow(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"


def _shallow_boundary(repo: Path) -> set[str]:
    """The commits whose parents this repository does not have. Empty for a full clone."""
    where = _git(repo, "rev-parse", "--path-format=absolute", "--git-path", "shallow")
    try:
        text = Path(where.stdout.strip()).read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()
    return {line.strip() for line in text.splitlines() if line.strip()}


def list_range(repo: Path, base: str, head: str) -> list[Commit]:
    # NUL-separated records: a subject can hold a form feed, U+2028 or a bare CR, each of which
    # `str.splitlines` would split into a phantom commit whose "SHA" is subject text.
    out = _git(repo, "log", "-z", "--no-color", f"--format=%H{_FIELD}%s", f"{base}..{head}").stdout
    commits = []
    for record in out.split(_RECORD):
        sha, _, subject = record.partition(_FIELD)
        if sha:
            commits.append(Commit(sha.strip(), subject))
    return commits


def _fetch(
    repo: Path, remote: str, base: str, head: str, depth: int | None, *, shallow: bool
) -> None:
    """Fetch both SHAs, only ever ADDING history.

    On a shallow repository ``--deepen`` extends the existing boundary, and ``depth=None`` means
    ``--unshallow``. A full repository gets a plain fetch.
    """
    args = ["fetch", "--no-tags", "--quiet"]
    if shallow:
        args.append(f"--deepen={depth}" if depth is not None else "--unshallow")
    args += [remote, base, head]
    _git(repo, *args)


@dataclass(frozen=True)
class Resolved:
    commits: list[Commit] | None
    merge_base: str | None
    reason: str


def _assess(repo: Path, base: str, head: str, expected: int | None) -> Resolved:
    missing = [rev for rev in (base, head) if not _present(repo, rev)]
    if missing:
        return Resolved(None, None, f"commit(s) not present locally: {', '.join(missing)}")
    mb = _merge_base(repo, base, head)
    if mb is None:
        return Resolved(None, None, "no merge base between base and head in the local history")
    commits = list_range(repo, base, head)
    boundary = _shallow_boundary(repo)
    cut = [c.sha for c in commits if c.sha in boundary]
    if cut:
        return Resolved(
            None,
            mb,
            f"the range reaches the shallow boundary at {', '.join(cut)}, so older commits of the "
            "branch may be missing from it",
        )
    if expected is not None and len(commits) != expected:
        return Resolved(
            None,
            mb,
            f"the range holds {len(commits)} commit(s) but the pull request has {expected}",
        )
    return Resolved(commits, mb, "")


def resolve(repo: Path, base: str, head: str, expected: int | None, remote: str | None) -> Resolved:
    """Return the whole range, deepening a shallow checkout until it is provably whole."""
    got = _assess(repo, base, head, expected)
    if got.commits is not None or remote is None:
        return got
    for depth in (*_DEPTHS, None):
        shallow = _is_shallow(repo)
        _fetch(repo, remote, base, head, depth, shallow=shallow)
        got = _assess(repo, base, head, expected)
        if got.commits is not None:
            return got
        if not shallow:
            # A full repository cannot be deepened; one plain fetch was all there was to try.
            break
    return got


def _in_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _escape(data: str) -> str:
    """Escape a workflow-command message, so multi-line git stderr stays one annotation."""
    return data.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _error(line: str) -> None:
    print(f"::error::{_escape(line)}" if _in_actions() else line)


def _print_untrusted(lines: Sequence[str]) -> None:
    """Print commit subjects, which anyone who can push a branch controls.

    On a runner, workflow-command processing is paused around them, so a subject carrying
    ``::add-mask::`` or ``##[...]`` is printed rather than executed.
    """
    # Unpredictable, so a subject cannot carry the resume token. Not a secret and not crypto: uuid4 is
    # enough, and it keeps this file out of the crypto inventory.
    token = uuid.uuid4().hex if _in_actions() else ""
    if token:
        print(f"::stop-commands::{token}")
    for line in lines:
        print(line)
    if token:
        print(f"::{token}::")


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--base", required=True, help="base SHA of the pull request")
    parser.add_argument("--head", required=True, help="head SHA of the pull request")
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="the pull request's commit count; the range must hold exactly this many",
    )
    parser.add_argument(
        "--fetch-remote",
        default=None,
        help="remote to fetch the SHAs from, deepening a shallow checkout as needed",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=DEFAULT_BUDGET,
        help=f"time budget for every git call together (default {DEFAULT_BUDGET})",
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="repository to read")
    args = parser.parse_args(argv)

    for name, rev in (("--base", args.base), ("--head", args.head)):
        # A leading dash would reach git as an option, and `fetch --upload-pack=...` runs a command.
        if not rev or rev.startswith("-"):
            _error(f"refused-subjects: {name} must name a commit, got {rev!r}")
            return EXIT_UNRESOLVED

    _Clock.deadline = time.monotonic() + args.budget_seconds
    try:
        got = resolve(args.repo, args.base, args.head, args.expected_count, args.fetch_remote)
    except (GitError, OSError) as exc:
        _error(f"refused-subjects: could not read the range: {exc}")
        return EXIT_UNRESOLVED
    finally:
        _Clock.deadline = None
    if got.commits is None:
        _error(
            f"refused-subjects: could not establish the range {args.base}..{args.head}: "
            f"{got.reason}. Nothing was scanned, so this is a failure and not a pass."
        )
        return EXIT_UNRESOLVED

    refused = [c for c in got.commits if is_refused(c.subject)]
    scope = (
        f"{len(got.commits)} commit(s) in {args.base}..{args.head} (merge base {got.merge_base})"
    )
    if args.expected_count is not None:
        scope += f", matching the pull request's own count of {args.expected_count}"
    if not refused:
        print(f"refused-subjects: scanned {scope}; none carries a refusal in its subject.")
        return EXIT_CLEAN
    _error(
        f"refused-subjects: {len(refused)} of {scope} carry a refusal in the subject "
        "(DO NOT LAND / NOT LANDABLE). Their author marked them as not to land."
    )
    _print_untrusted([f"  {c.sha}  {c.subject}" for c in refused])
    print(
        "Take these commits off the branch, for example on a fresh branch without them. If a subject "
        "only QUOTES the phrase, reword that commit and move the quotation into its body, after a "
        "blank line; only the subject is read. There is no override."
    )
    return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
