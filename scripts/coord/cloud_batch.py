#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cloud batch helper: wait for a cloud Builder's pull request, and check a batch for file overlap.

A local Manager hands work to Claude Code cloud sessions, and the pull request is the only surface
both sides reach. This talks to GitHub only through ``gh api`` over REST, because a cloud VM's
GitHub proxy refuses GraphQL, so ``gh pr`` fails there. The same script runs on either side.

Usage::

    python scripts/coord/cloud_batch.py await-start --repo OWNER/NAME --branch BRANCH
        [--start-deadline-min 45] [--interval-sec 120]
    python scripts/coord/cloud_batch.py overlap --repo OWNER/NAME --path P [--path P ...]
        [--exclude-pr N ...] [--json]

``await-start`` polls for the open pull request whose head is BRANCH, prints ONE line and exits,
so a caller running it in the background is woken once::

    STARTED pr=N author=LOGIN    exit 0
    LAPSED branch=B after=MIN    exit 2; no open pull request by the start deadline
    ERROR WHAT                   exit 3; after 3 failed polls in a row, or a usage error

A closed pull request on BRANCH does not count. It is most likely left from an earlier dispatch
that reused the branch name. The start deadline defaults to 45 minutes. On canary PR 2497
(measured 2026-10-22), a cloud session first pushed about 30 minutes after the start request. A
20-minute deadline would report LAPSED on that healthy start.

The repository is public. This script cannot tell whose account a cloud Builder works under, so
the line names the author and the caller checks it. Everything after the start belongs to
``scripts/coord/wait-pr.ps1 -Until comment``, including the Builder's questions and status. Pull
request 2490 adds it, and it was not yet on main when this was written. It counts only the pull
request author's comments, so a stranger cannot answer for the Builder.

``overlap`` reads every open pull request's files. It prints ``OVERLAP pr=N branch=REF
paths=A,B`` for each one touching a given path, then always ``scanned K open PRs, M files``. A path
matches that file. When it names a directory, it matches every file under it, with or without a
trailing ``/``. A renamed file also matches by its old name. Exit 0 for no overlap, 1 for overlap,
3 for an error. A pull request past GitHub's 3000-file listing cap counts as an overlap, because
the files past the cap were never checked. Only pull requests are read, so a pushed branch with no
pull request yet is not seen. Parse ``--json`` rather than the text: a file name may hold a comma.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, NoReturn, TextIO

type JsonObj = dict[str, Any]
# Takes a full gh argv and returns its stdout, or raises GhError. Tests swap in a fake.
type Runner = Callable[[list[str]], str]

EXIT_OK = 0
EXIT_OVERLAP = 1
EXIT_LAPSED = 2
EXIT_ERROR = 3
PER_PAGE = 100
# A proxy that ignored the page parameter would otherwise return the same full page forever.
MAX_PAGES = 50
# GitHub stops listing a pull request's files at 3000, so nothing past that can be checked.
FILES_CAP = 3000
MAX_FAILURES = 3
# Every poll spends the REST budget the whole fleet shares, so one wait may not poll faster.
MIN_INTERVAL_SEC = 30.0
GH_TIMEOUT_SEC = 60
_REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")


class GhError(Exception):
    """A gh call failed, or GitHub answered with something this script cannot read."""


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)


def run_gh(argv: list[str]) -> str:
    """Run one gh command and return its stdout."""
    try:
        # The locale codec is cp1252 on Windows, which silently garbles non-ASCII JSON.
        proc = subprocess.run(  # nosec B603 - argv is a list built by _get, no shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=GH_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhError(_one_line(str(exc))) from exc
    if proc.returncode != 0:
        raise GhError(f"exited {proc.returncode}: {_one_line(proc.stderr)[:300]}")
    return proc.stdout


def _get(runner: Runner, endpoint: str, **params: str) -> Any:
    # -X GET makes gh send each -f field as a query parameter, so no `&` or `?` ever reaches a
    # command line, and -f (unlike -F) never reads a value starting with @ as a file.
    argv = ["gh", "api", "-X", "GET", endpoint]
    for key, value in params.items():
        argv += ["-f", f"{key}={value}"]
    try:
        return json.loads(runner(argv))
    except GhError as exc:
        raise GhError(f"gh api {endpoint}: {exc}") from exc
    except ValueError as exc:
        raise GhError(f"gh api {endpoint}: reply is not JSON ({exc})") from exc


def _get_list(
    runner: Runner, endpoint: str, *, limit: int | None = None, **params: str
) -> list[JsonObj]:
    """Every page of a REST list, stopping once `limit` items are in hand."""
    items: list[JsonObj] = []
    for page in range(1, MAX_PAGES + 1):
        batch = _get(runner, endpoint, **params, per_page=str(PER_PAGE), page=str(page))
        if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
            raise GhError(f"gh api {endpoint}: expected a JSON list of objects")
        items.extend(batch)
        if len(batch) < PER_PAGE or (limit is not None and len(items) >= limit):
            return items
    raise GhError(f"gh api {endpoint}: still full after {MAX_PAGES} pages")


def _field[T](obj: JsonObj, key: str, kind: type[T]) -> T:
    value = obj.get(key)
    if not isinstance(value, kind):
        raise GhError(f"GitHub reply field {key!r} is {type(value).__name__}, not {kind.__name__}")
    return value


def _number(obj: JsonObj) -> int:
    return _field(obj, "number", int)


def _is_head(pull: JsonObj, owner: str, branch: str) -> bool:
    # GitHub logins ignore case and branch names do not, and the label carries the login's
    # canonical case whatever case --repo used.
    label = _field(pull, "head", dict).get("label")
    head_owner, _, ref = label.partition(":") if isinstance(label, str) else ("", "", "")
    return ref == branch and head_owner.casefold() == owner.casefold()


def _find_pr(runner: Runner, repo: str, branch: str) -> str | None:
    owner = repo.split("/", 1)[0]
    pulls = _get_list(runner, f"repos/{repo}/pulls", state="open", head=f"{owner}:{branch}")
    # Checked again here, so a head filter GitHub ignored or misread cannot hand back another
    # branch's PR.
    mine = [p for p in pulls if _is_head(p, owner, branch)]
    if not mine:
        return None
    pull = max(mine, key=_number)
    author = _field(_field(pull, "user", dict), "login", str)
    return f"STARTED pr={_number(pull)} author={author}"


def await_start(
    runner: Runner,
    repo: str,
    branch: str,
    deadline_min: float,
    interval_sec: float,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> tuple[str, int]:
    """The STARTED or LAPSED line and its exit code. Re-raises the GhError of the last of
    MAX_FAILURES failed polls in a row."""
    deadline = deadline_min * 60
    start = clock()
    failures = 0
    while True:
        try:
            line = _find_pr(runner, repo, branch)
            failures = 0
        except GhError:
            failures += 1
            if failures >= MAX_FAILURES:
                raise
        else:
            if line is not None:
                return line, EXIT_OK
        elapsed = clock() - start
        # Judged only after a good poll: a failed one cannot show that no PR exists.
        if not failures and elapsed >= deadline:
            return f"LAPSED branch={branch} after={round(elapsed / 60, 1):g}", EXIT_LAPSED
        # Wake at the deadline rather than up to one interval past it, but leave a failed poll
        # some room to recover before its retry.
        floor = MIN_INTERVAL_SEC if failures else 0.0
        sleep(min(interval_sec, max(deadline - elapsed, floor)))


@dataclass
class OverlapReport:
    overlaps: list[JsonObj] = field(default_factory=list)
    capped: list[JsonObj] = field(default_factory=list)
    scanned_prs: int = 0
    scanned_files: int = 0


def _normalise(path: str) -> str:
    # GitHub names files with single forward slashes, and no leading ./ or / or trailing /.
    path = re.sub(r"/+", "/", path.strip().replace("\\", "/"))
    while path.startswith("./"):
        path = path[2:]
    return path.strip("/")


def _matches(name: str, wanted: Sequence[str]) -> bool:
    # A directory matches with or without its trailing slash: a missed overlap is the costly error.
    return any(name == w or name.startswith(w + "/") for w in wanted)


def _file_names(entry: JsonObj) -> list[str]:
    names = [_field(entry, "filename", str)]
    # A renamed file also carries its old name, which another batch may still be editing.
    previous = entry.get("previous_filename")
    if isinstance(previous, str):
        names.append(previous)
    return names


def overlap(
    runner: Runner, repo: str, wanted: Sequence[str], exclude: Sequence[int]
) -> OverlapReport:
    report = OverlapReport()
    # A PR that opens while the pages are read makes the next page repeat one, and a PR that
    # closes makes it skip one. Two listings merged by number catch what one listing skipped.
    pulls: dict[int, JsonObj] = {}
    for _ in range(2):
        for pull in _get_list(runner, f"repos/{repo}/pulls", state="open"):
            pulls.setdefault(_number(pull), pull)
    for number, pull in sorted(pulls.items()):
        if number in exclude:
            continue
        branch = _field(_field(pull, "head", dict), "ref", str)
        files = _get_list(runner, f"repos/{repo}/pulls/{number}/files", limit=FILES_CAP)
        report.scanned_prs += 1
        report.scanned_files += len(files)
        if len(files) >= FILES_CAP:
            report.capped.append({"pr": number, "branch": branch, "files": len(files)})
        hits = sorted({n for f in files for n in _file_names(f) if _matches(n, wanted)})
        if hits:
            report.overlaps.append({"pr": number, "branch": branch, "paths": hits})
    return report


def _overlap_lines(report: OverlapReport) -> list[str]:
    lines = [
        f"OVERLAP pr={o['pr']} branch={o['branch']} paths={','.join(o['paths'])}"
        for o in report.overlaps
    ]
    lines += [
        f"CAPPED pr={c['pr']} branch={c['branch']} files={c['files']} :: GitHub lists at most"
        f" {FILES_CAP} files per pull request; the rest were not checked, so this counts as an"
        " overlap"
        for c in report.capped
    ]
    lines.append(f"scanned {report.scanned_prs} open PRs, {report.scanned_files} files")
    return lines


def _positive(value: str) -> float:
    number = float(value)
    if not (math.isfinite(number) and number > 0):
        raise argparse.ArgumentTypeError(f"must be a finite number above 0, got {value}")
    return number


def _interval(value: str) -> float:
    number = _positive(value)
    if number < MIN_INTERVAL_SEC:
        raise argparse.ArgumentTypeError(f"must be at least {MIN_INTERVAL_SEC:g}, got {value}")
    return number


def _repo(value: str) -> str:
    if not _REPO.fullmatch(value):
        raise argparse.ArgumentTypeError(f"expected OWNER/NAME, got {value!r}")
    return value


def _path(value: str) -> str:
    path = _normalise(value)
    parts = path.split("/")
    # Each of these could never equal a name GitHub lists, so it would match nothing, silently.
    if (
        not path
        or re.match(r"[A-Za-z]:", path)
        or "." in parts
        or ".." in parts
        or any(ch in path for ch in "*?")
    ):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a file or directory path relative to the repository root"
        )
    return path


def _nonempty(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    # argparse exits 2 on a usage error, which a caller would read as LAPSED. Subparsers take
    # this class too, so every usage error ends as one ERROR line and exit 3.
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        raise _UsageError(f"{self.prog}: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("await-start", help="wait for a cloud Builder to open its pull request")
    a.add_argument("--repo", required=True, type=_repo)
    a.add_argument("--branch", required=True, type=_nonempty)
    a.add_argument("--start-deadline-min", type=_positive, default=45.0)
    a.add_argument("--interval-sec", type=_interval, default=120.0)

    o = sub.add_parser("overlap", help="list open pull requests touching the given paths")
    o.add_argument("--repo", required=True, type=_repo)
    o.add_argument("--path", required=True, action="append", type=_path, dest="paths")
    o.add_argument("--exclude-pr", action="append", type=int, default=[], dest="exclude")
    o.add_argument("--json", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner = run_gh,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    out: TextIO | None = None,
) -> int:
    stream = sys.stdout if out is None else out
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parser().parse_args(raw)
    except _UsageError as exc:
        # The flag is read from the raw words, since a failed parse leaves no namespace.
        return _fail(stream, f"usage: {exc}", as_json="--json" in raw)
    as_json = args.command == "overlap" and args.json
    try:
        if args.command == "await-start":
            line, code = await_start(
                runner,
                args.repo,
                args.branch,
                args.start_deadline_min,
                args.interval_sec,
                clock,
                sleep,
            )
            return _emit(stream, [line], code)
        report = overlap(runner, args.repo, args.paths, args.exclude)
    except GhError as exc:
        return _fail(stream, str(exc), as_json)
    code = EXIT_OVERLAP if report.overlaps or report.capped else EXIT_OK
    if as_json:
        print(json.dumps(asdict(report)), file=stream)
        return code
    return _emit(stream, _overlap_lines(report), code)


def _fail(stream: TextIO, message: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"error": message}), file=stream)
        return EXIT_ERROR
    return _emit(stream, [f"ERROR {message}"], EXIT_ERROR)


def _emit(stream: TextIO, lines: list[str], code: int) -> int:
    # Branch names, file names and gh's errors come from outside. A control character in one
    # could forge a second line of output or drive the reader's terminal; JSON escapes its own.
    for line in lines:
        print(_printable(line), file=stream)
    return code


if __name__ == "__main__":
    if isinstance(sys.stdout, io.TextIOWrapper):
        # A branch or file name can hold any character, and the cp1252 a Windows pipe defaults
        # to would raise on one.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
