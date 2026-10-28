#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which ledger acts were asked of the Lander on a merged pull request and are still not done.

WHY THIS EXISTS. A Manager asks the Lander to flip a vault ledger row, or to file one, in a comment
on the pull request (and often by fleet mail too). Nothing carried that ask forward: the Lander kept
it in its own context and an untracked notes file. On 2026-10-28 two flips asked on engine PRs 2545
and 2546 (rows #3844 and #3025) survived a context compaction only as a summary, were left out of
the next ledger pass's brief, and a peer had to relay them twice. This report re-derives what is
owed from GitHub and the vault's git history on every run, so a ledger pass is briefed from its
output and nothing depends on what a session remembers.

READ-ONLY, AND ALWAYS EXIT 0. It is a report, not a gate. It reads GitHub with ``gh`` and the vault
with ``git show`` / ``git rev-list`` against a ref (``origin/main`` by default); it never fetches,
checks out or writes. A read that fails prints an ERROR line naming the reason, never an empty
list, because "nothing owed" and "could not read" must not look alike. A bad command line still
exits 2, argparse's usage error.

THE ASK. Two shapes, in a comment on a MERGED pull request by an OWNER, MEMBER or COLLABORATOR
(every seat posts under one login, so this keeps out outside accounts, not other seats), not
minimized:

* PRIMARY, machine-readable: ``<!-- lander-ledger-ask rows=#3844,#3025 file=2 -->``. ``rows`` names
  existing rows whose banner the Lander owes (a flip, a PARTIAL, a note); ``file`` counts new rows
  to file. Either may be left out. It may also sit in the PR body. A comment carrying a marker is
  read for its marker only.
* FALLBACK, prose, deliberately loose so it over-reports rather than under-reports: a comment that
  names the Lander, and does not start with ``Lander (session`` (the Lander's own comments), is
  split into sentences. A sentence with an ask word (flip, banner, owed, close, or "file ... row")
  contributes its ``#N`` row numbers (``PR #N`` excluded) and, for "file ... row", a file ask. A
  comment with an ask word but nothing extractable prints as READ, for a person to read.

WHEN AN ASK COUNTS AS DONE. Its baseline is the later of the merge and the ask. A row is DONE when
its banner block (heading plus leading blockquotes, cut with the vault's own ``parse_items``) at the
ledger ref differs from the block at the vault's last first-parent commit before the baseline, AND
cites the PR (``PR <N>`` or ``/pull/<N>``, the PR itself or one named in the ask sentence) more
times than it did. A change that does not cite the PR is not taken as the act, so an unrelated
edit to the row leaves it OWED. A file ask is DONE when at least that many rows absent at the
baseline now exist and cite the PR. Everything else prints: OWED, MISSING (the row is in neither
ledger file at the ref), READ.

WHAT IT CANNOT SEE. At least: an ask sent only by fleet mail (so a Manager should also put the
marker on the PR), an ask in an inline review comment, a pull request merged before the window, and
an ask whose act a pass recorded without citing the PR. The vault ledger's own PRs are not read by
default (``--repo`` adds them): a ledger PR's comments cite rows that the PR itself changed, before
its merge, and would read as owed.

Stdlib only. It loads ``pr_state.py`` by path for its gh runner, and the vault's
``scripts/docs/backlog_status_check.py`` by path for ``parse_items``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol

ENGINE_REPO = "MEFORORG/MessageFoundry"
VAULT_REPO = "MEFORORG/MessageFoundry-vault"
KORUS_REPO = "MEFORORG/korus"
REPOS = (ENGINE_REPO, VAULT_REPO, KORUS_REPO)
DEFAULT_REPOS = (ENGINE_REPO, KORUS_REPO)
DEFAULT_REF = "origin/main"
DEFAULT_DAYS = 14
PR_LIMIT = 300
GIT_TIMEOUT = 120
PARSER_PATH = Path("scripts/docs/backlog_status_check.py")

TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
LANDER_OWN_PREFIX = "Lander (session"

_MARKER = re.compile(r"<!--\s*lander-ledger-ask\b(?P<attrs>[^>]{0,400}?)-->")
_MARKER_ROWS = re.compile(r"\brows=(?P<v>#?\d{1,6}(?:\s*,\s*#?\d{1,6})*)")
_MARKER_FILE = re.compile(r"\bfile=(?P<v>\d{1,3})\b")
#: A row reference. ``PR #N`` and ``pull/#N`` are pull requests, not rows.
_ROW_REF = re.compile(r"(?<![Pp][Rr] )(?<![Pp][Rr])(?<!/)#(\d{1,6})\b")
_FILE_ASK_RE = r"\bfile\b[^.\n]{0,40}?\brows?\b|\brows?\b[^.\n]{0,20}?\bto file\b"
_FILE_ASK = re.compile(_FILE_ASK_RE, re.IGNORECASE)
_ASK_WORD = re.compile(
    rf"\bflip|\bbanner|\bowed\b|\bclos(?:e|es|ing)\b|{_FILE_ASK_RE}", re.IGNORECASE
)
_SENTENCE = re.compile(r"\n+|(?<=[.!?])\s+")
#: The rows a PR title names, the fallback for a handover whose ask names no row.
_TITLE_ROW = re.compile(r"\bBACKLOG\s+#(\d{1,6})\b", re.IGNORECASE)
#: A pull request cited in prose or in a ledger banner, with an optional repository word before it.
#: Unqualified means the engine: the ledger writes "engine PR N" or "PR N" for the engine and
#: "vault PR N" / "korus PR N" for the others, so a bare number never matches a korus or vault PR.
_PR_CITE = re.compile(
    r"(?:\b(?P<word>engine|vault|korus)\s+)?\b(?:PR|pull request)\s*#?(?P<n>\d{1,6})\b"
    r"|/(?P<slug>MessageFoundry-vault|MessageFoundry|korus)/pull/(?P<un>\d{1,6})\b",
    re.IGNORECASE,
)
_REPO_WORD = {"engine": ENGINE_REPO, "vault": VAULT_REPO, "korus": KORUS_REPO}
_REPO_SLUG = {
    "messagefoundry": ENGINE_REPO,
    "messagefoundry-vault": VAULT_REPO,
    "korus": KORUS_REPO,
}
#: A cited pull request: ``(owner/repo, number)``.
Cite = tuple[str, int]

DONE, OWED, MISSING, READ, ERROR = "DONE", "OWED", "MISSING", "READ", "ERROR"

_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


pr_state = _load("_owed_ledger_acts_pr_state", _HERE / "pr_state.py")

#: ``gh(args, stdin) -> stdout``, pr_state's runner: a by-path module is Any to mypy.
Gh = Callable[[list[str], str | None], str]


class ReadError(RuntimeError):
    """A GitHub or vault read could not be completed."""


@dataclass(frozen=True)
class Ask:
    repo: str
    pr: int
    merged_at: datetime
    asked_at: datetime
    source: str  # "marker" or "prose"
    url: str
    rows: tuple[int, ...] = ()
    file_count: int = 0
    #: PRs whose citation in a banner counts as the act: this PR plus any the ask sentence names.
    cites: frozenset[Cite] = frozenset()
    #: Prose that asked something this script could not extract; a person reads it.
    unread: bool = False

    @property
    def baseline(self) -> datetime:
        """A flip is owed after the merge; a row may be filed from the ask on, before the merge."""
        return max(self.merged_at, self.asked_at)


@dataclass
class Row:
    status: str
    ask: Ask | None
    what: str
    detail: str = ""


def parse_marker(text: str) -> list[tuple[tuple[int, ...], int]]:
    """Every ``lander-ledger-ask`` marker in ``text`` as ``(rows, file_count)``."""
    out = []
    for m in _MARKER.finditer(text):
        attrs = m.group("attrs")
        rows_m = _MARKER_ROWS.search(attrs)
        file_m = _MARKER_FILE.search(attrs)
        rows = (
            tuple(int(r.strip().lstrip("#")) for r in rows_m.group("v").split(","))
            if rows_m
            else ()
        )
        out.append((rows, int(file_m.group("v")) if file_m else 0))
    return out


def cited_prs(text: str) -> list[Cite]:
    """Every pull request ``text`` cites, with repeats, as ``(owner/repo, number)``."""
    out: list[Cite] = []
    for m in _PR_CITE.finditer(text):
        if m.group("n"):
            out.append(
                (
                    _REPO_WORD[(m.group("word") or "engine").lower()],
                    int(m.group("n")),
                )
            )
        else:
            out.append((_REPO_SLUG[m.group("slug").lower()], int(m.group("un"))))
    return out


def parse_prose(text: str, title: str = "") -> tuple[tuple[int, ...], int, set[Cite], bool] | None:
    """``(rows, file_count, cited PRs, unread)`` for a Lander-addressed prose ask, else ``None``.

    An ask that names no row and no filing (a handover's "banner text is in the body") falls back
    to the ``BACKLOG #N`` rows the PR title names; with none there, it is ``unread``.
    """
    if "Lander" not in text or text.lstrip().startswith(LANDER_OWN_PREFIX):
        return None
    if not _ASK_WORD.search(text):
        return None
    rows: list[int] = []
    cites: set[Cite] = set()
    file_count = 0
    for sentence in _SENTENCE.split(text):
        if not _ASK_WORD.search(sentence):
            continue
        found = [int(n) for n in _ROW_REF.findall(sentence)]
        is_file = bool(_FILE_ASK.search(sentence))
        if found or is_file:
            rows.extend(n for n in found if n not in rows)
            cites |= set(cited_prs(sentence))
        if is_file:
            file_count = 1
    if not rows and not file_count:
        rows = [int(n) for n in _TITLE_ROW.findall(title)]
    return tuple(rows), file_count, cites, not rows and not file_count


def _when(value: object) -> datetime | None:
    parsed: datetime | None = pr_state.parse_iso(value)
    return parsed


def extract_asks(repo: str, pr: dict[str, Any]) -> list[Ask]:
    """Every ask on one merged PR, from its body (marker only) and its comments."""
    number = int(pr["number"])
    merged = _when(pr.get("mergedAt"))
    if merged is None:
        raise ReadError(f"PR {number} has no readable mergedAt")
    url = str(pr.get("url") or "")
    title = str(pr.get("title") or "")
    # A marker in the body was written by the PR's creation at the latest.
    opened = _when(pr.get("createdAt")) or merged
    own = frozenset({(repo, number)})
    asks = [
        Ask(repo, number, merged, opened, "marker", url, rows, file_count, own)
        for rows, file_count in parse_marker(str(pr.get("body") or ""))
    ]
    for c in pr.get("comments") or []:
        if not isinstance(c, dict) or c.get("isMinimized"):
            continue
        if c.get("authorAssociation") not in TRUSTED_ASSOCIATIONS:
            continue
        body = str(c.get("body") or "")
        asked = _when(c.get("createdAt")) or merged
        curl = str(c.get("url") or url)
        markers = parse_marker(body)
        if markers:
            asks.extend(
                Ask(repo, number, merged, asked, "marker", curl, r, f, own) for r, f in markers
            )
            continue
        prose = parse_prose(body, title)
        if prose is None:
            continue
        rows, file_count, cites, unread = prose
        asks.append(
            Ask(
                repo, number, merged, asked, "prose", curl,
                rows=rows, file_count=file_count, cites=own | cites, unread=unread,
            )
        )  # fmt: skip
    return asks


def split_acts(asks: Iterable[Ask]) -> list[Ask]:
    """One ask per act (a row, a filing, an unread comment), the latest ask for each act only.

    The latest ask has the strictest baseline, and deduping before judging spares the ledger
    reads an earlier ask's baseline would cost.
    """
    latest: dict[tuple[str, int, object], Ask] = {}
    for ask in asks:
        acts: list[tuple[object, Ask]] = [
            (n, replace(ask, rows=(n,), file_count=0)) for n in ask.rows
        ]
        if ask.file_count:
            acts.append(("file", replace(ask, rows=())))
        if ask.unread:
            acts.append((("read", ask.url), ask))
        for act, one in acts:
            key = (ask.repo, ask.pr, act)
            if key not in latest or one.asked_at >= latest[key].asked_at:
                latest[key] = one
    return list(latest.values())


class Ledger(Protocol):
    def tip(self) -> tuple[str, str]:
        """``(sha, committer date)`` of the ledger ref."""

    def sha_before(self, when: datetime) -> str | None:
        """The ref's last first-parent commit at or before ``when``; ``None`` if none."""

    def blocks(self, sha: str) -> dict[int, str]:
        """Row number to banner block text (heading plus leading blockquotes) at ``sha``."""


def cite_count(text: str, prs: Iterable[Cite]) -> int:
    wanted = set(prs)
    return sum(1 for c in cited_prs(text) if c in wanted)


def judge(ask: Ask, ledger: Ledger, tip: dict[int, str]) -> list[Row]:
    if ask.unread:
        return [Row(READ, ask, "read the comment", "an ask word with no row or file ask in it")]
    out: list[Row] = []
    # DONE needs the tip block to cite the PR, so the baseline (a full ledger parse) is read only
    # when some named row's tip block does.
    cited = any(cite_count(tip.get(n, ""), ask.cites) for n in ask.rows)
    base_sha = ledger.sha_before(ask.baseline) if cited else None
    base = ledger.blocks(base_sha) if base_sha else {}
    for n in ask.rows:
        now = tip.get(n)
        if now is None:
            out.append(Row(MISSING, ask, f"row #{n}", "not in either ledger file at the ref"))
            continue
        before = base.get(n, "")
        acted = now != before and cite_count(now, ask.cites) > cite_count(before, ask.cites)
        out.append(
            Row(
                DONE if acted else OWED,
                ask,
                f"row #{n}",
                "banner changed and cites the PR"
                if acted
                else "banner unchanged since the baseline, or changed without citing the PR",
            )
        )
    if ask.file_count:
        # Filing may precede the merge (a finding is filed before it, under the 2026-10-12 rule),
        # so the filing baseline is the ask itself.
        asked_sha = ledger.sha_before(ask.asked_at)
        asked = ledger.blocks(asked_sha) if asked_sha else {}
        filed = sorted(
            n for n, text in tip.items() if n not in asked and cite_count(text, ask.cites)
        )
        done = len(filed) >= ask.file_count
        out.append(
            Row(
                DONE if done else OWED,
                ask,
                f"file {ask.file_count} row(s)",
                f"filed since, citing the PR: {', '.join(f'#{n}' for n in filed) or 'none'}",
            )
        )
    return out


def fetch_merged(gh: Gh, repo: str, since: datetime) -> list[dict[str, Any]]:
    out = gh(
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "merged",
            "--search",
            f"merged:>={since.strftime('%Y-%m-%d')}",
            "--limit",
            str(PR_LIMIT),
            "--json",
            "number,title,url,createdAt,mergedAt,body,comments",
        ],
        None,
    )
    try:
        prs = json.loads(out)
    except ValueError as exc:
        raise ReadError(f"gh pr list did not return JSON: {exc}") from exc
    if not isinstance(prs, list):
        raise ReadError("gh pr list did not return a list")
    if len(prs) >= PR_LIMIT:
        raise ReadError(f"{PR_LIMIT} or more merged PRs in the window; narrow --days")
    return [p for p in prs if isinstance(p, dict)]


class GitLedger:
    """The vault ledger read from a local checkout's git objects. Never touches its working tree."""

    def __init__(self, vault: Path, ref: str) -> None:
        self.vault = vault
        self.ref = ref
        try:
            checker = _load("_owed_ledger_acts_backlog_check", vault / PARSER_PATH)
        except (ImportError, OSError, SyntaxError) as exc:
            raise ReadError(f"cannot load the vault's parse_items: {exc}") from exc
        self.parse_items: Callable[[str], Sequence[Any]] = checker.parse_items
        self.sources: tuple[Path, ...] = tuple(checker.LEDGER_SOURCES)
        self._cache: dict[str, dict[int, str]] = {}
        self._before: dict[datetime, str | None] = {}

    def _git(self, *args: str) -> str:
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                # showSignature off: a signature line would corrupt the sha/date parse.
                ["git", "-C", str(self.vault), "-c", "log.showSignature=false", *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=GIT_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReadError(f"git {args[0]} failed: {exc}") from exc
        if proc.returncode != 0:
            raise ReadError(f"git {args[0]} failed: {proc.stderr.strip()[:200]}")
        return proc.stdout

    def tip(self) -> tuple[str, str]:
        sha, _, date = self._git("log", "-1", "--format=%H %cI", self.ref).strip().partition(" ")
        return sha, date

    def sha_before(self, when: datetime) -> str | None:
        if when not in self._before:
            out = self._git(
                "rev-list", "-1", "--first-parent", f"--before={pr_state.iso(when)}", self.ref
            ).strip()
            self._before[when] = out or None
        return self._before[when]

    def blocks(self, sha: str) -> dict[int, str]:
        if sha in self._cache:
            return self._cache[sha]
        result: dict[int, str] = {}
        for source in self.sources:
            try:
                text = self._git("show", f"{sha}:{source.as_posix()}")
            except ReadError:
                continue  # an archive file that did not exist yet at this commit
            lines = text.split("\n")
            for item in self.parse_items(text):
                result[int(item.num)] = "\n".join(lines[item.line - 1 : item.body_line - 1])
        if not result:
            raise ReadError(f"no ledger rows parsed at {sha[:10]}")
        self._cache[sha] = result
        return result


def collect(
    repos: Iterable[str], gh: Gh, ledger: Ledger, now: datetime, days: int
) -> tuple[list[Row], int, str]:
    """``(rows, PRs scanned, a description of the ledger tip)``."""
    since = now - timedelta(days=days)
    rows: list[Row] = []
    scanned = 0
    try:
        sha, date = ledger.tip()
        tip = ledger.blocks(sha)
    except ReadError as exc:
        return [Row(ERROR, None, "vault ledger", str(exc))], 0, "ledger unreadable"
    described = f"{sha[:10]} ({date})"
    for repo in repos:
        try:
            prs = fetch_merged(gh, repo, since)
        except (ReadError, pr_state.GhError, OSError) as exc:
            rows.append(Row(ERROR, None, repo, f"read failed: {exc}"[:300]))
            continue
        scanned += len(prs)
        for pr in prs:
            try:
                for ask in split_acts(extract_asks(repo, pr)):
                    rows.extend(judge(ask, ledger, tip))
            except (ReadError, KeyError, TypeError, ValueError) as exc:
                rows.append(Row(ERROR, None, f"{repo} PR {pr.get('number')}", str(exc)[:300]))
    return rows, scanned, described


_ORDER = {ERROR: 0, MISSING: 1, OWED: 2, READ: 3, DONE: 4}


def render(rows: list[Row], header: str, show_done: bool) -> str:
    shown = sorted(
        (r for r in rows if show_done or r.status != DONE),
        key=lambda r: (_ORDER[r.status], r.ask.repo if r.ask else "", r.ask.pr if r.ask else 0),
    )
    lines = [header]
    if not shown:
        lines.append("nothing owed")
    for r in shown:
        if r.ask is None:
            lines.append(f"{r.status:7}  {r.what}: {r.detail}")
            continue
        a = r.ask
        lines.append(
            f"{r.status:7}  {a.repo.split('/', 1)[1]} PR {a.pr} (merged {pr_state.iso(a.merged_at)})"
            f"  {r.what}  [{a.source}]  {r.detail}  {a.url}"
        )
    # Comment text and URLs come from GitHub: a control or bidi character must not rewrite a line.
    return "\n".join("".join(c if c.isprintable() else "?" for c in line) for line in lines)


def to_json(rows: list[Row]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        item: dict[str, Any] = {"status": r.status, "what": r.what, "detail": r.detail}
        if r.ask:
            a = r.ask
            item |= {
                "repo": a.repo,
                "pr": a.pr,
                "mergedAt": pr_state.iso(a.merged_at),
                "askedAt": pr_state.iso(a.asked_at),
                "source": a.source,
                "url": a.url,
            }
        out.append(item)
    return out


def main(
    argv: list[str] | None = None,
    *,
    gh: Gh = pr_state.run_gh,
    ledger: Ledger | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    ap = argparse.ArgumentParser(
        description="Ledger acts asked of the Lander on merged PRs that the vault ledger lacks."
    )
    ap.add_argument("--vault", type=Path, help="a vault checkout, read through git only")
    ap.add_argument("--ref", default=DEFAULT_REF, help=f"ledger ref (default {DEFAULT_REF})")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS, help="merge window in days")
    ap.add_argument(
        "--repo", action="append", choices=REPOS, help="repeatable; default engine+korus"
    )
    ap.add_argument("--all", action="store_true", help="also print asks already done")
    ap.add_argument("--json", action="store_true", help="emit a JSON list")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if ledger is None:
        if args.vault is None:
            print("ERROR    vault ledger: pass --vault <vault checkout>; nothing was read")
            return 0
        try:
            ledger = GitLedger(args.vault, args.ref)
        except ReadError as exc:
            print(f"ERROR    vault ledger: {exc}")
            return 0
    rows, scanned, tip = collect(args.repo or DEFAULT_REPOS, gh, ledger, now(), args.days)
    if args.json:
        print(json.dumps(to_json(rows), indent=2))
        return 0
    header = f"ledger {args.ref} {tip}; {scanned} merged PR(s) in the last {args.days} day(s)"
    print(render(rows, header, args.all))
    return 0


if __name__ == "__main__":
    sys.exit(main())
