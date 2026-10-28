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
with ``git show`` / ``git rev-list`` against a ref (``origin/main`` by default), the vault's ledger
parser included; it never fetches, checks out, reads the working tree or writes. A read that fails
prints an ERROR line naming the reason, never an empty list, because "nothing owed" and "could not
read" must not look alike. A bad command line still exits 2, argparse's usage error.

THE ASK. Two shapes, in a comment on a MERGED pull request by an OWNER, MEMBER or COLLABORATOR
(every seat posts under one login, so this keeps out outside accounts, not other seats), not
minimized:

* PRIMARY, machine-readable: ``<!-- lander-ledger-ask rows=#3844,#3025 file=2 -->``. ``rows`` names
  existing rows whose banner the Lander owes; ``file`` counts new rows to file. Either may be left
  out. It may also sit in the PR body. A comment carrying a marker is read for its marker only, and
  a marker that names nothing prints as READ rather than vanishing.
* FALLBACK, prose, deliberately loose so it over-reports rather than under-reports: a comment that
  names the Lander, and does not start like one of the Lander's own (``Lander (`` or ``Lander`` and
  a hex session id), is split into sentences. A sentence with an ask word (flip, banner, owed,
  close, or "file ... row") contributes its row numbers (``#N`` or ``row N``; pull request
  citations and ``repo#N`` are removed first) and, for "file ... row", a file ask whose count is
  the number the sentence puts before "rows" (one if none). With an ask word but no row in any
  such sentence, the comment's ``BACKLOG #N`` rows are taken, then the PR title's; with none at all
  it prints as READ, for a person to read.

WHEN AN ASK COUNTS AS DONE. Prose asks for one act are read as one, from the EARLIEST, so a later
reminder or acknowledgement cannot move the baseline past the act; a file ask takes the largest
count. Each marker is its own ask. A row's baseline is the later of the merge and the ask. A row
is DONE when it is CLOSED at the ledger ref (the vault parser's own verdict), or when its status
banner lines (the parser's ``_BANNER``, inside the block its ``parse_items`` cuts) cite the PR more
times at the ref than at the vault's last first-parent commit before the baseline. A citation is
``PR <N>``, ``PRs <N> and <M>`` or ``/pull/<N>``; a bare number is the engine, ``vault``/``korus``
qualify the others; the PR itself or one named in the ask sentence counts. A note, an in-place edit
of a banner that already cited the PR, or a banner that does not cite it, leaves the row OWED; so
does a baseline row with no banner line the parser recognises (a grammar change). A file ask is
DONE when at least that many rows absent at its ask now exist and cite the PR anywhere in their
block (filing may precede the merge). Everything else prints: OWED, MISSING (the row is in neither
ledger file at the ref), READ, and ERROR when no ledger commit precedes a baseline (a shallow
clone).

WHAT IT CANNOT SEE. At least: an ask sent only by fleet mail (so a Manager should also put the
marker on the PR), an ask in an inline review comment, an ask past the first 100 comments ``gh``
returns, a pull request merged before the window, and an act a pass recorded without citing the PR
in a banner line. A PARTIAL banner set ahead of the merge stays OWED. A later re-banner that drops the
citation puts a done act back on the report, the safe direction. The vault ledger's own PRs are
not read by default (``--repo`` adds them): a ledger PR's comments cite rows that the PR itself
changed, before its merge, and would read as owed.

Stdlib only. It loads ``pr_state.py`` by path for its gh runner, and the vault's
``scripts/docs/backlog_status_check.py`` from the ledger ref for ``parse_items``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple, Protocol

ENGINE_REPO = "MEFORORG/MessageFoundry"
VAULT_REPO = "MEFORORG/MessageFoundry-vault"
KORUS_REPO = "MEFORORG/korus"
REPOS = (ENGINE_REPO, VAULT_REPO, KORUS_REPO)
DEFAULT_REPOS = (ENGINE_REPO, KORUS_REPO)
DEFAULT_REF = "origin/main"
DEFAULT_DAYS = 14
#: Measured 2026-10-28: 278 engine PRs merged in 14 days, so 300 was too close.
PR_LIMIT = 1000
GIT_TIMEOUT = 300
GH_TIMEOUT = 300
#: Ledger snapshots kept besides the tip: each is a full parse of a ~23 MB file.
CACHE_SIZE = 4
PARSER_PATH = "scripts/docs/backlog_status_check.py"

TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
#: How the Lander's own comments start: ``Lander (session ...``, ``Lander (local_...``,
#: ``Lander b58f86:``, ``Lander decision``, ``QA (Lander``, and its routine ``Lander: enqueuing``
#: and similar. A bare ``Lander:`` is not here, because Managers address the Lander that way.
_LANDER_OWN = re.compile(
    r"\s*(?:Lander (?:\(|[0-9a-f]{6,}\b|decision\b)|QA \(Lander"
    r"|Lander:\s+(?:enqueu|re-enqueu|dequeu|held\b|merged\b|armed\b|review proof))",
    re.IGNORECASE,
)

_MARKER = re.compile(r"<!--\s*lander-ledger-ask\b(?P<attrs>[^>]{0,400}?)-->")
#: ``rows=`` (or ``row=``) takes every number up to the next ``key=`` or the marker's end, so any
#: separator works.
_MARKER_ROWS = re.compile(r"\brows?\s*=(?P<v>[^=]*?)(?=\s\w+\s*=|$)")
_MARKER_FILE = re.compile(r"\bfile\s*=\s*(?P<v>\d{1,3})\b")
_NUMBER = re.compile(r"\d{1,6}")
#: A row reference: ``#N`` or ``row N``. Pull request citations are removed before this runs.
_ROW_REF = re.compile(r"(?<![\w/])#(\d{1,6})\b|\brows?\s+(\d{1,6})\b", re.IGNORECASE)
#: The count a filing sentence asks for: "Eight NEW ledger rows", "3 rows".
_COUNT_WORDS = {
    w: i
    for i, w in enumerate(
        ["zero", "one", "two", "three", "four", "five", "six"]
        + ["seven", "eight", "nine", "ten", "eleven", "twelve"]
    )
}
_FILE_COUNT = re.compile(
    rf"\b(\d{{1,3}}|{'|'.join(_COUNT_WORDS)})\s+(?:[\w-]+\s+){{0,5}}?rows\b", re.IGNORECASE
)
_FILE_ASK_RE = r"\bfile\b[^.\n]{0,40}?\brows?\b|\brows?\b[^.\n]{0,20}?\bto file\b"
_FILE_ASK = re.compile(_FILE_ASK_RE, re.IGNORECASE)
_ASK_WORD = re.compile(
    rf"\bflip|\bbanner|\bowed\b|\bclos(?:e|es|ing)\b|{_FILE_ASK_RE}", re.IGNORECASE
)
_SENTENCE = re.compile(r"\n+|(?<=[.!?])\s+")
#: ``BACKLOG #N``: the fallback rows of a comment, then of the PR title.
_TITLE_ROW = re.compile(r"\bBACKLOG\s+#(\d{1,6})\b", re.IGNORECASE)
#: A pull request citation, with an optional repository word before it and a list after it
#: (``engine PRs 2545 and 2546``). Unqualified means the engine: the ledger writes "engine PR N" or
#: "PR N" for the engine and "vault PR N" / "korus PR N" for the others.
_PR_CITE = re.compile(
    r"(?:\b(?P<word>engine|vault|korus)\s+)?\b(?:PRs?|pull requests?)\s*"
    r"(?P<list>#\d{1,6}(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)#\d{1,6}\b(?!-))*"
    r"|\d{1,6}(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)\d{1,6}\b(?!-))*)\b"
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
# This private copy of pr_state only: a paginated list with bodies and comments outlasts the
# poller's 30 seconds (measured 15.8 s for 278 PRs).
pr_state.__dict__["GH_TIMEOUT_SECONDS"] = GH_TIMEOUT

#: ``gh(args, stdin) -> stdout``, pr_state's runner: a by-path module is Any to mypy.
Gh = Callable[[list[str], str | None], str]


class ReadError(RuntimeError):
    """A GitHub or vault read could not be completed."""


class Block(NamedTuple):
    """One ledger row's banner block: its text, and the status banner lines within it."""

    text: str
    banners: tuple[str, ...]
    #: The vault parser's verdict: a CLOSED banner and no OPEN one.
    closed: bool = False


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
    #: An ask this script could not extract; a person reads it.
    unread: bool = False

    @property
    def baseline(self) -> datetime:
        """A flip is owed after the merge (a filing uses ``asked_at`` alone)."""
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
        attrs = m.group("attrs").strip()
        rows_m = _MARKER_ROWS.search(attrs)
        file_m = _MARKER_FILE.search(attrs)
        rows = tuple(int(n) for n in _NUMBER.findall(rows_m.group("v"))) if rows_m else ()
        out.append((rows, int(file_m.group("v")) if file_m else 0))
    return out


def cited_prs(text: str) -> list[Cite]:
    """Every pull request ``text`` cites, with repeats, as ``(owner/repo, number)``."""
    out: list[Cite] = []
    for m in _PR_CITE.finditer(text):
        if m.group("list"):
            repo = _REPO_WORD[(m.group("word") or "engine").lower()]
            out.extend((repo, int(n)) for n in _NUMBER.findall(m.group("list")))
        else:
            out.append((_REPO_SLUG[m.group("slug").lower()], int(m.group("un"))))
    return out


def row_refs(text: str) -> list[int]:
    """Row numbers ``text`` names, in order, without repeats; pull request citations excluded."""
    out: list[int] = []
    for a, b in _ROW_REF.findall(_PR_CITE.sub(" ", text)):
        n = int(a or b)
        if n not in out:
            out.append(n)
    return out


def parse_prose(text: str, title: str = "") -> tuple[tuple[int, ...], int, set[Cite], bool] | None:
    """``(rows, file_count, cited PRs, unread)`` for a Lander-addressed prose ask, else ``None``."""
    if "Lander" not in text or _LANDER_OWN.match(text):
        return None
    if not _ASK_WORD.search(text):
        return None
    rows: list[int] = []
    cites: set[Cite] = set()
    file_count = 0
    for sentence in _SENTENCE.split(text):
        if not _ASK_WORD.search(sentence):
            continue
        found = row_refs(sentence)
        is_file = bool(_FILE_ASK.search(sentence))
        if found or is_file:
            rows.extend(n for n in found if n not in rows)
            cites |= set(cited_prs(sentence))
        if is_file:
            file_count = max([file_count, 1] + [_count(c) for c in _FILE_COUNT.findall(sentence)])
    if not rows and not file_count:
        # The ask word and the row can sit in different sentences ("BACKLOG #3844 ships here.
        # Please flip it."): take the comment's BACKLOG rows, then the title's.
        rows = [int(n) for n in _TITLE_ROW.findall(text)] or [
            int(n) for n in _TITLE_ROW.findall(title)
        ]
        rows = list(dict.fromkeys(rows))
        cites |= set(cited_prs(text))
    return tuple(rows), file_count, cites, not rows and not file_count


def _count(word: str) -> int:
    return int(word) if word.isdigit() else _COUNT_WORDS[word.lower()]


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
    own = frozenset({(repo, number)})

    def marked(asked: datetime, where: str, rows: tuple[int, ...], files: int) -> Ask:
        return Ask(
            repo, number, merged, asked, "marker", where, rows, files, own, not rows and not files
        )

    # A marker in the body was written by the PR's creation at the latest.
    opened = _when(pr.get("createdAt")) or merged
    asks = [marked(opened, url, r, f) for r, f in parse_marker(str(pr.get("body") or ""))]
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
            asks.extend(marked(asked, curl, r, f) for r, f in markers)
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
    """One ask per act (a row, a filing, an unread comment).

    Asks for one act merge into the EARLIEST, so a later reminder or "done" note cannot move the
    baseline past the act; the citations are pooled and a filing keeps the largest count.
    """
    merged: dict[tuple[str, int, object, str], Ask] = {}
    for ask in asks:
        acts: list[tuple[object, Ask]] = [
            (n, replace(ask, rows=(n,), file_count=0)) for n in ask.rows
        ]
        if ask.file_count:
            acts.append(("file", replace(ask, rows=())))
        if ask.unread:
            acts.append((("read", ask.url), ask))
        for act, one in acts:
            # A marker is a deliberate, separate ask (a second filing round, a re-flip), so it is
            # never folded into an earlier one; prose repeats are.
            key = (ask.repo, ask.pr, act, ask.url if ask.source == "marker" else "")
            if (have := merged.get(key)) is not None:
                first = have if have.asked_at <= one.asked_at else one
                one = replace(
                    first,
                    cites=have.cites | one.cites,
                    file_count=max(have.file_count, one.file_count),
                )
            merged[key] = one
    return list(merged.values())


class Ledger(Protocol):
    def tip(self) -> tuple[str, str]:
        """``(sha, committer date)`` of the ledger ref."""

    def sha_before(self, when: datetime) -> str | None:
        """The ref's last first-parent commit at or before ``when``; ``None`` if none."""

    def blocks(self, sha: str) -> dict[int, Block]:
        """Row number to its banner block at ``sha``."""


def cite_count(text: str, prs: Iterable[Cite]) -> int:
    wanted = set(prs)
    return sum(1 for c in cited_prs(text) if c in wanted)


def judge(ask: Ask, ledger: Ledger, tip: dict[int, Block]) -> list[Row]:
    if ask.unread:
        return [Row(READ, ask, "read the comment", "an ask this script could not extract")]
    out: list[Row] = []
    for n in ask.rows:
        now = tip.get(n)
        what = f"row #{n}"
        if now is None:
            out.append(Row(MISSING, ask, what, "not in either ledger file at the ref"))
            continue
        if now.closed:
            out.append(Row(DONE, ask, what, "the row is CLOSED at the ref"))
            continue
        cites_now = sum(cite_count(line, ask.cites) for line in now.banners)
        if not cites_now:  # DONE needs one, so the baseline (a full ledger parse) is not read
            out.append(Row(OWED, ask, what, "no banner line cites the PR"))
            continue
        base_sha = ledger.sha_before(ask.baseline)
        if base_sha is None:
            out.append(Row(ERROR, ask, what, "no ledger commit before the baseline (shallow?)"))
            continue
        before = ledger.blocks(base_sha).get(n)
        if before is not None and not before.banners:
            out.append(Row(OWED, ask, what, "the baseline row has no banner the parser reads"))
            continue
        cites_then = sum(cite_count(line, ask.cites) for line in before.banners) if before else 0
        acted = cites_now > cites_then
        out.append(
            Row(
                DONE if acted else OWED,
                ask,
                what,
                "its banners cite the PR more than at the baseline"
                if acted
                else "its banners cite the PR no more than at the baseline",
            )
        )
    if ask.file_count:
        # Filing may precede the merge (a finding is filed before it, under the 2026-10-12 rule),
        # so the filing baseline is the ask itself.
        asked_sha = ledger.sha_before(ask.asked_at)
        if asked_sha is None:
            return [*out, Row(ERROR, ask, "file", "no ledger commit before the ask (shallow?)")]
        asked = ledger.blocks(asked_sha)
        filed = sorted(
            n for n, b in tip.items() if n not in asked and cite_count(b.text, ask.cites)
        )
        out.append(
            Row(
                DONE if len(filed) >= ask.file_count else OWED,
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


#: git's answer when a path is absent at a commit: an archive file that did not exist yet.
_ABSENT_PATH = ("does not exist in", "exists on disk, but not in")


class GitLedger:
    """The vault ledger read from a checkout's git objects at ``ref``. Never reads its work tree."""

    def __init__(self, vault: Path, ref: str) -> None:
        self.vault = vault
        self.ref = ref
        # The parser comes from the ref too, so it matches the ledger it cuts, whatever branch a
        # peer has the shared checkout on.
        source = self._git("show", f"{ref}:{PARSER_PATH}")
        name = "_owed_ledger_acts_backlog_check"
        checker = ModuleType(name)
        checker.__file__ = f"{ref}:{PARSER_PATH}"
        sys.modules[name] = checker  # dataclasses and friends look the module up by name
        try:
            # The vault's own parser at the ref, the single owner of the banner grammar.
            exec(compile(source, checker.__file__, "exec"), checker.__dict__)  # nosec B102
            self.parse_items: Callable[[str], Sequence[Any]] = checker.parse_items
            self.banner: re.Pattern[str] = checker._BANNER
            self.sources: tuple[str, ...] = tuple(
                Path(p).as_posix() for p in checker.LEDGER_SOURCES
            )
        except Exception as exc:  # any failure in foreign code is a read failure, reported
            raise ReadError(f"cannot load the vault's parser at {ref}: {exc!r}") from exc
        self._cache: OrderedDict[str, dict[int, Block]] = OrderedDict()
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

    def blocks(self, sha: str) -> dict[int, Block]:
        if sha in self._cache:
            self._cache.move_to_end(sha)
            return self._cache[sha]
        result: dict[int, Block] = {}
        for source in self.sources:
            try:
                text = self._git("show", f"{sha}:{source}")
            except ReadError as exc:
                if any(s in str(exc) for s in _ABSENT_PATH):
                    continue
                raise  # a timeout or a missing blob must not leave a partial ledger
            # parse_items numbers lines with splitlines(), which breaks on more than "\n".
            lines = text.splitlines()
            try:
                for item in self.parse_items(text):
                    cut = lines[item.line - 1 : item.body_line - 1]
                    result[int(item.num)] = Block(
                        "\n".join(cut),
                        tuple(ln for ln in cut if self.banner.match(ln)),
                        bool(item.closed) and not item.open,
                    )
            except Exception as exc:  # the vault parser refusing the ledger is a read failure
                raise ReadError(
                    f"the vault parser refused {source} at {sha[:10]}: {exc!r}"
                ) from exc
        if not result:
            raise ReadError(f"no ledger rows parsed at {sha[:10]}")
        self._cache[sha] = result
        while len(self._cache) > CACHE_SIZE + 1:  # the tip plus CACHE_SIZE baselines
            self._cache.popitem(last=False)
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
        return [Row(ERROR, None, "vault ledger", str(exc)[:300])], 0, "unreadable"
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
            except (ReadError, LookupError, TypeError, ValueError) as exc:
                rows.append(Row(ERROR, None, f"{repo} PR {pr.get('number')}", str(exc)[:300]))
    return rows, scanned, described


_ORDER = {ERROR: 0, MISSING: 1, OWED: 2, READ: 3, DONE: 4}


def shown(rows: list[Row], show_done: bool) -> list[Row]:
    return sorted(
        (r for r in rows if show_done or r.status != DONE),
        key=lambda r: (_ORDER[r.status], r.ask.repo if r.ask else "", r.ask.pr if r.ask else 0),
    )


def render(rows: list[Row], header: str) -> str:
    lines = [header]
    if not rows:
        lines.append("nothing owed")
    for r in rows:
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


def to_json(rows: list[Row], ledger: str, scanned: int) -> dict[str, Any]:
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
    # The ledger tip and the scan count travel with the rows, so an empty list with nothing
    # scanned cannot pass for "nothing owed".
    return {"ledger": ledger, "scannedPullRequests": scanned, "rows": out}


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
    ap.add_argument("--json", action="store_true", help="emit a JSON object")
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
            print(f"ERROR    vault ledger: {exc}"[:400])
            return 0
    rows, scanned, tip = collect(args.repo or DEFAULT_REPOS, gh, ledger, now(), args.days)
    rows = shown(rows, args.all)
    if args.json:
        print(json.dumps(to_json(rows, f"{args.ref} {tip}", scanned), indent=2))
        return 0
    header = f"ledger {args.ref} {tip}; {scanned} merged PR(s) in the last {args.days} day(s)"
    print(render(rows, header))
    return 0


if __name__ == "__main__":
    sys.exit(main())
