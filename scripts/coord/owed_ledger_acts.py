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

THE DEFECT CLASS IS A MISSED ACT. Every rule below leans toward printing an ask that may already be
done (an over-report a person clears in seconds) rather than calling one DONE that is not.

READ-ONLY, AND ALWAYS EXIT 0. It is a report, not a gate. It reads GitHub with ``gh`` and the vault
ledger as text with ``git log`` / ``ls-tree`` / ``cat-file`` against a ref (``origin/main`` by
default); it never fetches, checks out, reads the working tree, writes, or runs any code from the
vault. The ledger's heading and status-banner grammar is restated here (``parse_ledger``) rather
than loaded from the vault, so whoever can push the vault cannot run code as the reader. A read
that fails
prints an ERROR line naming the reason, never an empty list, because "nothing owed" and "could not
read" must not look alike. A bad command line still exits 2, argparse's usage error.

THE ASK. Two shapes, in a comment on a MERGED pull request by an OWNER, MEMBER or COLLABORATOR
(every seat posts under one login, so this keeps out outside accounts, not other seats), not
minimized:

* PRIMARY, machine-readable: ``<!-- lander-ledger-ask rows=#3844,#3025 file=2 -->``. ``rows`` names
  existing rows whose banner the Lander owes; ``file`` counts new rows to file. Either may be left
  out. It may also sit in the PR body; on a fork PR's body it prints as READ, since an outside
  account wrote it. A marker inside a code span, a fenced block or a quoted line is an example, not
  an ask. A comment carrying a marker is read for its marker only. A marker that names nothing,
  carries an unknown key or a malformed value, or is not closed prints as READ, beside whatever it
  did name.
* FALLBACK, prose. A comment that names the Lander (any case) is split into sentences. A sentence
  with an ask word (at least flip, banner, owed, close, mark, re-open, status, retire, decline, or
  "file ... rows/findings", "rows follow") contributes its row numbers (``#N``, ``row(s) N and M``,
  a range ``N-M``, ``BACKLOG #N``; pull request citations and ``repo#N`` are removed first). A flip
  sentence with no row borrows the rows of the nearest sentence before it (two back), else the next
  one, and adds every ``BACKLOG #N`` of the comment, else of the PR title; with no row at all and
  no filing it prints as READ, for a person to read. A filing sentence's count is the nearest count
  before each "rows"/"findings" in it, summed ("13 open findings", "2 rows for A and 3 rows for B");
  a filing sentence with no count, or "a row for each finding", makes the count UNKNOWN. The
  Lander's own comments (first line ``<!-- lander-hold`` or ``Lander (session``) are read for their
  filings only: its enqueue comment is where the rows it owes after a merge are recorded. This read
  errs toward over-reporting, but it can still miss an ask phrased in words it does not know, which
  is why the marker is the reliable form.

WHEN AN ASK COUNTS AS DONE. Prose asks for one row are read as one, from the EARLIEST, so a later
reminder or acknowledgement cannot move the baseline past the act. Each marker is its own ask. A
row's baseline is the later of the merge and the ask, read at the vault's last first-parent commit
at or before it. A row is DONE only when it CHANGED after the baseline: it was OPEN there and is
CLOSED at the ref; or a banner line new since the baseline cites the PR and does not say the act is
still owed (owed, flip, pending, waits), and either the row was CLOSED at the baseline (a re-open or
a re-banner) or its set of status glyphs changed. A row absent at the baseline, or with no banner
line the grammar recognises there (a grammar change), stays OWED. A citation is ``engine PR <N>``,
``vault PRs <N> and <M>``, ``korus PR <N>`` or a ``/pull/<N>`` URL; a ledger citation without its
repository word counts for nothing, because the vault writes a bare ``PR <N>`` for its own pull
requests too. (In an ask, a bare PR is the repository the comment sits on.) The PR itself or one
named in the ask sentence counts. FILING asks on one PR are SUMMED, every marker and prose ask
alike, and are DONE only when the total is known and at least that many rows absent at the earliest
filing ask now exist and cite this PR, with its repository word, anywhere in their block (filing may
precede the merge). Statuses printed: OWED, MISSING (the row is in neither ledger file at the ref),
READ, ERROR (a failed read, or no ledger commit before a baseline: a shallow clone), and DONE with
``--all``.

WHAT IT CANNOT SEE. At least: an ask sent only by fleet mail (so a Manager should also put the
marker on the PR), an ask in an inline review comment, an ask past the first 100 comments ``gh``
returns, a pull request merged before the window, a prose ask in words it does not know, a ledger
file the vault adds beyond ``LEDGER_SOURCES`` (its rows print as MISSING), and an act a pass
recorded without citing the PR, with its repository word, in a banner line. A row filed after the
ask that cites the PR for another reason (an ASVS follow-up, say) counts toward its filing. A later
re-banner that drops the citation puts a done act back on the report, the safe direction. The
vault ledger's own PRs are not read by default (``--repo`` adds them): a ledger PR's comments cite rows that the PR
itself changed, before its merge, and would read as owed.

Stdlib only. It loads ``pr_state.py`` by path for its gh runner.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Iterable
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

# ---- The vault ledger's grammar, restated so that no vault code runs here. ----------------------
#: The ledger files, in the order of the vault's ``LEDGER_SOURCES`` (its
#: ``scripts/docs/backlog_status_check.py`` at ``origin/main`` on 2026-10-28). A file the vault
#: adds later is not read, so its rows print as MISSING: the safe direction.
LEDGER_SOURCES = ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md")
#: The status glyphs, written as escapes because this repository forbids new glyphs in source:
#: CLOSED is shipped, declined, retired; OPEN is prioritized, in progress.
_CLOSED_GLYPHS = "\u2705\u26d4\U0001faa6"
_OPEN_GLYPHS = "\U0001f522\U0001f6a7"
#: A status banner line: ``> `` then a status glyph (an optional variation selector) and a space.
_BANNER = re.compile(rf"^>\s(?P<glyph>[{_CLOSED_GLYPHS}{_OPEN_GLYPHS}])\ufe0f?\s")
_HEADING = re.compile(r"^## (?P<num>\d+)\.\s")
#: A line shaped like a banner whose first character is outside ASCII, to catch a glyph the
#: vault added after this copy was written.
_BANNER_SHAPE = re.compile(r"^>\s(?P<glyph>[^\x00-\x7f])")
#: The decorative glyphs that open blockquote lines in the vault ledger, measured over both files
#: at vault ``origin/main`` on 2026-10-28 (warning sign, tools, pushpin, ruler, up arrow, magnifier,
#: circles, compass, lock, repeat, star). They are not statuses, so a row carrying one keeps the
#: vault's verdict. Any other symbol in that place is treated as a status this copy does not know.
_DECORATION = frozenset(
    map(chr, (0x26A0, 0x1F6E0, 0x1F4CC, 0x1F4D0, 0x2B06, 0x1F50E, 0x1F7E2, 0x1F536, 0x1F9ED))
) | frozenset(map(chr, (0x1F512, 0x1F501, 0x2B50)))
#: The vault parser refuses a conflicted ledger, which would otherwise yield rows from both sides.
_CONFLICT = re.compile(r"^(?:<{7}|>{7})(?:\s|$)", re.MULTILINE)

TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
#: The Lander's own comments, by the exact shapes it writes on its FIRST line: a hold marker, or
#: ``Lander (session <id>)``. Nothing looser: a Manager writes "Lander (8a04c9f3): flip #N" or
#: "Lander: ..." when addressing it, and that is an ask.
_LANDER_OWN = re.compile(r"(?:<!--\s*lander-hold\b|Lander \(session\s)")
_LANDER = re.compile(r"\blander\b", re.IGNORECASE)

#: A marker's opening; its closing ``-->`` is looked for within ``_MARKER_SPAN`` characters.
_MARKER_OPEN = re.compile(r"<!--\s*lander-ledger-ask\b")
_MARKER_SPAN = 2000
_MARKER_KEY = re.compile(r"(?P<key>[A-Za-z_][\w-]*)\s*=")
_NUMBER = re.compile(r"\d{1,6}")
#: What may separate a marker's row numbers, once the numbers are taken out.
_MARKER_ROW_JUNK = re.compile(r"[\s,;#]+|\band\b", re.IGNORECASE)
#: The opening of a fenced code block, indented at most three spaces. A backtick fence's info
#: string holds no backtick, so a line like ```x``` is an inline span, not a fence.
_FENCE = re.compile(r"^ {0,3}(?P<run>`{3,}|~{3,})(?P<info>.*)$")
_CODE_SPAN = re.compile(
    r"(?<!`)(?P<run>`+)(?!`)(?:(?!\n[ \t]*\n).)+?(?<!`)(?P=run)(?!`)", re.DOTALL
)

#: One number in a list: not the start of a date, a time or a dotted version.
_END = r"\b(?![-:/.]\d)"
_N = rf"#?\d{{1,6}}{_END}"
#: A row in a list may be a range, ``3844-3846``.
_ITEM = rf"#?\d{{1,6}}(?:\s*-\s*#?\d{{1,6}})?{_END}"
_SEP = r"(?:\s*[,;]\s*(?:and\s+)?|\s+and\s+|\s*/\s*)"
_LIST = rf"{_N}(?:{_SEP}{_N})*"
_ROW_LIST = rf"{_ITEM}(?:{_SEP}{_ITEM})*"
#: A number, or a range of them, inside a matched list.
_RANGE = re.compile(r"(\d{1,6})(?:\s*-\s*#?(\d{1,6}))?")
#: The widest range read as every row in it; a wider one is read as its two ends.
_RANGE_MAX = 50
#: ``BACKLOG``, ``BACKLOG rows``, ``BACKLOG item``: the word before a row list.
_BACKLOG_WORD = r"BACKLOG(?:\s+(?:rows?|items?))?"
#: A row reference: ``#N``, ``row N``, ``rows N and M``, ``BACKLOG #N, #M``. Pull request citations
#: are removed before this runs.
_ROW_REF = re.compile(
    r"(?<![\w/])#(?P<hash>\d{1,6}(?:\s*-\s*#?\d{1,6}\b)?)\b"
    rf"|\b(?:rows?|{_BACKLOG_WORD})\s+(?P<list>{_ROW_LIST})",
    re.IGNORECASE,
)
_BACKLOG_REF = re.compile(rf"\b{_BACKLOG_WORD}\s+(?P<list>{_ROW_LIST})", re.IGNORECASE)
#: A pull request citation. A plural (``engine PRs 2545 and 2546``) takes a list; a singular takes
#: one number, so "PR #2546 and #3025" leaves row #3025 alone. The repository word is optional and
#: its absence is reported as ``None`` unless the caller names a default.
_PR_CITE = re.compile(
    r"(?:\b(?P<word>engine|vault|korus)\s+)?"
    rf"(?:\b(?:PRs|pull\s+requests)\s*(?P<list>{_LIST})"
    rf"|\b(?:PR|pull\s+request)\s*(?P<one>{_N}))"
    r"|/(?P<slug>MessageFoundry-vault|MessageFoundry|korus)/pull/(?P<un>\d{1,6})\b",
    re.IGNORECASE,
)
_REPO_WORD = {"engine": ENGINE_REPO, "vault": VAULT_REPO, "korus": KORUS_REPO}
_REPO_SLUG = {
    "messagefoundry": ENGINE_REPO,
    "messagefoundry-vault": VAULT_REPO,
    "korus": KORUS_REPO,
}

_COUNT_WORDS = {
    w: i
    for i, w in enumerate(
        ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]
        + ["eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen"]
        + ["eighteen", "nineteen", "twenty"]
    )
}
_NOUN = r"(?:rows?|findings?|items?|entries|entry)"
_NOUN_RE = re.compile(rf"\b(?P<noun>{_NOUN})\b", re.IGNORECASE)
#: A count word: "8", "eight", or the article in "a row".
_COUNT_TOKEN = re.compile(
    rf"(?<![#\w-])(?:\d{{1,3}}|{'|'.join(_COUNT_WORDS)}|an?)(?![\w-])", re.IGNORECASE
)
#: How many words before a noun its count may sit: "Eight NEW ledger rows".
_COUNT_REACH = 5
#: "a row for each finding": the count is per finding, so it is not stated.
_EACH = re.compile(r"\s+(?:for\s+(?:each|every)|per|each)\b", re.IGNORECASE)
_PLURAL_NOUNS = frozenset({"rows", "findings", "items", "entries"})
_FILE_ASK = re.compile(
    rf"\bfil(?:e|ing)\b[^.\n]{{0,60}}?\b{_NOUN}\b|\b{_NOUN}\b[^.\n]{{0,40}}?\bto (?:be )?filed?\b"
    r"|\brows?\b[^.\n]{0,20}?\bfollow",
    re.IGNORECASE,
)
_FLIP_WORD = re.compile(
    r"\bflip|\bbanner|\bowed\b|\bclos(?:e|es|ed|ing)\b|\bmark(?:s|ed|ing)?\b|\bre-?open"
    r"|\bstatus\b|\bretir(?:e|es|ed|ing)\b|\bdeclin(?:e|es|ed|ing)\b",
    re.IGNORECASE,
)
#: A new banner line that says the act is still to come is not the act.
_STILL_OWED = re.compile(r"\bowed\b|\bflip\b|\bpending\b|\bawait|\bwaits?\b|\bnot yet\b", re.I)
_SENTENCE = re.compile(r"\n+|(?<=[.!?])\s+")

#: A cited pull request: ``(owner/repo, number)``; the repository is ``None`` when the text did not
#: name it.
Cite = tuple[str | None, int]

DONE, OWED, MISSING, READ, ERROR = "DONE", "OWED", "MISSING", "READ", "ERROR"
_UNEXTRACTED = "an ask this script could not extract"

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
    #: A CLOSED glyph and no OPEN one, the vault's own verdict; never True when a banner-shaped
    #: line carries a symbol this copy of the grammar does not know.
    closed: bool = False
    #: The status glyphs its banner lines carry.
    status: frozenset[str] = frozenset()


def _merge_blocks(a: Block, b: Block) -> Block:
    """A row number seen twice (mid-move between the files): OPEN if either copy is."""
    return Block(
        f"{a.text}\n{b.text}", a.banners + b.banners, a.closed and b.closed, a.status | b.status
    )


def _unknown_glyph(line: str) -> bool:
    shape = _BANNER_SHAPE.match(line)
    if shape is None or _BANNER.match(line):
        return False
    glyph = shape.group("glyph")
    known = glyph in _CLOSED_GLYPHS or glyph in _OPEN_GLYPHS or glyph in _DECORATION
    return unicodedata.category(glyph) == "So" and not known


def _put(out: dict[int, Block], num: int, block: Block) -> None:
    out[num] = _merge_blocks(out[num], block) if num in out else block


def parse_ledger(text: str) -> dict[int, Block]:
    """Row number to its banner block: the heading and the blank or ``>`` lines under it."""
    conflict = _CONFLICT.search(text)
    if conflict is not None:
        line = text.count("\n", 0, conflict.start()) + 1
        raise ReadError(f"a git conflict marker at ledger line {line}")
    lines = text.splitlines()
    out: dict[int, Block] = {}
    i = 0
    while i < len(lines):
        heading = _HEADING.match(lines[i])
        if heading is None:
            i += 1
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].startswith(">")):
            j += 1
        cut = lines[i:j]
        banners = [(ln, m.group("glyph")) for ln in cut if (m := _BANNER.match(ln))]
        status = frozenset(g for _, g in banners)
        closed = (
            any(g in _CLOSED_GLYPHS for g in status)
            and not any(g in _OPEN_GLYPHS for g in status)
            and not any(_unknown_glyph(ln) for ln in cut)
        )
        block = Block("\n".join(cut), tuple(ln for ln, _ in banners), closed, status)
        num = int(heading.group("num"))
        _put(out, num, block)
        i = j
    return out


@dataclass(frozen=True)
class Ask:
    repo: str
    pr: int
    merged_at: datetime
    asked_at: datetime
    source: str  # "marker", "prose", or "marker+prose" for summed filings
    url: str
    rows: tuple[int, ...] = ()
    #: Rows to file; with ``file_unknown`` this is a lower bound.
    file_count: int = 0
    #: A filing was asked with no count this script could read: never DONE.
    file_unknown: bool = False
    #: PRs whose citation in a banner counts as the act: this PR plus any the ask sentence names.
    cites: frozenset[Cite] = frozenset()
    #: An ask this script could not (fully) extract; a person reads it.
    unread: bool = False
    note: str = ""

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


class Marker(NamedTuple):
    rows: tuple[int, ...]
    file_count: int
    #: What could not be read, for a READ line.
    problems: tuple[str, ...] = ()


def _live_text(text: str) -> str:
    """``text`` less its fenced code blocks, quoted lines and code spans: where an example lives."""
    kept: list[str] = []
    fence = ""
    for line in text.splitlines():
        if fence:
            stripped = line.strip()
            if stripped.startswith(fence) and not stripped.lstrip(fence[0]):
                fence = ""
            continue
        opened = _FENCE.match(line)
        if opened is not None and not (opened["run"][0] == "`" and "`" in opened["info"]):
            fence = opened.group("run")
            continue
        if line.lstrip().startswith(">"):
            continue
        kept.append(line)
    return _CODE_SPAN.sub(" ", "\n".join(kept))


def _marker_attrs(attrs: str) -> Marker:
    keys = list(_MARKER_KEY.finditer(attrs))
    problems: list[str] = []
    lead = attrs[: keys[0].start()] if keys else attrs
    if lead.strip():
        problems.append(f"unrecognised text {lead.strip()[:40]!r}")
    rows: list[int] = []
    files = 0
    for k, m in enumerate(keys):
        end = keys[k + 1].start() if k + 1 < len(keys) else len(attrs)
        key, value = m.group("key").lower(), attrs[m.end() : end].strip()
        if key in ("rows", "row"):
            digits = re.findall(r"\d+", value)
            if not digits or _MARKER_ROW_JUNK.sub("", re.sub(r"\d+", "", value)):
                problems.append(f"{key}={value[:40]!r} is not a list of row numbers")
            if any(len(d) > 6 for d in digits):  # "#38443025": a missing separator
                problems.append(f"{key}={value[:40]!r} holds a number too long for a row")
            rows.extend(n for n in map(int, digits) if len(str(n)) <= 6 and n not in rows)
        elif key == "file":
            if re.fullmatch(r"\d{1,3}", value):
                files += int(value)
            else:
                problems.append(f"file={value[:40]!r} is not a number")
        else:
            problems.append(f"unknown key {m.group('key')[:40]!r}")
    return Marker(tuple(rows), files, tuple(problems))


def parse_marker(text: str) -> list[Marker]:
    """Every ``lander-ledger-ask`` marker in ``text`` outside code and quotes."""
    if "lander-ledger-ask" not in text:
        return []
    live = _live_text(text)
    out = []
    for m in _MARKER_OPEN.finditer(live):
        end = live.find("-->", m.end(), m.end() + _MARKER_SPAN)
        if end < 0:
            out.append(Marker((), 0, ("a marker with no closing '-->'",)))
            continue
        out.append(_marker_attrs(live[m.end() : end]))
    return out


def cited_prs(text: str, bare: str | None = None) -> list[Cite]:
    """Every pull request ``text`` cites, with repeats; one with no repository word is ``bare``."""
    out: list[Cite] = []
    for m in _PR_CITE.finditer(text):
        if m.group("slug"):
            out.append((_REPO_SLUG[m.group("slug").lower()], int(m.group("un"))))
            continue
        word = m.group("word")
        repo = _REPO_WORD[word.lower()] if word else bare
        out.extend((repo, int(n)) for n in _NUMBER.findall(m.group("list") or m.group("one")))
    return out


def _numbers(found: Iterable[str]) -> list[int]:
    """The numbers in each matched list, a range ``a-b`` read as every row in it."""
    out: list[int] = []
    for chunk in found:
        for m in _RANGE.finditer(chunk):
            first, last = int(m.group(1)), int(m.group(2) or m.group(1))
            span = range(first, last + 1) if 0 < last - first <= _RANGE_MAX else (first, last)
            out.extend(n for n in span if n not in out)
    return out


def row_refs(text: str) -> list[int]:
    """Row numbers ``text`` names, in order, without repeats; pull request citations excluded."""
    return _numbers(
        m.group("hash") or m.group("list") for m in _ROW_REF.finditer(_PR_CITE.sub(" ", text))
    )


def backlog_refs(text: str) -> list[int]:
    """Every row a ``BACKLOG #N`` (or ``BACKLOG #N and #M``) in ``text`` names."""
    return _numbers(m.group("list") for m in _BACKLOG_REF.finditer(_PR_CITE.sub(" ", text)))


def file_count_of(sentence: str) -> int | None:
    """The count a filing sentence states, or ``None`` when it states none.

    Each noun takes the nearest count in the few words before it, and the nouns' counts are
    SUMMED: "2 rows for slice A and 3 rows for slice B" is five. Summing can over-count ("13
    findings ... as 2 rows"), the safe direction; an under-count would let a filing read DONE early.
    "A row for each finding" states no count.
    """
    text = _PR_CITE.sub(" ", sentence)
    total, start = 0, 0
    for m in _NOUN_RE.finditer(text):
        before, start = " ".join(text[start : m.start()].split()[-_COUNT_REACH:]), m.end()
        tokens = _COUNT_TOKEN.findall(before)
        if not tokens:
            continue
        if _EACH.match(text, m.end()):
            return None
        word, noun = tokens[-1].lower(), m.group("noun").lower()
        if word in ("a", "an"):
            total += 0 if noun in _PLURAL_NOUNS else 1  # "a few rows" states no count
        else:
            total += int(word) if word.isdigit() else _COUNT_WORDS[word]
    return total or None


class Prose(NamedTuple):
    rows: tuple[int, ...]
    file_count: int
    file_unknown: bool
    cites: frozenset[Cite]
    unread: bool


def _is_landers_own(text: str) -> bool:
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return bool(_LANDER_OWN.match(first))


def parse_prose(text: str, title: str = "", repo: str = ENGINE_REPO) -> Prose | None:
    """The ask in a Lander-addressed prose comment on a ``repo`` PR, else ``None``."""
    if not _LANDER.search(text):
        return None
    # The Lander's own comment is not an ask of it, except that its enqueue comment is where the
    # filings it owes after a merge are recorded ("Rows follow in a Lander ledger pass"), so only
    # its filings are read.
    own = _is_landers_own(text)
    sentences = [s for s in _SENTENCE.split(text) if s.strip()]
    flips = [not own and bool(_FLIP_WORD.search(s)) for s in sentences]
    filings = [bool(_FILE_ASK.search(s)) for s in sentences]
    if not any(flips) and not any(filings):
        return None
    refs = [row_refs(s) for s in sentences]
    rows: list[int] = []
    cites: set[Cite] = set()
    file_count, file_unknown, orphan = 0, False, False
    for k, sentence in enumerate(sentences):
        if not flips[k] and not filings[k]:
            continue
        found = [] if own else refs[k]
        if not found and flips[k]:
            # "Please flip it.": the row is named before, or failing that, just after. The
            # comment's and the title's BACKLOG rows are added below too, since a borrowed row may
            # be a different one.
            orphan = True
            for j in (k - 1, k - 2, k + 1):
                if 0 <= j < len(sentences) and refs[j]:
                    found = refs[j]
                    cites |= set(cited_prs(sentences[j], repo))
                    break
        rows.extend(n for n in found if n not in rows)
        cites |= set(cited_prs(sentence, repo))
        if filings[k]:
            count = file_count_of(sentence)
            if count is None:
                file_unknown = True
            else:
                file_count += count  # two filing sentences are two asks: summed, never merged
    filing = file_count > 0 or file_unknown
    if orphan:
        # A flip sentence named no row: the comment's BACKLOG rows, then the title's.
        rows.extend(n for n in backlog_refs(text) or backlog_refs(title) if n not in rows)
        cites |= set(cited_prs(text, repo))
    return Prose(tuple(rows), file_count, file_unknown, frozenset(cites), not rows and not filing)


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
    own: frozenset[Cite] = frozenset({(repo, number)})

    def marked(asked: datetime, where: str, mk: Marker) -> Ask:
        named = bool(mk.rows or mk.file_count)
        note = "; ".join(mk.problems) or ("" if named else "the marker names no row and no filing")
        return Ask(
            repo, number, merged, asked, "marker", where, mk.rows, mk.file_count,
            cites=own, unread=bool(mk.problems) or not named, note=note,
        )  # fmt: skip

    # A marker in the body was written by the PR's creation at the latest. A fork PR's body is
    # written by an outside account, which the comment trust gate keeps out: a person reads it.
    opened = _when(pr.get("createdAt")) or merged
    asks = [marked(opened, url, mk) for mk in parse_marker(str(pr.get("body") or ""))]
    if pr.get("isCrossRepository") is not False:
        asks = [
            replace(a, rows=(), file_count=0, unread=True, note="a marker in a fork PR's body")
            for a in asks
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
            asks.extend(marked(asked, curl, mk) for mk in markers)
            continue
        prose = parse_prose(body, title, repo)
        if prose is None:
            continue
        asks.append(
            Ask(
                repo, number, merged, asked, "prose", curl,
                rows=prose.rows, file_count=prose.file_count, file_unknown=prose.file_unknown,
                cites=own | prose.cites, unread=prose.unread,
                note=_UNEXTRACTED if prose.unread else "",
            )
        )  # fmt: skip
    return asks


def _sum_filings(group: list[Ask]) -> Ask:
    first = min(group, key=lambda a: a.asked_at)
    return replace(
        first,
        source="+".join(sorted({a.source for a in group})),
        file_count=sum(a.file_count for a in group),
        file_unknown=any(a.file_unknown for a in group),
        note=f"{len(group)} filing asks, summed" if len(group) > 1 else "",
    )


def split_acts(asks: Iterable[Ask]) -> list[Ask]:
    """One ask per act: a row, a PR's filing, an unread comment.

    Prose asks for one row merge into the EARLIEST, so a later reminder or "done" note cannot move
    the baseline past the act; their citations are pooled. Every filing ask on a PR is SUMMED into
    one act, because filed rows cannot be told apart by which ask they answer.
    """
    merged: dict[tuple[str, int, object, str], Ask] = {}
    filings: dict[tuple[str, int], list[Ask]] = {}
    for ask in asks:
        bare = replace(ask, rows=(), file_count=0, file_unknown=False, unread=False, note="")
        acts: list[tuple[object, Ask]] = [(n, replace(bare, rows=(n,))) for n in ask.rows]
        if ask.unread:
            acts.append((("read", ask.url, ask.note), replace(bare, unread=True, note=ask.note)))
        if ask.file_count or ask.file_unknown:
            filings.setdefault((ask.repo, ask.pr), []).append(
                replace(bare, file_count=ask.file_count, file_unknown=ask.file_unknown)
            )
        for act, one in acts:
            # A marker is a deliberate, separate ask (a re-flip), so it is never folded into an
            # earlier one; prose repeats are.
            key = (ask.repo, ask.pr, act, ask.url if ask.source == "marker" else "")
            if (have := merged.get(key)) is not None:
                first = have if have.asked_at <= one.asked_at else one
                one = replace(first, cites=have.cites | one.cites)
            merged[key] = one
    return [*merged.values(), *(_sum_filings(g) for g in filings.values())]


class Ledger(Protocol):
    def tip(self) -> tuple[str, str]:
        """``(sha, committer date)`` of the ledger ref."""

    def sha_before(self, when: datetime) -> str | None:
        """The ref's last first-parent commit at or before ``when``; ``None`` if none."""

    def blocks(self, sha: str) -> dict[int, Block]:
        """Row number to its banner block at ``sha``."""


def cite_count(text: str, prs: Iterable[Cite]) -> int:
    """How often ``text`` cites one of ``prs``; a bare one, with no repository, never counts."""
    wanted = {c for c in prs if c[0] is not None}
    return sum(1 for c in cited_prs(text) if c in wanted)


def cite_index(tip: dict[int, Block]) -> dict[Cite, frozenset[int]]:
    """Each repository-qualified PR to the rows whose block cites it: the tip, indexed once."""
    index: dict[Cite, set[int]] = {}
    for n, block in tip.items():
        for cite in cited_prs(block.text):
            if cite[0] is not None:
                index.setdefault(cite, set()).add(n)
    return {c: frozenset(rows) for c, rows in index.items()}


def _judge_row(ask: Ask, n: int, ledger: Ledger, tip: dict[int, Block]) -> Row:
    what = f"row #{n}"
    now = tip.get(n)
    if now is None:
        return Row(MISSING, ask, what, "not in either ledger file at the ref")
    citing = [ln for ln in now.banners if cite_count(ln, ask.cites)]
    if not now.closed and not citing:
        # DONE needs a CLOSED row or a citing banner, so the baseline (a full parse) is not read.
        return Row(OWED, ask, what, "OPEN at the ref, and no banner line cites the PR")
    base_sha = ledger.sha_before(ask.baseline)
    if base_sha is None:
        return Row(ERROR, ask, what, "no ledger commit before the baseline (shallow?)")
    before = ledger.blocks(base_sha).get(n)
    if before is None:
        return Row(OWED, ask, what, "the row did not exist at the baseline")
    if not before.banners:
        return Row(OWED, ask, what, "the baseline row has no banner the grammar reads")
    recorded = any(ln not in before.banners and not _STILL_OWED.search(ln) for ln in citing)
    if before.closed:
        # A re-open, or a re-banner of a closed row, shows only as a new banner line.
        if recorded:
            return Row(DONE, ask, what, "CLOSED at the baseline; a new banner line cites the PR")
        return Row(OWED, ask, what, "CLOSED at the baseline, and no new banner line cites the PR")
    if now.closed:
        return Row(DONE, ask, what, "OPEN at the baseline, CLOSED at the ref")
    if now.status == before.status:
        return Row(OWED, ask, what, "its status glyphs are unchanged since the baseline")
    if not recorded:
        return Row(OWED, ask, what, "its status changed, but no new banner line records the act")
    return Row(DONE, ask, what, "its status changed and a new banner line cites the PR")


def _judge_filing(ask: Ask, ledger: Ledger, index: dict[Cite, frozenset[int]]) -> Row:
    what = (
        f"file {ask.file_count} row(s)"
        if not ask.file_unknown
        else f"file at least {ask.file_count} row(s)"
        if ask.file_count
        else "file row(s)"
    )
    # Filing may precede the merge (a finding is filed before it, under the 2026-10-12 rule), so
    # the filing baseline is the ask itself.
    asked_sha = ledger.sha_before(ask.asked_at)
    if asked_sha is None:
        return Row(ERROR, ask, what, "no ledger commit before the ask (shallow?)")
    existing = ledger.blocks(asked_sha)
    # Only this PR's own citation counts: a row citing another PR the ask named is not its filing.
    filed = sorted(n for n in index.get((ask.repo, ask.pr), ()) if n not in existing)
    detail = f"filed since, citing the PR: {', '.join(f'#{n}' for n in filed) or 'none'}"
    if ask.note:
        detail = f"{ask.note}; {detail}"
    if ask.file_unknown:
        return Row(OWED, ask, what, f"count unknown, so it stays owed; {detail}")
    return Row(DONE if len(filed) >= ask.file_count else OWED, ask, what, detail)


def judge(
    ask: Ask, ledger: Ledger, tip: dict[int, Block], index: dict[Cite, frozenset[int]]
) -> list[Row]:
    if ask.unread:
        return [Row(READ, ask, "read the comment", ask.note or _UNEXTRACTED)]
    out = [_judge_row(ask, n, ledger, tip) for n in ask.rows]
    if ask.file_count or ask.file_unknown:
        out.append(_judge_filing(ask, ledger, index))
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
            "number,title,url,createdAt,mergedAt,body,comments,isCrossRepository",
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
    """The vault ledger read as text from a checkout's git objects at ``ref``. Never reads its work
    tree, and never runs anything the vault holds."""

    def __init__(self, vault: Path, ref: str) -> None:
        self.vault = vault
        self.ref = ref
        #: Parses keyed by the ledger files' blob ids: most vault commits leave them untouched.
        self._cache: OrderedDict[tuple[str, ...], dict[int, Block]] = OrderedDict()
        #: The tip's first-parent history, newest first, as ``(committer time, sha)``.
        self._history: list[tuple[int, str]] | None = None
        self._tip: str | None = None
        #: Each commit's ledger blob ids, so a commit is listed once.
        self._keys: dict[str, tuple[str, ...]] = {}

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
        self._tip = sha  # baselines are read from this commit, not the ref a peer may move
        return sha, date

    def sha_before(self, when: datetime) -> str | None:
        # What ``rev-list -1 --first-parent --before`` answers, from one history read: the first
        # commit in first-parent order whose committer time is not after ``when``.
        if self._history is None:
            out = self._git("log", "--first-parent", "--format=%ct %H", self._tip or self.ref)
            history = []
            for line in out.splitlines():
                stamp, _, sha = line.strip().partition(" ")
                if not stamp.isdigit() or not sha:
                    raise ReadError(f"git log printed an unexpected line: {line[:80]!r}")
                history.append((int(stamp), sha))
            self._history = history
        cutoff = int(when.timestamp())
        return next((sha for stamp, sha in self._history if stamp <= cutoff), None)

    def _blobs(self, sha: str) -> tuple[str, ...]:
        """The ledger files' blob ids at ``sha``, ``""`` for a file absent there."""
        if sha not in self._keys:
            # An absent path (an archive file that did not exist yet) is simply not listed.
            listing = self._git("ls-tree", "-z", sha, "--", *LEDGER_SOURCES)
            blobs: dict[str, str] = {}
            for entry in filter(None, listing.split("\0")):
                meta, _, path = entry.partition("\t")
                kind, oid = meta.split()[1:3]
                if kind != "blob":
                    raise ReadError(f"{path} at {sha[:10]} is a {kind}, not a file")
                blobs[path] = oid
            self._keys[sha] = tuple(blobs.get(source, "") for source in LEDGER_SOURCES)
        return self._keys[sha]

    def blocks(self, sha: str) -> dict[int, Block]:
        key = self._blobs(sha)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        result: dict[int, Block] = {}
        for source, oid in zip(LEDGER_SOURCES, key, strict=True):
            if not oid:
                continue
            text = self._git("cat-file", "blob", oid)
            try:
                parsed = parse_ledger(text)
            except ReadError as exc:
                raise ReadError(f"{source} at {sha[:10]}: {exc}") from exc
            for n, block in parsed.items():
                _put(result, n, block)
        if not result:
            raise ReadError(f"no ledger rows parsed at {sha[:10]}")
        self._cache[key] = result
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
    index = cite_index(tip)
    described = f"{sha[:10]} ({date})"
    acts: list[Ask] = []
    for repo in repos:
        try:
            prs = fetch_merged(gh, repo, since)
        except (ReadError, pr_state.GhError, OSError) as exc:
            rows.append(Row(ERROR, None, repo, f"read failed: {exc}"[:300]))
            continue
        scanned += len(prs)
        for pr in prs:
            try:
                acts.extend(split_acts(extract_asks(repo, pr)))
            except (ReadError, LookupError, TypeError, ValueError) as exc:
                rows.append(Row(ERROR, None, f"{repo} PR {pr.get('number')}", str(exc)[:300]))
    # In the order of the commit each act reads (a filing reads at its ask), so acts sharing a
    # ledger snapshot share one cached parse.
    for ask in sorted(acts, key=lambda a: a.baseline if a.rows else a.asked_at):
        try:
            rows.extend(judge(ask, ledger, tip, index))
        except ReadError as exc:
            rows.append(Row(ERROR, ask, "ledger read", str(exc)[:300]))
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
        ledger = GitLedger(args.vault, args.ref)
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
