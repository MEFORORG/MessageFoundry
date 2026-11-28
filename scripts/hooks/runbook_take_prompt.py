# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tell a session that holds claims on a batch's rows the runbook workbook does not show as held.

Run by ``scripts/hooks/runbook-take-prompt.ps1`` with the interpreter that has openpyxl, on
SessionStart and UserPromptSubmit. Owner decision 2026-11-27 ("Stop hook + Lander"): a session that
picks up a batch through a handoff, /carry-on or a respawn never reads the /batch skill's step that
runs ``read_batch.py --take``, so the owner's runbook dashboard reads FREE for a batch somebody holds.
This hands the session the command that fixes it.

IT NEVER BLOCKS AND NEVER FAILS. Every path exits 0. The only stdout it ever writes is one JSON object,
``{"additionalContext": ...}``, which the wrapper puts in the event's hookSpecificOutput so that it
reaches the model's context. Anything it cannot read (no workbook, no openpyxl, no claims, a locked or
unreadable file, an unresolvable claim registry) means no stdout at all; a one-line reason goes to
stderr, which the wrapper passes on to its own.

WHOSE CLAIMS. Only claims whose ``worktree`` is this session's worktree, on this machine, and none at
all in the primary checkout: claim.ps1 records the checkout of the copy it ran from, so the primary's
claims belong to whichever sessions ran that copy. Builder, Lander and Watchdog seats are never told
(only a seat label starting ``manager``, or no declared seat, is told): a Manager takes a batch,
and a Builder's claims sit under its Manager's hold by design (claim.ps1's header: the holder of
a batch is not always the worktree a claim names). A clone that sets git config
``mefor.claimsRoot`` is read from that registry, the one hop claim.ps1 follows.

WHO HOLDS A BATCH. Only the holder cell's CURRENT text counts, the part before any ``||`` history.
It names this session when it carries the worktree name, the session id's first eight characters or
the whole id, each as a whole token, and does not record a release ("released by ..."). A release
never earns ``--force-take`` in the printed command. A batch is named only while its State is
empty, FREE or TAKEN (``TAKEABLE_STATES``): later, --take would move the dashboard backwards.

COLUMN LAYOUT. Read by row-1 header, never by letter, as the batch skill's ``read_batch.py`` reads it:
the Batch queue tab's ``Batch``, ``State``, ``Status`` and ``Manager / session``, and the Rows tab's
``Batch``, ``Row`` and ``Status``. Nothing is imported from the skill directory: that file sits outside
the repository, and this one runs at every prompt.

CHEAP WHEN NOTHING CHANGED. State lives in <git-common-dir>/mefor-coord/runbook-take/<session>.json.
The batches found are cached against the workbook's mtime and size and this worktree's claim keys, so
an unchanged state reads no xlsx. The claim files are re-read when the claims directory's mtime moves,
and after any scan that met an unreadable claim. A batch is named at most once per
``COOLDOWN_SECONDS`` per session, so UserPromptSubmit does not repeat SessionStart's notice.

Workbook and claim content are DATA. A holder cell is shown quoted, with every control, format and
line or paragraph separator character replaced, and nothing read from either file reaches the
printed command except a batch number.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

COOLDOWN_SECONDS = 30 * 60
STATE_RETENTION_DAYS = 14
# Only a Manager takes a batch, so only a Manager seat label (manager, manager-2) is told, plus a
# session that has declared no seat yet: a respawned Manager may not have, and its --holder then
# carries a <seat> placeholder it is told to replace. Every other label, aliases included, is not.
TAKES_PREFIX = "manager"
# Bumped whenever the classification changes, so a cached answer from older rules is not reused.
RULES_VERSION = 2
SEAT_WORDS = frozenset({"manager", "builder", "lander", "watchdog", "special"})
# The States read_batch.py --take may write over without moving the dashboard backwards. A batch
# at PR OPEN or later is past taking: --take would rewrite its State to TAKEN.
TAKEABLE_STATES = ("", "FREE", "TAKEN")

# Claim-key readings, built from read_batch.py's patterns but narrower, because here a false warning
# costs more than a missed one. PR numbers (pr-3385) and dates are read as nothing, anywhere.
#   - The long form ("batch" anywhere) names batches only: every number in it and every number
#     inside a range it writes, as read_batch.py's goal_batches holds them (batch-462-and-465,
#     batches-462-465).
#   - The short form names one batch and must START the key, and its other numbers are rows
#     (b472-3765-b), so a part suffix such as 3765-b2 is not batch 2.
#   - Any other key names only its LEADING number, as a row (3765, 3765-b), and no row when it
#     leads with a date.
# A marker is a whole word followed by a number (batch-472, never batch-mode), and a number stuck
# to letters (hl7, x12) is no number. A short form must be followed by the key's end or a number.
_LONG_BATCH = re.compile(r"(?i)(?<![a-z0-9])batch(?:es)?[-_.]?\d")
_SHORT_BATCH = re.compile(r"(?i)^b[-_.]?(\d+)(?=$|[-_. ]+\d)")
_NUMBER = re.compile(r"(?<![\da-z])\d{1,6}(?![\da-z])", re.IGNORECASE)
_RANGE = re.compile(r"(?<!\d)(\d{1,6})\s*[-–]\s*(\d{1,6})(?!\d)")
_LEADING = re.compile(r"^(\d{1,6})(?!\d)")
_DATE = re.compile(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)")
_PR = re.compile(r"(?i)(?<![a-z0-9])(?:pr|pull)[-_. #]?\d+")
_RELEASED = re.compile(r"(?i)\breleased\b")
RANGE_MAX = 100
# read_batch.py's _FINISHED, applied to the upper-cased queue Status: a batch finished there is no
# batch to take. Its State column is checked against the --done states that end a batch.
_FINISHED = re.compile(
    r"^\s*(DONE|DRAINED|MERGED|TERMINAL|SUPERSEDED|FULLY RE-BATCHED|WORKED|CLOSED)\b"
)
_ENDED_STATES = ("MERGED", "BUILT", "DONE")
# A Rows tab Status that leaves the row's work open. A blank Status is open too.
_OPEN_ROW = re.compile(r"^\s*(Not started|In progress)\b")
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._-]")
_SEAT = re.compile(r"[a-z][a-z0-9-]{0,39}")
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,100}")


@dataclass(frozen=True)
class QueueEntry:
    state: str
    status: str
    holder: str


@dataclass(frozen=True)
class Book:
    """The two tabs, reduced to what this hook reads."""

    queue: dict[int, QueueEntry]
    # Row number -> every (batch, Rows tab Status) it appears under.
    rows: dict[int, list[tuple[int, str]]]


@dataclass(frozen=True)
class Pending:
    batch: int
    holder: str
    rows: tuple[int, ...]
    # The holder cell names this session, and only the State column reads FREE.
    named_us: bool = False
    state: str = ""


def _cell(v: object) -> str:
    return "" if v is None else str(v).strip()


def _int(v: object) -> int | None:
    try:
        return int(float(_cell(v)))
    except (ValueError, OverflowError):
        return None


def key_targets(key: str) -> tuple[set[int], set[int]]:
    """The rows and the batches a claim key names, read as the comment above the patterns says."""
    runs = re.findall(r"\d+", key)
    if any(len(x) > 6 for x in runs):
        return set(), set()
    rest = _PR.sub(" ", _DATE.sub(" ", key))
    if _LONG_BATCH.search(key):
        batches = {int(x) for x in _NUMBER.findall(rest)}
        for a, b in _RANGE.findall(rest):
            lo, hi = int(a), int(b)
            if lo < hi <= lo + RANGE_MAX:
                batches.update(range(lo, hi + 1))
        return set(), batches
    short = _SHORT_BATCH.match(rest)
    if short:
        n = int(short.group(1))
        return {int(x) for x in _NUMBER.findall(rest[short.end() :])} - {n}, {n}
    if _DATE.match(key):
        return set(), set()
    m = _LEADING.match(key)
    return ({int(m.group(1))} if m else set()), set()


def safe_label(text: str) -> str:
    return _SAFE_LABEL.sub("", text)


def session_names(worktree: str, session_id: str) -> tuple[str, ...]:
    """The names a holder cell may know this session by: its worktree and its session id's first
    eight characters, spelled as holder_text prints them, and the whole session id."""
    sid = safe_label(session_id)
    wt = safe_label(Path(worktree).name)
    # A worktree named after a seat (manager, builder) would match every holder cell's seat word.
    if wt.lower() in SEAT_WORDS:
        wt = ""
    return tuple(n for n in (wt, sid[:8], sid) if n)


def names_us(holder: str, names: Iterable[str]) -> bool:
    """The holder cell carries one of names as a whole token, so agent-a1 never matches agent-a1b2."""
    return any(
        re.search(rf"(?<![A-Za-z0-9._-]){re.escape(n)}(?![A-Za-z0-9._-])", holder, re.IGNORECASE)
        for n in names
        if n
    )


def current_holder(cell: str) -> str:
    """The cell's current holder text: what precedes any ``||`` history."""
    return cell.split("||", 1)[0].strip()


def released(cell: str) -> bool:
    """The current text records a release rather than a holder."""
    return bool(_RELEASED.search(current_holder(cell)))


def holder_is_us(cell: str, names: Iterable[str]) -> bool:
    """The current text names this session and is not a release."""
    return not released(cell) and names_us(current_holder(cell), names)


def _live(entry: QueueEntry) -> bool:
    if _FINISHED.match(entry.status.upper()):
        return False
    state = entry.state.upper()
    return not state.startswith(_ENDED_STATES) and state.split(" ", 1)[0] in TAKEABLE_STATES


def _ours(entry: QueueEntry, names: tuple[str, ...]) -> bool:
    """The queue tab records this session as the holder, and its State is set and not FREE."""
    state = entry.state.upper()
    return bool(state) and not state.startswith("FREE") and holder_is_us(entry.holder, names)


def pending_batches(keys: Iterable[str], book: Book, names: Iterable[str]) -> list[Pending]:
    """The live batches this worktree's claims hold that the queue tab does not record it holding.

    A claimed row counts only while its Rows tab Status leaves it open, and only under a batch the
    queue tab does not show as finished. A row two batches share is satisfied when either one
    records this session, whatever the row's status there; otherwise each live one is named."""
    names = tuple(names)
    hits: dict[int, set[int]] = {}
    for key in keys:
        rows, batches = key_targets(key)
        for b in batches:
            entry = book.queue.get(b)
            if entry is not None and _live(entry) and not _ours(entry, names):
                hits.setdefault(b, set())
        for r in rows:
            entries = book.rows.get(r, [])
            if any(b in book.queue and _ours(book.queue[b], names) for b, _st in entries):
                continue
            cands = [
                b
                for b, st in entries
                if (not st or _OPEN_ROW.match(st))
                and (e := book.queue.get(b)) is not None
                and _live(e)
            ]
            for b in cands:
                hits.setdefault(b, set()).add(r)
    out = []
    for b in sorted(hits):
        e = book.queue[b]
        out.append(
            Pending(b, e.holder, tuple(sorted(hits[b])), holder_is_us(e.holder, names), e.state)
        )
    return out


def _columns(head: list[str], names: tuple[str, ...]) -> list[int]:
    out = []
    for name in names:
        idx = [i for i, h in enumerate(head) if h == name]
        if len(idx) != 1:
            raise ValueError(f"{len(idx)} columns headed {name!r}, need exactly one")
        out.append(idx[0])
    return out


def _at(row: tuple[object, ...], i: int) -> object:
    """A short row stops at its last filled cell, so a missing column reads as an empty cell."""
    return row[i] if i < len(row) else None


def read_book(path: Path) -> Book:
    """Both tabs, read-only. Raises on anything it cannot read; the caller stays silent then."""
    import openpyxl  # type: ignore[import-untyped]  # noqa: PLC0415 - only the tools interpreter has it

    # An XML parse surface (OOXML is XML), recorded in tests/test_security_static.py's ASVS 1.5.3
    # _XML_PARSER_ALLOWLIST and tests/test_csv_formula_consistency.py's 1.2.10 record, by owner
    # decision 2026-11-28. The input is the owner's own local runbook workbook, never engine data. It
    # is opened read_only (nothing is written back) and data_only (cached values, not formulas), from
    # a dev hook under scripts/ that the wheel does not ship. It is not fully defused on the tools
    # interpreter; the allowlist entry states which parser reads which part.
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        q = wb["Batch queue"]
        it = q.iter_rows(values_only=True)
        head = [_cell(c) for c in next(it)]
        qb, qstate, qstatus, qmgr = _columns(
            head, ("Batch", "State", "Status", "Manager / session")
        )
        queue: dict[int, QueueEntry] = {}
        for r in it:
            n = _int(_at(r, qb))
            if n is None:
                continue
            queue[n] = QueueEntry(*(_cell(_at(r, i)) for i in (qstate, qstatus, qmgr)))
        rws = wb["Rows"]
        it = rws.iter_rows(values_only=True)
        head = [_cell(c) for c in next(it)]
        rb, rrow, rstatus = _columns(head, ("Batch", "Row", "Status"))
        rows: dict[int, list[tuple[int, str]]] = {}
        for r in it:
            b, n = _int(_at(r, rb)), _int(_at(r, rrow))
            if b is None or n is None:
                continue
            rows.setdefault(n, []).append((b, _cell(_at(r, rstatus))))
        return Book(queue, rows)
    finally:
        wb.close()


def _load_coord_root() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "coord" / "coord_root.py"
    spec = importlib.util.spec_from_file_location("mefor_coord_root_runbook", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    # Registered before it runs: its @dataclass looks its own module up in sys.modules.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _claims_registry(worktree: str) -> str:
    """The repository whose registry holds this worktree's claims: the one git config
    mefor.claimsRoot names, as claim.ps1 and claim_check.py follow it (one hop), else this one."""

    def git(*argv: str) -> str:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-C", worktree, *argv], capture_output=True, text=True, check=False, timeout=5
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    root = git("config", "--get", "mefor.claimsRoot")
    if not root:
        return worktree
    top = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", root, "rev-parse", "--path-format=absolute", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if top.returncode != 0 or not top.stdout.strip():
        raise OSError(f"mefor.claimsRoot names {root}, not a repository")
    return top.stdout.strip()


def _wt_key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def our_claim_keys(
    claims: Path,
    worktree: str,
    read_text: Callable[[Path], str],
    is_here: Callable[[object], bool],
) -> tuple[list[str], int]:
    """Keys of the claims this worktree holds on this machine, and how many claim files could not
    be read. An unreadable claim is skipped, because a wrong warning gives the session a false
    instruction; it may be one claim.ps1 has created and not yet written, so the caller does not
    trust a scan that skipped one."""
    mine = _wt_key(worktree)
    out = []
    unreadable = 0
    for entry in os.scandir(claims):
        if not entry.name.lower().endswith(".json"):
            continue
        try:
            rec = json.loads(read_text(Path(entry.path)))
        except (OSError, ValueError, RecursionError):
            unreadable += 1
            continue
        if not isinstance(rec, dict):
            unreadable += 1
            continue
        if not is_here(rec):
            continue
        wt = rec.get("worktree")
        try:
            if isinstance(wt, str) and wt.strip() and _wt_key(wt) == mine:
                out.append(entry.name[: -len(".json")])
        except (OSError, ValueError):
            unreadable += 1
    return sorted(out), unreadable


def _display(text: str, limit: int = 80) -> str:
    """Cell text made safe to show: every character in Unicode category C* (control, format, such as
    a bidi override) or Z* other than a plain space (U+2028, U+2029 and the like) becomes a space."""
    chars = [" " if unicodedata.category(c)[0] in "CZ" and c != " " else c for c in text]
    shown = re.sub(" +", " ", "".join(chars)).replace('"', "'").strip()
    return shown if len(shown) <= limit else shown[: limit - 3] + "..."


def holder_text(seat: str, worktree_name: str, session_id: str) -> str:
    seat_word = seat.capitalize() if _SEAT.fullmatch(seat) else "<seat>"
    wt = safe_label(worktree_name) or "<worktree>"
    sid = safe_label(session_id)[:8] or "<session>"
    return f"{seat_word} {wt} ({sid})"


def _quote(path: str) -> str:
    return f'"{path}"' if " " in path else path


def message(
    pending: list[Pending], python: str, read_batch: str, workbook: str, holder: str
) -> str:
    # A quoted first token is an expression to PowerShell, so it takes the call operator there.
    lead = f"& {_quote(python)}" if " " in python else python
    parts = []
    for p in pending:
        rows = f" (rows {', '.join(map(str, p.rows))})" if p.rows else ""
        now_text = current_holder(p.holder)
        # read_batch.py refuses --take while the cell names any other text, our own older one too.
        force, advice = "", ""
        if p.named_us:
            seen, force = "names this session but its State does not read TAKEN", " --force-take"
            advice = (
                "If the batch was returned to FREE on purpose (ledger ruling R8, or by the owner), "
                "do not take it back: release this session's claims on its rows instead."
            )
        elif released(p.holder):
            seen = f'records a release ("{_display(now_text)}")'
            advice = (
                "--take refuses while the cell holds that text. Add --force-take only if this "
                "session has taken the batch back; if it has not, release its stale claims on "
                "the batch's rows instead."
            )
        elif now_text:
            seen = f'names "{_display(now_text)}"'
            advice = (
                "The cell names another holder, so --take refuses unless you add --force-take; "
                "add it only once that holder has released the batch."
            )
        elif p.holder:
            seen, force = "names no current holder, only history after ||", " --force-take"
            advice = "--take compares the whole cell, so it refuses without --force-take here."
        elif p.state.upper().startswith("FREE") or not p.state:
            seen = "reads FREE"
        else:
            seen = "has an empty Manager / session cell"
        parts.append(
            f"[runbook] This session holds claims on batch {p.batch}{rows}, but the runbook "
            f"workbook's Batch queue tab {seen} for it, so the owner's dashboard does not show the "
            "hold. If this session holds the batch, record it:"
        )
        parts.append(
            f"  {lead} {_quote(read_batch)} --workbook {_quote(workbook)} --take {p.batch} "
            f'--holder "{holder}"{force}'
        )
        if advice:
            parts.append(advice)
    if "<account skills dir>" in read_batch:
        parts.append("Replace <account skills dir> with this account's skills directory first.")
    if "<seat>" in holder:
        parts.append("No seat is declared here: replace <seat> with this session's seat first.")
    parts.append(
        "If you are working only these rows and not the batch, ignore this. Otherwise run "
        "read_batch.py --done for the batch, with --holder, --state, --note and a --row for every "
        "row still open, when the batch PR opens and again when it merges."
    )
    return "\n".join(parts)


def _state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def _prune(directory: Path) -> None:
    """Drop state no session has touched for STATE_RETENTION_DAYS, and stray temp files, once per
    new session, so the directory does not grow by one file per session forever."""
    cutoff = time.time() - STATE_RETENTION_DAYS * 86400
    with contextlib.suppress(OSError):
        for entry in os.scandir(directory):
            with contextlib.suppress(OSError):
                if entry.is_file() and entry.stat().st_mtime < cutoff:
                    os.remove(entry.path)


def _cached_pending(state: dict[str, Any], key: list[Any]) -> list[Pending] | None:
    if state.get("key") != key:
        return None
    try:
        return [
            Pending(int(b), str(h), tuple(int(r) for r in rs), bool(u), str(st))
            for b, h, rs, u, st in state["pending"]
        ]
    except (KeyError, TypeError, ValueError):
        return None  # an unreadable cache is recomputed, never trusted


def run(args: argparse.Namespace) -> str | None:
    """The context text to print, or None. Raises on what it cannot read."""
    if not _SESSION_ID.fullmatch(args.session):
        return None
    if args.seat and not args.seat.startswith(TAKES_PREFIX):
        return None
    workbook = Path(args.workbook)
    wst = workbook.stat()
    if args.claims_dir:
        claims = Path(args.claims_dir)

        def read_text(p: Path) -> str:
            return p.read_text(encoding="utf-8-sig")

        def is_here(_rec: object) -> bool:
            return True

        local = Path(args.state_dir) if args.state_dir else None
    else:
        cr = _load_coord_root()
        local_root = cr.local_root(args.worktree)
        if local_root is None:
            raise OSError(f"git could not name the common dir for {args.worktree}")
        registry = _claims_registry(args.worktree)
        if registry != args.worktree:
            local_root = cr.local_root(registry)
            if local_root is None:
                raise OSError(f"mefor.claimsRoot names {registry}, not a repository")
        resolved = cr.resolve("claims", registry, local=local_root)
        if resolved.path is None:
            raise OSError(resolved.error or "no claims directory")
        claims = Path(resolved.path)

        def read_text(p: Path) -> str:
            return str(cr.read_text(p, encoding="utf-8-sig"))

        is_here = cr.record_is_here
        # claim.ps1 records the checkout of the copy it ran from, so the primary's claims belong to
        # whichever sessions ran the primary's copy; they say nothing about a session there.
        own_root = cr.local_root(args.worktree) if registry != args.worktree else local_root
        if own_root is None or _wt_key(str(Path(own_root).parent.parent)) == _wt_key(args.worktree):
            return None
        local = Path(args.state_dir) if args.state_dir else Path(own_root) / "runbook-take"
    if local is None:
        return None
    state_path = local / f"{args.session}.json"
    state = _state(state_path)
    before = json.dumps(state, sort_keys=True)
    wt = _wt_key(args.worktree)
    # The claim files are re-read only when the directory changed; the workbook only when it, or
    # this worktree's own keys, did. On a shared root any session's claim moves the directory.
    if not state:
        _prune(local)
    claims_mtime = claims.stat().st_mtime_ns
    stamp: list[Any] | None = [claims_mtime, wt]
    keys = state.get("keys")
    fresh = isinstance(keys, list) and all(isinstance(k, str) for k in keys)
    if state.get("claims") != stamp or not fresh:
        keys, unreadable = our_claim_keys(claims, args.worktree, read_text, is_here)
        if unreadable:
            # Not cached against the directory: a claim being written moves no directory mtime.
            stamp = None
            print(f"runbook-take-prompt: {unreadable} claim file(s) unreadable", file=sys.stderr)
    key = [RULES_VERSION, str(workbook), wst.st_mtime_ns, wst.st_size, wt, keys]
    names = session_names(args.worktree, args.session)
    pending = _cached_pending(state, key)
    if pending is None:
        pending = pending_batches(keys, read_book(workbook), names) if keys else []
    now = float(args.now) if args.now is not None else time.time()
    saved = state.get("warned")
    warned: dict[str, Any] = saved if isinstance(saved, dict) else {}
    due = []
    for p in pending:
        last = warned.get(str(p.batch))
        # A stamp in the future (a clock set back) never silences a warning.
        if not args.fresh and isinstance(last, (int, float)) and 0 <= now - last < COOLDOWN_SECONDS:
            continue
        due.append(p)
        warned[str(p.batch)] = now
    new = {
        "claims": stamp,
        "keys": keys,
        "key": key,
        "pending": [[p.batch, p.holder, list(p.rows), p.named_us, p.state] for p in pending],
        "warned": warned,
    }
    # Saved BEFORE the warning goes out, so a warning whose cooldown was not recorded never
    # repeats; and only when something changed, so a quiet prompt writes nothing.
    if json.dumps(new, sort_keys=True) != before:
        _save(state_path, new)
    if not due:
        return None
    holder = holder_text(args.seat, Path(args.worktree).name, args.session)
    return message(due, args.python, args.read_batch, args.workbook, holder)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--session", required=True)
    ap.add_argument("--seat", default="")
    ap.add_argument("--workbook", required=True)
    ap.add_argument("--python", required=True, help="the interpreter the printed command names")
    ap.add_argument("--read-batch", required=True, help="the read_batch.py the command names")
    ap.add_argument("--claims-dir", help="read claims here instead of resolving the registry")
    ap.add_argument("--state-dir", help="keep the cache here instead of <coord>/runbook-take")
    ap.add_argument("--now", type=float, help=argparse.SUPPRESS)
    ap.add_argument(
        "--fresh", action="store_true", help="ignore the cooldown (context was compacted)"
    )
    try:
        args = ap.parse_args(argv)
        text = run(args)
    except SystemExit:
        return 0
    except Exception as exc:  # noqa: BLE001 - this hook must never fail; the reason goes to stderr
        with contextlib.suppress(OSError):
            print(
                f"runbook-take-prompt: nothing printed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
        return 0
    if text:
        sys.stdout.write(json.dumps({"additionalContext": text}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
