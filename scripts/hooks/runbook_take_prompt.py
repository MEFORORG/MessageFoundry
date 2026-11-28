# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Warn a session that holds claims on a batch's rows the runbook workbook does not show as held.

Run by ``scripts/hooks/runbook-take-prompt.ps1``, a Stop hook, with the interpreter that has openpyxl.
Owner decision 2026-11-27 ("Stop hook + Lander"): a session that picks up a batch through a handoff,
/carry-on or a respawn never reads the /batch skill's step that runs ``read_batch.py --take``, so the
owner's runbook dashboard reads FREE for a batch somebody holds. This prints the command that fixes it.

IT NEVER BLOCKS AND NEVER FAILS. Every path exits 0. The only stdout it ever writes is one JSON object,
``{"systemMessage": ...}``, the form the installer's notice shim uses on Stop. Anything it cannot read
(no workbook, no openpyxl, no claims, a locked or unreadable file, an unresolvable claim registry)
means no stdout at all; a one-line reason goes to stderr, which the wrapper passes on to its own.

WHOSE CLAIMS. Only claims whose ``worktree`` is this session's worktree, on this machine. A session
is recognised in a holder cell by its worktree name or by its session id's first eight characters,
each as a whole token. A Builder seat is never warned: a Manager takes the batch, and a Builder's
claims sit under its Manager's hold by design (claim.ps1's header: the holder of a batch is not
always the worktree a claim names).

COLUMN LAYOUT. Read by row-1 header, never by letter, as the batch skill's ``read_batch.py`` reads it:
the Batch queue tab's ``Batch``, ``State``, ``Status`` and ``Manager / session``, and the Rows tab's
``Batch``, ``Row`` and ``Status``. Nothing is imported from the skill directory: that file sits outside
the repository, and this one runs in every session's Stop.

CHEAP WHEN NOTHING CHANGED. The batches found are cached per session against the workbook's mtime and
size and this worktree's claim keys, so an unchanged state reads no xlsx; the claim files are re-read
only when the claims directory's mtime moves. A batch is warned about at most once per
``COOLDOWN_SECONDS`` per session.

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
import sys
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

COOLDOWN_SECONDS = 30 * 60

# Claim-key readings, built from read_batch.py's patterns but narrower, because here a false warning
# costs more than a missed one. A key that mentions a batch names the batches it marks and every
# batch inside a range it writes (batch-472, batches-462-465), and any other number in it as a row
# (b472-3765-b). A key with no batch marker names only its LEADING number, as a row (3765, 3765-b).
_MENTIONS_BATCH = re.compile(r"(?i)batch|(?<![a-z0-9])b[-_.]?\d")
_BATCH_MARK = re.compile(r"(?i)(?:batch(?:es)?[-_. ]?|(?<![a-z0-9])b[-_.]?)(\d+)")
_NUMBER = re.compile(r"(?<!\d)\d{1,6}(?!\d)")
_RANGE = re.compile(r"(?<!\d)(\d{1,6})\s*[-–]\s*(\d{1,6})(?!\d)")
_LEADING = re.compile(r"^(\d{1,6})(?!\d)")
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
_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


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
    if _MENTIONS_BATCH.search(key):
        batches = {int(x) for x in _BATCH_MARK.findall(key)}
        for a, b in _RANGE.findall(key):
            lo, hi = int(a), int(b)
            if lo in batches and lo < hi <= lo + RANGE_MAX:
                batches.update(range(lo, hi + 1))
        return {int(x) for x in _NUMBER.findall(key)} - batches, batches
    m = _LEADING.match(key)
    return ({int(m.group(1))} if m else set()), set()


def safe_label(text: str) -> str:
    return _SAFE_LABEL.sub("", text)


def session_names(worktree: str, session_id: str) -> tuple[str, ...]:
    """The names a holder cell may know this session by, spelled as holder_text prints them."""
    return tuple(n for n in (safe_label(Path(worktree).name), safe_label(session_id)[:8]) if n)


def names_us(holder: str, names: Iterable[str]) -> bool:
    """The holder cell carries one of names as a whole token, so agent-a1 never matches agent-a1b2."""
    return any(
        re.search(rf"(?<![A-Za-z0-9._-]){re.escape(n)}(?![A-Za-z0-9._-])", holder, re.IGNORECASE)
        for n in names
        if n
    )


def _live(entry: QueueEntry) -> bool:
    if _FINISHED.match(entry.status.upper()):
        return False
    return not entry.state.upper().startswith(_ENDED_STATES)


def _ours(entry: QueueEntry, names: tuple[str, ...]) -> bool:
    """The queue tab records this session as the holder, and does not read FREE."""
    return not entry.state.upper().startswith("FREE") and names_us(entry.holder, names)


def pending_batches(keys: Iterable[str], book: Book, names: Iterable[str]) -> list[Pending]:
    """The live batches this worktree's claims hold that the queue tab does not record it holding.

    A claimed row counts only while its Rows tab Status leaves it open, and only under a batch the
    queue tab does not show as finished. A row two live batches share is satisfied when either one
    records this session; otherwise each is named."""
    names = tuple(names)
    hits: dict[int, set[int]] = {}
    for key in keys:
        rows, batches = key_targets(key)
        for b in batches:
            entry = book.queue.get(b)
            if entry is not None and _live(entry) and not _ours(entry, names):
                hits.setdefault(b, set())
        for r in rows:
            cands = [
                b
                for b, st in book.rows.get(r, [])
                if (not st or _OPEN_ROW.match(st))
                and (e := book.queue.get(b)) is not None
                and _live(e)
            ]
            if not cands or any(_ours(book.queue[b], names) for b in cands):
                continue
            for b in cands:
                hits.setdefault(b, set()).add(r)
    out = []
    for b in sorted(hits):
        e = book.queue[b]
        out.append(Pending(b, e.holder, tuple(sorted(hits[b])), names_us(e.holder, names), e.state))
    return out


def _columns(head: list[str], names: tuple[str, ...]) -> list[int]:
    out = []
    for name in names:
        idx = [i for i, h in enumerate(head) if h == name]
        if len(idx) != 1:
            raise ValueError(f"{len(idx)} columns headed {name!r}, need exactly one")
        out.append(idx[0])
    return out


def read_book(path: Path) -> Book:
    """Both tabs, read-only. Raises on anything it cannot read; the caller stays silent then."""
    import openpyxl  # type: ignore[import-untyped]  # noqa: PLC0415 - only the tools interpreter has it

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
            n = _int(r[qb]) if qb < len(r) else None
            if n is None:
                continue
            vals = [_cell(r[i]) if i < len(r) else "" for i in (qstate, qstatus, qmgr)]
            queue[n] = QueueEntry(*vals)
        rws = wb["Rows"]
        it = rws.iter_rows(values_only=True)
        head = [_cell(c) for c in next(it)]
        rb, rrow, rstatus = _columns(head, ("Batch", "Row", "Status"))
        rows: dict[int, list[tuple[int, str]]] = {}
        for r in it:
            b = _int(r[rb]) if rb < len(r) else None
            n = _int(r[rrow]) if rrow < len(r) else None
            if b is None or n is None:
                continue
            rows.setdefault(n, []).append((b, _cell(r[rstatus]) if rstatus < len(r) else ""))
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


def _wt_key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def our_claim_keys(
    claims: Path,
    worktree: str,
    read_text: Callable[[Path], str],
    is_here: Callable[[object], bool],
) -> list[str]:
    """Keys of the claims this worktree holds on this machine. An unreadable claim is skipped: a
    missed warning costs little, a wrong one gives the session a false instruction."""
    mine = _wt_key(worktree)
    out = []
    for entry in os.scandir(claims):
        if not entry.name.lower().endswith(".json"):
            continue
        try:
            rec = json.loads(read_text(Path(entry.path)))
        except (OSError, ValueError, RecursionError):
            continue
        if not isinstance(rec, dict) or not is_here(rec):
            continue
        wt = rec.get("worktree")
        try:
            if isinstance(wt, str) and wt.strip() and _wt_key(wt) == mine:
                out.append(entry.name[: -len(".json")])
        except (OSError, ValueError):
            continue
    return sorted(out)


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
        if p.named_us:
            seen = "names this session but reads FREE in its State column"
        elif p.holder:
            seen = f'names "{_display(p.holder)}"'
        elif p.state.upper().startswith("FREE") or not p.state:
            seen = "reads FREE"
        else:
            seen = "has an empty Manager / session cell"
        # read_batch.py refuses --take while the cell names any other text, our own older one too.
        force = " --force-take" if p.named_us else ""
        parts.append(
            f"[runbook] This session holds claims on batch {p.batch}{rows}, but the runbook "
            f"workbook's Batch queue tab {seen} for it, so the owner's dashboard does not show the "
            "hold. If this session holds the batch, record it:"
        )
        parts.append(
            f"  {lead} {_quote(read_batch)} --workbook {_quote(workbook)} --take {p.batch} "
            f'--holder "{holder}"{force}'
        )
        if p.holder and not p.named_us:
            parts.append(
                "The cell names another holder, so --take refuses unless you add --force-take; "
                "add it only once that holder has released the batch."
            )
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
    """The systemMessage to print, or None. Raises on what it cannot read."""
    if not _SESSION_ID.match(args.session) or args.seat == "builder":
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
        resolved = cr.resolve("claims", args.worktree, local=local_root)
        if resolved.path is None:
            raise OSError(resolved.error or "no claims directory")
        claims = Path(resolved.path)

        def read_text(p: Path) -> str:
            return str(cr.read_text(p, encoding="utf-8-sig"))

        is_here = cr.record_is_here
        local = Path(args.state_dir) if args.state_dir else Path(local_root) / "runbook-take"
    if local is None:
        return None
    state_path = local / f"{args.session}.json"
    state = _state(state_path)
    before = json.dumps(state, sort_keys=True)
    wt = _wt_key(args.worktree)
    # The claim files are re-read only when the directory changed; the workbook only when it, or
    # this worktree's own keys, did. On a shared root any session's claim moves the directory.
    claims_mtime = claims.stat().st_mtime_ns
    keys = state.get("keys")
    if state.get("claims") != [claims_mtime, wt] or not isinstance(keys, list):
        keys = our_claim_keys(claims, args.worktree, read_text, is_here)
    key = [wst.st_mtime_ns, wst.st_size, wt, keys]
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
        if isinstance(last, (int, float)) and now - last < COOLDOWN_SECONDS:
            continue
        due.append(p)
        warned[str(p.batch)] = now
    new = {
        "claims": [claims_mtime, wt],
        "keys": keys,
        "key": key,
        "pending": [[p.batch, p.holder, list(p.rows), p.named_us, p.state] for p in pending],
        "warned": warned,
    }
    # Saved BEFORE the warning goes out, so a warning whose cooldown was not recorded never
    # repeats; and only when something changed, so a quiet Stop writes nothing.
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
    try:
        args = ap.parse_args(argv)
        text = run(args)
    except SystemExit:
        return 0
    except Exception as exc:  # noqa: BLE001 - a Stop hook must never fail; the reason goes to stderr
        with contextlib.suppress(OSError):
            print(
                f"runbook-take-prompt: nothing printed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
        return 0
    if text:
        sys.stdout.write(json.dumps({"systemMessage": text}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
