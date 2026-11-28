# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remind a session that just opened a batch pull request to record it on the runbook workbook.

Run by ``scripts/hooks/runbook-done-prompt.ps1``, a PostToolUse hook on the Bash and PowerShell
tools, with the hook input on stdin. Owner instruction 2026-11-28, in a Manager's chat: nothing
reminded a Manager to run ``read_batch.py --done NN --state "PR OPEN"`` when it opened a batch's
pull request, so the owner's runbook dashboard kept reading TAKEN or FREE for a batch with a PR.

WHAT IT MATCHES. A command that creates a pull request: ``gh pr create``, or ``gh api`` on a
``.../pulls`` path with ``-X POST``/``--method POST`` (or with a field flag and no GET, which gh
sends as a POST). The tool response must show that it succeeded: no failure flag, no "already
exists", and one pull request named in the output (a ``.../pull/N`` URL, a REST JSON object with
``number``, or a bare number printed by ``--jq .number``). Output sent to a file, or anything else it
cannot read, means no reminder.

WHAT IT PRINTS. One JSON object, ``{"additionalContext": ...}``, which the wrapper puts in the
event's hookSpecificOutput. It names every runbook batch the command text or its body file mentions
("batch NN", "Batch NN", "batches NN and MM") and gives the exact ``--done`` command. With no batch
named, it says so only when the PR cites ``BACKLOG #N`` rows this session's worktree holds claims on,
since those rows may belong to a batch. Otherwise it prints nothing.

WHAT IT NEVER DOES. It never blocks, and every path exits 0. It never reads the workbook, and makes
no network or gh call; the only child it starts is a local ``git rev-parse`` for the head SHA, and
``git config`` for the claims registry hop that claim.ps1 follows. It writes no file. A body file is
read only when it sits inside the session's worktree or its own scratchpad, and only its first
``BODY_CAP_BYTES``.

Command and file content are DATA. Nothing read from them reaches the printed text except integers
(batch, row and PR numbers), a repository name and a hex SHA, each held to a fixed pattern.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

BODY_CAP_BYTES = 64 * 1024
COMMAND_CAP_CHARS = 256 * 1024
MAX_ROWS = 12
MAX_BATCHES = 6
GIT_TIMEOUT_SECONDS = 3

_GH = r"(?<![\w.\\/-])gh(?:\.exe)?"
PR_CREATE = re.compile(_GH + r"\s+pr\s+create(?![\w-])", re.IGNORECASE)
API_CALL = re.compile(_GH + r"\s+api(?![\w-])", re.IGNORECASE)
# The pulls collection itself, never one PR under it (/pulls/12/comments).
# {owner}/{repo} placeholders count too; gh fills them from the current clone.
PULLS_PATH = re.compile(
    r"(?:^|[\s'\"/])(?:/?repos/)?([\w.{}-]+)/([\w.{}-]+)/pulls(?![\w/-])", re.IGNORECASE
)
_LITERAL_NAME = re.compile(r"\A[\w.-]+\Z")
POST = re.compile(r"(?:-X|--method)(?:\s+|=)?['\"]?POST\b", re.IGNORECASE)
GET = re.compile(r"(?:-X|--method)(?:\s+|=)?['\"]?GET\b", re.IGNORECASE)
FIELD = re.compile(r"(?<![\w-])(?:-f|-F|--field|--raw-field|--input)(?![\w-])")

PR_URL = re.compile(r"https://github\.com/([\w.-]+)/([\w.-]+)/pull/(\d{1,7})(?![\w/])")
BARE_NUMBER = re.compile(r"\A\s*(\d{1,7})\s*\Z")
ALREADY_EXISTS = re.compile(r"already exists", re.IGNORECASE)

# "batch 20014", "Batch #52", "batch-20014", "batches 20014 and 20015", "batches 52, 53".
BATCH = re.compile(
    r"(?<![\w])batch(?:es)?[\s#:_-]*(\d{2,6}(?:\s*(?:,|&|\band\b)\s*#?\d{2,6})*)(?![\w])",
    re.IGNORECASE,
)
# "BACKLOG #5973", "BACKLOG #5973, #5936", "BACKLOG 5973 and #5936".
BACKLOG = re.compile(
    r"(?<![\w])BACKLOG\s*#?(\d{1,6}(?:\s*(?:,|&|\band\b)\s*#\d{1,6})*)(?![\w])",
    re.IGNORECASE,
)
_NUM = re.compile(r"\d{1,7}")

# A body file: gh pr create's --body-file or -F, and gh api's -F body=@file or --input file.
_PATH = r"(\"[^\"\x00-\x1f]+\"|'[^'\x00-\x1f]+'|[^\s'\";|&]+)"
CLI_BODY_FILE = re.compile(r"(?<![\w-])(?:--body-file|-F)(?:\s+|=)(?![\w-]+=)" + _PATH)
API_BODY_FILE = re.compile(
    r"(?<![\w-])(?:(?:-F|--field)(?:\s+|=)['\"]?body=@|--input(?:\s+|=))" + _PATH
)
CLI_HEAD = re.compile(r"(?<![\w-])(?:--head|-H)(?:\s+|=)['\"]?([\w./:-]+)")
API_HEAD = re.compile(r"(?<![\w-])head=['\"]?([\w./:-]+)")
_SAFE_REF = re.compile(r"\A[\w./-]{1,200}\Z")
_SHA = re.compile(r"\A[0-9a-f]{7,40}\Z")
_SESSION_ID = re.compile(r"\A[A-Za-z0-9_-]{1,100}\Z")
_LEADING_ROW = re.compile(r"\A(\d{1,6})(?![\d])")
_DATE_KEY = re.compile(r"\A\d{4}-\d{2}-\d{2}")

REPO_LABELS = {"messagefoundry": "engine", "messagefoundry-vault": "vault", "korus": "korus"}


@dataclass(frozen=True)
class Created:
    """The pull request a command created."""

    owner: str
    repo: str
    number: int

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/pull/{self.number}"

    @property
    def label(self) -> str:
        return REPO_LABELS.get(self.repo.lower(), self.repo)


def is_pr_create(command: str) -> str | None:
    """'cli' for gh pr create, 'rest' for a POST to a pulls collection, else None."""
    if PR_CREATE.search(command):
        return "cli"
    if API_CALL.search(command) and PULLS_PATH.search(command):
        if POST.search(command):
            return "rest"
        if FIELD.search(command) and not GET.search(command):
            return "rest"
    return None


def response_text(response: object) -> tuple[str, bool]:
    """The tool response's output text, and whether it shows a failure."""
    if isinstance(response, str):
        return response, False
    if not isinstance(response, dict):
        return "", False
    failed = False
    for key in ("interrupted", "is_error", "isError"):
        if response.get(key) is True:
            failed = True
    for key in ("exitCode", "exit_code", "returncode", "returnCode", "code"):
        value = response.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value != 0:
            failed = True
    parts = [
        response[k]
        for k in ("stdout", "output", "result", "content", "stderr")
        if isinstance(response.get(k), str)
    ]
    return "\n".join(parts), failed


def created_pr(kind: str, command: str, text: str) -> Created | None:
    """The one pull request the output names, or None when it names none or several."""
    if ALREADY_EXISTS.search(text):
        return None
    if kind == "rest":
        try:
            obj = json.loads(text.strip())
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            m = PR_URL.search(str(obj.get("html_url", "")))
            number = obj.get("number")
            if m and isinstance(number, int) and int(m.group(3)) == number:
                return Created(m.group(1), m.group(2), number)
            return None
        bare = BARE_NUMBER.match(text)
        path = PULLS_PATH.search(command)
        if (
            bare
            and path
            and _LITERAL_NAME.match(path.group(1))
            and _LITERAL_NAME.match(path.group(2))
        ):
            return Created(path.group(1), path.group(2), int(bare.group(1)))
    found = {(m.group(1), m.group(2), int(m.group(3))) for m in PR_URL.finditer(text)}
    if len(found) != 1:
        return None
    owner, repo, number = found.pop()
    return Created(owner, repo, number)


def _numbers(groups: Iterable[str]) -> list[int]:
    out: list[int] = []
    for g in groups:
        for n in _NUM.findall(g):
            if int(n) not in out:
                out.append(int(n))
    return out


def batches_in(text: str) -> list[int]:
    return _numbers(m.group(1) for m in BATCH.finditer(text))[:MAX_BATCHES]


def backlog_rows_in(text: str) -> list[int]:
    return _numbers(m.group(1) for m in BACKLOG.finditer(text))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _real(path: Path) -> Path:
    return Path(os.path.normcase(os.path.realpath(path)))


def allowed_body_file(
    raw: str, cwd: str | None, worktree: str | None, session: str, temp_dir: str
) -> Path | None:
    """The body file a command names, when it is inside the worktree or this session's scratchpad.

    The scratchpad is any folder under ``<temp>/claude`` with this session's id as a path part,
    which is where the harness puts it. Relative paths resolve against the tool's cwd.
    """
    name = raw.strip().strip("'\"")
    if not name or name == "-":
        return None
    p = Path(name)
    if not p.is_absolute():
        if not cwd:
            return None
        p = Path(cwd) / p
    try:
        real = _real(p)
    except (OSError, ValueError):
        return None
    if worktree and _inside(real, _real(Path(worktree))):
        return real
    scratch = _real(Path(temp_dir) / "claude")
    if _SESSION_ID.match(session) and _inside(real, scratch):
        parts = [x.lower() for x in real.relative_to(scratch).parts[:-1]]
        if session.lower() in parts:
            return real
    return None


def body_texts(
    kind: str, command: str, cwd: str | None, worktree: str | None, session: str, temp_dir: str
) -> list[str]:
    out: list[str] = []
    pattern = CLI_BODY_FILE if kind == "cli" else API_BODY_FILE
    for m in pattern.finditer(command):
        path = allowed_body_file(m.group(1), cwd, worktree, session, temp_dir)
        if path is None:
            continue
        try:
            with path.open("rb") as fh:
                out.append(fh.read(BODY_CAP_BYTES).decode("utf-8", errors="replace"))
        except OSError:
            continue
    return out


def _git(cwd: str, *argv: str) -> str:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-C", cwd, *argv],
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def head_sha(kind: str, command: str, cwd: str | None) -> str | None:
    """The short SHA of the PR's head, read from the local clone, or None."""
    if not cwd or not os.path.isdir(cwd):
        return None
    m = (CLI_HEAD if kind == "cli" else API_HEAD).search(command)
    ref = m.group(1) if m else ("HEAD" if kind == "cli" else None)
    if not ref:
        return None
    ref = ref.split(":", 1)[-1]
    if not _SAFE_REF.match(ref) or ref.startswith("-"):
        return None
    for candidate in (ref, f"origin/{ref}"):
        sha = _git(cwd, "rev-parse", "--verify", "--quiet", "--short=11", f"{candidate}^{{commit}}")
        if _SHA.match(sha):
            return sha
    return None


def _load_coord_root() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "coord" / "coord_root.py"
    spec = importlib.util.spec_from_file_location("mefor_coord_root_runbook_done", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    # Registered before it runs: its @dataclass looks its own module up in sys.modules.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def claimed_rows(
    claims: Path, worktree: str, is_here: Callable[[object], bool] | None = None
) -> set[int]:
    """Rows this worktree holds claims on: a claim file whose key leads with a row number and whose
    record names this worktree (and this machine, when ``is_here`` is given)."""
    mine = os.path.normcase(os.path.realpath(worktree))
    out: set[int] = set()
    for entry in os.scandir(claims):
        name = entry.name.lower()
        if not name.endswith(".json") or _DATE_KEY.match(name):
            continue
        m = _LEADING_ROW.match(name)
        if not m:
            continue
        try:
            rec = json.loads(Path(entry.path).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, RecursionError):
            continue
        if not isinstance(rec, dict):
            continue
        if is_here is not None and not is_here(rec):
            continue
        wt = rec.get("worktree")
        try:
            if isinstance(wt, str) and os.path.normcase(os.path.realpath(wt)) == mine:
                out.add(int(m.group(1)))
        except (OSError, ValueError):
            continue
    return out


def session_claimed_rows(worktree: str) -> set[int]:
    """Rows this worktree's claims hold, read through coord_root.py as claim.ps1 resolves them,
    following one ``mefor.claimsRoot`` hop. Raises on what it cannot resolve."""
    cr = _load_coord_root()
    registry = worktree
    hop = _git(worktree, "config", "--get", "mefor.claimsRoot")
    if hop:
        top = _git(hop, "rev-parse", "--path-format=absolute", "--show-toplevel")
        if not top:
            raise OSError("mefor.claimsRoot names no repository")
        registry = top
    local = cr.local_root(registry)
    if local is None:
        raise OSError("git could not name the common dir")
    # claim.ps1 records the checkout of the copy it ran from, so the primary's claims belong to
    # whichever sessions ran the primary's copy; they say nothing about a session there.
    own = cr.local_root(worktree)
    if own is None or _real(Path(own).parent) == _real(Path(worktree)):
        return set()
    resolved = cr.resolve("claims", registry, local=local)
    if resolved.path is None:
        raise OSError(resolved.error or "no claims directory")
    return claimed_rows(Path(resolved.path), worktree, cr.record_is_here)


def _q(path: str) -> str:
    return f'"{path}"'


def done_command(
    python: str, read_batch: str, batch: str, pr: Created, sha: str | None, rows: list[int]
) -> str:
    sha_text = sha or "<head sha>"
    note = f"{pr.label} PR {pr.number} ({sha_text}) open"
    row_args = (
        " ".join(f'--row {r}="In {pr.label} PR {pr.number} (batch {batch})"' for r in rows)
        if rows
        else '--row <ROW>="<where it stands>"'
    )
    return (
        f'{_q(python)} {_q(read_batch)} --done {batch} --holder "<the text you gave --take>" '
        f'--state "PR OPEN" --note "{note}" {row_args}'
    )


AFTER = (
    "Give --holder the same text you gave --take. --done refuses until every row of the batch "
    "still reading Not started or In progress has a --row, and refuses a row that is not in the "
    "batch, so run read_batch.py with the batch number to list its rows. Run --done again when "
    "the PR merges, with --state MERGED. A row recorded PARTIAL (in its --row text or its Rows "
    "tab Status) makes --state MERGED refuse, so a batch with a PARTIAL row is never recorded "
    "MERGED: leave it at PR OPEN so --next still offers the remainder. This reminder read only "
    "the command and its body file, never the workbook. Off switch: MEFOR_RUNBOOK_PROMPT=off."
)


def message(
    pr: Created,
    batches: list[int],
    held: list[int],
    rows: list[int],
    sha: str | None,
    python: str,
    read_batch: str,
) -> str | None:
    shown_rows = rows[:MAX_ROWS]
    if batches:
        names = ", ".join(str(b) for b in batches)
        cmds = "\n".join(
            "  " + done_command(python, read_batch, str(b), pr, sha, shown_rows) for b in batches
        )
        return (
            f"[runbook] This command opened {pr.label} PR {pr.number} ({pr.url}), and its title "
            f"or body names runbook batch {names}. Record it on the owner's runbook workbook now, "
            f"as the /batch skill's Step 7 requires:\n{cmds}\n{AFTER}"
        )
    if held:
        cited = ", ".join(f"#{r}" for r in held[:MAX_ROWS])
        cmd = done_command(python, read_batch, "<NN>", pr, sha, held[:MAX_ROWS])
        return (
            f"[runbook] This command opened {pr.label} PR {pr.number} ({pr.url}). It names no "
            f"runbook batch, but it cites BACKLOG {cited}, which this session holds claims on, so "
            "those rows may belong to a runbook batch. To look it up, find each row in the Row "
            "column of the workbook's Rows tab, or ask the Manager that briefed you, and confirm "
            "with read_batch.py and the batch number. If they are in a batch, record the PR:\n"
            f"  {cmd}\n{AFTER}"
        )
    return None


def run(args: argparse.Namespace, raw: str) -> str | None:
    """The context text to print, or None. Raises on what it cannot read."""
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("tool_name") not in ("Bash", "PowerShell"):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        return None
    command: str = tool_input["command"][:COMMAND_CAP_CHARS]
    kind = is_pr_create(command)
    if kind is None:
        return None
    text, failed = response_text(payload.get("tool_response"))
    if failed:
        return None
    pr = created_pr(kind, command, text)
    if pr is None:
        return None
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    worktree = args.worktree or None
    session = str(payload.get("session_id") or args.session or "")
    corpus = "\n".join(
        [
            command,
            *body_texts(
                kind, command, cwd, worktree, session, args.temp_dir or tempfile.gettempdir()
            ),
        ]
    )
    batches = batches_in(corpus)
    rows = [r for r in backlog_rows_in(corpus) if r not in batches]
    held: list[int] = []
    if not batches and rows and worktree:
        if args.claims_dir:
            mine = claimed_rows(Path(args.claims_dir), worktree)
        else:
            mine = session_claimed_rows(worktree)
        held = [r for r in rows if r in mine]
    if not batches and not held:
        return None
    sha = head_sha(kind, command, cwd)
    return message(pr, batches, held, rows, sha, args.python, args.read_batch)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", default="")
    ap.add_argument("--session", default="")
    ap.add_argument("--python", default="python")
    ap.add_argument("--read-batch", default="read_batch.py")
    ap.add_argument("--temp-dir", default="")
    ap.add_argument("--claims-dir", default="")
    try:
        args = ap.parse_args(argv)
        raw = sys.stdin.buffer.read(4 * COMMAND_CAP_CHARS).decode("utf-8", errors="replace")
        text = run(args, raw)
    except SystemExit:
        return 0
    except Exception as exc:  # noqa: BLE001 - a hook helper must never fail the tool call
        print(f"runbook-done-prompt: nothing printed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 0
    if text:
        sys.stdout.write(json.dumps({"additionalContext": text}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
