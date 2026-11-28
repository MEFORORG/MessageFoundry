# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remind a session that just opened a batch pull request to record it on the runbook workbook.

Run by ``scripts/hooks/runbook-done-prompt.ps1``, a PostToolUse hook on the Bash and PowerShell
tools, with the hook input on stdin. Owner instruction 2026-11-28, in a Manager's chat: nothing
reminded a Manager to run ``read_batch.py --done NN --state "PR OPEN"`` when it opened a batch's
pull request, so the owner's runbook dashboard kept reading TAKEN or FREE for a batch with a PR.

WHAT IT MATCHES. One segment of the command (split at ``;``, ``&``, ``|`` and line breaks outside
quotes) that creates a pull request: ``gh pr create``, or ``gh api`` on a ``.../pulls`` path with
``-X POST``/``--method POST``, or with a field flag and no GET, which gh sends as a POST. Every flag
it reads afterwards (body file, head, method) is read from that segment only. The tool response
must show that it succeeded: no failure flag, no "already exists" from gh pr create, and one pull
request named in the output (a ``.../pull/N`` URL, a REST JSON object with ``number``, or a bare
number printed by ``--jq .number``). Output sent to a file, or anything else it cannot read, means
no reminder.

WHAT IT PRINTS. One JSON object, ``{"additionalContext": ...}``, which the wrapper puts in the
event's hookSpecificOutput. It names every runbook batch that segment or its body file mentions
("batch NN", "Batch NN", "batches NN and MM") and gives the exact ``--done`` command. A number after
"batch" in prose ("batch 100 messages") reads as a batch too, so the text tells the session to check
the batch with read_batch.py. With no batch named, it says so only when the PR cites ``BACKLOG #N``
rows this session's worktree holds claims on, since those rows may belong to a batch. Otherwise it
prints nothing.

WHAT IT NEVER DOES. It never blocks, and every path exits 0. It never reads the workbook, makes no
gh call and sends nothing to GitHub. The children it starts are a local ``git rev-parse`` for the
head SHA and, on the claims path only, the ``git config`` and ``git rev-parse`` calls the claims
registry hop needs. That path resolves the claims directory through coord_root.py, which may probe
the shared root's server and write coord_root.py's own down-cache, as every claims reader does; this
file writes nothing itself. A body file is read only when the session's worktree is known and the
file sits inside it or the session's own scratchpad, only from a local (not UNC) path, and only its
first ``BODY_CAP_BYTES``.

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

# gh as the segment's own program: first word, after any PowerShell call operator and VAR=value
# prefixes, called by bare name or by path (C:\\...\\gh.exe, /usr/bin/gh), quoted or not. A "gh pr
# create" inside another program's argument (a commit message) is not a call.
_GH = (
    r"\A\s*(?:&\s*)?(?:\w+=\S*\s+)*"
    r"(?:\"[^\"]*[\\/]|'[^']*[\\/]|[^\s'\"]*[\\/])?gh(?:\.exe)?['\"]?"
)
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

# "batch 7", "Batch #52", "batch-20014"; a list or range only after the plural, "batches 20014 and
# 20015", "batches 118-120", so "batch 20014, 5850 and 5851" names one batch and two other numbers.
BATCH = re.compile(r"(?<![\w])batch[\s#:_-]*(\d{1,6})(?![\w])", re.IGNORECASE)
BATCHES = re.compile(
    r"(?<![\w])batches[\s#:_-]*(\d{1,6}(?:\s*(?:,|&|-|\band\b|\bto\b)\s*#?\d{1,6})*)(?![\w])",
    re.IGNORECASE,
)
_RANGE = re.compile(r"(\d{1,6})\s*(?:-|\bto\b)\s*#?(\d{1,6})")
RANGE_MAX = 30
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
    r"(?<![\w-])(?:(?:-F|--field)(?:\s+|=)"
    r"(?:\"body=@([^\"\x00-\x1f]+)\"|'body=@([^'\x00-\x1f]+)'|body=@([^\s'\";|&]+))"
    r"|--input(?:\s+|=)" + _PATH + ")"
)
CLI_HEAD = re.compile(r"(?<![\w-])(?:--head|-H)(?:\s+|=)['\"]?([\w./:-]+)")
# Only a head field, never "head=" inside another field's value.
API_HEAD = re.compile(r"(?<![\w-])(?:-f|-F|--field|--raw-field)(?:\s+|=)['\"]?head=([\w./:-]+)")
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


def segments(command: str, shell: str = "bash") -> list[str]:
    """The command split at ``;``, ``&``, ``|`` and line breaks that sit outside quotes.

    The escape character is the shell's: backslash for bash (outside quotes and inside double
    quotes), backtick for PowerShell (likewise). An escaped line break is a line continuation, so it
    joins the lines rather than splitting them. A rough reading, and it only has to be good enough
    to keep one call's flags apart from the next call's; ``$(...)`` nesting is not followed."""
    esc = "`" if shell == "pwsh" else "\\"
    out: list[str] = []
    cur: list[str] = []
    quote = ""
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if c == esc and quote != "'" and i + 1 < n:
            nxt = command[i + 1]
            if nxt in "\r\n":
                # A continuation: the line break and a CR LF pair read as one space.
                i += 3 if command[i + 1 : i + 3] == "\r\n" else 2
                cur.append(" ")
                continue
            cur.append(c + nxt)
            i += 2
            continue
        if quote:
            cur.append(c)
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c in ";&|\r\n":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [x for x in out if x.strip()]


def classify(segment: str) -> str | None:
    """'cli' for gh pr create, 'rest' for a POST to a pulls collection, else None."""
    if PR_CREATE.match(segment):
        return "cli"
    if API_CALL.match(segment) and PULLS_PATH.search(segment):
        if POST.search(segment):
            return "rest"
        if FIELD.search(segment) and not GET.search(segment):
            return "rest"
    return None


def find_create(command: str, shell: str = "bash") -> tuple[str, str] | None:
    """The kind and the segment of the first pull request creation in the command, or None."""
    for segment in segments(command, shell):
        kind = classify(segment)
        if kind is not None:
            return kind, segment
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
    # gh pr create's refusal; a REST response echoes the PR's own body, which may say anything.
    if kind == "cli" and ALREADY_EXISTS.search(text):
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


def _expand(group: str) -> str:
    """A batches list with each short range written out: "118-120" reads as "118 119 120"."""

    def one(m: re.Match[str]) -> str:
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo < hi <= lo + RANGE_MAX:
            return " ".join(str(x) for x in range(lo, hi + 1))
        return m.group(0)

    return _RANGE.sub(one, group)


def batches_in(text: str) -> list[int]:
    found = sorted(
        [(m.start(), m.group(1)) for m in BATCH.finditer(text)]
        + [(m.start(), _expand(m.group(1))) for m in BATCHES.finditer(text)]
    )
    return _numbers(g for _, g in found)[:MAX_BATCHES]


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
    if not name or name == "-" or not worktree:
        return None
    # A UNC or device path would open a network connection inside realpath, before any check.
    if name[:2] in ("\\\\", "//", "\\/", "/\\"):
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
    if _inside(real, _real(Path(worktree))):
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
        raw = next((g for g in m.groups() if g), "")
        path = allowed_body_file(raw, cwd, worktree, session, temp_dir)
        if path is None:
            continue
        try:
            with path.open("rb") as fh:
                out.append(fh.read(BODY_CAP_BYTES).decode("utf-8", errors="replace"))
        except OSError as exc:
            _note(f"body file not read: {type(exc).__name__}")
    return out


def _note(text: str) -> None:
    """A reason on stderr, which the wrapper passes on; the model never sees it."""
    print(f"runbook-done-prompt: {text}", file=sys.stderr)


# The git the wrapper resolved from PATH, absolute, so a git.exe sitting in the session's worktree
# is never the one that runs (install-gate.ps1 records the hazard). Bare "git" only when unset.
GIT = "git"


def _git_run(cwd: str, *argv: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [GIT, "-C", cwd, *argv],
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    return proc.returncode, proc.stdout.strip()


def _git(cwd: str, *argv: str) -> str:
    code, out = _git_run(cwd, *argv)
    return out if code == 0 else ""


_OTHER_REPO = re.compile(r"(?<![\w-])(?:-R|--repo)(?:\s+|=)")


def head_sha(kind: str, command: str, cwd: str | None, response: str) -> str | None:
    """The short SHA of the PR's head: a REST create's own ``head.sha``, else the pushed branch in
    the local clone. None when the clone may be another repository's (a REST create, or ``-R``)."""
    if kind == "rest":
        try:
            obj = json.loads(response.strip())
        except ValueError:
            return None
        head = obj.get("head") if isinstance(obj, dict) else None
        sha = head.get("sha") if isinstance(head, dict) else None
        return sha[:11] if isinstance(sha, str) and _SHA.match(sha) else None
    if not cwd or not os.path.isdir(cwd) or _OTHER_REPO.search(command):
        return None
    m = CLI_HEAD.search(command)
    ref = m.group(1) if m else "HEAD"
    ref = ref.split(":", 1)[-1]
    if not _SAFE_REF.match(ref) or ref.startswith("-"):
        return None
    # The pushed branch first: the PR's head is what is on origin, not local commits after it.
    candidates = (ref,) if ref == "HEAD" else (f"origin/{ref}", ref)
    for candidate in candidates:
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
        except (OSError, ValueError, RecursionError) as exc:
            _note(f"claim {entry.name} not read: {type(exc).__name__}")
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


def is_primary(own_local_root: Path | None, worktree: str) -> bool:
    """Whether ``worktree`` is the primary checkout, given what coord_root.local_root() names for it
    (or None, which counts as primary so nothing is read). That directory sits in the common dir,
    whose parent is the primary checkout."""
    if own_local_root is None:
        return True
    return _real(Path(own_local_root).parent.parent) == _real(Path(worktree))


def session_claimed_rows(worktree: str) -> set[int]:
    """Rows this worktree's claims hold, read through coord_root.py as claim.ps1 resolves them,
    following one ``mefor.claimsRoot`` hop. Raises on what it cannot resolve."""
    cr = _load_coord_root()
    registry = worktree
    # Exit 1 is an unset key; anything else is a read that failed, and is not read as unset, as
    # claim_check.py's _config refuses it: that would resolve a registry nothing writes.
    code, hop = _git_run(worktree, "config", "--get", "mefor.claimsRoot")
    if code not in (0, 1):
        raise OSError(f"git config --get mefor.claimsRoot exited {code}")
    if code == 0 and hop:
        top = _git(hop, "rev-parse", "--path-format=absolute", "--show-toplevel")
        if not top:
            raise OSError("mefor.claimsRoot names no repository")
        registry = top
    local = cr.local_root(registry)
    if local is None:
        raise OSError("git could not name the common dir")
    # claim.ps1 records the checkout of the copy it ran from, so the primary's claims belong to
    # whichever sessions ran the primary's copy; they say nothing about a session there.
    if is_primary(cr.local_root(worktree), worktree):
        return set()
    resolved = cr.resolve("claims", registry, local=local)
    if resolved.path is None:
        raise OSError(resolved.error or "no claims directory")
    return claimed_rows(Path(resolved.path), worktree, cr.record_is_here)


def _q(path: str, shell: str) -> str:
    # Bash eats an unquoted backslash, so a path is always single-quoted there. PowerShell keeps it
    # bare unless it has a space; a quoted first word is a string there, so done_command then adds
    # the call operator.
    if shell == "bash":
        return "'" + path.replace("'", "'\\''") + "'"
    return f'"{path}"' if " " in path else path


def done_command(
    python: str,
    read_batch: str,
    batch: str,
    pr: Created,
    sha: str | None,
    rows: list[int],
    shell: str = "pwsh",
) -> str:
    sha_text = sha or "<head sha>"
    note = f"{pr.label} PR {pr.number} ({sha_text}) open"
    row_args = (
        " ".join(f'--row {r}="In {pr.label} PR {pr.number} (batch {batch})"' for r in rows)
        if rows
        else '--row <ROW>="<where it stands>"'
    )
    lead = "& " if shell == "pwsh" and " " in python else ""
    return (
        f'{lead}{_q(python, shell)} {_q(read_batch, shell)} --done {batch} --holder "<the text you gave --take>" '
        f'--state "PR OPEN" --note "{note}" {row_args}'
    )


AFTER = (
    "Give --holder the same text you gave --take. --done refuses until every row of the batch "
    "still reading Not started or In progress has a --row, and refuses a row that is not in the "
    "batch, so run read_batch.py with the batch number to list its rows, and drop or add --row "
    "arguments to match; the rows above are the ones the PR cites. Run --done again when "
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
    shell: str = "pwsh",
) -> str | None:
    # With several batches, which cited row is in which is unknown here, and --done refuses a row
    # from another batch, so no row is filled in.
    shown_rows = rows[:MAX_ROWS] if len(batches) <= 1 else []
    if batches:
        names = ", ".join(str(b) for b in batches)
        cmds = "\n".join(
            "  " + done_command(python, read_batch, str(b), pr, sha, shown_rows, shell)
            for b in batches
        )
        return (
            f"[runbook] This command opened {pr.label} PR {pr.number} ({pr.url}), and its title "
            f"or body names runbook batch {names}. If that is a runbook batch (read_batch.py with "
            "the number shows it), record the PR on the owner's runbook workbook now, as the "
            f"/batch skill's Step 7 requires:\n{cmds}\n{AFTER}"
        )
    if held:
        cited = ", ".join(f"#{r}" for r in held[:MAX_ROWS])
        cmd = done_command(python, read_batch, "<NN>", pr, sha, held[:MAX_ROWS], shell)
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
    shell = "pwsh" if payload.get("tool_name") == "PowerShell" else "bash"
    found = find_create(tool_input["command"][:COMMAND_CAP_CHARS], shell)
    if found is None:
        return None
    kind, command = found
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
    rows = backlog_rows_in(corpus)
    held: list[int] = []
    if not batches and rows and worktree:
        if args.claims_dir:
            mine = claimed_rows(Path(args.claims_dir), worktree)
        else:
            mine = session_claimed_rows(worktree)
        held = [r for r in rows if r in mine]
    if not batches and not held:
        return None
    sha = head_sha(kind, command, cwd, text)
    return message(pr, batches, held, rows, sha, args.python, args.read_batch, shell)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", default="")
    ap.add_argument("--session", default="")
    ap.add_argument("--python", default="python")
    ap.add_argument("--read-batch", default="read_batch.py")
    ap.add_argument("--temp-dir", default="")
    ap.add_argument("--claims-dir", default="")
    ap.add_argument("--git", default="")
    try:
        args = ap.parse_args(argv)
        global GIT
        if args.git:
            GIT = args.git
        # Read whole: the input carries the tool's output too, and a cut one is not JSON.
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
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
