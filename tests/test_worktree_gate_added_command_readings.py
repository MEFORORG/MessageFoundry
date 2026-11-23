# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rules 3c, 3d, 3 and 3b also judge rewritten readings of the whole command (BACKLOG #5655 step 3).

The hook's Get-AddedCommandReadings returns the command as given, then at most these rewrites: a git
word the owning-word search skips (``\\git``, ``/usr/bin/git``, on Windows ``GIT``) spelled ``git``,
a posix backtick substitution spelled ``$( )``, each git-bearing inner invocation hoisted to where the
shell runs it, and the outer invocation with its closed ``$( )`` replaced by ``_``. Each is judged by
the same rules after the command as given, so a rewrite can only add a deny.

Each ``_is_denied`` row was measured ALLOW at ``BASELINE`` (origin/main when this was built). The
differential test runs every row of this file, and the shapes of the earlier quoted-path file,
through both the shipped hook and the hook as it stood at ``BASELINE``, and fails on any input the
baseline denies and the shipped hook allows. It also checks that each ``_is_denied`` row really was
an ALLOW there, so a row that pinned nothing new would be seen.
"""

from __future__ import annotations

import shutil
import string
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import run_gate
from tests.test_worktree_gate_hijack import _make_repo, shell

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)

#: origin/main when the rewrites were added: the hook every differential row is compared against.
BASELINE = "1983d8eb79ab84281a646c53b030f0378ccfd370"
_HOOK = "scripts/hooks/worktree_gate.ps1"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DISARM = "core." + "hooksPath /nope"
_BT = "`"

#: (template, cwd, tool, text in the refusal). Each was ALLOW at BASELINE.
DENIED: list[tuple[str, str, str, str]] = [
    # An inner `config` anchored the disarm match on the inner invocation (step 3, first shape).
    (
        "git -C '{p}' -c user.name=$(git config user.name) config {k}",
        "outside",
        "Bash",
        "SHARED git",
    ),
    (
        "git -C '{p}' -c user.name=$(git config user.name) config {k}",
        "outside",
        "PowerShell",
        "SHARED git",
    ),
    # A path-qualified or escaped outer git the owning-word search skipped.
    ("\\git -C '{p}' -c user.name=$(git log -1) config {k}", "outside", "Bash", "SHARED git"),
    (
        "/usr/bin/git -C '{p}' -c user.name=$(git log -1) config {k}",
        "outside",
        "Bash",
        "SHARED git",
    ),
    (
        "C:/x/git.exe -C '{p}' -c user.name=$(git log -1) config {k}",
        "outside",
        "PowerShell",
        "SHARED git",
    ),
    # A repository token in the owning window, behind a `-c` whose value is a substitution.
    (
        "git --git-dir='{p}/.git' -c user.name=$( git log -1) config {k}",
        "outside",
        "Bash",
        "SHARED git",
    ),
    (
        "GIT_DIR='{p}/.git' git -c user.name=$( git log -1) config {k}",
        "outside",
        "Bash",
        "SHARED git",
    ),
    # A chdir ahead of a bracket-joined invocation the rules did not read as git.
    ("cd {p} && git -C {o} log {bt}git reset --hard{bt}", "outside", "Bash", "SHARED PRIMARY"),
    ("cd {p} && git -C {o} log $(\\git reset --hard)", "outside", "Bash", "SHARED PRIMARY"),
    ("cd {p} && git -C {o} log $(/usr/bin/git reset --hard)", "outside", "Bash", "SHARED PRIMARY"),
    # ...or where an earlier substitution stopped the chdir follower.
    (
        "cd {p} && echo $(date); git -C {o} log $(git reset --hard)",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    (
        "cd {p}\necho $(date); git -C {o} log $(git reset --hard)",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    # A backtick inner invocation run in the session's governed cwd.
    ("git -C {o} log {bt}git config {k}{bt}", "primary", "Bash", "SHARED git"),
    ("git -C {o} log {bt}git reset --hard{bt}", "primary", "Bash", "SHARED PRIMARY"),
    # Rules 3b and 3d on an inner invocation.
    ("echo $(git -C {wt} checkout {b})", "outside", "Bash", "LINKED WORKTREE"),
    ("git -C {o} log $(git -C '{wt}' checkout {b})", "outside", "Bash", "LINKED WORKTREE"),
    ("git -C {o} log {bt}git -C '{wt}' checkout {b}{bt}", "outside", "Bash", "LINKED WORKTREE"),
    ("x={bt}git -C {p} worktree remove {wt}{bt}", "outside", "Bash", "worktree remove"),
    # Inside DOUBLE quotes bash runs a backtick and a `$( )`, so the reset really runs.
    (
        'git commit -m "never run {bt}git reset --hard{bt} here"',
        "primary",
        "Bash",
        "SHARED PRIMARY",
    ),
    ('git commit -m "never run $(git reset --hard) here"', "primary", "Bash", "SHARED PRIMARY"),
]

#: Rows that hold only on Windows, where `GIT` runs git.exe.
DENIED_WINDOWS: list[tuple[str, str, str, str]] = [
    ("GIT reset --hard", "primary", "PowerShell", "SHARED PRIMARY"),
    ("GIT config {k}", "primary", "PowerShell", "SHARED git"),
    ("GIT reset --hard", "primary", "Bash", "SHARED PRIMARY"),
]

#: (template, cwd, tool). Allowed at BASELINE and still allowed: the rewrites must not refuse these.
ALLOWED: list[tuple[str, str, str]] = [
    # What the shell takes literally is not rewritten: single quotes, a quoted heredoc, a here-string.
    ("git commit -m 'never run {bt}git reset --hard{bt} here'", "primary", "Bash"),
    ("git commit -m 'never run $(git reset --hard) here'", "primary", "Bash"),
    ("git commit -m 'never run {bt}\\git -C {p} config {k}{bt}'", "outside", "Bash"),
    (
        "cat <<'EOF' > notes.md\nrun {bt}git reset --hard{bt} or $(git reset --hard)\nEOF",
        "primary",
        "Bash",
    ),
    ("Write-Output '$(git reset --hard)'", "primary", "PowerShell"),
    ("git -C '{o}' -c user.name=$(git config user.name) config {k}", "outside", "Bash"),
    ("git -C '{o}' -c user.name=$(git config user.name) config {k}", "outside", "PowerShell"),
    ("\\git -C '{o}' -c user.name=$(git log -1) config {k}", "outside", "Bash"),
    ("/usr/bin/git -C '{o}' -c user.name=$(git log -1) config {k}", "outside", "Bash"),
    ("cd {o} && git -C {o} log {bt}git reset --hard{bt}", "outside", "Bash"),
    ("cd {o} && git -C {o} log $(\\git reset --hard)", "outside", "Bash"),
    ("GIT_DIR='{o}/.git' git -c user.name=$( git log -1) config {k}", "outside", "Bash"),
    ("git --git-dir='{o}/.git' -c user.name=$( git log -1) config {k}", "outside", "Bash"),
    ("git log {bt}git rev-parse HEAD{bt}", "primary", "Bash"),
    ("echo 'a {bt}b{bt} c'", "primary", "Bash"),
    ('git commit -m "$(cat msg)"', "primary", "Bash"),
    ("ls /usr/bin/git", "primary", "Bash"),
    ("cd {tmp}/git && ls", "primary", "Bash"),
    ("X={p}/git ls", "outside", "Bash"),
    ("\\git reset --hard", "wt", "Bash"),
    ("git reset --hard $(git rev-parse HEAD)", "wt", "Bash"),
    ("git -C {wt} log {bt}git rev-parse HEAD{bt}", "wt", "Bash"),
    ('git commit -m "fix {bt}x{bt}"', "wt", "Bash"),
    ('Write-Output "a{bt}tb"', "primary", "PowerShell"),
    ('git log --format="%H{bt}t%s"', "primary", "PowerShell"),
    ("& 'C:\\Program Files\\Git\\cmd\\git.exe' -C '{o}' status", "outside", "PowerShell"),
    ("C:/x/git.exe status", "primary", "PowerShell"),
    ("git -C {o} log $(git -C {o} rev-parse HEAD)", "primary", "Bash"),
    ("echo $(git -C {o} checkout main)", "outside", "Bash"),
]


@pytest.fixture
def rig(tmp_path: Path) -> SimpleNamespace:
    """A governed primary with a linked worktree, plus an UNGOVERNED repository beside it."""
    r = _make_repo(tmp_path, "Primary")
    outside = tmp_path / "Outside"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(outside)], check=True, capture_output=True
    )
    r.outside = outside
    r.tmp = tmp_path
    return r


def _fmt(rig: SimpleNamespace, template: str) -> str:
    return template.format(
        p=rig.primary.as_posix(),
        tmp=rig.tmp.as_posix(),
        wt=rig.wt.as_posix(),
        o=rig.outside.as_posix(),
        b=rig.other,
        k=_DISARM,
        bt=_BT,
    )


def _cwd(rig: SimpleNamespace, where: str) -> Path:
    return {"primary": rig.primary, "outside": rig.outside, "wt": rig.wt, "tmp": rig.tmp}[where]


def _verdict(rig: SimpleNamespace, row: tuple[str, ...], gate: Path | None = None) -> str | None:
    """The refusal text, or None for an allow."""
    template, where, tool = row[0], row[1], row[2]
    result = run_gate(shell(_fmt(rig, template), _cwd(rig, where), tool), rig.repos, gate=gate)
    if result is None:
        return None
    return str(result["hookSpecificOutput"]["permissionDecisionReason"])


@pytest.mark.parametrize("row", DENIED, ids=lambda r: f"{r[2]}-{r[1]}-{r[0]}")
def test_a_rewritten_reading_is_denied(
    rig: SimpleNamespace, row: tuple[str, str, str, str]
) -> None:
    reason = _verdict(rig, row)
    assert reason is not None, "expected a DENY, got allow"
    assert row[3] in reason, reason


@pytest.mark.skipif(sys.platform != "win32", reason="`GIT` runs git.exe only on a Windows volume")
@pytest.mark.parametrize("row", DENIED_WINDOWS, ids=lambda r: f"{r[2]}-{r[1]}-{r[0]}")
def test_an_upper_case_git_word_is_denied_on_windows(
    rig: SimpleNamespace, row: tuple[str, str, str, str]
) -> None:
    reason = _verdict(rig, row)
    assert reason is not None, "expected a DENY, got allow"
    assert row[3] in reason, reason


@pytest.mark.parametrize("row", ALLOWED, ids=lambda r: f"{r[2]}-{r[1]}-{r[0]}")
def test_a_rewritten_reading_does_not_refuse_a_harmless_command(
    rig: SimpleNamespace, row: tuple[str, str, str]
) -> None:
    assert _verdict(rig, row) is None


# ------------------------------------------------------------------ the differential


def _baseline_hook(dest: Path) -> Path | None:
    """The hook at BASELINE, written to ``dest``, or None where this clone does not hold that commit."""
    probe = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "cat-file", "-e", f"{BASELINE}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        return None
    blob = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "show", f"{BASELINE}:{_HOOK}"],
        capture_output=True,
        check=True,
    )
    dest.write_bytes(blob.stdout)
    return dest


@pytest.fixture
def baseline(tmp_path: Path) -> Path:
    hook = _baseline_hook(tmp_path / "worktree_gate_baseline.ps1")
    if hook is None:
        pytest.skip(f"this clone does not hold {BASELINE}; fetch it to run the differential")
    return hook


_KNOWN_PLACEHOLDERS = {"p", "tmp", "wt", "o", "b", "k", "bt"}


def _placeholders(template: str) -> set[str]:
    return {field for _, field, _, _ in string.Formatter().parse(template) if field is not None}


def _quoted_file_rows() -> list[tuple[str, str, str]]:
    """Every (template, cwd, tool) the earlier quoted-path file states, read from its parametrize marks.

    A template is taken from any string parameter that names only this file's placeholders, and a
    cwd or tool from a sibling parameter when the row carries one; a row without one runs from
    outside, under Bash.
    """
    import tests.test_worktree_gate_quoted_and_every_invocation as quoted

    cwds = {"primary", "outside", "wt", "tmp"}
    tools = {"Bash", "PowerShell"}
    rows: list[tuple[str, str, str]] = []
    for name in dir(quoted):
        fn = getattr(quoted, name)
        if not name.startswith("test_") or not callable(fn):
            continue
        marks = [m for m in getattr(fn, "pytestmark", []) if m.name == "parametrize"]
        tool_choices = [
            list(m.args[1]) for m in marks if m.args[0] == "tool" and set(m.args[1]) <= tools
        ]
        for m in marks:
            for value in m.args[1]:
                params = value if isinstance(value, tuple) else (value,)
                strings = [p for p in params if isinstance(p, str)]
                templates = [
                    s
                    for s in strings
                    if "{" in s and "git" in s.lower() and _placeholders(s) <= _KNOWN_PLACEHOLDERS
                ]
                if not templates:
                    continue
                where = next((s for s in strings if s in cwds), "outside")
                row_tools = [s for s in strings if s in tools] or (
                    tool_choices[0] if tool_choices else ["Bash"]
                )
                for tool in row_tools:
                    rows.append((templates[0], where, tool))
    return sorted(set(rows))


#: Shapes the baseline already denied that the rewrites touch: a substitution, a backtick, a qualified
#: git word, a worktree remove or move. Only the differential reads these.
ALREADY_DENIED: list[tuple[str, str, str]] = [
    ("git -C {p} -c user.name=$(git config user.name) config {k}", "outside", "Bash"),
    ("git -C '{p}' -c user.name={bt}git log -1{bt} config {k}", "outside", "Bash"),
    ("\\git -C {p} -c user.name=$(git log -1) config {k}", "outside", "Bash"),
    ("/usr/bin/git -C '{p}' reset --hard", "outside", "Bash"),
    ("git -C '{p}' log $(\\git reset --hard)", "outside", "Bash"),
    ("git -C '{p}' log {bt}git reset --hard{bt}", "outside", "Bash"),
    ("cd {p} && git -C {o} log $(git reset --hard)", "outside", "Bash"),
    ("git -C {o} log {bt}\\git -C {p} config {k}{bt}", "outside", "Bash"),
    ("echo {bt}git reset --hard{bt}", "primary", "Bash"),
    ("\\git config {k}", "primary", "Bash"),
    ("git -C {p} -c x=$(git rev-parse HEAD) worktree remove {wt}", "outside", "Bash"),
    ("\\git -C {p} worktree remove {wt}", "outside", "Bash"),
    ("git -C {p} worktree move {wt} {tmp}/moved", "outside", "Bash"),
    ("/usr/bin/git -C '{wt}' checkout {b}", "outside", "Bash"),
    ("git config --get core.hooksPath $(echo x)", "primary", "Bash"),
    ("& git -C '{p}' -c user.name=$(git log -1) config {k}", "outside", "PowerShell"),
    ("git -C '{p}' reset --hard ; echo $(git status)", "outside", "PowerShell"),
]


def _differential_rows() -> list[tuple[str, str, str]]:
    own = [(r[0], r[1], r[2]) for r in DENIED + ALLOWED] + ALREADY_DENIED
    if sys.platform == "win32":
        own += [(r[0], r[1], r[2]) for r in DENIED_WINDOWS]
    return sorted(set(own + _quoted_file_rows()))


@pytest.mark.parametrize("row", _differential_rows(), ids=lambda r: f"{r[2]}-{r[1]}-{r[0]}")
def test_every_input_the_baseline_denies_is_still_denied(
    rig: SimpleNamespace, baseline: Path, row: tuple[str, str, str]
) -> None:
    before = _verdict(rig, row, gate=baseline)
    after = _verdict(rig, row)
    if before is not None:
        assert after is not None, f"DENY at {BASELINE[:11]}, ALLOW now: {row}"
    if row in [(r[0], r[1], r[2]) for r in DENIED + DENIED_WINDOWS]:
        assert before is None, (
            f"a DENIED row that {BASELINE[:11]} already denied pins nothing: {row}"
        )
