# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rules 3c, 3d, 3 and 3b also judge rewritten readings of the whole command (BACKLOG #5655 step 3).

The hook's Get-AddedCommandReadings note says what the rewrites are. Each is judged by the same rules
after the command as given, so a rewrite can only add a deny.

Each ``DENIED`` row was measured ALLOW at ``BASELINE`` (origin/main when this was built). The
differential test runs this file's rows, and the rows it can harvest from the parametrize marks of
the earlier quoted-path file, through both the shipped hook and the hook as it stood at ``BASELINE``,
and fails on any of those inputs the baseline denies and the shipped hook allows. A harvested row runs
from the cwd it names, or from outside where it names none, so it can differ from the context its own
test uses; rows with other placeholders, rows no rewrite could act on, and tests with no parametrize
mark, are not harvested. It also
checks that each ``DENIED`` row really was an ALLOW there, so a row that pinned nothing new would be
seen. The differential is skipped in a clone that does not hold ``BASELINE``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import string
import subprocess
import sys
import time
from collections import Counter
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
    ("cd {p} && cd sub && git -C {o} log $(git reset --hard)", "outside", "Bash", "SHARED PRIMARY"),
    # Review round c8390202ab: an apostrophe the walk took as a quote, an escaped backtick that
    # swallowed the real opener, and eight harmless decoys that used up the hoist budget.
    (
        "cat > notes.md <<EOF\ndon't\nEOF\ncd {p} && git -C {o} log {bt}git reset --hard{bt}",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    (
        "echo $'it\\'s' && cd {p} && git -C {o} log {bt}git reset --hard{bt}",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    (
        "echo hi # it's\ncd {p} && git -C {o} log {bt}git reset --hard{bt}",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    (
        "cd {p} && echo \\{bt} && git -C {o} log {bt}git reset --hard{bt}",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    (
        "cd {p} && echo $(date)"
        + " $(git status)" * 8
        + " $(git log -1) $(git log -2); git -C {o} log $(git reset --hard)",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    # Review round e115e5da59: a PowerShell comment holding an apostrophe, and an arithmetic `<<`.
    (
        "# don't\ncd {p}; echo $(Get-Date); git -C {o} log $(git reset --hard)",
        "outside",
        "PowerShell",
        "SHARED PRIMARY",
    ),
    (
        "<# it's #>\ncd {p}; echo $(Get-Date); git -C {o} log $(git reset --hard)",
        "outside",
        "PowerShell",
        "SHARED PRIMARY",
    ),
    (
        "echo $((1<<2))\ncd {p} && echo $(date); git -C {o} log $(git reset --hard)",
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
    # Inside DOUBLE quotes bash runs a backtick and a `$( )`, so the reset really runs.
    (
        'git commit -m "never run {bt}git reset --hard{bt} here"',
        "primary",
        "Bash",
        "SHARED PRIMARY",
    ),
    ('git commit -m "never run $(git reset --hard) here"', "primary", "Bash", "SHARED PRIMARY"),
]

#: Rows that hold only where `GIT` runs git: Windows here; macOS is rewritten too but not run in CI.
DENIED_WINDOWS: list[tuple[str, str, str, str]] = [
    # Review round e115e5da59: an unrewritten `GIT` inside double quotes was dropped by the hoist.
    (
        'cd {p} && echo $(date); git -C {o} log "$(GIT reset --hard)"',
        "outside",
        "Bash",
        "SHARED PRIMARY",
    ),
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
    # Review round c8390202ab: a hoisted inner read keeps its closing `)`, so a verb-named argument
    # at its end is not read as the verb, and a separator inside quotes does not cut it.
    ("echo $(git log --grep reset)", "primary", "Bash"),
    ("n=$(git rev-list --count HEAD --grep merge)", "primary", "Bash"),
    ("git log --oneline {bt}git rev-parse --verify checkout{bt}", "primary", "Bash"),
    ("Write-Output $(git log --grep reset)", "primary", "PowerShell"),
    ("git -C {wt} log $(git -C {wt} log --format=%H --grep reset)", "primary", "Bash"),
    ('git commit -m "fix; see $(git log -1)"', "wt", "Bash"),
    # Review round e115e5da59: quoting starts afresh inside `"$( )"`, so a quoted heredoc or a single
    # quote there is literal, as the shell reads it. This is the usual commit-message idiom.
    (
        "git commit -m \"$(cat <<'EOF'\nUse {bt}git checkout {b}{bt} there.\nEOF\n)\"",
        "wt",
        "Bash",
    ),
    (
        "git commit -m \"$(cat <<'EOF'\nRun {bt}git -C {p} worktree remove {wt}{bt} later.\nEOF\n)\"",
        "outside",
        "Bash",
    ),
    ("echo \"$(echo 'never {bt}git reset --hard{bt}')\"", "primary", "Bash"),
    ("x=\"$(printf '%s' '{bt}git -C {p} config {k}{bt}')\"", "outside", "Bash"),
    ("Write-Output \"$(Write-Output '$(git reset --hard)')\"", "primary", "PowerShell"),
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


@pytest.mark.skipif(sys.platform != "win32", reason="these rows are measured on Windows only")
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


# ------------------------------------------------------------------ the cost of the passes


def test_each_git_question_is_asked_once_across_the_passes(
    rig: SimpleNamespace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hoisted string carries the lines before it, so each pass met their invocations again.

    Before Invoke-GitRead cached the hook's git calls, each pass asked git again what an earlier pass
    had asked, and the Lander measured a 1.7 s command taking 19.9 s. Git's trace2 log records each
    process the hook starts, with its argument list, so a repeated question shows as a repeated line.
    """
    trace = tmp_path / "trace2.log"
    lines = [f"echo line{i} $(git -C {{o}} checkout -q y{i})" for i in range(9)]
    command = _fmt(rig, "echo start\n" + "\n".join(lines))
    monkeypatch.setenv("GIT_TRACE2", str(trace))
    result = run_gate(shell(command, rig.wt, "Bash"), rig.repos)
    monkeypatch.delenv("GIT_TRACE2")
    assert result is None, result
    starts = [
        line.split(" start ", 1)[1].strip()
        for line in trace.read_text(encoding="utf-8", errors="replace").splitlines()
        if " start " in line
    ]
    assert starts, "the hook started no git process, so this measured nothing"
    repeated = {argv: n for argv, n in Counter(starts).items() if n > 1}
    assert not repeated, f"{len(starts)} git calls, repeated: {repeated}"


_FILLER = "abcdefghij " * 2700
_NINE = range(9)
#: (shape, template, cwd, tool): the long commands of the Lander's timing probes on 2026-11-23, nine
#: judged substitutions each behind about 30 KB of text. Every one is allowed.
TIMED: list[tuple[str, str, str, str]] = [
    (
        "one line, nine hoists, short",
        "echo " + " ".join(f"$(git -C {{o}}/d{i} checkout -q x{i})" for i in _NINE),
        "outside",
        "Bash",
    ),
    (
        "one line, nine hoists, 30 KB before them",
        f"echo {_FILLER}; echo "
        + " ".join(f"$(git -C {{o}}/d{i} checkout -q x{i})" for i in _NINE),
        "outside",
        "Bash",
    ),
    (
        "nine lines, a substitution each",
        f"echo {_FILLER}\n"
        + "\n".join(f"echo line{i} $(git -C {{o}} checkout -q y{i})" for i in _NINE),
        "wt",
        "Bash",
    ),
    (
        "nine lines, a substitution each, PowerShell",
        f"echo {_FILLER}\n"
        + "\n".join(f"echo line{i} $(git -C {{o}} checkout -q y{i})" for i in _NINE),
        "wt",
        "PowerShell",
    ),
    (
        "nine lines, a backtick each",
        f"echo {_FILLER}\n"
        + "\n".join(f"echo line{i} {{bt}}git -C {{o}} checkout -q y{i}{{bt}}" for i in _NINE),
        "wt",
        "Bash",
    ),
]


@pytest.mark.skipif(
    not os.environ.get("MEFOR_GATE_TIMING"),
    reason="a wall-clock measurement; set MEFOR_GATE_TIMING=1 to run it",
)
@pytest.mark.parametrize("case", TIMED, ids=lambda c: c[0])
def test_a_long_command_is_judged_well_inside_the_proof_wait(
    rig: SimpleNamespace, tmp_path: Path, case: tuple[str, str, str, str]
) -> None:
    """Times the shipped hook, and the hook at PRE_CACHE_HEAD where this clone holds it.

    Opt-in, because a shared CI runner's load decides a wall-clock number. Run it with ``-s`` to see
    the times. The bound is the shell entry's 20 s proof wait (scripts/worktree/install-gate.ps1).
    """
    _shape, template, where, tool = case
    payload = shell(_fmt(rig, template), _cwd(rig, where), tool)
    gates: list[tuple[str, Path | None]] = [("now", None)]
    probe = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "show", f"{PRE_CACHE_HEAD}:{_HOOK}"],
        capture_output=True,
        check=False,
    )
    if probe.returncode == 0:
        before = tmp_path / "worktree_gate_pre_cache.ps1"
        before.write_bytes(probe.stdout)
        gates.append((PRE_CACHE_HEAD[:11], before))
    times = {}
    for label, gate in gates:
        start = time.perf_counter()
        if gate is None:
            assert run_gate(payload, rig.repos) is None
        else:
            # Not run_gate: its 45 s launch limit is shorter than this hook took on these commands.
            subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(gate), "-ReposFile"]
                + [str(rig.repos)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        times[label] = round(time.perf_counter() - start, 2)
    print(f"\n{case[0]}: {times}")
    assert times["now"] < 20, times


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
def baseline(tmp_path: Path) -> Path | None:
    """The hook at BASELINE, or None where this clone does not hold it; the test skips that part."""
    return _baseline_hook(tmp_path / "worktree_gate_baseline.ps1")


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
    # A harvested row is kept only where a rewrite could apply to it. Without one the hook judges the
    # command as given alone, which is the baseline's own pass, so the row would cost two launches and
    # measure nothing the rows kept here do not.
    harvested = [r for r in _quoted_file_rows() if _REWRITE_TRIGGER.search(r[0])]
    return sorted(set(own + harvested))


#: Text a rewrite could act on: a substitution, a backtick, or a git word the rewrites respell.
_REWRITE_TRIGGER = re.compile(r"\$\(|`|\{bt\}|\\git|/git|(?i:git\.exe)|\bGIT\b")


#: The rows the harvest adds that the hook denied at PRE_CACHE_HEAD, measured on Windows on 2026-11-23.
#: With this file's own DENIED, DENIED_WINDOWS and ALREADY_DENIED rows they were that head's whole deny
#: set over the 124 differential rows then: 69 of them, and the hook with the git cache gave the same
#: verdict on all 124.
HARVESTED_DENIED_AT_PRE_CACHE_HEAD: list[tuple[str, str, str]] = [
    (
        "(cd {tmp} && ls)\ngit -C '{o}' log $(git -C '{p}' rev-parse HEAD) -- config core.hooksPath x",
        "outside",
        "Bash",
    ),
    ("(cd {tmp} && ls)\ngit -c a=$(git -C '{p}' log -1) config {k}", "outside", "Bash"),
    ("cd {p}\necho $(date)\ngit -C {o} status ; git reset --hard", "outside", "Bash"),
    ("cd {p} && git -C {o} log $(git config {k})", "outside", "Bash"),
    ("cd {p} && git -C {o} log $(git config {k})", "outside", "PowerShell"),
    ("cd {p} && git -C {o} log $(git reset --hard)", "outside", "PowerShell"),
    ("echo $(git -C '{p}' log -1) $(/usr/bin/git config {k})", "outside", "Bash"),
    ("git -C '{p}' --git-dir=$(pwd)/.git reset --hard", "outside", "Bash"),
    ("git -C '{p}' -c user.name=$(git log -1 --format=%an) config {k}", "outside", "Bash"),
    ("git -C '{p}' log $(git rev-parse HEAD) -- config core.hooksPath x", "outside", "Bash"),
    ("git -C {o} --git-dir=$(echo .git) config {k}", "primary", "Bash"),
    ("git -C {o} -c user.name=$(git log -1 --format=%an) config {k}", "primary", "Bash"),
    ("git -C {o} stash list ; git.EXE reset --hard", "primary", "Bash"),
    ("git -C {o} status ; git.EXE config {k}", "primary", "Bash"),
    ("git config alias.lg log ; /usr/bin/git -C '{p}' config {k}", "outside", "Bash"),
    ("git.EXE config {k}", "primary", "Bash"),
    ("git.EXE config {k}", "primary", "PowerShell"),
    ("git.Exe -C {p} reset --hard", "outside", "Bash"),
    ("git.Exe -C {p} reset --hard", "outside", "PowerShell"),
]

#: The rows the harvest adds that the hook allowed at PRE_CACHE_HEAD, measured with the list above.
HARVESTED_ALLOWED_AT_PRE_CACHE_HEAD: list[tuple[str, str, str]] = [
    ("cd {o} && git -C {o} log $(git config {k})", "outside", "Bash"),
    ("cd {o} && git -C {o} log $(git config {k})", "outside", "PowerShell"),
    ("cd {o} && git -C {o} log $(git reset --hard)", "outside", "Bash"),
    ("cd {o} && git -C {o} log $(git reset --hard)", "outside", "PowerShell"),
    ("git -C '{o}' -c user.name=$(git log -1 --format=%an) config {k}", "outside", "Bash"),
    ("git -C '{p}' log ; /usr/bin/git config {k}", "outside", "Bash"),
    ("git -C '{p}' log ; \\git config {k}", "outside", "Bash"),
    ("git -C {o} --git-dir=$(pwd)/.git reset --hard", "outside", "Bash"),
    ("git -C {o} log $(git reset --hard)", "outside", "Bash"),
    ("git -C {o} status ; /usr/bin/git reset --hard", "outside", "Bash"),
    ("git -C {o} status ; C:/Tools/Git/cmd/git.exe reset --hard", "outside", "Bash"),
    ("git -C {o} status ; \\git reset --hard", "outside", "Bash"),
    ("git -C {o} status; C:\\Tools\\Git\\cmd\\git.exe reset --hard", "outside", "PowerShell"),
    ("git.EXE config {k}", "outside", "Bash"),
    ("git.EXE config {k}", "outside", "PowerShell"),
]

#: The PR head before Invoke-GitRead cached the hook's git calls (BACKLOG #5655 step 3, Lander hold of
#: 2026-11-23 on the run time of the added readings). The cache must change no verdict.
PRE_CACHE_HEAD = "cf790ecc157987d2e2c0bf408db143c083d64d3e"


def _denied_at_pre_cache_head() -> set[tuple[str, str, str]]:
    own = [(r[0], r[1], r[2]) for r in DENIED + DENIED_WINDOWS] + ALREADY_DENIED
    return set(own + HARVESTED_DENIED_AT_PRE_CACHE_HEAD)


@pytest.mark.parametrize("row", _differential_rows(), ids=lambda r: f"{r[2]}-{r[1]}-{r[0]}")
def test_every_input_the_baseline_denies_is_still_denied(
    rig: SimpleNamespace, baseline: Path | None, row: tuple[str, str, str]
) -> None:
    """Also: on Windows, where it was measured, each row keeps its verdict at PRE_CACHE_HEAD.

    One launch of the shipped hook serves both checks, so the deny-set pin adds no launch per row. A
    row added to either file since that head has no recorded verdict there, and is not pinned here.
    """
    after = _verdict(rig, row)
    if sys.platform == "win32":
        allowed = {(r[0], r[1], r[2]) for r in ALLOWED} | set(HARVESTED_ALLOWED_AT_PRE_CACHE_HEAD)
        if row in _denied_at_pre_cache_head():
            assert after is not None, f"DENY at {PRE_CACHE_HEAD[:11]}, ALLOW now: {row}"
        elif row in allowed:
            assert after is None, f"ALLOW at {PRE_CACHE_HEAD[:11]}, DENY now: {row}"
    if baseline is None:
        pytest.skip(f"this clone does not hold {BASELINE}; fetch it to run the differential")
    before = _verdict(rig, row, gate=baseline)
    if before is not None:
        assert after is not None, f"DENY at {BASELINE[:11]}, ALLOW now: {row}"
    if row in [(r[0], r[1], r[2]) for r in DENIED + DENIED_WINDOWS]:
        assert before is None, (
            f"a DENIED row that {BASELINE[:11]} already denied pins nothing: {row}"
        )
