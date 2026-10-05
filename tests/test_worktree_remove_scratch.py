# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Execution tests for ``scripts/worktree/remove-scratch.ps1``.

The script deletes a folder tree under the temp root when it can show the delete is safe. Its bias
is fixed: a false refusal is a minor annoyance and a false delete destroys work. These tests drive
the REAL script as a subprocess.

Four rules hold for every test here.

* **Nothing outside ``tmp_path`` is ever a delete target.** Every rig is built under ``tmp_path``
  and the script is re-rooted there with ``-TempRoot``. The registry is a fixture passed with
  ``-ConfigRoot``, so no real session is read. Only one test runs without ``-TempRoot``, and it is
  a dry run.
* **A refusal test runs with ``-Delete`` on a rig the script would otherwise delete.** A rig that
  some other check also refuses proves nothing about the check under test. So each hazard has a
  CONTROL: a twin without the hazard, in the same invocation where one fits, or the same rig run
  again with the hazard removed. The control must be DELETED. That is also what shows one refusal
  does not stop the other targets.
* **Assert the check that refused, not only that something did.** The receipt names each check and
  its result. A test reads which check refused and that every earlier check passed.
* **Assert survival by content.** A surviving directory is not enough: the hazard tree is compared
  entry by entry, and the reparse-point tests read a canary file outside the tree.

Two things the rigs need that ``os`` cannot do, both through ``ctypes``. The idle check reads
CREATION time as well as write time, and ``os.utime`` cannot backdate a creation time, so ``_age``
calls ``SetFileTime``. And a fixture session record only reads LIVE when its ``startedAt`` matches
the start time of the process its pid names, so ``_start_ms`` calls ``GetProcessTimes``.

THE UBUNTU LEG SKIPS THIS WHOLE FILE. The script judges drive-absolute Windows paths against a
Windows known folder, and nothing in it has a POSIX meaning. Its only execution is the Windows leg.

The child's ``TEMP`` and ``TMP`` are set to the known-folder spelling of the temp root. A hosted
Windows runner spells ``TEMP`` as an 8.3 name, and the script refuses every target while ``TEMP``
and the temp root are spelled differently (see ``test_a_redirected_TEMP_refuses_every_target``).
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests._dead_pid import never_live_pid

_REPO = Path(__file__).resolve().parents[1]
SCRIPT = _REPO / "scripts" / "worktree" / "remove-scratch.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or sys.platform != "win32",
    reason="remove-scratch.ps1 judges Windows paths against a Windows known folder",
)

CHECKS = ["spelling", "temp-root", "exists", "reparse", "git", "cwd", "sessions", "idle", "in-use"]
CALLER = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
THIRD = "33333333-3333-4333-8333-333333333333"
GONE = "44444444-4444-4444-8444-444444444444"
EVERYONE = "*S-1-1-0"

_FILETIME_EPOCH = 116444736000000000  # 1601-01-01 to 1970-01-01, in 100 ns ticks


def _kernel32() -> ctypes.CDLL:
    if sys.platform != "win32":
        raise RuntimeError("Windows only")
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.SetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    k32.SetFileTime.restype = wintypes.BOOL
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.c_void_p] * 4
    k32.GetProcessTimes.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    return k32


def _stamp(path: Path, when: float, created: float | None = None) -> None:
    """Set creation, access and write time of ONE entry, never through a reparse point.

    ``created`` sets a creation time that differs from the other two.
    """
    if sys.platform != "win32":
        raise RuntimeError("Windows only")
    k32 = _kernel32()
    # FILE_WRITE_ATTRIBUTES; share everything; OPEN_EXISTING; BACKUP_SEMANTICS so a directory opens,
    # OPEN_REPARSE_POINT so a junction is stamped itself and its target is left alone.
    handle = k32.CreateFileW(str(path), 0x0100, 0x7, None, 3, 0x02000000 | 0x00200000, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        born = when if created is None else created
        made = ctypes.c_ulonglong(int(born * 10_000_000) + _FILETIME_EPOCH)
        ticks = ctypes.c_ulonglong(int(when * 10_000_000) + _FILETIME_EPOCH)
        ref = ctypes.byref(ticks)
        if not k32.SetFileTime(handle, ctypes.byref(made), ref, ref):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(handle)


def _entries(tree: Path) -> list[Path]:
    """Every entry under ``tree``, the tree itself excluded, never entering a reparse point."""
    out: list[Path] = []
    stack = [tree]
    while stack:
        with os.scandir(stack.pop()) as it:
            for entry in it:
                out.append(Path(entry.path))
                if entry.is_dir(follow_symlinks=False) and not entry.is_junction():
                    stack.append(Path(entry.path))
    return out


def _age(tree: Path, minutes: float) -> Path:
    """Make every entry of ``tree`` look created and last written ``minutes`` ago."""
    when = time.time() - minutes * 60
    for entry in [tree, *_entries(tree)]:
        _stamp(entry, when)
    return tree


def _start_ms(pid: int) -> int:
    """The process's start time as Unix milliseconds, from the clock the liveness fence reads."""
    if sys.platform != "win32":
        raise RuntimeError("Windows only")
    k32 = _kernel32()
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        times = [ctypes.c_ulonglong() for _ in range(4)]
        if not k32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        return int((times[0].value - _FILETIME_EPOCH) // 10_000)
    finally:
        k32.CloseHandle(handle)


def _junction(link: Path, target: Path) -> None:
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
        text=True,
    )


def _snapshot(tree: Path) -> list[str]:
    """Relative names of everything under ``tree``, with file sizes, for an exact survival check."""
    out = []
    for entry in _entries(tree):
        rel = str(entry.relative_to(tree))
        out.append(rel if entry.is_dir() else f"{rel} [{entry.stat().st_size}]")
    return sorted(out)


@dataclass
class Block:
    """One target's part of the output: the receipt lines and the verdict line under them."""

    raw: str
    receipt: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    extra: list[str] = field(default_factory=list)

    def refused_by(self) -> list[str]:
        return [name for name, result in self.receipt.items() if result.startswith("REFUSED")]


@dataclass
class Result:
    code: int
    out: str
    blocks: list[Block]
    summary: str

    def block(self, target: Path | str) -> Block:
        hits = [b for b in self.blocks if b.raw == str(target)]
        assert len(hits) == 1, f"expected one block for {target}, found {len(hits)}:\n{self.out}"
        return hits[0]

    def refused(self, target: Path | str, check: str, needle: str = "") -> Block:
        """Assert ``target`` was refused by ``check`` alone, with every earlier check passing."""
        b = self.block(target)
        assert b.verdict.startswith("REFUSED"), self.out
        assert b.refused_by() == [check], self.out
        if check in CHECKS:
            for earlier in CHECKS[: CHECKS.index(check)]:
                assert b.receipt[earlier].startswith(("PASS", "not decided")), self.out
        assert needle in b.receipt[check], self.out
        assert "Nothing was deleted." in b.verdict, self.out
        return b

    def deleted(self, target: Path | str) -> Block:
        b = self.block(target)
        assert b.verdict.startswith("DELETED"), self.out
        assert all(b.receipt[name].startswith("PASS") for name in CHECKS), self.out
        return b


def _parse(code: int, out: str) -> Result:
    blocks: list[Block] = []
    summary = ""
    for line in out.splitlines():
        if line.startswith("TARGET "):
            blocks.append(Block(raw=line[len("TARGET ") :]))
        elif line.startswith("SUMMARY "):
            summary = line
        elif blocks and line.startswith("  ") and not blocks[-1].verdict:
            m = re.fullmatch(r"  ([a-z-]+): (.*)", line)
            assert m, f"unparsed receipt line: {line!r}"
            blocks[-1].receipt[m.group(1)] = m.group(2)
        elif blocks and line.startswith("  "):
            blocks[-1].extra.append(line.strip())
        elif blocks and line.strip() and not blocks[-1].verdict:
            blocks[-1].verdict = line
    return Result(code=code, out=out, blocks=blocks, summary=summary)


class Rig:
    """A re-rooted temp root, a fixture session registry, and helpers that build aged trees."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.anchor = Path(os.environ["LOCALAPPDATA"]) / "Temp"
        if self.anchor not in base.parents:
            # Not a skip: a Windows leg that silently ran none of these would read as green.
            pytest.fail(
                f"tmp_path ({base}) is not inside {self.anchor}, and remove-scratch.ps1 refuses to "
                "re-root anywhere else. Run without --basetemp, or point it under that folder."
            )
        self.root = base / "root"
        self.root.mkdir()
        self.config = base / "config"
        (self.config / "sessions").mkdir(parents=True)
        self._n = 0

    def record(self, **fields: object) -> Path:
        self._n += 1
        path = self.config / "sessions" / f"rec{self._n}.json"
        path.write_text(json.dumps(fields), encoding="utf-8")
        return path

    def live_record(self, sid: str, pid: int, cwd: Path | None = None) -> Path:
        return self.record(
            pid=pid,
            sessionId=sid,
            cwd=str(cwd or self.base / "elsewhere"),
            startedAt=_start_ms(pid),
        )

    def caller(self, sid: str = CALLER) -> Path:
        """Register this pytest process, an ancestor of the script, as a LIVE session."""
        return self.live_record(sid, os.getpid())

    def tree(self, path: Path, minutes: float = 600) -> Path:
        """A small aged tree: 2 files, 1 folder, 12 bytes."""
        (path / "sub").mkdir(parents=True)
        (path / "a.txt").write_text("alpha", encoding="utf-8")
        (path / "sub" / "b.bin").write_bytes(b"1234567")
        return _age(path, minutes)

    def scratch(self, sid: str, name: str = "work") -> Path:
        return self.root / "claude" / "proj" / sid / "scratchpad" / name

    def run(
        self,
        *targets: Path | str,
        delete: bool = True,
        extra: tuple[str, ...] = (),
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        temp_root: Path | str | None = None,
        config_root: Path | str | None = None,
    ) -> Result:
        argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT)]
        root = self.root if temp_root is None else temp_root
        if root != "":
            argv += ["-TempRoot", str(root)]
        config = self.config if config_root is None else config_root
        if config != "":
            argv += ["-ConfigRoot", str(config)]
        if delete:
            argv.append("-Delete")
        child = dict(os.environ)
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
            child.pop(name, None)
        child["TEMP"] = child["TMP"] = str(self.anchor)
        child.update(env or {})
        proc = subprocess.run(
            [*argv, *extra, *[str(t) for t in targets]],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            cwd=cwd,
            env=child,
        )
        assert proc.stderr == "", proc.stderr
        return _parse(proc.returncode, proc.stdout)


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    # resolve(): a hosted runner hands out an 8.3 spelling, which the spelling check refuses.
    return Rig(tmp_path.resolve())


@pytest.fixture(scope="module")
def sleeper() -> Iterator[int]:
    """A live process that is NOT an ancestor of the script, to stand for another live session."""
    # An hour, not minutes: under -n this module's tests interleave with slower files, and a
    # sleeper that exits early turns the LIVE cases into DEAD ones. Teardown kills it either way.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"])
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=30)


# --- success, dry run and the receipt (rule 9) ---------------------------------------------------


def test_a_dry_run_is_the_default_and_changes_nothing(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    before = _snapshot(victim)

    r = rig.run(victim, delete=False)

    assert r.code == 0, r.out
    b = r.block(victim)
    assert b.verdict.startswith("WOULD DELETE"), r.out
    assert "2 file(s), 1 folder(s), 12 byte(s)" in b.verdict, r.out
    assert list(b.receipt) == CHECKS, r.out
    assert all(b.receipt[name].startswith("PASS") for name in CHECKS[:-1]), r.out
    assert b.receipt["in-use"].startswith("NOT TESTED"), r.out
    assert "mode=dry-run" in r.summary and "would-delete=1" in r.summary, r.out
    assert _snapshot(victim) == before
    assert [p.name for p in rig.root.iterdir()] == ["victim"]


def test_delete_removes_the_tree_and_leaves_no_renamed_folder(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    os.chmod(victim / "a.txt", 0o444)  # a read-only file must not stop the delete
    keep = rig.tree(rig.root / "keep")

    # Forward slashes are accepted.
    r = rig.run(str(victim).replace("\\", "/"))

    assert r.code == 0, r.out
    b = r.blocks[0]
    assert b.verdict == f"DELETED {victim}: 2 file(s), 1 folder(s), 12 byte(s)", r.out
    assert all(b.receipt[name].startswith("PASS") for name in CHECKS), r.out
    assert "deleted=1" in r.summary and "refused=0" in r.summary, r.out
    assert [p.name for p in rig.root.iterdir()] == ["keep"]
    assert _snapshot(keep) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_a_name_holding_wildcard_characters_is_taken_literally(rig: Rig) -> None:
    rig.caller()
    # To PowerShell `a[1]` is a pattern that matches `a1`. The script must read it as a name.
    bracketed = rig.tree(rig.root / "a[1]" / "build (x86) & co")
    (rig.root / "a1" / ".git").mkdir(parents=True)
    plain = rig.tree(rig.root / "a1" / "build (x86) & co")
    _age(rig.root / "a[1]", 600)
    _age(rig.root / "a1", 600)

    r = rig.run(bracketed, plain)

    assert r.code == 1, r.out
    r.deleted(bracketed)
    r.refused(plain, "git", "sits inside the git checkout")
    assert sorted(p.name for p in rig.root.iterdir()) == ["a1", "a[1]"]
    assert list((rig.root / "a[1]").iterdir()) == []
    assert _snapshot(plain) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_each_target_is_judged_alone_and_the_exit_code_says_one_was_refused(rig: Rig) -> None:
    rig.caller()
    first = rig.tree(rig.root / "first")
    fresh = rig.tree(rig.root / "fresh", minutes=0)
    last = rig.tree(rig.root / "last")

    r = rig.run(first, fresh, rig.root / "missing", last)

    assert r.code == 1, r.out
    r.deleted(first)
    r.refused(fresh, "idle")
    r.refused(rig.root / "missing", "exists")
    r.deleted(last)
    assert "targets=4 deleted=2 would-delete=0 refused=2 partial=0" in r.summary, r.out
    assert sorted(p.name for p in rig.root.iterdir()) == ["fresh"]


# --- rule 1: spelling ----------------------------------------------------------------------------


def test_every_unplain_spelling_of_an_existing_folder_is_refused(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim-long-name")
    control = rig.tree(rig.root / "control")
    before = _snapshot(victim)
    v = str(victim)
    drive, rest = v[0], v[3:]
    spellings = {
        "relative": "victim-long-name",
        "dot-dot": f"{rig.root}\\control\\..\\victim-long-name",
        "dot": f"{rig.root}\\.\\victim-long-name",
        "trailing dot": v + ".",
        "trailing space": v + " ",
        "unc": f"\\\\localhost\\{drive}$\\{rest}",
        "device": "\\\\?\\" + v,
        "short name": f"{rig.root}\\VICTIM~1",
        "stream": v + ":stream",
        "directory stream": v + "::$INDEX_ALLOCATION",
        "star": f"{rig.root}\\victim*",
        "question mark": v[:-1] + "?",
        "reserved": f"{rig.root}\\NUL",
        "reserved with extension": f"{rig.root}\\con.txt",
        "doubled separator": f"{rig.root}\\\\victim-long-name",
        "drive-relative": f"{drive}:{rest}",
    }

    r = rig.run(*spellings.values(), control, cwd=rig.root)

    assert r.code == 1, r.out
    # One comparison over every spelling, so a failure names each one that got through.
    got = {label: r.block(spelling).refused_by() for label, spelling in spellings.items()}
    assert got == dict.fromkeys(spellings, ["spelling"]), r.out
    r.deleted(control)
    assert _snapshot(victim) == before
    assert sorted(p.name for p in rig.root.iterdir()) == ["victim-long-name"]


# --- rule 2: the temp root -----------------------------------------------------------------------


def test_the_temp_root_itself_and_anything_outside_it_are_refused(rig: Rig) -> None:
    rig.caller()
    outside = rig.tree(rig.base / "outside" / "victim")
    control = rig.tree(rig.root / "control")
    kept = rig.tree(rig.root / "kept", minutes=0)

    r = rig.run(rig.root, outside, rig.base, control)

    assert r.code == 1, r.out
    r.refused(rig.root, "temp-root", "the temp root itself")
    r.refused(outside, "temp-root", "not inside the temp root")
    r.refused(rig.base, "temp-root", "not inside the temp root")
    r.deleted(control)
    assert _snapshot(outside) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]
    assert _snapshot(kept) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_under_claude_only_the_inside_of_a_scratchpad_is_deletable(rig: Rig) -> None:
    rig.caller()
    work = rig.tree(rig.scratch(CALLER, "work"))
    scratchpad = work.parent
    session = scratchpad.parent
    tasks = rig.tree(session / "tasks" / "out")
    not_a_sid = rig.tree(rig.root / "claude" / "proj" / "not-a-session" / "scratchpad" / "work")
    control = rig.tree(rig.scratch(CALLER, "control"))
    for folder in (scratchpad, session, session.parent, session.parent.parent):
        _stamp(folder, time.time() - 36000)
    before = _snapshot(rig.root / "claude")

    r = rig.run(session.parent.parent, session.parent, session, scratchpad, tasks, not_a_sid)

    assert r.code == 1, r.out
    for target in (session.parent.parent, session.parent, session, scratchpad, tasks):
        r.refused(target, "temp-root", "only the inside of a session scratchpad")
    r.refused(not_a_sid, "temp-root", "is not a session id")
    assert _snapshot(rig.root / "claude") == before

    # The control: the same layout one level further in is the caller's own, and goes.
    r = rig.run(control, work)
    assert r.code == 0, r.out
    r.deleted(control)
    r.deleted(work)


def test_a_redirected_TEMP_refuses_every_target(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    elsewhere = rig.base / "redirected"
    elsewhere.mkdir()

    r = rig.run(victim, env={"TEMP": str(elsewhere), "TMP": str(elsewhere)})

    assert r.code == 1, r.out
    r.refused(victim, "run", "is not the temp root")
    assert f"NOTE: TEMP resolves to '{elsewhere}'" in r.out, r.out
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]

    r = rig.run(victim)
    assert r.code == 0, r.out
    r.deleted(victim)


@pytest.mark.parametrize("where", ["anchor", "claude", "outside", "missing"])
def test_TempRoot_can_only_narrow(rig: Rig, where: str) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    bad = {
        "anchor": rig.anchor,
        "claude": rig.anchor / "claude",
        "outside": _REPO / "tests",
        "missing": rig.base / "no-such-root",
    }[where]

    r = rig.run(victim, temp_root=bad)

    assert r.code == 1, r.out
    b = r.block(victim)
    assert b.refused_by() == ["run"], r.out
    assert "-TempRoot" in b.receipt["run"], r.out
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


@pytest.mark.parametrize("flag", ["-ConfigRoot", "-RepoRoot"])
def test_a_test_only_parameter_is_refused_without_TempRoot(rig: Rig, flag: str) -> None:
    victim = rig.tree(rig.root / "victim")
    value = rig.config if flag == "-ConfigRoot" else _REPO

    # A DRY RUN, on purpose: this is the one invocation not re-rooted under tmp_path.
    r = rig.run(victim, delete=False, temp_root="", config_root="", extra=(flag, str(value)))

    assert r.code == 1, r.out
    r.refused(victim, "run", "work only together with -TempRoot")
    assert "(RE-ROOTED" not in r.out
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


# --- rule 3: exists, as a directory --------------------------------------------------------------


def test_a_missing_path_and_a_single_file_are_refused(rig: Rig) -> None:
    rig.caller()
    a_file = rig.root / "single.txt"
    a_file.write_text("keep me", encoding="utf-8")
    _stamp(a_file, time.time() - 36000)
    control = rig.tree(rig.root / "control")

    r = rig.run(rig.root / "missing", a_file, control)

    assert r.code == 1, r.out
    r.refused(rig.root / "missing", "exists", "was not found")
    r.refused(a_file, "exists", "the target is a file")
    r.deleted(control)
    assert a_file.read_text(encoding="utf-8") == "keep me"


# --- rule 4: reparse points ----------------------------------------------------------------------


def _canary(rig: Rig) -> Path:
    real = rig.base / "real"
    (real / "deep").mkdir(parents=True)
    (real / "deep" / "canary.txt").write_text("alive", encoding="utf-8")
    _age(real, 600)
    return real


def test_a_junction_inside_the_tree_refuses_the_whole_target(rig: Rig) -> None:
    rig.caller()
    real = _canary(rig)
    victim = rig.tree(rig.root / "victim")
    _junction(victim / "sub" / "link", real)
    _age(victim, 600)
    control = rig.tree(rig.root / "control")

    r = rig.run(victim, control)

    assert r.code == 1, r.out
    r.refused(victim, "reparse", "is a reparse point inside the tree")
    r.deleted(control)
    assert (real / "deep" / "canary.txt").read_text(encoding="utf-8") == "alive"
    assert (victim / "sub" / "link").is_junction()
    assert (victim / "a.txt").read_text(encoding="utf-8") == "alpha"


def test_a_junction_on_the_path_is_refused_and_never_followed(rig: Rig) -> None:
    rig.caller()
    real = _canary(rig)
    as_target = rig.root / "link"
    _junction(as_target, real)
    _stamp(as_target, time.time() - 36000)
    control = rig.tree(rig.root / "control")

    r = rig.run(as_target, as_target / "deep", control)

    assert r.code == 1, r.out
    r.refused(as_target, "reparse", "on the path")
    r.refused(as_target / "deep", "reparse", "on the path")
    r.deleted(control)
    assert as_target.is_junction()
    assert (real / "deep" / "canary.txt").read_text(encoding="utf-8") == "alive"


# --- rule 5: git ---------------------------------------------------------------------------------


def test_a_git_entry_at_any_depth_refuses_the_target(rig: Rig) -> None:
    rig.caller()
    with_dir = rig.tree(rig.root / "with-dir")
    (with_dir / "sub" / "deeper" / ".git").mkdir(parents=True)
    with_file = rig.tree(rig.root / "with-file")
    (with_file / "sub" / ".git").write_text("gitdir: C:/nowhere/.git/worktrees/x", encoding="utf-8")
    bare = rig.tree(rig.root / "holds-bare")
    for name in ("objects", "refs"):
        (bare / "sub" / "repo.git" / name).mkdir(parents=True)
    (bare / "sub" / "repo.git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    control = rig.tree(rig.root / "control")
    hazards = (with_dir, with_file, bare)
    for tree in hazards:
        _age(tree, 600)
    before = [_snapshot(tree) for tree in hazards]

    r = rig.run(*hazards, control)

    assert r.code == 1, r.out
    r.refused(with_dir, "git", "is a git entry inside the tree")
    r.refused(with_file, "git", "is a git entry inside the tree")
    r.refused(bare, "git", "holds HEAD, objects and refs")
    r.deleted(control)
    assert [_snapshot(tree) for tree in hazards] == before


def test_a_folder_inside_a_checkout_is_refused(rig: Rig) -> None:
    rig.caller()
    checkout = rig.root / "checkout"
    build = rig.tree(checkout / "pkg" / "build")
    (checkout / ".git").mkdir()
    bare = rig.root / "bare.git"
    objects = rig.tree(bare / "objects")
    (bare / "refs").mkdir()
    (bare / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    control = rig.tree(rig.root / "plain" / "pkg" / "build")
    for tree in (checkout, bare, rig.root / "plain"):
        _age(tree, 600)

    r = rig.run(build, objects, control)

    assert r.code == 1, r.out
    r.refused(build, "git", "sits inside the git checkout")
    r.refused(objects, "git", "sits inside the bare git repository")
    r.deleted(control)
    assert _snapshot(build) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]
    assert _snapshot(objects) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_a_registered_worktree_is_refused_even_with_its_git_pointer_gone(rig: Rig) -> None:
    rig.caller()
    repo = rig.base / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (repo / "seed.txt").write_text("seed", encoding="utf-8")
    git("add", "--", "seed.txt")
    git("commit", "-qm", "seed")
    holder = rig.root / "holder"
    holder.mkdir()
    worktree = holder / "wt"
    git("worktree", "add", "-q", "-b", "side", str(worktree))
    # Without its pointer no walk can tell this is a checkout. Only git's own registry still can.
    (worktree / ".git").unlink()
    inside = rig.tree(worktree / "build")
    _age(holder, 600)
    before = _snapshot(holder)
    extra = ("-RepoRoot", str(repo))

    r = rig.run(holder, worktree, inside, extra=extra)

    assert r.code == 1, r.out
    for target in (holder, worktree, inside):
        r.refused(target, "git", "use remove.ps1 for a worktree")
    assert _snapshot(holder) == before

    # The control: with that repository not consulted, the same folder goes.
    r = rig.run(inside)
    assert r.code == 0, r.out
    r.deleted(inside)


def test_a_git_redirect_in_the_environment_refuses_every_target(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")

    r = rig.run(victim, env={"GIT_DIR": str(rig.base / "some.git")})

    assert r.code == 1, r.out
    r.refused(victim, "run", "GIT_DIR is set")
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]

    r = rig.run(victim)
    r.deleted(victim)


# --- rule 6: the calling shell -------------------------------------------------------------------


@pytest.mark.parametrize("stand_in", ["", "sub"])
def test_the_shell_standing_in_the_target_refuses_it(rig: Rig, stand_in: str) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    control = rig.tree(rig.root / "control")

    r = rig.run(victim, control, cwd=victim / stand_in)

    assert r.code == 1, r.out
    r.refused(victim, "cwd", "standing in the target")
    r.deleted(control)
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


# --- rule 7: sessions ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fault", ["no-registry", "empty", "unparseable", "no-cwd", "no-session-id"]
)
def test_a_registry_that_cannot_be_read_refuses_every_target(rig: Rig, fault: str) -> None:
    victim = rig.tree(rig.root / "victim")
    own = rig.tree(rig.scratch(CALLER))
    broken: Path | None = None
    if fault == "no-registry":
        (rig.config / "sessions").rmdir()
    elif fault == "unparseable":
        rig.caller()
        broken = rig.record()
        broken.write_text('{"pid": 12, "sessionId": ', encoding="utf-8")
    elif fault == "no-cwd":
        rig.caller()
        broken = rig.record(pid=never_live_pid(), sessionId=OTHER)
    elif fault == "no-session-id":
        rig.caller()
        broken = rig.record(pid=never_live_pid(), cwd=str(rig.base / "elsewhere"))

    r = rig.run(victim, own)

    assert r.code == 1, r.out
    r.refused(victim, "run", "the session registry could not be read")
    r.refused(own, "run", "the session registry could not be read")
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]

    # The control: the same two folders with a readable registry.
    (rig.config / "sessions").mkdir(exist_ok=True)
    if broken is not None:
        broken.unlink()
    else:
        rig.caller()
    r = rig.run(victim, own)
    assert r.code == 0, r.out
    r.deleted(victim)
    r.deleted(own)


def test_another_sessions_scratchpad_is_refused_live_dead_or_absent(rig: Rig, sleeper: int) -> None:
    rig.caller()
    rig.live_record(OTHER, sleeper)
    rig.record(pid=never_live_pid(), sessionId=THIRD, cwd=str(rig.base / "elsewhere"))
    live = rig.tree(rig.scratch(OTHER))
    dead = rig.tree(rig.scratch(THIRD))
    absent = rig.tree(rig.scratch(GONE))
    own = rig.tree(rig.scratch(CALLER))

    # The environment variable names the other session. It must not make that scratchpad the caller's.
    r = rig.run(live, dead, absent, own, env={"CLAUDE_CODE_SESSION_ID": OTHER})

    assert r.code == 1, r.out
    assert (
        "LIVE pid"
        in r.refused(live, "sessions", "Another session's scratchpad").receipt["sessions"]
    )
    assert (
        "DEAD pid"
        in r.refused(dead, "sessions", "Another session's scratchpad").receipt["sessions"]
    )
    r.refused(absent, "sessions", "no registry record")
    assert "the caller's own" in r.deleted(own).receipt["sessions"], r.out
    for tree in (live, dead, absent):
        assert _snapshot(tree) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_a_scratchpad_is_refused_when_the_caller_cannot_be_identified(rig: Rig) -> None:
    # A registry that reads fine and holds no record for any ancestor of the script.
    rig.record(pid=never_live_pid(), sessionId=THIRD, cwd=str(rig.base / "elsewhere"))
    own = rig.tree(rig.scratch(CALLER))
    top = rig.tree(rig.root / "top-level")

    r = rig.run(own, top, env={"CLAUDE_CODE_SESSION_ID": CALLER})

    assert r.code == 1, r.out
    r.refused(own, "sessions", "no ancestor of this process holds a LIVE session record")
    r.deleted(top)
    assert _snapshot(own) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]

    rig.caller()
    r = rig.run(own)
    r.deleted(own)


@pytest.mark.parametrize("state", ["LIVE", "UNVERIFIED", "UNREADABLE"])
def test_a_session_working_inside_the_target_refuses_it(rig: Rig, sleeper: int, state: str) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    control = rig.tree(rig.root / "control")
    # A record that reads DEAD is not a veto, so it must not refuse the control.
    rig.record(pid=never_live_pid(), sessionId=THIRD, cwd=str(control / "sub"))
    cwd = str(victim / "sub")
    if state == "LIVE":
        rig.live_record(OTHER, sleeper, victim / "sub")
    elif state == "UNVERIFIED":
        rig.record(pid=sleeper, sessionId=OTHER, cwd=cwd)  # a live pid and no startedAt
    else:
        rig.record(pid="not-a-number", sessionId=OTHER, cwd=cwd)

    r = rig.run(victim, control)

    assert r.code == 1, r.out
    b = r.refused(victim, "sessions", "have their working directory in the target")
    assert f"{state} {OTHER}" in b.receipt["sessions"], r.out
    r.deleted(control)
    assert _snapshot(victim) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


# --- rule 8: idle --------------------------------------------------------------------------------


def test_the_window_is_ten_minutes_for_the_callers_scratchpad_and_sixty_elsewhere(rig: Rig) -> None:
    rig.caller()
    top_30 = rig.tree(rig.root / "top-30", minutes=30)
    top_90 = rig.tree(rig.root / "top-90", minutes=90)
    own_5 = rig.tree(rig.scratch(CALLER, "five"), minutes=5)
    own_30 = rig.tree(rig.scratch(CALLER, "thirty"), minutes=30)

    r = rig.run(top_30, top_90, own_5, own_30)

    assert r.code == 1, r.out
    r.refused(top_30, "idle", "inside the 60-minute window")
    assert "window 60" in r.deleted(top_90).receipt["idle"], r.out
    r.refused(own_5, "idle", "inside the 10-minute window")
    assert "window 10" in r.deleted(own_30).receipt["idle"], r.out
    assert _snapshot(top_30) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]
    assert _snapshot(own_5) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_one_fresh_entry_anywhere_refuses_and_creation_time_counts(rig: Rig) -> None:
    rig.caller()
    deep = rig.tree(rig.root / "deep")
    _stamp(deep / "sub" / "b.bin", time.time() - 60)
    # An old write time on an entry created two minutes ago: what an extracted or copied file
    # looks like. One rig has it on a file inside, the other on the target folder itself.
    old = time.time() - 36000
    copied = rig.tree(rig.root / "copied")
    _stamp(copied / "sub" / "b.bin", old, created=time.time() - 120)
    copied_top = rig.tree(rig.root / "copied-top")
    _stamp(copied_top, old, created=time.time() - 120)
    future = rig.tree(rig.root / "future")
    _stamp(future / "a.txt", time.time() + 86400)
    control = rig.tree(rig.root / "control")

    r = rig.run(deep, copied, copied_top, future, control)

    assert r.code == 1, r.out
    assert (
        "b.bin' was created or modified 1 minute(s) ago" in r.refused(deep, "idle").receipt["idle"]
    )
    assert (
        "b.bin' was created or modified 2 minute(s) ago"
        in (r.refused(copied, "idle").receipt["idle"])
    )
    r.refused(copied_top, "idle", "copied-top' was created or modified 2 minute(s) ago")
    r.refused(future, "idle", "in the future")
    r.deleted(control)
    for tree in (deep, copied, copied_top, future):
        assert _snapshot(tree) == ["a.txt [5]", "sub", "sub\\b.bin [7]"]


def test_IdleMinutes_raises_a_window_and_never_lowers_one(rig: Rig) -> None:
    rig.caller()
    top_30 = rig.tree(rig.root / "top-30", minutes=30)
    own_5 = rig.tree(rig.scratch(CALLER, "five"), minutes=5)
    top_90 = rig.tree(rig.root / "top-90", minutes=90)
    own_30 = rig.tree(rig.scratch(CALLER, "thirty"), minutes=30)

    r = rig.run(top_30, own_5, extra=("-IdleMinutes", "1"))
    assert r.code == 1, r.out
    r.refused(top_30, "idle", "inside the 60-minute window")
    r.refused(own_5, "idle", "inside the 10-minute window")

    r = rig.run(top_90, own_30, extra=("-IdleMinutes", "120"))
    assert r.code == 1, r.out
    r.refused(top_90, "idle", "inside the 120-minute window")
    r.refused(own_30, "idle", "inside the 120-minute window")

    # The control: the same two folders without the raised window.
    r = rig.run(top_90, own_30)
    assert r.code == 0, r.out
    r.deleted(top_90)
    r.deleted(own_30)


# --- rule 9: the rename, and a delete that stops part-way ---------------------------------------


def test_an_open_file_inside_the_tree_refuses_the_delete_and_changes_nothing(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    before = _snapshot(victim)

    with open(victim / "sub" / "b.bin", "rb"):
        dry = rig.run(victim, delete=False)
        r = rig.run(victim)

    # A dry run does not rename, so it cannot see the handle. That is why its receipt says NOT TESTED.
    assert dry.code == 0 and dry.block(victim).receipt["in-use"].startswith("NOT TESTED"), dry.out
    assert r.code == 1, r.out
    r.refused(victim, "in-use", "could not be renamed")
    assert [p.name for p in rig.root.iterdir()] == ["victim"]
    assert _snapshot(victim) == before

    r = rig.run(victim)
    assert r.code == 0, r.out
    r.deleted(victim)


def test_a_delete_that_stops_part_way_lists_exactly_what_remains(rig: Rig) -> None:
    rig.caller()
    victim = rig.tree(rig.root / "victim")
    stuck = victim / "sub" / "b.bin"

    def icacls(*args: str, check: bool = True) -> None:
        subprocess.run(["icacls", *args], check=check, capture_output=True, text=True)

    # Deny deleting the file, and deny its folder the right to delete children. The top folder can
    # still be renamed, so the delete starts and then cannot finish.
    icacls(str(stuck), "/deny", f"{EVERYONE}:(DE)")
    icacls(str(stuck.parent), "/deny", f"{EVERYONE}:(DC)")
    try:
        r = rig.run(victim)

        assert r.code == 3, r.out
        b = r.block(victim)
        assert b.verdict.startswith(f"PARTIAL {victim}: the delete stopped part-way"), r.out
        assert "partial=1" in r.summary and "deleted=0" in r.summary, r.out
        left = list(rig.root.iterdir())
        assert len(left) == 1 and re.fullmatch(r"victim\.removing-[0-9a-f]{8}", left[0].name), left
        tomb = left[0]
        assert _snapshot(tomb) == ["sub", "sub\\b.bin [7]"]
        remains = sorted(
            line[len("remains: ") :] for line in b.extra if line.startswith("remains: ")
        )
        assert remains == [str(tomb / "sub"), str(tomb / "sub" / "b.bin")], r.out
        assert any(line.startswith(f"failed: {tomb / 'sub' / 'b.bin'}") for line in b.extra), r.out
    finally:
        # check=False: a failed restore must not replace the assertion that explains the test.
        icacls(str(rig.root), "/remove:d", EVERYONE, "/T", "/C", check=False)
