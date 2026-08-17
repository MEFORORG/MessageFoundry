# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The verify step must name the source it LOADED, not the file it installed (BACKLOG #1080).

``setup-leak-gate.ps1 -Synthetic`` printed *"Installed the SYNTHETIC template"* and, three lines
later, *"CONFIGURED with the real token set."* Both were individually true whenever
``MEFOR_FORBIDDEN_TOKENS`` was set -- the script wrote the synthetic file, and the scanner loaded the
real list from the environment, which wins over the file -- but nothing said the environment had
OVERRIDDEN what had just been written. The pair reads as a contradiction or, worse, as confirmation
that a synthetic install produced a real-token gate.

The script's own header is what makes that a defect rather than a nit: *"A green gate is evidence
only if you confirmed it can see the class it is meant to catch"*. Printing the detector counts
without printing WHERE they came from leaves exactly the ambiguity the step exists to close.

**These tests pin a duplicated rule against its definition.** Precedence lives in
``scan_forbidden._resolve_token_text``; the script necessarily re-expresses it in order to name the
source, and a second expression drifts silently. So every case here asserts the script's claim about
the source AND the scanner's own ``loaded names=`` line from the SAME run, and the two-source case
asserts those lines DIFFER -- a fixture whose two sources were indistinguishable would pass while
measuring nothing.

**The token fixtures are DERIVED from the shipped example, never hand-written.** Two reasons, both
load-bearing. Every floor section must be non-empty or the scanner refuses (see
``token_floor_failure``), and one of those sections is a numeric site prefix -- a value this repo's
own gate scans tracked files for. Deriving keeps the numeric prefix out of this file entirely and
keeps the fixture valid if the example's sections are ever renamed.

**Assertions are ASCII-only, deliberately.** The output crosses two encoding boundaries (python's
stderr into pwsh, pwsh's stdout into pytest) and the em dash in the scanner's mode line arrives
mojibake on a stock Windows code page. Asserting on it would be testing the code pages.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SETUP = _ROOT / "scripts" / "dev" / "setup-leak-gate.ps1"
_SECURITY = _ROOT / "scripts" / "security"
_EXAMPLE = _SECURITY / "scan-tokens.local.txt.example"
_TIMEOUT = 55  # under pyproject's per-test --timeout=60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="setup-leak-gate.ps1 needs pwsh (PowerShell 7)"
)

#: Not echoed anywhere by a correct implementation -- see the inline-content test.
_INLINE_MARKER = "ZzInlineOnlyMarkerZz"
_EXTERNAL_MARKER = "ZzExternalCorpZz"


def _derived_tokens(marker: str) -> str:
    """The shipped synthetic example plus one extra name detector.

    Real-SHAPED without being the example: ``is_synthetic_token_set()`` compares the parsed name
    patterns, so one extra entry is enough for the scanner to stop labelling it SYNTHETIC, while the
    detector counts move by exactly one -- which is what makes "which source loaded" observable.
    """
    return (
        _EXAMPLE.read_text(encoding="utf-8")
        + f"\n[names]\n\\b{marker}\\b | synthetic external token | i\n"
    )


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _checkout(path: Path) -> Path:
    """A minimal checkout carrying the script and the three files it reaches for.

    Only those files are copied, NOT the whole of scripts/security: a maintainer running this suite
    has the real ``scan-tokens.local.txt`` sitting in that directory, and a copytree would sweep the
    private token list into a temp dir -- the one mistake the script itself refuses to make.
    """
    (path / "scripts" / "dev").mkdir(parents=True)
    (path / "scripts" / "security").mkdir(parents=True)
    shutil.copy2(_SETUP, path / "scripts" / "dev" / "setup-leak-gate.ps1")
    for name in ("scan_forbidden.py", "scan-allowlist.txt", "scan-tokens.local.txt.example"):
        shutil.copy2(_SECURITY / name, path / "scripts" / "security" / name)
    # check-ignore reads the working-tree .gitignore, so no commit is needed -- but the repo must
    # exist, or the script's own not-git-ignored guard deletes what it wrote and throws.
    (path / ".gitignore").write_text("scripts/security/scan-tokens.local.txt\n", encoding="utf-8")
    _git("init", "-b", "main", ".", cwd=path)
    return path


def _python_shim(path: Path) -> Path:
    """A directory holding a ``python`` that forwards to THIS interpreter.

    The script resolves ``<repo>/.venv/Scripts/python.exe`` or falls back to bare ``python`` on PATH.
    A temp checkout has no venv, so the verify step would otherwise depend on whichever ``python`` the
    runner happens to expose -- which is why the neighbouring anchoring test declines to assert the
    verify step at all. The shim makes the interpreter an INPUT of the test rather than an accident of
    the leg, so the emitted strings and the exit code are assertable wherever pwsh runs.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        (path / "python.cmd").write_text(
            f'@echo off\r\n"{sys.executable}" %*\r\nexit /b %ERRORLEVEL%\r\n', encoding="ascii"
        )
    else:
        shim = path / "python"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="ascii")
        shim.chmod(0o755)
    return path


def _env(shim: Path, **over: str) -> dict[str, str]:
    """The child's environment, PINNED -- never merely inherited.

    Every variable that steers the scanner is removed first, then set explicitly by the caller. A
    maintainer with ``MEFOR_FORBIDDEN_TOKENS`` exported would otherwise run these tests against their
    own real list and get greens that mean something else entirely. ``PYTHONIOENCODING`` / ``PYTHONUTF8``
    go too: they change the grandchild's stderr encoding, so leaving them ambient makes the result
    depend on the developer's shell rather than on the code -- measured in this repo, on a test that
    passed locally and reddened at integration for exactly that.
    """
    env = dict(os.environ)
    for var in (
        "MEFOR_FORBIDDEN_TOKENS",
        "MEFOR_REQUIRE_TOKENS",
        "MEFOR_MIN_DETECTORS",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
    ):
        env.pop(var, None)
    env["PATH"] = str(shim) + os.pathsep + env.get("PATH", "")
    env.update(over)
    return env


def _run(root: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(root / "scripts" / "dev" / "setup-leak-gate.ps1"),
            *args,
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_TIMEOUT,
        env=env,
    )


def _loaded(proc: subprocess.CompletedProcess[str]) -> str:
    """The scanner's own detector-count line, as echoed by the script."""
    line = next((ln for ln in proc.stdout.splitlines() if "loaded names=" in ln), "")
    assert line, f"no detector-count line in the output:\n{proc.stdout}\n{proc.stderr}"
    return line.strip()


def _source_line(proc: subprocess.CompletedProcess[str]) -> str:
    """The line that names the RESOLVED source, isolated from the rest of the run.

    Extracted rather than searched for as a substring of the whole output, and that is not fussiness.
    ``-Synthetic`` already prints ``Installed the SYNTHETIC template -> scripts/security/
    scan-tokens.local.txt``, so a whole-output search for that path passes with the defect fully
    present -- measured: the first draft of the file-source test below was green before the fix, for
    exactly that reason. The claim under test is about the line that says what was LOADED.
    """
    line = next((ln for ln in proc.stdout.splitlines() if "token source" in ln.lower()), "")
    assert line, f"no line naming the resolved token source:\n{proc.stdout}\n{proc.stderr}"
    return line.strip()


@pytest.fixture
def rig(tmp_path: Path) -> tuple[Path, Path, Path]:
    """``(checkout, shim dir, an external token file)``."""
    root = _checkout(tmp_path / "repo")
    shim = _python_shim(tmp_path / "shim")
    ext = tmp_path / "external-tokens.txt"
    ext.write_text(_derived_tokens(_EXTERNAL_MARKER), encoding="utf-8")
    return root, shim, ext


# --------------------------------------------------------------------------------------------------
# the source is named -- and the negative control that it is not named unconditionally
# --------------------------------------------------------------------------------------------------


def test_the_installed_file_is_named_as_the_source_when_nothing_overrides_it(
    rig: tuple[Path, Path, Path],
) -> None:
    root, shim, _ = rig
    proc = _run(root, "-Synthetic", env=_env(shim))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "scripts/security/scan-tokens.local.txt" in _source_line(proc)
    assert "MEFOR_FORBIDDEN_TOKENS" not in _source_line(proc)
    assert "SYNTHETIC" in _loaded(proc), "the scanner did not load the file that was just installed"
    # THE NEGATIVE CONTROL. An override banner printed unconditionally would satisfy the override test
    # below while telling the operator something false here.
    assert "OVERRIDDEN" not in proc.stdout, proc.stdout


def test_an_env_file_override_is_named_and_announced(rig: tuple[Path, Path, Path]) -> None:
    """The exact shape #1080 was filed for: install the synthetic file, load the environment's list."""
    root, shim, ext = rig
    proc = _run(root, "-Synthetic", env=_env(shim, MEFOR_FORBIDDEN_TOKENS=str(ext)))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    # The two lines that used to read as a contradiction are both still there ...
    assert "Installed the SYNTHETIC template" in proc.stdout
    assert "CONFIGURED with the real token set" in proc.stdout
    # ... and are now reconciled, by name.
    assert "OVERRIDDEN" in proc.stdout, proc.stdout
    assert "MEFOR_FORBIDDEN_TOKENS" in _source_line(proc)
    assert str(ext) in _source_line(proc), (
        "the resolved path must be named, not merely the variable"
    )


def test_the_source_the_script_names_is_the_source_the_scanner_USED(
    rig: tuple[Path, Path, Path],
) -> None:
    """Pins the script's copy of the precedence rule against the scanner's actual behaviour.

    The script re-expresses ``scan_forbidden._resolve_token_text``; nothing but this stops the two
    drifting. The detector-count lines must DIFFER between the two runs -- if the fixture's two token
    sets were indistinguishable, every other assertion in this file would pass while measuring
    nothing.
    """
    root, shim, ext = rig
    from_file = _run(root, "-Synthetic", env=_env(shim))
    from_env = _run(root, "-Synthetic", env=_env(shim, MEFOR_FORBIDDEN_TOKENS=str(ext)))

    assert _loaded(from_file) != _loaded(from_env), (
        f"the fixture cannot distinguish the two sources: {_loaded(from_file)!r}"
    )
    assert "scripts/security/scan-tokens.local.txt" in _source_line(from_file)
    assert str(ext) in _source_line(from_env)
    # Direction, not merely difference: the env run must not be reported as the file it just wrote.
    assert "SYNTHETIC" in _loaded(from_file)
    assert "SYNTHETIC" not in _loaded(from_env)


def test_INLINE_token_content_is_named_but_never_echoed(rig: tuple[Path, Path, Path]) -> None:
    """A non-path value IS the token list. Naming the variable is the diagnostic; printing it is a leak.

    The load-bearing negative for the whole change: the obvious way to "name the resolved source" is
    to print the variable's value, which passes every other test here and publishes the private list
    into whatever log the operator was capturing.
    """
    root, shim, _ = rig
    tokens = _derived_tokens(_INLINE_MARKER)
    proc = _run(root, "-Synthetic", env=_env(shim, MEFOR_FORBIDDEN_TOKENS=tokens))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OVERRIDDEN" in proc.stdout
    assert "MEFOR_FORBIDDEN_TOKENS" in _source_line(proc)
    assert "inline" in _source_line(proc).lower(), _source_line(proc)
    assert _INLINE_MARKER not in proc.stdout, "the inline token content was echoed to stdout"
    assert _INLINE_MARKER not in proc.stderr, "the inline token content was echoed to stderr"


def test_an_EMPTY_env_value_is_reported_as_the_cause_rather_than_a_missing_file(
    rig: tuple[Path, Path, Path],
) -> None:
    """The state where the ordinary advice is WRONG advice.

    An explicitly-empty ``MEFOR_FORBIDDEN_TOKENS`` means "no source" and does NOT fall back to the
    file, so the script can install a token list, correctly report NOT CONFIGURED, and send the
    operator round the same loop forever. Naming the cause is the difference between a diagnosis and a
    restatement of the symptom.
    """
    root, shim, _ = rig
    proc = _run(root, "-Synthetic", env=_env(shim, MEFOR_FORBIDDEN_TOKENS=""))

    assert proc.returncode != 0, proc.stdout
    assert "STRUCTURAL-ONLY" in _loaded(proc), "the scanner loaded a source after all"
    assert "NOT CONFIGURED" in proc.stdout
    assert "MEFOR_FORBIDDEN_TOKENS" in proc.stdout, proc.stdout
    assert "EMPTY" in proc.stdout, proc.stdout


def test_status_mode_names_the_source_without_claiming_an_override(
    rig: tuple[Path, Path, Path],
) -> None:
    """No switch installs nothing, so nothing can have been overridden -- but the operator still needs
    to know which source armed the gate, which is the one question the verify step exists to answer."""
    root, shim, _ = rig
    assert _run(root, "-Synthetic", env=_env(shim)).returncode == 0  # arm it first
    proc = _run(root, env=_env(shim))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Installed" not in proc.stdout, "status mode must not install anything"
    assert "scripts/security/scan-tokens.local.txt" in _source_line(proc)
    assert "OVERRIDDEN" not in proc.stdout


# --------------------------------------------------------------------------------------------------
# the verdict must follow the scanner, not the happy path
# --------------------------------------------------------------------------------------------------


def test_a_nonzero_scanner_exit_is_not_reported_as_CONFIGURED(
    rig: tuple[Path, Path, Path],
) -> None:
    """The script's header promises it "exits non-zero if the sections are empty"; it discarded the
    scanner's exit code entirely, so a refusal came back out as CONFIGURED and exit 0.

    An impossible ``MEFOR_MIN_DETECTORS`` floor is the cheapest way to make the scanner refuse with a
    source genuinely loaded -- the state the old code could not tell apart from success.
    """
    root, shim, _ = rig
    proc = _run(root, "-Synthetic", env=_env(shim, MEFOR_MIN_DETECTORS="99999"))

    assert proc.returncode != 0, (
        f"the scanner refused and the script reported success:\n{proc.stdout}"
    )
    assert "VERIFY FAILED" in proc.stdout, proc.stdout
    assert "CONFIGURED (synthetic)" not in proc.stdout, proc.stdout


def test_a_healthy_run_still_exits_zero(rig: tuple[Path, Path, Path]) -> None:
    """The paired positive. Propagating an exit code is only a fix if the ordinary path stays green."""
    root, shim, _ = rig
    proc = _run(root, "-Synthetic", env=_env(shim))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFY FAILED" not in proc.stdout
