# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CLAUDE.md's wiki command names the SHARED coordination root, and stops when it cannot.

The wiki inbox is a shared kind (docs/COORD-SHARED-ROOT.md). The command seats copy from CLAUDE.md
once built the path from ``--git-common-dir``, so after a share is configured every note it wrote
landed in an inbox the other PC never reads. The command now runs scripts/coord/wiki-query.ps1.
These tests run the documented line itself, in a throwaway repository holding the real resolver and
wrapper, with the korus script swapped for a stub that prints the ``-StateRoot`` it was given.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAUDE_MD = ROOT / "CLAUDE.md"
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="the resolver and the documented command need pwsh"
)

STUB = r"""
param([string] $Text, [string] $StateRoot, [string] $RecordRepo, [string] $Seat)
Write-Output ('STATEROOT=' + $StateRoot)
"""


def _command_block() -> str:
    """The indented block that follows the paragraph about the shared inbox."""
    text = CLAUDE_MD.read_text(encoding="utf-8")
    m = re.search(r"The inbox is shared across PCs(?s:.*?)\n\n((?:    [^\n]*\n)+)", text)
    assert m, "CLAUDE.md lost the wiki command block after 'The inbox is shared across PCs'"
    return "\n".join(line[4:] for line in m.group(1).splitlines())


def _clean_env() -> dict[str, str]:
    """The fixture decides what git reads, not whoever runs the suite. A GIT_DIR inherited from a
    git hook would point `git -C <tmp>` at the REAL repository, and a test would then write a temp
    path into its live root.toml. Mirrors test_wiki_write_prompt_hook._clean_env."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("GIT_") and k.upper() != "MEFOR_COORD_ROOT"
    }


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        encoding="utf-8",
        env=_clean_env(),
        timeout=TIMEOUT,
        check=True,
    ).stdout.strip()


def _local_root(repo: Path) -> Path:
    return (
        Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")) / "mefor-coord"
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway engine-shaped repository: git, plus the real resolver and wrapper at their
    tracked paths. It refuses to hand back a repository whose coordination root is not under
    tmp_path, before any test can write a root.toml into it."""
    r = tmp_path / "engine"
    (r / "scripts" / "coord").mkdir(parents=True)
    for name in ("coord-root.ps1", "wiki-query.ps1"):
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    _git(r, "init", "-q", "-b", "main")
    assert _local_root(r).resolve().is_relative_to(tmp_path.resolve()), "fixture is the real clone"
    return r


def _invoke(
    repo: Path,
    tmp_path: Path,
    env_root: str | None = None,
    prelude: str = "",
    in_process: bool = False,
    cloud: bool = False,
) -> subprocess.CompletedProcess[str]:
    stub = tmp_path / "korus" / "scripts" / "wiki" / "query.ps1"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(STUB, encoding="ascii")
    block = (
        _command_block()
        .replace("<korus checkout>", str(tmp_path / "korus").replace("\\", "/"))
        .replace("<vault checkout>", "VAULT")
    )
    if in_process:
        # The wrapper run inside the calling shell, where a stale resolver could be in scope.
        block = block.replace("pwsh -NoProfile -File ", "& ./", 1)
    env = _clean_env()
    if env_root is not None:
        env["MEFOR_COORD_ROOT"] = env_root
    env.pop("CLAUDE_CODE_REMOTE", None)
    if cloud:
        env["CLAUDE_CODE_REMOTE"] = "true"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", prelude + block],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(repo),
        env=env,
        timeout=TIMEOUT,
    )


def _run(
    repo: Path,
    tmp_path: Path,
    env_root: str | None = None,
    prelude: str = "",
    in_process: bool = False,
) -> str:
    proc = _invoke(repo, tmp_path, env_root, prelude, in_process)
    assert proc.returncode == 0, proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("STATEROOT=")]
    assert len(lines) == 1, proc.stdout + proc.stderr
    return lines[0][len("STATEROOT=") :]


def _stops(proc: subprocess.CompletedProcess[str], *needles: str) -> None:
    """A loud stop: non-zero, the query never ran, and the cause is named."""
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "STATEROOT=" not in proc.stdout, proc.stdout
    assert "STOP" in proc.stderr, proc.stderr
    for needle in needles:
        assert needle in proc.stderr, proc.stderr


def _write_root_toml(repo: Path, body: str) -> None:
    local = _local_root(repo)
    local.mkdir(parents=True, exist_ok=True)
    (local / "root.toml").write_text(body, encoding="utf-8")


def _same(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


def test_the_block_is_one_line_through_the_wrapper() -> None:
    block = _command_block()
    assert "--git-common-dir" not in block
    assert len(block.strip().splitlines()) == 1, block
    assert block.startswith("pwsh -NoProfile -File scripts/coord/wiki-query.ps1 "), block


def test_control_with_nothing_configured_it_is_the_local_root(repo: Path, tmp_path: Path) -> None:
    assert _same(_run(repo, tmp_path), _local_root(repo))


def test_a_root_toml_moves_it_to_the_shared_root(repo: Path, tmp_path: Path) -> None:
    shared = tmp_path / "share" / "mefor-coord"
    shared.mkdir(parents=True)
    _write_root_toml(repo, f"shared_root = '{shared}'\n")
    got = _run(repo, tmp_path)
    assert _same(got, shared)
    assert not _same(got, _local_root(repo))


def test_the_env_override_wins(repo: Path, tmp_path: Path) -> None:
    pinned = tmp_path / "pinned"
    pinned.mkdir()
    assert _same(_run(repo, tmp_path, str(pinned)), pinned)


def test_a_malformed_root_toml_stops_the_command(repo: Path, tmp_path: Path) -> None:
    """A broken root must not reach query.ps1 as an empty -StateRoot, which prints `no note` and
    exits 0."""
    _write_root_toml(repo, "this is not a shared_root line\n")
    _stops(_invoke(repo, tmp_path), "root.toml")


def test_a_configured_root_that_does_not_exist_stops_the_command(
    repo: Path, tmp_path: Path
) -> None:
    """The unprobed resolver passed this path on; the probed one refuses it."""
    absent = tmp_path / "absent" / "mefor-coord"
    _write_root_toml(repo, f"shared_root = '{absent}'\n")
    _stops(_invoke(repo, tmp_path), "does not exist")


def test_a_relative_env_root_stops_the_command(repo: Path, tmp_path: Path) -> None:
    _stops(_invoke(repo, tmp_path, "relative/coord"), "MEFOR_COORD_ROOT")


STALE = """
function Get-CoordSharedRoot { @{ Path = '/stale/root'; Source = 'file'; Error = $null } }
function Resolve-CoordSharedRoot { @{ Path = '/stale/root'; Source = 'file'; Error = $null } }
"""


@pytest.mark.parametrize("in_process", [False, True], ids=["child", "in-process"])
def test_a_stale_resolver_in_the_calling_shell_is_never_used(
    repo: Path, tmp_path: Path, in_process: bool
) -> None:
    """With the library in place, the wrapper's own copy answers, not the shell's."""
    got = _run(repo, tmp_path, prelude=STALE, in_process=in_process)
    assert _same(got, _local_root(repo))


@pytest.mark.parametrize("in_process", [False, True], ids=["child", "in-process"])
def test_a_missing_library_stops_even_with_a_stale_resolver_loaded(
    repo: Path, tmp_path: Path, in_process: bool
) -> None:
    (repo / "scripts" / "coord" / "coord-root.ps1").unlink()
    _stops(_invoke(repo, tmp_path, prelude=STALE, in_process=in_process), "coord-root.ps1")


def test_a_cloud_session_is_refused_before_any_query(repo: Path, tmp_path: Path) -> None:
    """A VM's own inbox is empty, so a query there would read as a clean miss. The control is
    test_control_with_nothing_configured_it_is_the_local_root, the same call outside the cloud."""
    # The documented line runs the wrapper as a child of -Command, which reports any non-zero
    # child as 1; the wrapper's own exit 3 is held by test_coord_cloud_refusal.py.
    proc = _invoke(repo, tmp_path, cloud=True)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "STATEROOT=" not in proc.stdout, proc.stdout
    assert "wiki-query.ps1: refused in a Claude Code cloud session" in proc.stderr, proc.stderr
    assert not _local_root(repo).exists(), "a refused call created the coordination directory"
