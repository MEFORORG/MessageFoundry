"""The SessionStart backstop's allowlist, and the self-protection its installer was missing.

Two findings from the drift audit, both about the *second* half of the estate — the part everyone forgets
because the PreToolUse gate is the loud one.

**One allowlist, not two.** The gate read ``~/.claude/hooks/worktree-gate.repos.txt``; this backstop read
``~/.claude-hooks/worktree-gate.repos.txt``. ``install-gate.ps1`` rewrote its own unconditionally,
``install-selfheal.ps1`` seeded the other only if absent, and nothing kept them in sync: adding a governed
repo through one installer never reached the other, and ``install-gate.ps1 -Uninstall`` left this hook
armed and still willing to run ``git checkout`` on the primary long after the gate was gone. They agreed
only by luck.

**The higher-privilege installer was the less protected one.** ``install-gate.ps1`` has refused to run
under ``CLAUDECODE`` since it shipped. ``install-selfheal.ps1`` did not — while wiring a user-scope hook
that repairs the shared primary *unattended*, from a script whose canonical source is the calling
session's own worktree.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELFHEAL = ROOT / "scripts" / "worktree" / "worktree-selfheal.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-selfheal.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_selfheal(home: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Drive the real hook with a synthetic HOME so it reads OUR allowlists, never the machine's."""
    env = {**os.environ, "USERPROFILE": str(home), "HOME": str(home)}
    env.pop("CLAUDECODE", None)
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(SELFHEAL)],
        input="{}",
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(cwd),
        env=env,
    )


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    (h / ".claude" / "hooks").mkdir(parents=True)
    (h / ".claude-hooks").mkdir(parents=True)
    return h


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None, check=True, capture_output=True, text=True
    )


def head_of(repo: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


@pytest.fixture
def drifted(tmp_path: Path) -> Path:
    """A clean repo sitting on the WRONG branch -- the state the backstop exists to repair. Asserting on
    the repair, not on an exit code, is the difference between testing the allowlist and testing nothing:
    the hook exits 0 whether or not it read a thing."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")
    repo = tmp_path / "Primary"
    git("init", "-b", "main", str(repo))
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    (repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-m", "seed", cwd=repo)
    git("checkout", "-b", "drifted", cwd=repo)
    assert head_of(repo) == "drifted"
    return repo


def test_the_backstop_reads_the_gates_allowlist(home: Path, drifted: Path) -> None:
    """The whole point of collapsing them: a repo added through the GATE installer is now guarded by the
    backstop too, with no second edit. Proved by the repair actually happening."""
    (home / ".claude" / "hooks" / "worktree-gate.repos.txt").write_text(
        f"{drifted}\n", encoding="utf-8"
    )
    r = run_selfheal(home, cwd=drifted)
    assert r.returncode == 0, r.stderr
    assert head_of(drifted) == "main", "the shared allowlist was not read -- no repair happened"


def test_the_legacy_allowlist_still_works_when_the_shared_one_is_absent(
    home: Path, drifted: Path
) -> None:
    """This script is installed as a COPY, so an older installed copy can outlive a newer allowlist and
    vice versa. Falling back keeps a version skew from silently turning the backstop off -- the exact
    class of failure that left rule 4 inert."""
    (home / ".claude-hooks" / "worktree-gate.repos.txt").write_text(
        f"{drifted}\n", encoding="utf-8"
    )
    r = run_selfheal(home, cwd=drifted)
    assert r.returncode == 0, r.stderr
    assert head_of(drifted) == "main", "the legacy fallback was not read -- no repair happened"


def test_no_allowlist_anywhere_is_a_clean_no_op(home: Path, drifted: Path) -> None:
    """The kill switch: no allowlist and the backstop touches nothing, without erroring. This is also the
    control for the two tests above -- if the repair happened here too, they would prove nothing."""
    r = run_selfheal(home, cwd=drifted)
    assert r.returncode == 0, r.stderr
    assert head_of(drifted) == "drifted", "an ungoverned repo was repaired anyway"


def test_the_shared_allowlist_wins_over_the_legacy_one(home: Path, tmp_path: Path) -> None:
    """Both present: the gate's location is authoritative, so there is one source of truth to edit."""
    (home / ".claude" / "hooks" / "worktree-gate.repos.txt").write_text(
        f"{tmp_path / 'Shared'}\n", encoding="utf-8"
    )
    (home / ".claude-hooks" / "worktree-gate.repos.txt").write_text(
        f"{tmp_path / 'Legacy'}\n", encoding="utf-8"
    )
    src = SELFHEAL.read_text(encoding="utf-8")
    shared_at = src.index(".claude\\hooks\\worktree-gate.repos.txt")
    legacy_at = src.index(".claude-hooks\\worktree-gate.repos.txt")
    assert shared_at < legacy_at, "the shared path must be tried first"
    assert "if (Test-Path -LiteralPath $shared) { $shared } else { $legacy }" in src


# --------------------------------------------------------------------- installer self-protection


def test_the_selfheal_installer_refuses_to_run_inside_claude_code(tmp_path: Path) -> None:
    """A session that can install this hook can also point it at a script it wrote. Its sibling
    install-gate.ps1 has refused since it shipped; this one did not, and it is the more privileged of the
    two -- it wires a hook that runs `git checkout` on the shared primary unattended."""
    cfg = tmp_path / "cfgdir"
    cfg.mkdir()
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), "-ConfigDir", str(cfg)],
        capture_output=True,
        text=True,
        timeout=90,
        env={**os.environ, "CLAUDECODE": "1"},
    )
    assert r.returncode != 0, "the installer must refuse under CLAUDECODE"
    assert "Refusing to run inside Claude Code" in (r.stderr + r.stdout)
    assert not (cfg / "settings.json").exists(), "it must refuse BEFORE writing anything"


def test_both_installers_carry_the_same_refusal() -> None:
    """Pin the pair. The asymmetry existed for months precisely because nothing compared them."""
    gate = (ROOT / "scripts" / "worktree" / "install-gate.ps1").read_text(encoding="utf-8")
    selfheal = INSTALLER.read_text(encoding="utf-8")
    for name, text in (("install-gate.ps1", gate), ("install-selfheal.ps1", selfheal)):
        assert "CLAUDECODE" in text and "Refusing to run inside Claude Code" in text, (
            f"{name} lost its human-only guard"
        )
