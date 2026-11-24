# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import json
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
    shared_at = src.index(".claude/hooks/worktree-gate.repos.txt")
    legacy_at = src.index(".claude-hooks/worktree-gate.repos.txt")
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


# ------------------------------------------------------ no script may assume $env:USERPROFILE exists


HOME_DEPENDENT_SCRIPTS = [
    ROOT / "scripts" / "worktree" / "install-selfheal.ps1",
    ROOT / "scripts" / "worktree" / "worktree-selfheal.ps1",
    ROOT / "scripts" / "worktree" / "install-gate.ps1",
    ROOT / "scripts" / "hooks" / "worktree_gate.ps1",
]


@pytest.mark.parametrize("script", HOME_DEPENDENT_SCRIPTS, ids=lambda p: p.name)
def test_no_script_dies_when_USERPROFILE_is_unset(script: Path, tmp_path: Path) -> None:
    """$env:USERPROFILE is Windows-only and is NULL everywhere else, where `Join-Path $null ...` raises
    "Cannot bind argument to parameter 'Path' because it is null" rather than returning a path.

    This is not a portability nicety. In a PARAMETER DEFAULT the expression is evaluated during BINDING,
    before the script's first line -- so it preempts whatever guard the body opens with. It did exactly
    that: install-selfheal.ps1's CLAUDECODE refusal became unreachable on Linux CI, and the test written
    to prove the refusal failed with a null-path error instead. For worktree_gate.ps1 the same crash would
    be worse and quieter: a hook exiting non-zero-but-not-2 lets the tool call through SILENTLY, so the
    gate would simply be off.

    Asserts the ABSENCE of that specific crash, not success -- these scripts legitimately fail for other
    reasons here (a missing config dir, a refusal, an absent allowlist). Only the null-path bind is a bug.
    """
    env = {k: v for k, v in os.environ.items() if k != "USERPROFILE"}
    env["CLAUDECODE"] = "1"  # keep the installers refusing rather than touching this machine
    args = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)]
    if script.name == "install-selfheal.ps1":
        args += ["-ConfigDir", str(tmp_path)]  # Mandatory, or pwsh prompts and the run hangs
    r = subprocess.run(args, input="{}", capture_output=True, text=True, timeout=90, env=env)
    combined = r.stderr + r.stdout
    assert "because it is null" not in combined, (
        f"{script.name} dereferenced $env:USERPROFILE without a fallback:\n{combined[:600]}"
    )
    assert "Join-Path" not in r.stderr, f"{script.name} raised a Join-Path error:\n{r.stderr[:600]}"


def test_the_selfheal_installer_completes_with_USERPROFILE_unset(tmp_path: Path) -> None:
    """Covers the path the CLAUDECODE test cannot reach.

    The guard now runs BEFORE $homeDir is computed -- which is the fix, and which means a test that sets
    CLAUDECODE=1 exits before that line and cannot see a regression in it. Verified by mutation: reverting
    the fallback in install-selfheal.ps1 left the CLAUDECODE test green. The uncovered path is the one
    that matters in real use, since an operator runs this from a plain terminal with no CLAUDECODE set.

    -HookPath and -ConfigDir both land in tmp. The installer no longer creates an allowlist (BACKLOG
    #7613); it only tests whether the gate's allowlist exists under the resolved home, so nothing outside
    tmp is written.
    """
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "worktree-gate.repos.txt").write_text("# none\n", encoding="utf-8")

    env = {k: v for k, v in os.environ.items() if k not in ("USERPROFILE", "CLAUDECODE")}
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-ConfigDir",
            str(cfg),
            "-HookPath",
            str(shared / "worktree-selfheal.ps1"),
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    combined = r.stderr + r.stdout
    assert "because it is null" not in combined, f"null $homeDir reached:\n{combined[:600]}"
    assert r.returncode == 0, f"installer failed:\n{combined[:900]}"
    assert (cfg / "settings.json").is_file(), "it should have wired the SessionStart hook"
    assert (shared / "worktree-selfheal.ps1").is_file(), "it should have copied the hook script"


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows: GetFolderPath('UserProfile') ignores $HOME, so the default HookPath cannot be "
    "redirected away from the real home and this test would write there. Linux CI covers it.",
)
def test_the_default_hook_path_resolves_without_USERPROFILE(tmp_path: Path) -> None:
    """The last uncovered use of the fallback: the DEFAULT -HookPath.

    Verified by mutation that neither test above can see a regression here -- reverting install-selfheal's
    fallback left all 11 green, because the CLAUDECODE test exits at the guard and the completion test
    passes -HookPath explicitly, so $homeDir is never dereferenced in either. The only path that touches it
    is a plain-terminal run with no -HookPath, which is exactly how an operator invokes it.

    That path writes under the resolved home, so it is only safe where the home can be redirected:
    on Unix the fallback resolves $HOME, which this test controls. Skipped on Windows rather than faked,
    because a test that cannot fail is worse than an admitted gap.
    """
    fake_home = tmp_path / "home"
    (fake_home / ".claude-hooks").mkdir(parents=True)
    (fake_home / ".claude-hooks" / "worktree-gate.repos.txt").write_text(
        "# none\n", encoding="utf-8"
    )
    cfg = tmp_path / "cfg"
    cfg.mkdir()

    env = {k: v for k, v in os.environ.items() if k not in ("USERPROFILE", "CLAUDECODE")}
    env["HOME"] = str(fake_home)
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), "-ConfigDir", str(cfg)],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    combined = r.stderr + r.stdout
    assert "because it is null" not in combined, (
        f"the default HookPath hit a null home:\n{combined[:600]}"
    )
    assert r.returncode == 0, f"installer failed:\n{combined[:900]}"
    assert (fake_home / ".claude-hooks" / "worktree-selfheal.ps1").is_file(), (
        "the hook should have been copied under the resolved home"
    )


# ------------------------------------------- the settings write, the wiring check, the seeded copy
#
# BACKLOG #7612 and #7613. Every run below points USERPROFILE and HOME at a temporary home and passes
# -HookPath and -ConfigDir under tmp, so nothing reads or writes the real ~/.claude.


def run_installer(
    home: Path, cfg: Path, hook_path: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "USERPROFILE": str(home), "HOME": str(home)}
    env.pop("CLAUDECODE", None)
    hp = hook_path if hook_path is not None else home / ".claude-hooks" / "worktree-selfheal.ps1"
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-ConfigDir",
            str(cfg),
            "-HookPath",
            str(hp),
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    c = tmp_path / "cfg"
    c.mkdir()
    return c


def _session_start(cfg: Path) -> list[dict[str, object]]:
    data = json.loads((cfg / "settings.json").read_text(encoding="utf-8-sig"))
    groups: list[dict[str, object]] = data["hooks"]["SessionStart"]
    return groups


def test_an_exec_form_hook_counts_as_already_wired(home: Path, cfg: Path) -> None:
    """A hook naming the script in ``args`` rather than ``command`` is the same wiring. Checking only
    ``command`` appended a second group, so every session would run the backstop twice."""
    original = {
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "pwsh",
                            "args": ["-NoProfile", "-File", "C:/x/worktree-selfheal.ps1"],
                        }
                    ]
                }
            ]
        }
    }
    (cfg / "settings.json").write_text(json.dumps(original), encoding="utf-8")
    r = run_installer(home, cfg)
    assert r.returncode == 0, r.stderr
    assert "already wired" in r.stdout
    assert len(_session_start(cfg)) == 1, "an exec-form hook was wired a second time"


def test_a_successful_install_preserves_keys_and_leaves_no_temp_file(home: Path, cfg: Path) -> None:
    (cfg / "settings.json").write_text(json.dumps({"model": "x", "hooks": {}}), encoding="utf-8")
    r = run_installer(home, cfg)
    assert r.returncode == 0, r.stderr
    data = json.loads((cfg / "settings.json").read_text(encoding="utf-8-sig"))
    assert data["model"] == "x"
    hooks = _session_start(cfg)[0]["hooks"]
    assert isinstance(hooks, list)
    assert "-NonInteractive" in str(hooks[0]["command"]), "the hook's pwsh could prompt on stdin"
    leftovers = sorted(p.name for p in cfg.iterdir() if p.name != "settings.json")
    assert leftovers == ["settings.json.bak-selfheal"], f"stray files: {leftovers}"


def test_an_invalid_result_leaves_settings_json_byte_identical(home: Path, cfg: Path) -> None:
    """The new text is parsed BEFORE settings.json is touched. A ConvertFrom-Json shim, defined in the
    calling scope so the script resolves it ahead of the cmdlet, fails the parse of the new text only,
    and records whether settings.json already held the new wiring at that moment. origin/main wrote
    first and rolled back after, so the marker is the witness of the order, not just the end state."""
    settings = cfg / "settings.json"
    original = b'{\r\n  "model": "keep-me",\r\n  "hooks": {}\r\n}\r\n'
    settings.write_bytes(original)
    marker = cfg.parent / "written-before-validate.txt"
    shim = (
        "function ConvertFrom-Json { param([Parameter(ValueFromPipeline)]$InputObject) "
        "process { if (\"$InputObject\" -match 'worktree-selfheal') { "
        f"if (Select-String -LiteralPath '{settings}' -SimpleMatch 'worktree-selfheal' -Quiet) "
        f"{{ Set-Content -LiteralPath '{marker}' -Value x }}; throw 'injected parse failure' }} "
        "$InputObject | Microsoft.PowerShell.Utility\\ConvertFrom-Json } }"
    )
    hp = home / ".claude-hooks" / "worktree-selfheal.ps1"
    env = {**os.environ, "USERPROFILE": str(home), "HOME": str(home)}
    env.pop("CLAUDECODE", None)
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"{shim}; & '{INSTALLER}' -ConfigDir '{cfg}' -HookPath '{hp}'",
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    assert r.returncode != 0, "an invalid result was written"
    assert "injected parse failure" in (r.stderr + r.stdout), "the shim never fired"
    assert not marker.exists(), "settings.json was written before the new text was validated"
    assert settings.read_bytes() == original, "settings.json changed"
    assert not (cfg / "settings.json.bak-selfheal").exists()


@pytest.mark.parametrize("bad", ["a$b", "a`b", 'a"b'])
def test_a_hook_path_the_shell_would_rewrite_is_refused(
    home: Path, cfg: Path, tmp_path: Path, bad: str
) -> None:
    """The path is embedded in a double-quoted shell command. A ``$`` or backtick there would be
    expanded by the shell that runs the hook, and a quote would end the argument, so the wired command
    would name a different file. Refused before anything is written, rather than escaped on a guess
    about which shell runs it."""
    if os.name == "nt" and '"' in bad:
        pytest.skip("a Windows path cannot contain a double quote")
    hp = tmp_path / bad / "worktree-selfheal.ps1"
    r = run_installer(home, cfg, hook_path=hp)
    assert r.returncode != 0, "a HookPath the shell would rewrite was wired"
    assert "HookPath" in (r.stderr + r.stdout)
    assert not (cfg / "settings.json").exists()
    assert not hp.parent.exists(), "it must refuse before creating the hook directory"


def test_the_installer_does_not_create_the_legacy_allowlist(home: Path, cfg: Path) -> None:
    """BACKLOG #7613. The backstop reads the gate's allowlist first and the legacy one only as a
    fallback. A copy seeded into ~/.claude-hooks would outlive ``install-gate.ps1 -Uninstall`` and keep
    the backstop armed after the gate's allowlist is gone, so the installer must not create one."""
    (home / ".claude" / "hooks" / "worktree-gate.repos.txt").write_text("C:/P\n", encoding="utf-8")
    r = run_installer(home, cfg)
    assert r.returncode == 0, r.stderr
    assert not (home / ".claude-hooks" / "worktree-gate.repos.txt").exists(), "legacy copy seeded"


def test_with_no_allowlist_the_installer_writes_no_template(home: Path, cfg: Path) -> None:
    r = run_installer(home, cfg)
    assert r.returncode == 0, r.stderr
    assert not (home / ".claude-hooks" / "worktree-gate.repos.txt").exists(), "template seeded"
    assert "install-gate.ps1" in r.stdout, "the operator is not told the backstop is off"


def test_an_existing_legacy_allowlist_is_left_alone(home: Path, cfg: Path) -> None:
    legacy = home / ".claude-hooks" / "worktree-gate.repos.txt"
    legacy.write_text("C:/Kept\n", encoding="utf-8")
    r = run_installer(home, cfg)
    assert r.returncode == 0, r.stderr
    assert legacy.read_text(encoding="utf-8") == "C:/Kept\n"
    assert "reads the legacy" in r.stdout, "the operator is told the backstop is off when it is not"


def test_the_note_reads_the_home_legacy_file_not_the_hook_dir(
    home: Path, cfg: Path, tmp_path: Path
) -> None:
    """The backstop's fallback is ~/.claude-hooks/worktree-gate.repos.txt whatever -HookPath says, so
    a file beside a non-default HookPath must not be reported as the one it reads."""
    hook_dir = tmp_path / "elsewhere"
    hook_dir.mkdir()
    (hook_dir / "worktree-gate.repos.txt").write_text("C:/Stray\n", encoding="utf-8")
    r = run_installer(home, cfg, hook_path=hook_dir / "worktree-selfheal.ps1")
    assert r.returncode == 0, r.stderr
    assert "guards nothing" in r.stdout, r.stdout


def test_a_tilde_config_dir_still_installs(home: Path, tmp_path: Path) -> None:
    """The temp file is written through .NET, which does not resolve PowerShell's ``~``. The old
    in-place Set-Content did, so a ``~``-relative ConfigDir must keep working."""
    (home / "cfg").mkdir()
    env = {**os.environ, "USERPROFILE": str(home), "HOME": str(home)}
    env.pop("CLAUDECODE", None)
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Set-Location -LiteralPath '{tmp_path}'; "
            f"(Get-PSProvider FileSystem).Home = '{home}'; "
            f"& '{INSTALLER}' -ConfigDir '~/cfg' -HookPath '{home / '.claude-hooks' / 'w' / 'worktree-selfheal.ps1'}'",
        ],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (home / "cfg" / "settings.json").is_file()
