# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SessionStart banner (``scripts/worktree/session-context.ps1``) must degrade, never throw.

Whatever this hook prints to stdout IS the chat's starting context. If it raises, the session opens
with a stack trace instead of its coordination rules -- and the failure is silent, because nobody
reads a hook's exit code. These tests pin the fail-safe contract around the presence roster it now
calls into: a missing, broken, or slow ``presence.ps1`` must cost you the live-session list and
nothing else.

The scripts are copied into a throwaway tree rather than edited in place, so a test run never mutates
the repo -- these same scripts are live in every sibling session while the suite runs.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "scripts" / "worktree" / "session-context.ps1"
PRESENCE = ROOT / "scripts" / "coord" / "presence.ps1"
HOOKINPUT = ROOT / "scripts" / "hooks" / "_hookinput.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="session-context.ps1 needs pwsh on Windows",
)

# The first thing the hook prints once it has real context. This fixture's repo has two worktrees, so
# the parallel-session block always runs here and its header is the signal that the hook produced
# context rather than dying early.
#
# It was the unconditional Ultracode preference banner until 2026-09-20, when the owner had that
# preference removed from every session. Nothing is printed unconditionally now, so the marker has to
# come from a block this fixture guarantees.
ALWAYS_PRINTED = "[PARALLEL SESSION"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def staged(tmp_path: Path) -> Path:
    return _make_staged(tmp_path)


def _make_staged(tmp_path: Path) -> Path:
    """A git repo with 2+ worktrees (so the parallel-session block runs) holding script copies."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "init")
    _git(repo, "worktree", "add", "-q", "-b", "second", str(tmp_path / "wt2"))

    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "coord").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    # The shipped layout: the hook dot-sources its input reader from scripts/hooks, and says aloud
    # when it is missing.
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    return repo


def run_context(repo: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "worktree" / "session-context.ps1"),
        ],
        cwd=str(repo),
        input="",  # the hook reads its input; an inherited stdin would hold the read to its bound
        capture_output=True,
        text=True,
        timeout=180,
        check=False,  # the whole point is that it exits 0 even when presence.ps1 fails
        env=env,
    )


def fake_presence(repo: Path, rows: list[dict[str, object]]) -> None:
    """Stand in for presence.ps1 -Json, emitting exactly the shape the real script emits."""
    payload = json.dumps(rows).replace("'", "''")  # '' escapes a quote in a PS single-quoted string
    (repo / "scripts" / "coord" / "presence.ps1").write_text(
        f"Write-Output '{payload}'\n", encoding="utf-8"
    )


def test_banner_survives_a_missing_presence_script(staged: Path) -> None:
    """presence.ps1 absent (an older checkout, a partial clone) must not cost the banner."""
    assert not (staged / "scripts" / "coord" / "presence.ps1").exists()
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "LIVE sessions" not in proc.stdout  # degraded, not crashed


def test_banner_survives_a_presence_script_that_throws(staged: Path) -> None:
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "throw 'presence exploded'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "LIVE sessions" not in proc.stdout


def test_banner_survives_presence_emitting_junk(staged: Path) -> None:
    """Malformed JSON on stdout must not take the hook down in ConvertFrom-Json."""
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "Write-Output 'not json at all'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout


def test_live_peers_are_rendered_when_presence_reports_them(staged: Path) -> None:
    """The positive arm: a peer in the shared primary on another surface must be called out.

    Without this the suite would pass with the presence block silently emitting nothing at all --
    every other test here asserts an ABSENCE, which a no-op integration also satisfies.
    """
    # One foreign vscode session sitting in the shared primary -- the worst case the banner exists for.
    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "vscode",
                "Worktree": "primary",
                "Branch": "main",
                "IsSelf": False,
                "IsPrimary": True,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions in this repo right now (1 besides you)" in proc.stdout
    assert "deadbeef" in proc.stdout
    assert "vscode" in proc.stdout
    assert "SHARED PRIMARY" in proc.stdout
    assert "cannot be reached by" in proc.stdout  # the non-desktop coordination note


def test_the_session_id_is_labelled_because_the_same_banner_prints_real_shas(
    staged: Path,
) -> None:
    """BACKLOG #1098: an 8-hex session id printed bare reads as an abbreviated commit SHA.

    It reads that way for a measured reason rather than a vague one, and this test measures it: the
    banner's own ``git worktree list`` row prints ``<path> <abbreviated sha> [branch]``, so the same
    banner already teaches "8 hex before a bracketed branch = commit SHA". The roster then reused the
    shape for a registry session id, which resolves to no git object at all. A session comparing "is that
    worktree ahead of mine" against it gets an error at best, and the wrong tree if the prefix resolves.

    The POSITIVE CONTROL is the first half: assert the real SHA is genuinely in this output, keyed to
    ``rev-parse HEAD`` so it is an object and not a shape. Without it the second assertion would be a
    claim about an ambiguity nobody had shown to exist.
    """
    head = subprocess.run(
        ["git", "-C", str(staged), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "desktop",
                "Worktree": "sibling",
                "Branch": "second",
                "IsSelf": False,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0

    sha_rows = [ln for ln in proc.stdout.splitlines() if head[:7] in ln]
    assert sha_rows, (
        f"no row carries HEAD ({head[:7]}), so this banner does not in fact print commit SHAs and the "
        f"ambiguity below is unproven -- fix this control before trusting the assertion after it"
    )
    print(f"real SHA rows in the same banner: {sha_rows}")

    row = next(ln for ln in proc.stdout.splitlines() if "deadbeef" in ln)
    print(f"roster row: {row!r}")
    assert row.strip().startswith("session deadbeef"), (
        f"the registry session id is printed bare, in the same shape the worktree rows use for a real "
        f"abbreviated SHA: {row!r}"
    )


def test_self_is_excluded_from_the_peer_count(staged: Path) -> None:
    fake_presence(
        staged,
        [
            {
                "Short": "aaaaaaaa",
                "Surface": "desktop",
                "Worktree": "w",
                "Branch": "b",
                "IsSelf": True,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions" not in proc.stdout  # you alone is not a coordination problem


# --------------------------------------------------------------------------------------------------
# Which worktree the banner describes.
#
# Measured 2026-10-12: the desktop app starts a worktree session's CLI with `--project-config-root
# <primary checkout>`, and a hook then runs in the PRIMARY. Across MessageFoundry worktree transcripts
# this banner printed "This chat's worktree: <primary>" 410 times against 48 for a worktree. Only the
# hook input's `cwd` names the worktree. These tests run the hook IN the primary, as the app does,
# and vary only that field.
# --------------------------------------------------------------------------------------------------


@functools.cache
def _top(path: Path) -> str:
    """The toplevel exactly as git prints it, which is how the banner prints it."""
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def primary_and_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """A primary checkout carrying the shipped hook and its helper, plus one linked worktree.

    realpath, because a short 8.3 temp path and its long form are two spellings git will not equate.
    """
    base = Path(os.path.realpath(tmp_path))
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "init")
    wt = base / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(wt))
    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    return repo, wt


def run_in_primary(repo: Path, payload: dict[str, object]) -> str:
    """Run the hook as the desktop app does: in the primary, with the input on stdin as UTF-8."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "worktree" / "session-context.ps1"),
        ],
        cwd=str(repo),
        input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout.decode("utf-8", "replace")


def test_the_banner_names_the_worktree_the_hook_input_names(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    repo, wt = primary_and_worktree
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(wt)})
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out
    assert "SHARED PRIMARY checkout" not in out, out


def test_a_cwd_below_the_worktree_root_names_the_same_worktree(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    repo, wt = primary_and_worktree
    sub = wt / "deep" / "er"
    sub.mkdir(parents=True)
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(sub)})
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out


def test_without_a_cwd_the_banner_names_where_the_hook_runs(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    """The control. With no `cwd` the same call describes the primary, so the arms above can fail."""
    repo, _ = primary_and_worktree
    out = run_in_primary(repo, {"hook_event_name": "SessionStart"})
    assert f"This chat's worktree: {_top(repo)}  (branch: main)" in out, out
    assert "SHARED PRIMARY checkout" in out, out
    assert "COULD NOT READ" not in out, "no `cwd` is not a fault and must not be reported as one"


def test_a_cwd_that_does_not_exist_is_said_aloud(
    primary_and_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, _ = primary_and_worktree
    gone = Path(os.path.realpath(tmp_path)) / "deleted-worktree"
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(gone)})
    assert "[session-context] COULD NOT READ THIS SESSION'S WORKTREE" in out, out
    assert "deleted-worktree, which does not exist" in out, out
    assert f"This chat's worktree: {_top(repo)}" in out, (
        "the fallback is the old behaviour, said aloud"
    )


def test_a_missing_input_reader_is_said_aloud(primary_and_worktree: tuple[Path, Path]) -> None:
    """Under SilentlyContinue a dot-source of a missing file does not throw, so a hook that relied
    on the throw would fall back to the primary in silence."""
    repo, wt = primary_and_worktree
    (repo / "scripts" / "hooks" / "_hookinput.ps1").unlink()
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(wt)})
    assert "[session-context] COULD NOT READ THIS SESSION'S WORKTREE" in out, out
    assert "_hookinput.ps1 is missing" in out, out


def test_a_primary_under_a_directory_named_worktrees_is_still_the_primary(
    tmp_path: Path,
) -> None:
    """Read from a subdirectory, git prints the git-dir in full, so a test for 'worktrees' in it
    misreads a primary that sits under a directory of that name. The common dir is the measure."""
    base = Path(os.path.realpath(tmp_path)) / "worktrees"
    base.mkdir()
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(base / "linked"))
    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    shutil.copy(HOOKINPUT, repo / "scripts" / "hooks" / "_hookinput.ps1")
    sub = repo / "sub"
    sub.mkdir()
    out = run_in_primary(repo, {"hook_event_name": "SessionStart", "cwd": str(sub)})
    assert "SHARED PRIMARY checkout" in out, out


def test_the_hook_reads_its_input_when_a_shim_runs_it_in_process(
    primary_and_worktree: tuple[Path, Path],
) -> None:
    """The user-level shim runs the hook with `& $s` inside its own pwsh -Command, stdin inherited.
    The read must reach the input from there too, not only under -File."""
    repo, wt = primary_and_worktree
    script = str(repo / "scripts" / "worktree" / "session-context.ps1").replace("'", "''")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f"& '{script}'"],
        cwd=str(repo),
        input=json.dumps({"hook_event_name": "SessionStart", "cwd": str(wt)}).encode("utf-8"),
        capture_output=True,
        timeout=180,
        check=False,
    )
    out = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert f"This chat's worktree: {_top(wt)}  (branch: linked)" in out, out


# --------------------------------------------------------------------------------------------------
# The banner must fit the harness's inline injection.
#
# Past a size threshold the harness saves a hook's output to a file and injects only a short preview
# of its head. Measured 2026-10-22 on a box with 471 worktrees and 155 claims, this banner printed
# 128,001 bytes, and the preview held only the start of the full worktree list: the live peers and
# the claims, printed after it, never reached the model. The threshold is not documented in this
# repository, so the script sets its own budget, and these tests hold it with every list past its cap.
# --------------------------------------------------------------------------------------------------

# The script's own budget, read from the line that sets it, so the fact is stated once.
_BUDGET_LINE = re.search(r"^\$byteBudget = (\d+)$", CONTEXT.read_text(encoding="utf-8"), re.M)
assert _BUDGET_LINE, "session-context.ps1 no longer sets $byteBudget on a line of its own"
BYTE_BUDGET = int(_BUDGET_LINE.group(1))

# A roster or in-flight row: the label, then the 8-hex registry id.
_PEER_ROW = re.compile(r"^session [0-9a-f]{8} ")


def _size(out: str, repo: Path) -> int:
    """The banner's bytes as the script counts them against its budget: without the newline
    Write-Output appends, and with this worktree's path counted as the token <ROOT>."""
    return len(_rooted(out, repo).rstrip("\r\n").encode("utf-8"))


def _rooted(out: str, repo: Path) -> str:
    return out.replace(_top(repo), "<ROOT>")


def _stamp(hours_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat()


def _claim_row(key: str, hours_ago: float, note: str) -> dict[str, str]:
    # Full-length fields, as the real registry holds them, so the budget is tested at real widths.
    return {
        "key": key,
        "note": note,
        "branch": f"claude/worktree-agent-{key}-a4cab2d83e0b3be2f",
        "worktree": f"D:/Code/MessageFoundry/.claude/worktrees/agent-{key}-a4cab2d83e0b3be2f",
        "claimed": _stamp(hours_ago),
    }


def _peer_rows(count: int, worktree: str = "agent-a4cab2d83e0b3be2f") -> list[dict[str, object]]:
    return [
        {
            "Short": f"{i:08x}",
            "Surface": "desktop",
            "Worktree": f"{worktree}-{i:02d}",
            "Branch": f"feature/peer-branch-0123456789abcdef0-{i:02d}",
            "IsSelf": False,
            "IsPrimary": False,
            "State": "LIVE",
        }
        for i in range(count)
    ]


def fake_overlap(repo: Path, count: int) -> None:
    """Stand in for overlap.ps1 -Json: live sessions, each with work and changed files."""
    rows = [
        {
            "Short": f"b{i:07x}",
            "Branch": f"feature/peer-branch-0123456789abcdef0-{i:02d}",
            "Live": True,
            "Work": [f"task {i}: " + "a long task subject from the peer's own list " * 3, "second"],
            "Files": ["a.py", "b.py"],
        }
        for i in range(count)
    ]
    payload = json.dumps(rows).replace("'", "''")
    (repo / "scripts" / "coord" / "overlap.ps1").write_text(
        f"Write-Output '{payload}'\n", encoding="utf-8"
    )


def _crowd(
    base: Path, peers: list[dict[str, object]], claims: dict[str, dict[str, str] | str]
) -> tuple[Path, dict[str, str]]:
    """Ten more worktrees, the given live peers, five busy sessions, and the given claim files."""
    repo = _make_staged(base)
    for i in range(10):
        _git(repo, "worktree", "add", "-q", "-b", f"extra-{i}", str(base / f"extra-wt-{i:02d}"))
    fake_presence(repo, peers)
    fake_overlap(repo, 5)
    shutil.copy(
        ROOT / "scripts" / "coord" / "coord-root.ps1",
        repo / "scripts" / "coord" / "coord-root.ps1",
    )
    # The resolver's first source, so the test never reads this box's real shared root.
    coord_root = base / "coord-root"
    (coord_root / "claims").mkdir(parents=True)
    for name, row in claims.items():
        text = row if isinstance(row, str) else json.dumps(row)
        (coord_root / "claims" / f"{name}.json").write_text(text, encoding="utf-8")
    return repo, {**os.environ, "MEFOR_COORD_ROOT": str(coord_root)}


def _many_claims() -> dict[str, dict[str, str] | str]:
    note = "a Manager batch note that runs well past the sixty characters a row may carry " * 3
    claims: dict[str, dict[str, str] | str] = {}
    for i in range(40):
        claims[f"fresh{i:02d}"] = _claim_row(f"fresh{i:02d}", hours_ago=i * 0.1, note=note)
    for i in range(20):
        claims[f"stale{i:02d}"] = _claim_row(f"stale{i:02d}", hours_ago=24 + i, note="old")
    return claims


def _banner(repo: Path, env: dict[str, str]) -> str:
    proc = run_context(repo, env)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _crowded_peers() -> list[dict[str, object]]:
    peers = _peer_rows(30)
    # One hazardous peer, sorted last by presence.ps1, so only the ranking can bring it under the cap.
    peers[-1] = {**peers[-1], "Surface": "vscode", "Short": "feedface"}
    return peers


@pytest.fixture(scope="module")
def crowded(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    """Every list past its cap at real field widths, run once: the tests below read one banner."""
    base = Path(os.path.realpath(tmp_path_factory.mktemp("crowded")))
    repo, env = _crowd(base, _crowded_peers(), _many_claims())
    return repo, _banner(repo, env)


def test_the_banner_fits_the_byte_budget_with_every_list_past_its_cap(
    crowded: tuple[Path, str],
) -> None:
    repo, out = crowded
    size = _size(out, repo)
    print(f"banner bytes, path counted as <ROOT>: {size} of {BYTE_BUDGET}")

    # Positive controls first: every list really was past its cap, so the budget below is earned.
    assert "[PARALLEL SESSION (12 worktrees active)]" in out, out
    assert "LIVE sessions in this repo right now (30 besides you)" in out, out
    assert "+22 more (run: pwsh -NoProfile -File scripts\\coord\\presence.ps1 -All)" in out, out
    assert "WHAT THEY ARE BUILDING" in out and "  +2 more" in out, out
    assert "Active work claims (60, 40 touched in the last 12h)" in out, out
    assert "+52 more, by key: fresh08, fresh09" in out and "claim.ps1 -List" in out, out
    # The row caps alone fit, so every section, the rules last, reaches the model.
    assert "cut the last" not in out, out
    assert "Coordination rules for parallel sessions" in out, out

    assert size <= BYTE_BUDGET, f"{size} bytes is past the {BYTE_BUDGET}-byte budget:\n{out}"


def test_peers_and_claims_print_before_any_worktree_listing(crowded: tuple[Path, str]) -> None:
    repo, out = crowded
    peers = out.index("LIVE sessions in this repo right now")
    claims = out.index("Active work claims")
    worktrees = out.index("Worktrees sharing this .git: 12")
    assert peers < claims < worktrees, out

    # The full list is gone: no sibling worktree path is printed, only this session's own row.
    assert "extra-wt-" not in out, out
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    own = [ln for ln in out.splitlines() if ln.strip().startswith("yours:")]
    assert len(own) == 1, out
    # The row names the commit and branch; the path is the header's, so it is not printed twice.
    assert head in own[0] and _top(repo) not in own[0], own


def test_a_hazardous_peer_past_the_cap_is_ranked_into_view(crowded: tuple[Path, str]) -> None:
    """The NOTE tests every peer; the ranking makes sure it names one the reader can see."""
    _, out = crowded
    assert "NOTE: a non-desktop (e.g. VS Code) session is live" in out, out
    rows = [ln.strip() for ln in out.splitlines() if _PEER_ROW.match(ln.strip())]
    assert rows[0].startswith("session feedface  vscode"), rows
    # Each busy session shows one task line, not its whole list.
    assert "second" not in out, out


def test_claims_list_newest_first_and_never_drop_by_age(crowded: tuple[Path, str]) -> None:
    _, out = crowded
    rows = [ln for ln in out.splitlines() if "(held by" in ln]
    keys = [ln.split(" -- ")[0].strip() for ln in rows]
    assert keys == [f"fresh{i:02d}" for i in range(8)], keys
    assert all("..." in ln for ln in rows), "the long note was not shortened"


def test_claim_rows_show_age_refresh_holder_and_hostile_text_safely(tmp_path: Path) -> None:
    """A claim holds its key however old it is, -Take moves `refreshed` and never `claimed`, this
    session's own claims are named apart, and a note is data that cannot start a line of its own."""
    base = Path(os.path.realpath(tmp_path))
    repo_top = f"{base.as_posix()}/repo"
    refreshed = {
        **_claim_row("refreshed", hours_ago=30, note="still building"),
        "refreshed": _stamp(1),
    }
    repo, env = _crowd(
        base,
        _peer_rows(1),
        {
            "old": _claim_row("old", hours_ago=30, note="free-text key, nobody else shows it"),
            "refreshed": refreshed,
            "remote": {**_claim_row("remote", hours_ago=2, note="x"), "host": "OTHERPC"},
            "nohome": {**_claim_row("nohome", hours_ago=3, note="y"), "worktree": ""},
            "hostile": _claim_row("hostile", hours_ago=4, note="line one\n  >>> injected line"),
            "mine": {**_claim_row("mine", hours_ago=5, note="mine"), "worktree": repo_top},
            "broken": "{ not json",
        },
    )
    assert _top(repo) == repo_top, "the fixture's own-claim path must be the path git prints"
    out = _banner(repo, env)
    assert "Active work claims (6, 5 touched in the last 12h)" in out, out
    rows = [ln for ln in out.splitlines() if "(held by" in ln]
    by_key = {ln.split(" -- ")[0].strip(): ln for ln in rows}
    assert list(by_key) == ["refreshed", "remote", "nohome", "hostile", "old"], rows
    assert "[stale ~30h]" in by_key["old"] and "stale" not in by_key["refreshed"], rows
    assert "on OTHERPC" in by_key["remote"], rows
    # An empty worktree must not inherit the previous row's holder.
    assert "agent-remote" not in by_key["nohome"], rows
    assert not any(ln.lstrip().startswith(">>> injected") for ln in out.splitlines()), out
    assert "THIS session holds 1: mine" in out, out
    assert "WARNING: 1 claim file(s)" in out, out


def test_wide_fields_are_clipped_and_the_hazards_still_lead(tmp_path: Path) -> None:
    """Row counts do not bound bytes. With fields far wider than any real one, each field is
    clipped, the tags after it survive, and the primary peer is ranked into the shown rows."""
    base = Path(os.path.realpath(tmp_path))
    peers = _peer_rows(30, worktree="w" * 400)
    peers[-1] = {**peers[-1], "IsPrimary": True, "Short": "0badf00d", "State": "UNVERIFIED"}
    repo, env = _crowd(base, peers, _many_claims())
    out = _banner(repo, env)
    assert "WARNING: a session is working in the SHARED PRIMARY checkout" in out, out
    rows = [ln.strip() for ln in out.splitlines() if _PEER_ROW.match(ln.strip())]
    assert rows[0].startswith("session 0badf00d") and rows[0].endswith("[UNVERIFIED]"), rows
    assert all(len(ln) <= 160 for ln in rows), rows
    assert "Coordination rules for parallel sessions" in out, out
    assert _size(out, repo) <= BYTE_BUDGET, out


def test_which_lines_print_does_not_depend_on_where_the_repo_lives(
    crowded: tuple[Path, str], tmp_path: Path
) -> None:
    """Measured on CI: a runner's longer temp path cut two list lines that a desktop kept. The same
    records 50 characters deeper must print the same banner, path aside."""
    deep = Path(os.path.realpath(tmp_path)) / ("d" * 50)
    deep.mkdir()
    repo, env = _crowd(deep, _crowded_peers(), _many_claims())
    outs = []
    for r, out in (crowded, (repo, _banner(repo, env))):
        # Each fixture repo has its own commit, so its SHA differs too; same length either way.
        outs.append(re.sub(r"(yours:  )[0-9a-f]+", r"\1<SHA>", _rooted(out, r)))
    assert outs[0] == outs[1], f"short base:\n{outs[0]}\n\nlong base:\n{outs[1]}"
    assert "cut the last" not in outs[1], outs[1]


def test_past_the_budget_the_lists_are_cut_and_the_rules_survive(tmp_path: Path) -> None:
    """The backstop, driven by a smaller budget written into the fixture's copy of the script:
    the head of the lists survives, the fixed rules always print, and the cut says what to run."""
    base = Path(os.path.realpath(tmp_path))
    repo, env = _crowd(base, _peer_rows(30), _many_claims())
    script = repo / "scripts" / "worktree" / "session-context.ps1"
    text = script.read_text(encoding="utf-8")
    small = text.replace(f"$byteBudget = {BYTE_BUDGET}", "$byteBudget = 1500")
    assert small != text, "the budget line was not found to shrink"
    script.write_text(small, encoding="utf-8")
    out = _banner(repo, env)
    assert "LIVE sessions in this repo right now (30 besides you)" in out, out
    assert "list line(s) to fit the budget" in out and "claim.ps1 -List" in out, out
    assert "Coordination rules for parallel sessions" in out, out
    assert "this session owns it" in out, out
    # The fixed sections print whole, the worktree count among them.
    assert "Worktrees sharing this .git: 12" in out, out
    assert _size(out, repo) <= 1500, out
