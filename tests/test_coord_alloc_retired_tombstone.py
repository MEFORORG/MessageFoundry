# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A stale PRE-RETIREMENT ``alloc.ps1`` must issue a harmless number once the tombstone is written
(BACKLOG #1829).

The reasoning lives once, in the header of ``scripts/coord/tombstone-retired-backlog-allocator.ps1``.
Read that first.

**THE SUBJECT IS OLD CODE, SO THE OLD CODE IS WHAT RUNS.** Each case materialises a pre-retirement
revision of ``alloc.ps1`` from this repository's own history into a throwaway clone and runs it
there. A test that ran head's allocator would prove nothing: head refuses ``-Kind backlog`` at
parameter binding and never reads the registry for it.

**EVERY CASE IS PAIRED.** The same stale copy runs against the same registry with and without the
tombstone, so the jump is attributable to the tombstone and not to a fixture that was already high.

These cases really allocate, like ``tests/test_coord_alloc_reentrancy.py``. That is safe for the
same reason: the registry is the fixture clone's own ``.git``, never this repository's.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_HEAD_ALLOC = _ROOT / "scripts" / "coord" / "alloc.ps1"
_TOMBSTONE = _ROOT / "scripts" / "coord" / "tombstone-retired-backlog-allocator.ps1"

pytestmark = [
    pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"),
    # The paired case spawns about a dozen git and pwsh processes, two of them full stale allocator
    # runs. Measured on a loaded Windows box on 2026-09-25: one git spawn cost 1.3 to 3 seconds there,
    # so the default 60s watchdog fired on a run that was working. This is a ceiling, not a target.
    pytest.mark.timeout(300),
]

# Pre-retirement revisions of scripts/coord/alloc.ps1, all on main before 11a3934c1.
#   e2a73752f -- its alloc.ps1 blob is byte-identical to the one at 4c68c28eb, the tree that issued
#                #1770 and #1771 on 2026-09-19. This is the copy that did the damage.
#   dc09f01c6 -- the LAST revision before the retirement (11a3934c1's parent for this file). It adds
#                the pre-flight fetch, so it is the newest shape a stale tree can hold.
#   4ea095719 -- an early revision with no #1000 partition clamp, so the floor is the raw maximum.
_STALE_REVISIONS = {
    "4c68c28eb-blob": "e2a73752fcb7d8a7dd61d21b558e575f1fa6b1ef",
    "last-before-retirement": "dc09f01c6259b67028db6de1c2436083d4288e76",
    "unclamped": "4ea0957194f4efa5496a7beb4e3fad38788ddc9c",
}

_TOMBSTONE_NUMBER = 1000000
_ALLOCATED = re.compile(r"ALLOCATED BACKLOG #(\d+)")


def _git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)
    return proc.stdout


@functools.cache
def _read_blob(revision: str) -> tuple[int, bytes, str]:
    """One ``git cat-file`` per revision per session; a git spawn costs seconds on a loaded box.

    BYTES, not text: text mode would fold the blob's line endings, and the file that runs should be
    the file that shipped.
    """
    proc = subprocess.run(
        ["git", "cat-file", "blob", f"{revision}:scripts/coord/alloc.ps1"],
        cwd=str(_ROOT),
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", errors="replace")


def _stale_alloc(revision: str) -> bytes:
    """The pre-retirement allocator's source, read from this repository's history.

    A missing revision is a SKIP locally (a shallow clone) and a FAILURE in CI, where the tooling job
    checks out with fetch-depth 0. A skip there would be a guard that cannot fail.
    """
    code, source, err = _read_blob(revision)
    if code != 0:
        message = f"revision {revision} is not in this clone: {err.strip()}"
        if os.environ.get("CI"):
            pytest.fail(message)
        pytest.skip(message)
    return source


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _commit(repo: Path, message: str) -> None:
    _git("add", "-A", cwd=repo)
    _git(
        "-c",
        "user.email=t@e.com",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "-m",
        message,
        "--no-verify",
        cwd=repo,
    )


def _stale_clone(tmp: Path, stale_source: bytes, *, main_retired: bool = True) -> Path:
    """A clone whose origin/main carries head's retired allocator, checked out at a STALE commit.

    That is the shape of the hazard: the clone's published allocator is retired, and a worktree that
    never moved still holds the old one. ``main_retired=False`` builds the vault's shape instead,
    where the published allocator still accepts ``-Kind backlog``.

    The stale copy reads PUBLIC_BACKLOG_FLOOR out of scripts/hooks/ledger_check.py and refuses to
    allocate without it, so the stale commit carries the one line it reads, at its real value.
    """
    upstream = tmp / "upstream"
    upstream.mkdir()
    _git("init", "-q", "-b", "main", ".", cwd=upstream)
    _write(upstream / "scripts" / "coord" / "alloc.ps1", stale_source)
    _write(upstream / "scripts" / "hooks" / "ledger_check.py", b"PUBLIC_BACKLOG_FLOOR = 1000\n")
    _commit(upstream, "stale: the pre-retirement allocator")
    if main_retired:
        shutil.copy2(_HEAD_ALLOC, upstream / "scripts" / "coord" / "alloc.ps1")
        _commit(upstream, "retire the backlog kind")

    clone = tmp / "clone"
    _git("clone", "-q", str(upstream), str(clone), cwd=tmp)
    if main_retired:
        # The stale tree: one commit behind the clone's own origin/main.
        _git("checkout", "-q", "--detach", "HEAD~1", cwd=clone)
    return clone


def _common_dir(repo: Path) -> Path:
    """A fresh non-worktree clone's common dir is its own .git; no git spawn needed to say so."""
    return repo / ".git"


def _seed_registry(repo: Path, numbers: list[int], *, owner: str = "C:/nowhere/else") -> Path:
    """Allocation records shaped exactly as alloc.ps1 writes them, owned by ``owner``."""
    registry = _common_dir(repo) / "mefor-coord" / "alloc" / "backlog"
    registry.mkdir(parents=True, exist_ok=True)
    for n in numbers:
        record = {
            "number": str(n),
            "kind": "backlog",
            "title": f"seeded {n}",
            "branch": "elsewhere",
            "worktree": owner,
            "claimed": "2026-09-12T00:00:00.0000000+00:00",
        }
        (registry / f"{n}.json").write_text(json.dumps(record), encoding="utf-8")
    return registry


def _pwsh(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=300,
    )


def _tombstone(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _pwsh(_TOMBSTONE, "-GitCommonDir", str(_common_dir(repo)), *args, cwd=repo)


def _allocate_with_stale_copy(repo: Path) -> int:
    proc = _pwsh(
        repo / "scripts" / "coord" / "alloc.ps1",
        "-Kind",
        "backlog",
        "-Title",
        "a number from a stale tree",
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    match = _ALLOCATED.search(proc.stdout)
    assert match, f"no ALLOCATED line in:\n{proc.stdout}\n{proc.stderr}"
    return int(match.group(1))


@pytest.mark.parametrize("revision", list(_STALE_REVISIONS.values()), ids=list(_STALE_REVISIONS))
def test_the_tombstone_lifts_a_stale_allocator_above_every_real_number(
    tmp_path: Path, revision: str
) -> None:
    """One stale copy, one registry, run before and after the tombstone.

    The first run is the control: max(registry) + 1, the #1770 shape. Running both in one clone
    makes the jump attributable to the tombstone alone.
    """
    repo = _stale_clone(tmp_path, _stale_alloc(revision))
    _seed_registry(repo, [1769, 1771])
    assert _allocate_with_stale_copy(repo) == 1772

    wrote = _tombstone(repo)
    assert wrote.returncode == 0, wrote.stdout + wrote.stderr
    assert "WROTE TOMBSTONE" in wrote.stdout

    assert _allocate_with_stale_copy(repo) == _TOMBSTONE_NUMBER + 1


def test_the_tombstone_is_idempotent_and_check_reports_it(tmp_path: Path) -> None:
    repo = _stale_clone(tmp_path, _stale_alloc(_STALE_REVISIONS["4c68c28eb-blob"]))
    record = _common_dir(repo) / "mefor-coord" / "alloc" / "backlog" / f"{_TOMBSTONE_NUMBER}.json"

    absent = _tombstone(repo, "-Check")
    assert absent.returncode == 1, absent.stdout + absent.stderr
    assert "ABSENT" in absent.stdout
    assert not record.exists(), "-Check must write nothing"

    first = _tombstone(repo)
    assert first.returncode == 0, first.stdout + first.stderr
    before = record.read_bytes()

    # The second run names a LINKED worktree's own git dir. It must resolve that to the common dir and
    # find the record there; writing under .git/worktrees/<name> would be a record no allocator reads.
    _git("worktree", "add", "-q", "--detach", str(tmp_path / "linked"), cwd=repo)
    linked_git_dir = _common_dir(repo) / "worktrees" / "linked"
    assert linked_git_dir.is_dir()
    second = _pwsh(_TOMBSTONE, "-GitCommonDir", str(linked_git_dir), cwd=repo)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "ALREADY PRESENT" in second.stdout
    assert record.read_bytes() == before
    assert not (linked_git_dir / "mefor-coord").exists()

    present = _tombstone(repo, "-Check")
    assert present.returncode == 0, present.stdout + present.stderr
    assert "PRESENT" in present.stdout


def test_the_tombstone_record_is_inert_to_the_ownership_readers(tmp_path: Path) -> None:
    """Empty ``worktree`` and ``branch`` are what keep every keyed reader from claiming it."""
    repo = _stale_clone(tmp_path, _stale_alloc(_STALE_REVISIONS["4c68c28eb-blob"]))
    assert _tombstone(repo).returncode == 0
    record_path = (
        _common_dir(repo) / "mefor-coord" / "alloc" / "backlog" / f"{_TOMBSTONE_NUMBER}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["number"] == str(_TOMBSTONE_NUMBER)
    assert record["kind"] == "backlog"
    assert record["worktree"] == ""
    assert record["branch"] == ""
    assert record["tombstone"] is True

    # Head's -List, run from a checkout at origin/main of the same clone, must not report it -- while
    # it DOES report a record this tree owns, so a -List that skipped the directory cannot pass.
    _git("checkout", "-q", "--detach", "origin/main", cwd=repo)
    _seed_registry(repo, [1771], owner=repo.as_posix())
    listed = _pwsh(repo / "scripts" / "coord" / "alloc.ps1", "-List", cwd=repo)
    assert listed.returncode == 0, listed.stdout + listed.stderr
    assert "backlog allocated to this worktree: 1771" in listed.stdout
    assert str(_TOMBSTONE_NUMBER) not in listed.stdout


def test_the_tombstone_refuses_a_clone_whose_allocator_is_live(tmp_path: Path) -> None:
    """The vault's shape: origin/main still accepts -Kind backlog, so a tombstone would break it."""
    repo = _stale_clone(
        tmp_path, _stale_alloc(_STALE_REVISIONS["4c68c28eb-blob"]), main_retired=False
    )
    refused = _tombstone(repo)
    assert refused.returncode != 0
    assert "LIVE" in refused.stdout + refused.stderr
    registry = _common_dir(repo) / "mefor-coord" / "alloc" / "backlog"
    assert not (registry / f"{_TOMBSTONE_NUMBER}.json").exists()


def test_the_tombstone_refuses_to_overwrite_a_real_record(tmp_path: Path) -> None:
    repo = _stale_clone(tmp_path, _stale_alloc(_STALE_REVISIONS["4c68c28eb-blob"]))
    registry = _seed_registry(repo, [_TOMBSTONE_NUMBER])
    before = (registry / f"{_TOMBSTONE_NUMBER}.json").read_bytes()

    refused = _tombstone(repo)
    assert refused.returncode != 0
    assert "NOT the tombstone" in refused.stdout + refused.stderr
    assert (registry / f"{_TOMBSTONE_NUMBER}.json").read_bytes() == before

    occupied = _tombstone(repo, "-Check")
    assert occupied.returncode == 2, occupied.stdout + occupied.stderr


def test_the_tombstone_replaces_an_empty_record(tmp_path: Path) -> None:
    """An empty file at that path is a crashed write, and remove.ps1 refuses every removal over it."""
    repo = _stale_clone(tmp_path, _stale_alloc(_STALE_REVISIONS["4c68c28eb-blob"]))
    registry = _common_dir(repo) / "mefor-coord" / "alloc" / "backlog"
    registry.mkdir(parents=True)
    (registry / f"{_TOMBSTONE_NUMBER}.json").write_bytes(b"")

    wrote = _tombstone(repo)
    assert wrote.returncode == 0, wrote.stdout + wrote.stderr
    assert _tombstone(repo, "-Check").returncode == 0
    assert not list(registry.glob(".tombstone-*")), "the temp file must not be left behind"
