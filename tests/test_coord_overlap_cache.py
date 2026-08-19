# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The overlap cache must round-trip ZERO rows as zero rows.

``scripts/coord/overlap.ps1`` writes its walk to a per-repo cache and every later run inside
``-CacheSeconds`` reads it back instead of re-walking. The empty answer does not survive that trip by
itself. ``Build-Map`` ends in ``return $rows`` over ``$rows = @()``, and PowerShell UNROLLS an empty
array on the way out, so a zero-row walk yields AutomationNull. In process that is harmless -- the
zero-rows guard still fires -- but ``ConvertTo-Json`` serialises it as ``"rows": null``, and the next
run reads that back with ``@($c.rows)``, which is a ONE-element array holding ``$null``. ``Count`` is
then 1, the guard does not fire, and the human report prints a PHANTOM OCCUPANT: a blank worktree
name on a blank branch with "0 changed file(s)".

This is the same class of defect as the ``Write-JsonArray`` null filter above it in the same script,
at the other end of the same round trip, and the same class as the ``Get-WiredMatchers`` unroll in
``scripts/worktree/install-gate.ps1`` -- an enumerable returned from a PowerShell function is not the
value the author wrote.

WHY IT MATTERS RATHER THAN MERELY BEING UNTIDY. ``collision_gate.ps1`` runs ``overlap.ps1 -File ...
-Json`` on every gated edit, and the cache is written BEFORE the ``-File`` early exit. So the hot path
arms the cache constantly, and any bare ``overlap.ps1`` run inside the window inherits it: a session
asking "who else is in this repo" is answered with an occupant that does not exist. An invented
collision is not a safe direction to fail in -- it is the answer people work around, and a report that
cries wolf on a quiet repo is one they stop reading, which is how a REAL collision goes unnoticed.

Driven against real throwaway git repos, because the question is entirely about what the script writes
to disk and reads back. A test over stub rows would assert only that a value someone else computed
gets carried, and the value is exactly what is wrong here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="overlap.ps1 needs pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def _repo(root: Path, name: str) -> Path:
    """A repo with an ``origin/main`` to diff against, and nothing else in it."""
    origin = root / f"{name}.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = root / name
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    _git(primary, "config", "user.email", "t@example.invalid")
    _git(primary, "config", "user.name", "t")
    (primary / "alpha.txt").write_text("base\n", encoding="utf-8")
    _git(primary, "add", "-A")
    _git(primary, "commit", "-qm", "base")
    _git(primary, "remote", "add", "origin", str(origin))
    _git(primary, "push", "-q", "origin", "main")
    return primary


def _cache_path(repo: Path) -> Path:
    common = _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "overlap-cache.json"


def _run(repo: Path, sandbox: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Drive overlap.ps1 against one throwaway repo, with every machine-global input redirected.

    ``-ConfigRoot`` and ``-TasksDir`` point at paths that do not exist on purpose: without them the
    script reads this developer's REAL session registry and task lists, and the answer would depend on
    who else is logged in. They cannot contribute a row here anyway (only worktrees of this repo are
    walked), but a fixture whose result varies with the machine is not a fixture.
    """
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(repo),
            "-ConfigRoot",
            str(sandbox / "no-such-config"),
            "-TasksDir",
            str(sandbox / "no-such-tasks"),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}\n{proc.stdout}"
    return proc


def _cached_rows(repo: Path) -> Any:
    """The ``rows`` member exactly as it was serialised -- deliberately NOT normalised.

    ``json.loads`` renders ``"rows": null`` as ``None`` and ``"rows": []`` as ``[]``, and the whole
    defect is that PowerShell then treats those two as the same length. Coercing them here (``or []``,
    ``len(rows or [])``) would reproduce the bug inside the instrument and the test would pass against
    the defect it exists to pin.
    """
    return json.loads(_cache_path(repo).read_text(encoding="utf-8"))["rows"]


def test_a_walk_that_finds_nobody_caches_an_empty_array_not_null(tmp_path: Path) -> None:
    """Zero rows must reach the cache as ``[]``, and come back out as zero rows.

    The positive control runs FIRST and against the same machinery: a repo that DOES have an occupant
    must cache a non-empty ``rows``. Without it, an assertion that ``rows == []`` is satisfied just as
    well by a script that never writes a row under any circumstances, or by a cache path this fixture
    computed wrongly -- and a null result printed by a broken instrument is indistinguishable from a
    null result printed by a working one.
    """
    # --- POSITIVE CONTROL: an occupied repo, so we know rows can be non-empty at all ---------------
    occupied = _repo(tmp_path, "occupied")
    peer = tmp_path / "occupied-peer"
    _git(occupied, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    (peer / "alpha.txt").write_text("peer edit\n", encoding="utf-8")

    _run(occupied, tmp_path, "-Refresh", "-Json")
    occupied_rows = _cached_rows(occupied)
    # Deliberately shape-AGNOSTIC: `ConvertTo-Json` renders a single row as a bare object rather than
    # a one-element array, and that shape is harmless -- `@($c.rows)` wraps it back into one row on
    # the way in. Asserting a list here would make the control the first thing to fail under the
    # defect below, which would report "the fixture is broken" for a fixture that is working.
    assert occupied_rows not in (None, []), (
        "the control repo has a peer worktree with a dirty file, so the cache must carry a row. It "
        f"does not, so this fixture cannot tell an empty cache from a broken one: {occupied_rows!r}"
    )

    # --- THE CASE: a repo with no peer worktree and nothing dirty ----------------------------------
    quiet = _repo(tmp_path, "quiet")
    first = _run(quiet, tmp_path, "-Refresh", "-Json")
    assert first.stdout.strip() == "[]", (
        f"the walk itself must find nobody in this repo, or the rest of this test is moot: "
        f"{first.stdout!r}"
    )

    rows = _cached_rows(quiet)
    assert rows == [], (
        "a walk that found nobody was serialised into the cache as something other than an empty "
        "array. `null` here is the unroll: `return $rows` over an empty array yields AutomationNull, "
        "and the next run reads it back as a one-element array holding $null, so the zero-rows guard "
        f"does not fire and a phantom occupant is printed. Got: {rows!r}"
    )

    # --- and the read-back half: the cached answer must still be "nobody" --------------------------
    before = _cache_path(quiet).read_bytes()
    second = _run(quiet, tmp_path, "-CacheSeconds", "3600")
    after = _cache_path(quiet).read_bytes()

    # Guard the guard: prove this run was a cache HIT. A miss re-walks and REWRITES the cache with a
    # fresh `at` stamp, so unchanged bytes are the evidence that the cached value is what was read --
    # otherwise a passing assertion below would only mean the second walk also found nobody, which
    # says nothing about the round trip.
    assert after == before, (
        "the second run rewrote the cache, so it re-walked instead of reading what the first run "
        "stored -- this assertion would then be testing the walk twice and the cache never."
    )
    assert "No other worktree has changes." in second.stdout, (
        "reading the cached empty walk back produced an occupant. Under the unroll the cache holds "
        f'`"rows": null`, which `@($c.rows)` turns into one $null row.\n{second.stdout!r}'
    )
    assert "changed file(s)" not in second.stdout, (
        f"a phantom row was printed from the cache:\n{second.stdout!r}"
    )
