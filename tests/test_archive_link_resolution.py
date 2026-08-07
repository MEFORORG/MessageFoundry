# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard the backlog archive against the link breakage that ARCHIVING ITSELF causes.

Closing an item moves its text verbatim from ``docs/BACKLOG.md`` into
``docs/archive/backlog/BACKLOG-CLOSED.md`` -- two directories deeper -- and nothing rewrites its
relative links. ``adr/0083-x.md`` was correct in ``docs/`` and is broken on arrival. This is not a
hypothetical: measured 2026-08-07, **267 of the archive's 270 broken links resolved cleanly when read
from** ``docs/``, which is what pins the cause to the move rather than to authoring.

The move is **manual** -- no script performs it -- so there is nothing to fix upstream. A guard is
the only thing that can catch the next one, and it has to run at the moment the item lands.

**Scope is deliberately the archive only.** A repo-wide assertion would be red on day one over
pre-existing breakage elsewhere, and a gate that is red on arrival gets suppressed rather than fixed
(the same reasoning the ledger gate records). Widening it is a one-line change to ``_SUBTREE`` once
the remaining subtrees are clean; the checker itself is already repo-wide capable.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "docs" / "link_check.py"
_SUBTREE = "docs/archive/backlog"


def _load():
    spec = importlib.util.spec_from_file_location("_link_check", _CHECKER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_link_check"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def checker():
    assert _CHECKER.is_file(), f"missing {_CHECKER}"
    return _load()


def test_archive_links_all_resolve(checker) -> None:
    """Every relative link in the backlog archive resolves."""
    failures, checked, files = checker.check(_ROOT, _SUBTREE, include_line_cites=False)
    # Assert the scan actually READ something. Without this the test passes just as happily when a
    # path change makes it scan zero files -- the anti-narrowing floor the status-check gate uses.
    assert files >= 1, f"scanned {files} files under {_SUBTREE} -- the scan itself is broken"
    assert checked >= 200, (
        f"only {checked} links checked under {_SUBTREE}; expected 200+. Either the archive shrank "
        "dramatically or the link regex stopped matching -- both make a green result meaningless."
    )
    assert not failures, "unresolved links in the backlog archive:\n" + "\n".join(failures)


def test_checker_detects_a_planted_break(tmp_path, checker) -> None:
    """A green result is only evidence if the checker can SEE the class it claims to cover.

    Builds a throwaway git repo containing one markdown file with one deliberately broken link and
    one good link, and asserts the checker reports exactly the broken one. Without this, a regex
    that silently stopped matching would make every run above pass.
    """
    import subprocess

    repo = tmp_path / "r"
    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    (repo / "docs" / "real.md").write_text("# real\n", encoding="utf-8")
    (repo / "docs" / "archive" / "backlog" / "A.md").write_text(
        "[good](../../real.md) and [bad](../../nope-does-not-exist.md)\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    failures, checked, files = checker.check(repo, _SUBTREE, include_line_cites=False)
    assert files == 1, f"expected to scan 1 planted file, scanned {files}"
    assert checked == 2, f"expected 2 relative links, saw {checked}"
    assert len(failures) == 1, f"expected exactly the planted break, got: {failures}"
    assert "nope-does-not-exist.md" in failures[0]


def test_withheld_directories_are_not_flagged(tmp_path, checker) -> None:
    """docs/security|reviews|marketing are gitignored by design; flagging them trains people to
    ignore the gate. Pinned so a future refactor cannot quietly start reporting them."""
    import subprocess

    repo = tmp_path / "r"
    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    (repo / "docs" / "archive" / "backlog" / "A.md").write_text(
        "[withheld](../../security/ASVS-L2.md)\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    failures, _checked, _files = checker.check(repo, _SUBTREE, include_line_cites=False)
    assert not failures, f"withheld path should be exempt, got: {failures}"
