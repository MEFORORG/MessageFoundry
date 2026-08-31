# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard every relative markdown link in the repository, archive included.

Closing an item moves its text verbatim from ``docs/BACKLOG.md`` into
``docs/archive/backlog/BACKLOG-CLOSED.md`` -- two directories deeper -- and nothing rewrites its
relative links. ``adr/0083-x.md`` was correct in ``docs/`` and is broken on arrival. This is not a
hypothetical: measured 2026-08-07, **267 of the archive's 270 broken links resolved cleanly when read
from** ``docs/``, which is what pins the cause to the move rather than to authoring.

The move is **manual** -- no script performs it -- so there is nothing to fix upstream. A guard is
the only thing that can catch the next one, and it has to run at the moment the item lands.

**Scope is the whole repository.** It was archive-only when first written, because a repo-wide
assertion was red over pre-existing breakage elsewhere and a gate that is red on arrival gets
suppressed rather than fixed. That reason has expired: the remaining subtrees were repaired in the
same change that widened this (333 root-relative hrefs under ``docs/testing/``, the 270 here, ADR
slug rot in ``docs/BACKLOG.md``), and the checker's three false-positive classes -- links inside
inline code, the withheld ``docs/releases/``, and the withheld ``.claude/`` -- were fixed rather than
tolerated. Repo-wide is now green, which is the only state in which widening is honest.

``.claude/`` is worth remembering: it is gitignored but PRESENT in a long-lived local checkout, so
the first repo-wide measurement was taken somewhere it resolved and undercounted this class by 7.
Widening on that number would have put the gate red on CI's clean clone on arrival -- the precise
outcome the paragraph above says gets a gate suppressed.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "docs" / "link_check.py"

# The gate reads the whole repo. The planted-repo tests below pass an explicit subtree instead, so
# their "scanned exactly one file" assertions keep meaning what they say.
_GATE_SUBTREE: str | None = None
_PLANTED_SUBTREE = "docs/archive/backlog"


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


def _plant(tmp_path: Path, name: str, body: str) -> Path:
    """A throwaway git repo containing one archive-shaped markdown file."""
    repo = tmp_path / "r"
    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    (repo / "docs" / "real.md").write_text("# real\n", encoding="utf-8")
    (repo / "docs" / "archive" / "backlog" / name).write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    return repo


def test_every_relative_link_in_the_repo_resolves(checker) -> None:
    failures, checked, files = checker.check(_ROOT, _GATE_SUBTREE, include_line_cites=False)
    # Assert the scan actually READ something. Without this the test passes just as happily when a
    # path change makes it scan zero files -- the anti-narrowing floor the status-check gate uses.
    assert files >= 100, f"scanned {files} markdown files -- the scan itself is broken"
    assert checked >= 4000, (
        f"only {checked} links checked repo-wide; expected 4000+ (5,327 at the time this floor was "
        "set). Either the docs shrank dramatically or the link regex stopped matching -- both make "
        "a green result meaningless."
    )
    assert not failures, "unresolved relative links:\n" + "\n".join(failures)


def test_checker_detects_a_planted_break(tmp_path, checker) -> None:
    """A green result is only evidence if the checker can SEE the class it claims to cover.

    Without this, a regex that silently stopped matching would make every run above pass.
    """
    repo = _plant(
        tmp_path, "A.md", "[good](../../real.md) and [bad](../../nope-does-not-exist.md)\n"
    )
    failures, checked, files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert files == 1, f"expected to scan 1 planted file, scanned {files}"
    assert checked == 2, f"expected 2 relative links, saw {checked}"
    assert len(failures) == 1, f"expected exactly the planted break, got: {failures}"
    assert "nope-does-not-exist.md" in failures[0]


def test_withheld_prefixes_are_the_gitignored_ones(checker) -> None:
    """Pin the exemption list as a SET, so adding a prefix to the checker is a deliberate act with a
    failing test attached rather than a silent widening of what goes unchecked.

    The two ADR 0160 D1 entries are TEMPORARY and the checker says so beside them. They cover the
    10 links in ``docs/BACKLOG.md`` that could not be repaired while PR 713 held that file. When
    those are repaired, both entries and the two cases below come out in the same change -- and
    this assertion is what makes forgetting fail loudly.
    """
    assert set(checker.WITHHELD) == {
        "docs/security/",
        "docs/reviews/",
        "docs/marketing/",
        "docs/releases/",
        "docs/archive/throughput/THROUGHPUT-IMPROVEMENTS.md",
        "docs/testing/master-test-plan/",
    }


@pytest.mark.parametrize(
    "prefix",
    [
        "docs/security/",
        "docs/reviews/",
        "docs/marketing/",
        "docs/releases/",
        "docs/testing/master-test-plan/",
    ],
)
def test_withheld_directories_are_not_flagged(tmp_path, checker, prefix: str) -> None:
    """A gitignored target is a publishing boundary, not a defect; flagging it trains people to
    ignore the gate. ``docs/releases/`` joined when ADR 0160 Phase 1 untracked it. ``.claude/``
    LEFT once ``.claude/settings.json`` became tracked: all 7 links it covered named that one file,
    so they now resolve through ``tracked_paths()`` and are counted instead of skipped.

    This list expresses INTENT. It is not what makes the gate environment-independent -- that is
    ``tracked_paths()`` never consulting the filesystem, pinned by
    ``test_resolution_ignores_the_filesystem``. Planted at the real relative depth so a resolution
    bug cannot pass this by accident."""
    href = "../../../" + prefix + "GONE.md"  # docs/archive/backlog/A.md is three levels down
    repo = _plant(tmp_path, "A.md", f"[withheld]({href})\n")
    failures, _checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert not failures, f"withheld prefix {prefix} should be exempt, got: {failures}"


def test_the_one_file_shaped_prefix_is_exercised_at_its_real_path(tmp_path, checker) -> None:
    """``docs/archive/throughput/THROUGHPUT-IMPROVEMENTS.md`` names a FILE, not a directory.

    It needs its own case because the directory test above appends a filename to its prefix. That is
    meaningful for ``docs/security/`` and meaningless here -- it would assert something about
    ``...THROUGHPUT-IMPROVEMENTS.mdGONE.md``, which passes for the uninteresting reason that
    ``startswith`` is prefix matching. Planting a link to the real path is the assertion worth having.

    TEMPORARY, with the tuple entry it exercises: it covers 4 of the 10 unrepaired
    ``docs/BACKLOG.md`` links and comes out when they do.
    """
    path = "docs/archive/throughput/THROUGHPUT-IMPROVEMENTS.md"
    href = "../../../" + path  # docs/archive/backlog/A.md is three levels down
    repo = _plant(tmp_path, "A.md", f"[withheld]({href})\n")
    failures, _checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert not failures, f"withheld path {path} should be exempt, got: {failures}"


@pytest.mark.parametrize(
    "path",
    [
        "docs/BRAND.md",
        "docs/CONTRIBUTOR-PROGRAM-PLAN.md",
        "docs/COUNSEL-ENGAGEMENT-BRIEF.md",
        "docs/DUAL_LICENSING_PLAN.md",
        "docs/POSITIONING.md",
        "docs/research/config-ux-review.md",
        "docs/testing/FEATURE-COVERAGE-PLAN.md",
        "docs/archive/throughput/throughput-roadmap.md",
    ],
)
def test_untracked_adr_0160_paths_are_checked_not_exempted(tmp_path, checker, path: str) -> None:
    """The must-FAIL arm, and the reason this file gained a test rather than lost one.

    ADR 0160 D1 untracked these paths and the same pass added them to ``WITHHELD``, which made the
    gate report every link into them as resolving while 59 of them 404'd for a reader. An
    exemption-shaped fix and a repair are indistinguishable from a green run, which is exactly why
    the exemptions needed a test that fails when they come back.

    So: a link to one of these must be a FAILURE. Paired with the exempt-arm tests above, that
    bounds the exemption from both sides -- neither a narrowing nor a widening can pass silently.
    Note ``docs/archive/throughput/`` and ``docs/testing/`` appear here as parent trees whose ONE
    withheld member is asserted separately; a re-widened prefix turns these red.
    """
    href = "../../../" + path  # docs/archive/backlog/A.md is three levels down
    repo = _plant(tmp_path, "A.md", f"[cited]({href})\n")
    failures, checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert checked == 1, f"{path} was skipped before it was ever counted -- checked={checked}"
    assert len(failures) == 1, f"{path} must be CHECKED and fail, not exempted; got: {failures}"


def test_resolution_ignores_the_filesystem(tmp_path, checker) -> None:
    """The gate must give the SAME answer in a long-lived checkout and on CI's clean clone.

    A filesystem fallback breaks that: it passes any path that merely happens to be PRESENT, and
    gitignored-but-present paths are precisely the ones a developer has and CI does not. Not
    hypothetical -- ``.claude/settings.json`` is untracked, present locally, absent on the runner,
    and 7 docs link to it; the first repo-wide measurement of this gate passed locally for exactly
    that reason and undercounted by 7.

    So a target that EXISTS ON DISK but is not tracked must still fail. This test fails against a
    resolver carrying an ``(root / target).exists()`` fallback, which is what makes it worth having.
    """
    repo = _plant(tmp_path, "A.md", "[present but untracked](../../untracked.txt)\n")
    (repo / "docs" / "untracked.txt").write_text("i am here\n", encoding="utf-8")
    assert (repo / "docs" / "untracked.txt").is_file(), "must really be on disk to prove anything"

    failures, _checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert len(failures) == 1, f"present-but-untracked must fail; got: {failures}"
    assert "untracked.txt" in failures[0]


def test_directory_links_resolve(tmp_path, checker) -> None:
    """``git ls-files`` lists files and never directories, so ancestor prefixes must be DERIVED or
    every link to a directory breaks -- 122 of them in this repo (``docs/adr``, ``environments``,
    ``.github/workflows``), all legitimate, since a directory link resolves for anyone who clones.
    This is the constraint that stops the fix above from being simply "drop the fallback"."""
    import subprocess as sp

    repo = _plant(tmp_path, "A.md", "[a directory](../../real-dir)\n")
    (repo / "docs" / "real-dir").mkdir()
    (repo / "docs" / "real-dir" / "kept.md").write_text("# kept\n", encoding="utf-8")
    sp.run(["git", "add", "-A"], cwd=repo, check=True)

    failures, checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert checked == 1, f"expected the directory link to be checked, saw {checked}"
    assert not failures, f"a directory containing a tracked file must resolve, got: {failures}"


def test_links_inside_inline_code_are_not_followed(tmp_path, checker) -> None:
    """A link inside backticks is being DISPLAYED, not offered -- the same reason fenced code is
    skipped. Four real sites depend on this: a regex containing ``](`` inside a character class, two
    VS Code ``command:`` URIs (one quoted as an attack payload), and ADR 0160 quoting the very link
    it records as removed. Repointing any of them would corrupt the text.

    The discriminator is POSITION, not shape. The dominant repo idiom ``[`x.md`](../x.md)`` closes
    its code span before the ``]``, so it must still be checked -- asserted here, because a rule that
    skipped by shape would silently stop checking most of the docs.
    """
    repo = _plant(
        tmp_path,
        "A.md",
        "a `[bad](../../nope.md)` shown as text\n"
        "b [`real.md`](../../real.md) a genuine link with a code-span label\n"
        "c [also bad](../../missing.md) a genuine broken link\n",
    )
    failures, checked, _files = checker.check(repo, _PLANTED_SUBTREE, include_line_cites=False)
    assert checked == 2, f"expected the code-span link skipped and 2 checked, saw {checked}"
    assert len(failures) == 1, f"expected only the uncoded break, got: {failures}"
    assert "missing.md" in failures[0]
