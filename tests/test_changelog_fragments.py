# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Changelog fragments under ``changelog.d/``, and the release-time assembler (BACKLOG #2080).

A pull request adds its changelog entry as a new file instead of editing ``CHANGELOG.md``, and the
release pull request runs ``scripts/release/changelog_fragments.py assemble``. The unit tests below
hold the assembler's contract: entries land after every existing bullet, nothing existing moves,
fragments are deleted only after the changelog is written, and a malformed fragment is refused
rather than skipped. The live-tree tests read the real ``changelog.d/`` and ``CHANGELOG.md`` and the
two workflows that call the script, so the gate cannot be wired to nothing.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "release" / "changelog_fragments.py"


def _load() -> ModuleType:
    assert _SCRIPT.is_file(), f"{_SCRIPT} is missing -- the changelog assembler moved"
    spec = importlib.util.spec_from_file_location("_mefor_changelog_fragments", _SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cf: Any = _load()

_CHANGELOG = """\
# Changelog

Intro.

## [Unreleased]

### Added
- existing added one
- existing added two,
  continued

### Fixed
- existing fixed

### Added
- a second Added block, never the target

## [0.4.0] - 2026-09-23

### Added
- released entry

[0.4.0]: https://example.invalid/v0.4.0
"""


def _repo(tmp_path: Path, fragments: dict[str, str], changelog: str = _CHANGELOG) -> Path:
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8", newline="")
    frag_dir = tmp_path / "changelog.d"
    frag_dir.mkdir()
    (frag_dir / "README.md").write_text("# not a fragment\n", encoding="utf-8")
    for name, body in fragments.items():
        (frag_dir / name).write_text(body, encoding="utf-8")
    return tmp_path


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
    it = iter(haystack)
    return all(line in it for line in needle)


# --- assembly ---------------------------------------------------------------------------------------


def test_entries_land_after_every_existing_bullet_of_the_first_matching_heading(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path, {"2080.added.md": "- new added\n", "12.fixed.md": "- new fixed\n"})
    cf.assemble(root)
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "- existing added two,\n  continued\n- new added\n\n### Fixed" in text
    assert "- existing fixed\n- new fixed\n\n### Added\n- a second Added block" in text
    # The released section is untouched.
    assert text.split("## [0.4.0]")[1] == _CHANGELOG.split("## [0.4.0]")[1]


def test_nothing_existing_changes_only_lines_are_added(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"1.added.md": "- a\n", "2.security.md": "- s\n", "3.fixed.md": "- f\n"})
    cf.assemble(root)
    after = (root / "CHANGELOG.md").read_text(encoding="utf-8").split("\n")
    before = _CHANGELOG.split("\n")
    assert _is_subsequence(before, after)
    added = len(after) - len(before)
    # a, f, and a new Security block of blank + heading + bullet.
    assert added == 1 + 1 + 3, added


def test_a_category_with_no_heading_gets_one_before_the_next_release(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"7.security.md": "- sec one\n"})
    cf.assemble(root)
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (
        "- a second Added block, never the target\n\n### Security\n- sec one\n\n## [0.4.0]" in text
    )


def test_no_blank_line_before_the_next_release_still_separates_the_new_heading() -> None:
    changelog = "## [Unreleased]\n### Added\n- x\n## [0.1.0]\n- old\n"
    frag = cf.Fragment(Path("9.removed.md"), "9", "removed", "- gone\n")
    out = cf.assemble_text(changelog, [frag])
    assert out == "## [Unreleased]\n### Added\n- x\n\n### Removed\n- gone\n\n## [0.1.0]\n- old\n"


def test_a_last_section_does_not_run_into_the_link_definitions() -> None:
    changelog = "## [Unreleased]\n\n### Added\n- x\n\n[0.1.0]: https://example.invalid\n"
    frag = cf.Fragment(Path("1.fixed.md"), "1", "fixed", "- y\n")
    out = cf.assemble_text(changelog, [frag])
    assert out == (
        "## [Unreleased]\n\n### Added\n- x\n\n### Fixed\n- y\n\n[0.1.0]: https://example.invalid\n"
    )


def test_order_is_numeric_then_slug(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "1000.added.md": "- thousand\n",
            "999.added.md": "- nine nine nine\n",
            "999-docs.added.md": "- nine nine nine docs\n",
            "fix-typo.added.md": "- slug\n",
        },
    )
    cf.assemble(root)
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    order = [text.index(s) for s in ("nine nine nine\n", "nine nine nine docs", "thousand", "slug")]
    assert order == sorted(order), order


def test_fragments_are_deleted_and_a_second_run_changes_nothing(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"5.changed.md": "- changed\n"})
    done = cf.assemble(root)
    assert [f.name for f in done] == ["5"]
    assert sorted(p.name for p in (root / "changelog.d").iterdir()) == ["README.md"]
    first = (root / "CHANGELOG.md").read_bytes()
    assert cf.assemble(root) == []
    assert (root / "CHANGELOG.md").read_bytes() == first


def test_an_empty_or_missing_directory_is_a_no_op(tmp_path: Path) -> None:
    root = _repo(tmp_path, {})
    assert cf.assemble(root) == []
    assert (root / "CHANGELOG.md").read_text(encoding="utf-8") == _CHANGELOG
    assert cf.load(tmp_path / "does-not-exist") == []


def test_dry_run_prints_and_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, {"5.changed.md": "- changed\n"})
    assert cf.main(["--root", str(root), "assemble", "--dry-run"]) == 0
    assert "### Changed\n- changed" in capsys.readouterr().out
    assert (root / "CHANGELOG.md").read_text(encoding="utf-8") == _CHANGELOG
    assert (root / "changelog.d" / "5.changed.md").is_file()


def test_the_changelog_must_hold_exactly_one_unreleased_heading() -> None:
    frag = cf.Fragment(Path("1.added.md"), "1", "added", "- x\n")
    for bad in ("# Changelog\n", "## [Unreleased]\n\n## [Unreleased]\n"):
        with pytest.raises(cf.FragmentError, match="exactly one"):
            cf.assemble_text(bad, [frag])


def test_crlf_fragments_assemble_as_lf(tmp_path: Path) -> None:
    root = _repo(tmp_path, {})
    (root / "changelog.d" / "4.added.md").write_bytes(b"- one\r\n  two\r\n")
    cf.assemble(root)
    raw = (root / "CHANGELOG.md").read_bytes()
    assert b"\r" not in raw
    assert b"- one\n  two\n" in raw


# --- refusal ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "body", "reason"),
    [
        ("2080.md", "- x\n", "not a fragment name"),
        ("2080.Added.md", "- x\n", "not a fragment name"),
        ("2080.add.md", "- x\n", "unknown category"),
        ("-2080.added.md", "- x\n", "not a fragment name"),
        ("2080.added.txt", "- x\n", "not a fragment name"),
        ("2080.added.md", "", "is empty"),
        ("2080.added.md", "\n\n", "is empty"),
        ("2080.added.md", "plain prose\n", "must start with a bullet"),
        ("2080.added.md", "- x\n### Added\n- y\n", "starts with '#'"),
        ("2080.added.md", "- x\nnot indented\n", "neither a bullet"),
    ],
)
def test_a_malformed_fragment_is_refused_and_nothing_is_written(
    tmp_path: Path, name: str, body: str, reason: str
) -> None:
    root = _repo(tmp_path, {name: body, "1.fixed.md": "- fine\n"})
    with pytest.raises(cf.FragmentError, match=reason):
        cf.assemble(root)
    assert (root / "CHANGELOG.md").read_text(encoding="utf-8") == _CHANGELOG
    assert (root / "changelog.d" / "1.fixed.md").is_file(), "a refusal must delete nothing"


def test_a_non_utf8_fragment_is_refused(tmp_path: Path) -> None:
    root = _repo(tmp_path, {})
    (root / "changelog.d" / "3.added.md").write_bytes(b"- caf\xe9\n")
    with pytest.raises(cf.FragmentError, match="not UTF-8"):
        cf.load(root / "changelog.d")


def test_every_problem_is_reported_at_once(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"a.md": "- x\n", "b.nope.md": "- x\n"})
    with pytest.raises(cf.FragmentError) as caught:
        cf.load(root / "changelog.d")
    assert "changelog.d/a.md" in str(caught.value)
    assert "changelog.d/b.nope.md" in str(caught.value)


def test_check_no_pending_refuses_any_fragment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, {"8.fixed.md": "- f\n"})
    assert cf.main(["--root", str(root), "check"]) == 0
    assert cf.main(["--root", str(root), "check", "--no-pending"]) == 1
    assert "changelog.d/8.fixed.md" in capsys.readouterr().err
    (root / "changelog.d" / "8.fixed.md").unlink()
    assert cf.main(["--root", str(root), "check", "--no-pending"]) == 0


def test_check_fails_on_a_malformed_fragment(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"8.fixd.md": "- f\n"})
    assert cf.main(["--root", str(root), "check"]) == 1


def test_one_faulty_line_gets_one_message(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"8.fixed.md": "plain prose\n"})
    with pytest.raises(cf.FragmentError) as caught:
        cf.load(root / "changelog.d")
    assert str(caught.value).count("line 1") == 1, str(caught.value)


def test_relative_links_are_written_from_changelog_d_and_land_from_the_root(tmp_path: Path) -> None:
    body = "- see [a](../docs/A.md), [b](https://example.invalid/x) and [c](#anchor)\n"
    root = _repo(tmp_path, {"6.fixed.md": body})
    cf.assemble(root)
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "[a](docs/A.md), [b](https://example.invalid/x) and [c](#anchor)" in text


@pytest.mark.parametrize("target", ["docs/A.md", "../../A.md", "./A.md"])
def test_a_relative_link_not_written_from_changelog_d_is_refused(
    tmp_path: Path, target: str
) -> None:
    root = _repo(tmp_path, {"6.fixed.md": f"- see [a]({target})\n"})
    with pytest.raises(cf.FragmentError, match="relative link"):
        cf.load(root / "changelog.d")


def test_a_new_heading_keeps_keep_a_changelog_order() -> None:
    changelog = "## [Unreleased]\n\n### Fixed\n- f\n\n## [0.1.0]\n"
    frag = cf.Fragment(Path("1.added.md"), "1", "added", "- a\n")
    out = cf.assemble_text(changelog, [frag])
    assert out == "## [Unreleased]\n\n### Added\n- a\n\n### Fixed\n- f\n\n## [0.1.0]\n"


def test_trailing_spaces_survive_assembly() -> None:
    frag = cf.Fragment(Path("1.added.md"), "1", "added", "- one  \n  two\n")
    out = cf.assemble_text(_CHANGELOG, [frag])
    assert "- one  \n  two\n" in out


def test_a_fragment_already_in_the_changelog_is_refused() -> None:
    """A second run after a partial delete would otherwise duplicate the entry."""
    frag = cf.Fragment(Path("1.fixed.md"), "1", "fixed", "- existing fixed\n")
    with pytest.raises(cf.FragmentError, match="already in"):
        cf.assemble_text(_CHANGELOG, [frag])


def test_a_repeated_bullet_from_a_released_section_is_not_a_duplicate() -> None:
    frag = cf.Fragment(Path("1.added.md"), "1", "added", "- released entry\n")
    assert cf.assemble_text(_CHANGELOG, [frag]).count("- released entry") == 2


def test_a_link_inside_a_code_span_is_left_alone(tmp_path: Path) -> None:
    body = "- `handlers[name](msg)` and `[x](../a)` now work\n"
    root = _repo(tmp_path, {"6.fixed.md": body})
    cf.assemble(root)
    assert body in (root / "CHANGELOG.md").read_text(encoding="utf-8")


def test_a_byte_order_mark_is_accepted(tmp_path: Path) -> None:
    root = _repo(tmp_path, {})
    (root / "changelog.d" / "6.fixed.md").write_bytes(b"\xef\xbb\xbf- fix\n")
    assert [f.body for f in cf.load(root / "changelog.d")] == ["- fix\n"]


def test_dot_files_are_ignored(tmp_path: Path) -> None:
    root = _repo(tmp_path, {".DS_Store": "x", ".2080.fixed.md.swp": "x"})
    assert cf.load(root / "changelog.d") == []


def test_an_untracked_fragment_is_refused_and_nothing_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not on PATH")
    root = _repo(tmp_path, {"1.fixed.md": "- tracked\n"})
    # Scrub GIT_* for this test AND for the script's own git call: a GIT_DIR exported by a hook
    # would otherwise point both at the real repository.
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    for argv in ([git, "init", "-q"], [git, "add", "CHANGELOG.md", "changelog.d"]):
        subprocess.run(argv, cwd=root, check=True)  # nosec B603
    (root / "changelog.d" / "2.fixed.md").write_text("- stray draft\n", encoding="utf-8")
    with pytest.raises(cf.FragmentError, match="not tracked") as caught:
        cf.assemble(root)
    assert "2.fixed.md" in str(caught.value) and "1.fixed.md" not in str(caught.value)
    assert (root / "CHANGELOG.md").read_text(encoding="utf-8") == _CHANGELOG


# --- the pull-request check against the base branch -------------------------------------------------

_RELEASED = _CHANGELOG.replace("## [Unreleased]\n", "## [Unreleased]\n\n## [0.5.0] - 2026-10-01\n")


def _pr_check(
    tmp_path: Path,
    fragments: dict[str, str],
    head: str,
    capsys: pytest.CaptureFixture[str],
    declared: str = "0.5.0",
) -> tuple[int, str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = _repo(tmp_path, fragments, changelog=head)
    (root / "messagefoundry").mkdir()
    (root / "messagefoundry" / "__init__.py").write_text(
        f'__version__ = "{declared}"\n', encoding="utf-8"
    )
    base = tmp_path / "base-CHANGELOG.md"
    base.write_text(_CHANGELOG, encoding="utf-8")
    status = cf.main(["--root", str(root), "pr-check", "--base-changelog", str(base)])
    out = capsys.readouterr()
    return status, out.out, out.err


def test_pr_check_refuses_a_new_version_heading_while_fragments_remain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, _, err = _pr_check(tmp_path, {"9.fixed.md": "- f\n"}, _RELEASED, capsys)
    assert status == 1
    assert "0.5.0" in err and "changelog.d/9.fixed.md" in err


def test_pr_check_refuses_entries_left_under_unreleased_after_the_rename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Running assemble AFTER the rename files the entries above the new version, not in it."""
    late = _RELEASED.replace("## [Unreleased]\n", "## [Unreleased]\n\n### Fixed\n- late entry\n", 1)
    status, _, err = _pr_check(tmp_path, {}, late, capsys)
    assert status == 1
    assert "still holds 1 bullet" in err


def test_pr_check_ignores_a_comment_left_under_unreleased(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    note = _RELEASED.replace("## [Unreleased]\n", "## [Unreleased]\n<!-- via changelog.d/ -->\n", 1)
    status, _, _ = _pr_check(tmp_path, {}, note, capsys)
    assert status == 0


def test_pr_check_refuses_a_release_that_drops_unreleased(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Renaming without adding a fresh heading would break every later fragment pull request."""
    renamed = _CHANGELOG.replace("## [Unreleased]\n", "## [0.5.0] - 2026-10-01\n", 1)
    status, _, err = _pr_check(tmp_path, {}, renamed, capsys)
    assert status == 1
    assert "exactly one" in err


def test_pr_check_allows_a_backfilled_heading_below_the_top(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shipped maintenance release recorded after the fact is not a release of pending work: the
    tree's declared version did not move to it."""
    backfill = _CHANGELOG.replace("## [0.4.0]", "## [0.4.1] - 2026-09-30\n\n- hotfix\n\n## [0.4.0]")
    status, _, _ = _pr_check(tmp_path, {"9.fixed.md": "- f\n"}, backfill, capsys, declared="0.4.0")
    assert status == 0
    # The same heading WITH the version bumped to it is a release, and is refused.
    status, _, _ = _pr_check(
        tmp_path / "bumped", {"9.fixed.md": "- f\n"}, backfill, capsys, declared="0.4.1"
    )
    assert status == 1


def test_pr_check_passes_an_assembled_release_without_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = _pr_check(tmp_path, {}, _RELEASED, capsys)
    assert status == 0
    assert "::warning" not in out


def test_pr_check_warns_but_passes_a_direct_changelog_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    edited = _CHANGELOG.replace("- existing fixed\n", "- existing fixed\n- direct edit\n")
    status, out, _ = _pr_check(tmp_path, {"9.fixed.md": "- f\n"}, edited, capsys)
    assert status == 0
    assert out.startswith("::warning file=CHANGELOG.md::")


def test_pr_check_is_silent_on_an_ordinary_fragment_pull_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = _pr_check(tmp_path, {"9.fixed.md": "- f\n"}, _CHANGELOG, capsys)
    assert status == 0
    assert "::warning" not in out


def test_new_versions_ignores_unreleased_and_known_headings() -> None:
    assert cf.new_versions(_CHANGELOG, _RELEASED) == ["0.5.0"]
    assert cf.new_versions(_RELEASED, _RELEASED) == []


# --- the live tree ----------------------------------------------------------------------------------


def test_the_live_fragments_assemble_into_the_live_changelog_without_moving_a_line() -> None:
    """Today's fragments are well-formed, and folding them into today's CHANGELOG.md keeps every
    existing line, in order. ``load`` raising is the malformed-fragment failure."""
    assert (_REPO / "changelog.d" / "README.md").is_file(), "changelog.d/ lost its README"
    fragments = cf.load(_REPO / "changelog.d")
    with (_REPO / "CHANGELOG.md").open(encoding="utf-8", newline="") as handle:
        before = handle.read()
    after = cf.assemble_text(before, fragments)
    assert _is_subsequence(before.split("\n"), after.split("\n"))
    for fragment in fragments:
        assert "\n".join(cf.rendered(fragment)) in after


def test_ci_checks_every_pull_request_and_release_refuses_leftovers() -> None:
    """The gate must be wired: an assembler nothing calls protects nothing. This module's own
    membership of ci.yml's docs-only lane is pinned in tests/test_doc_guards_lane.py."""
    yaml = pytest.importorskip("yaml")

    def steps(workflow: str, job: str) -> list[dict[str, Any]]:
        data = yaml.safe_load((_REPO / ".github" / "workflows" / workflow).read_text("utf-8"))
        return [s for s in data["jobs"][job]["steps"] if isinstance(s, dict)]

    ci = [
        s for s in steps("ci.yml", "test") if "changelog_fragments.py pr-check" in str(s.get("run"))
    ]
    assert len(ci) == 1, "ci.yml's test job must run the base-branch check exactly once"
    guard = str(ci[0].get("if") or "")
    assert "code" not in guard, "the base-branch check must not be skipped on docs-only PRs"
    for event in ("pull_request", "merge_group"):
        assert event in guard, f"the base-branch check must run on {event}"

    release = steps("release.yml", "release")
    names = [str(s.get("name") or s.get("uses")) for s in release]
    tag_guard = [
        i
        for i, s in enumerate(release)
        if "changelog_fragments.py check --no-pending" in str(s.get("run"))
    ]
    assert len(tag_guard) == 1, "release.yml must refuse a tag while fragments remain"
    build = next(i for i, n in enumerate(names) if n.startswith("Build sdist"))
    assert tag_guard[0] < build, "the fragment guard must run before anything is built"
    assert "refs/tags/" in str(release[tag_guard[0]].get("if")), "the guard binds only a tag push"
