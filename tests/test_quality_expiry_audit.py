# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the expiry-clause auditor.

**These are weighted toward the false-positive classes, because this tool produced all of them
before it produced a usable answer.** In order, on the live corpus: 18 DANGLING (bare-name citations
the resolver could not follow), then 9 (a basename index that matched nothing because the skip-dir
list contained "worktrees" and every root here IS a worktree path), then 16 DRIFTED (every backticked
token checked against every cited file, so a commit sha "missing" from a YAML file counted), then 3
(short, ubiquitous tokens like `.git` treated as anchors).

A noisy auditor is an ignored auditor, so each of those is pinned below.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "expiry_audit.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("expiry_audit", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod() -> ModuleType:
    return _load()


def test_self_test_passes(mod: ModuleType) -> None:
    """The built-in positive control. If it cannot fire, no verdict this tool prints is evidence."""
    assert mod._self_test() == 0


def test_only_paragraphs_with_a_marker_are_clauses(mod: ModuleType) -> None:
    text = (
        "A paragraph citing `pyproject.toml` and nothing else.\n\n*Expiry:* when `setup.cfg` moves."
    )
    clauses = mod.extract_clauses(text, "t.md")
    assert len(clauses) == 1
    assert clauses[0].line == 3


def test_a_missing_path_is_dangling(mod: ModuleType, tmp_path: Path) -> None:
    clause = mod.extract_clauses("*Expiry:* once `nope/gone.py` is deleted.", "t.md")[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict == "DANGLING"


def test_a_bare_name_resolving_once_is_not_dangling(mod: ModuleType, tmp_path: Path) -> None:
    """The first version called every bare-name citation missing. Most of them were real files."""
    (tmp_path / "alloc.ps1").write_text("param()\n", encoding="utf-8")
    index = mod.build_index([tmp_path])
    clause = mod.extract_clauses("*Expiry:* when `alloc.ps1` stops being used.", "t.md")[0]
    mod.judge(clause, [tmp_path], index)
    assert clause.verdict != "DANGLING"


def test_a_bare_name_resolving_twice_is_ambiguous_not_dangling(
    mod: ModuleType, tmp_path: Path
) -> None:
    """Ambiguity is a limit of the reader. Dangling is a defect in the prose. Do not conflate them."""
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "claim.ps1").write_text("param()\n", encoding="utf-8")
    index = mod.build_index([tmp_path])
    clause = mod.extract_clauses("*Expiry:* when `claim.ps1` changes.", "t.md")[0]
    mod.judge(clause, [tmp_path], index)
    assert clause.verdict == "AMBIGUOUS"


def test_a_bare_path_with_no_line_asserts_nothing(mod: ModuleType, tmp_path: Path) -> None:
    """A path alone makes no claim about content, so a token beside it must not produce DRIFTED.

    This is the fix for the 16-DRIFTED run: a clause citing a config file and quoting a commit sha
    was flagged because the sha is not in the config. It was never meant to be.
    """
    (tmp_path / "conf.yaml").write_text("key: value\n", encoding="utf-8")
    clause = mod.extract_clauses(
        "*Expiry:* see `conf.yaml`, fixed by `de896e0f` in `git commit`.", "t.md"
    )[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict == "UNCHECKABLE"


def test_a_line_anchored_token_that_moved_is_drifted(mod: ModuleType, tmp_path: Path) -> None:
    body = ["filler"] * 60 + ["the_distinctive_anchor_text"]
    (tmp_path / "conf.yaml").write_text("\n".join(body), encoding="utf-8")
    clause = mod.extract_clauses(
        "*Expiry:* while `conf.yaml:3` still says `the_distinctive_anchor_text`.", "t.md"
    )[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict == "DRIFTED"
    assert "MOVED" in " ".join(clause.detail)


def test_a_line_anchored_token_still_present_is_anchored(mod: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "conf.yaml").write_text("a\nb\nthe_distinctive_anchor_text\nd\n", encoding="utf-8")
    clause = mod.extract_clauses(
        "*Expiry:* while `conf.yaml:3` still says `the_distinctive_anchor_text`.", "t.md"
    )[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict == "ANCHORED"


def test_a_short_ubiquitous_token_is_not_treated_as_an_anchor(
    mod: ModuleType, tmp_path: Path
) -> None:
    """`.git` appears everywhere, so "found elsewhere in the file" is trivially true for it.

    The token must sit FAR from the cited line, or the test passes with the filter removed and pins
    nothing. That was the first version of this test, and a mutation caught it.
    """
    body = [".git"] * 40 + ["filler"] * 200
    (tmp_path / "conf.yaml").write_text("\n".join(body), encoding="utf-8")
    clause = mod.extract_clauses("*Expiry:* while `conf.yaml:200` mentions `.git`.", "t.md")[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict != "DRIFTED", (
        f"a short, ubiquitous token was treated as a moved anchor; detail was {clause.detail}"
    )


def test_a_cited_line_past_end_of_file_is_drifted(mod: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "conf.yaml").write_text("only\ntwo\n", encoding="utf-8")
    clause = mod.extract_clauses(
        "*Expiry:* see `conf.yaml:900` and `some_distinctive_token`.", "t.md"
    )[0]
    mod.judge(clause, [tmp_path], {})
    assert clause.verdict == "DRIFTED"
    assert "past the end" in " ".join(clause.detail)


def test_an_empty_index_refuses_to_report(
    mod: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An index that matched nothing reports every bare-name citation as DANGLING.

    That happened once, silently, and read as a corpus full of defects rather than a broken reader.
    """
    roles = tmp_path / "roles"
    roles.mkdir()
    (roles / "X.md").write_text("*Expiry:* when `thing.py` moves.", encoding="utf-8")
    rc = mod.main(["--roles", str(roles), "--repo", str(tmp_path)])
    assert rc == 1
    assert "INSTRUMENT ERROR" in capsys.readouterr().err


def test_zero_clauses_found_is_an_error_not_a_pass(
    mod: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A corpus known to carry expiry clauses returning none is a broken scan, not a clean result."""
    roles = tmp_path / "roles"
    roles.mkdir()
    (roles / "X.md").write_text("Nothing here mentions the marker word at all.", encoding="utf-8")
    for i in range(150):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
    rc = mod.main(["--roles", str(roles), "--repo", str(tmp_path)])
    assert rc == 1
    assert "broken scan" in capsys.readouterr().err
