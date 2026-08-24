# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The banner-sha agreement check must fire on a transposed banner and on nothing else (#1301).

Every test here is one half of a PAIR. The literal rule this check narrows fired 94 times across the
two ledgers with none of them the defect, so a suite of must-fire arms alone would be satisfied by a
check that alarms unconditionally -- which is the check that already existed and was unusable.

The fixture builds a throwaway repo with real commits, because the subject the check reads is a
property of git, not of the Markdown. A fake subject would test the regex and nothing else.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CHECK = _ROOT / "scripts" / "docs" / "banner_sha_check.py"


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_banner_sha_check", _CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=60
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    return r


def _commit(repo: Path, subject: str, name: str) -> str:
    (repo / name).write_text(name, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", subject)
    return _git(repo, "rev-parse", "HEAD").strip()


def _ledger(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "LEDGER.md"
    p.write_text(body, encoding="utf-8")
    return p


CLOSED = "✅"  # the closed-status banner glyph, quoted as a token per CLAUDE.md section 11


def test_a_banner_citing_a_commit_that_names_ANOTHER_item_is_reported(
    repo: Path, tmp_path: Path
) -> None:
    """MUST FIRE. The incident: a retirement banner written onto the wrong item, whose cited commit
    names the item it was meant for."""
    sha = _commit(repo, "fix(x): something (BACKLOG #999) (#42)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `{sha}`.**\n\nprose\n")
    report = _load().scan([led], repo)
    assert len(report.findings) == 1, report
    assert report.findings[0].item == 123
    assert report.findings[0].names == ["999"]


def test_a_banner_citing_its_OWN_item_is_not_reported(repo: Path, tmp_path: Path) -> None:
    """MUST NOT FIRE -- the twin. Differs by one digit in the commit subject."""
    sha = _commit(repo, "fix(x): something (BACKLOG #123) (#42)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `{sha}`.**\n\nprose\n")
    report = _load().scan([led], repo)
    assert report.findings == []
    assert report.agreed == 1


def test_a_subject_naming_NO_item_is_undecidable_and_does_not_fire(
    repo: Path, tmp_path: Path
) -> None:
    """MUST NOT FIRE, and this is the bucket that produced the 94.

    A legitimate closing commit often names a PR and a work package but no BACKLOG item. That is not
    evidence of anything, and alarming on it is what made the literal rule unusable."""
    sha = _commit(repo, "feat(console): step-up UX (WP-L3-16, ASVS 7.5.3) (#319)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `{sha}`.**\n\nprose\n")
    report = _load().scan([led], repo)
    assert report.findings == []
    assert report.undecidable == 1


def test_a_bare_hash_N_is_NOT_read_as_an_item_citation(repo: Path, tmp_path: Path) -> None:
    """MUST NOT FIRE, AND THIS IS THE NARROWING THE ITEM DID NOT HAVE.

    ``#N`` is ambiguous between a pull request and a backlog item; they share one numeric space and a
    squash-merge APPENDS the PR number in exactly that form. Here `#999` is a PR. Reading it as an
    item would manufacture a disagreement out of an ordinary merge."""
    sha = _commit(repo, "fix(x): something (#999)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `{sha}`.**\n\nprose\n")
    report = _load().scan([led], repo)
    assert report.findings == []
    assert report.undecidable == 1


def test_a_sha_NOT_on_a_closing_claim_line_is_a_cross_reference_and_does_not_fire(
    repo: Path, tmp_path: Path
) -> None:
    """MUST NOT FIRE. 53 of the literal rule's 85 hits were this: a banner truthfully citing another
    item's commit as a cross-reference. Flagging those is not noise, it is WRONG."""
    sha = _commit(repo, "fix(x): something (BACKLOG #999) (#42)", "a.txt")
    led = _ledger(
        tmp_path,
        f"## 123. an item\n\n> {CLOSED} **Filed.** The symptom was already handled (#999, `{sha}`).\n\nprose\n",
    )
    report = _load().scan([led], repo)
    assert report.findings == []
    assert report.examined == 0, "a non-closing line must not even be examined"


def test_an_OPEN_item_is_outside_the_check(repo: Path, tmp_path: Path) -> None:
    """MUST NOT FIRE. The incident is a retirement banner; an open item makes no closing claim."""
    sha = _commit(repo, "fix(x): something (BACKLOG #999) (#42)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> \U0001f522 **SHIPPED in `{sha}`.**\n\nprose\n")
    report = _load().scan([led], repo)
    assert report.findings == []


def test_an_unresolvable_sha_is_counted_not_reported(repo: Path, tmp_path: Path) -> None:
    """MUST NOT FIRE. A shallow clone or a dropped branch would otherwise read as corruption, which
    is the false-alarm direction this check exists to avoid."""
    led = _ledger(
        tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `deadbeef1234`.**\n\nprose\n"
    )
    report = _load().scan([led], repo)
    assert report.findings == []
    assert report.unresolved == 1


def test_the_clean_run_still_states_its_coverage(repo: Path, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """The row's own warning, in the direction that reads as a clean corpus: a screen that finds
    nothing is indistinguishable from a clean ledger until it says what it examined."""
    sha = _commit(repo, "fix(x): something (BACKLOG #123) (#42)", "a.txt")
    led = _ledger(tmp_path, f"## 123. an item\n\n> {CLOSED} **SHIPPED in `{sha}`.**\n\nprose\n")
    rc = _load().main([str(led), "--repo", str(repo)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "examined 1 closing-claim sha" in out
    assert "1 name their own item" in out
