# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The `docs/BACKLOG.md` dependency census (BACKLOG #1250).

TWO ARMS, AND NEITHER ONE ALONE IS A TEST. A detector that matches nothing passes every must-not-fire
assertion; a detector that matches everything passes every must-fire one. Only the pair separates a
working instrument from a broken one, which is the rule this repository already applies to its
required contexts in ``tests/negative_controls.toml``.

THE HEADLINE ASYMMETRY IS PINNED HERE DELIBERATELY. ``.pre-commit-config.yaml`` depends on the ledger
through a REGEX -- ``files: ^docs/(BACKLOG\\.md|archive/backlog/.*\\.md)$`` -- so a literal search for
``docs/BACKLOG.md`` over that file finds one prose comment and MISSES the functional filter. That is
the exact shape of the false zero the item exists to prevent, so the test below asserts BOTH halves:
the literal search misses it and the census does not.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "_backlog_dependency_census",
    _ROOT / "scripts" / "docs" / "backlog_dependency_census.py",
)
assert _SPEC is not None and _SPEC.loader is not None
census_mod = importlib.util.module_from_spec(_SPEC)
# REGISTERED BEFORE EXEC, and it is not optional here. `@dataclass` resolves its annotations through
# ``sys.modules[cls.__module__]``, so a module executed outside sys.modules raises AttributeError on
# the first dataclass rather than importing. The sibling checker tests get away without this only
# because they define NamedTuples.
sys.modules[_SPEC.name] = census_mod
_SPEC.loader.exec_module(census_mod)

#: The ref #1250's blast-radius paragraph was measured at. Immutable history, so pinning it is safe --
#: but a shallow clone may not carry it, hence the skip below rather than a hard failure.
_HISTORIC_REF = "c2241cfe"


@pytest.fixture(scope="module")
def real() -> object:
    """One census of the real tree, shared. It reads every tracked file, so eight fresh runs cost a
    minute of suite time and answer the same question eight times."""
    return census_mod.run_census(_ROOT)


@pytest.fixture(scope="module")
def historic() -> object:
    return census_mod.run_census(_ROOT, _HISTORIC_REF)


def _has_ref(ref: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(_ROOT), "cat-file", "-e", f"{ref}^{{commit}}"],
            capture_output=True,
        ).returncode
        == 0
    )


def _synthetic_repo(root: Path, files: dict[str, str]) -> Path:
    """A tiny git repo whose whole tracked corpus is ``files``.

    Built rather than mocked because the census's corpus IS ``git ls-files``: a fake that skips git
    would test a different program from the one that ships.
    """
    root.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-b", "main", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return root


# --- the must-fire arm, against the real tree -----------------------------------------------------


def test_every_control_fires_on_the_real_tree(real: object) -> None:
    """The census's own specification, asserted where it matters.

    A failure here is NOT automatically a broken detector: it is equally a piece of wiring that was
    legitimately removed. Either way the control table in the script is now wrong and must be edited
    in the SAME pull request, because a control that has quietly stopped applying is the defect this
    project keeps filing rather than a stale comment.
    """
    assert real.control_failures == []


def test_the_four_pieces_of_machinery_the_item_names_are_each_found_once(real: object) -> None:
    """#1250 names the pre-commit gate, the status checker, the hygiene workflow and the allocator.

    A reader comparing this output against the item must find those four words, so the roles are
    mapped by path rather than inferred from a directory -- inference files `ledger_check.py` under a
    generic "tooling" and the correspondence is lost.
    """
    roles = real.by_role
    for role in ("pre-commit-gate", "status-checker", "ci-workflow", "allocator"):
        assert roles.get(role, 0) >= 1, f"{role} vanished from the census"


def test_the_ledger_itself_is_the_subject_not_a_dependent(real: object) -> None:
    """Counting the file among the things that break when it moves inflates every total by two."""
    paths = {ref.path for ref in real.references}
    assert census_mod.LEDGER_PATH not in paths
    assert census_mod.LEDGER_PATH in real.subject


def test_parser_only_dependents_exist_and_name_no_path(real: object) -> None:
    """The class no hand count has ever seen: reads the ledger, spells nothing.

    These fail differently under a move -- a moved FILE leaves them working, and a changed
    ``DEFAULT_SOURCES`` breaks them -- so a migration that treats every dependency as a path edit
    will re-point the wrong set.
    """
    assert real.parser_only, "no parse_items-only dependent found; the detector has gone blind"
    for ref in real.parser_only:
        assert "parse-items" in ref.mechanisms
        assert not census_mod._NAMING_MECHANISMS.intersection(ref.mechanisms)


# --- the headline asymmetry -----------------------------------------------------------------------


def test_a_regex_spelling_is_invisible_to_a_literal_search_but_not_to_the_census(
    tmp_path: Path,
) -> None:
    """BOTH halves, because either alone proves nothing.

    The literal miss is what makes a hand count wrong; the census hit is what fixes it. Asserting
    only the second would pass just as well against a detector that matches every file in the tree.
    """
    hook = "files: ^docs/(BACKLOG\\.md|archive/backlog/.*\\.md)$\n"
    repo = _synthetic_repo(tmp_path / "repo", {".pre-commit-config.yaml": hook, "LICENSE": "x\n"})

    assert "docs/BACKLOG.md" not in hook  # the literal search a hand count runs finds nothing

    result = census_mod.run_census(repo)
    found = {ref.path: ref for ref in result.references}
    assert ".pre-commit-config.yaml" in found
    assert "path-pattern" in found[".pre-commit-config.yaml"].mechanisms
    assert "path-literal" not in found[".pre-commit-config.yaml"].mechanisms


# --- the must-not-fire arm ------------------------------------------------------------------------


def test_a_file_with_no_reference_is_not_reported(tmp_path: Path) -> None:
    repo = _synthetic_repo(
        tmp_path / "repo",
        {
            "LICENSE": "no mention here\n",
            "notes.md": "the backlog and the ledger, named only in prose\n",
        },
    )
    assert census_mod.run_census(repo).references == []


def test_the_closed_archive_filename_is_not_read_as_the_live_ledger(tmp_path: Path) -> None:
    """``BACKLOG-CLOSED.md`` shares a prefix with ``BACKLOG.md`` and is a DIFFERENT file.

    A bare-filename pattern without the hyphen lookbehind reports every archive reference as a live
    one, and the two halves of the namespace then look identical in the output -- which is precisely
    the distinction a move has to get right.
    """
    repo = _synthetic_repo(tmp_path / "repo", {"a.md": "see BACKLOG-CLOSED.md for retired items\n"})
    result = census_mod.run_census(repo)
    assert result.references == []


@pytest.mark.parametrize(
    "prose",
    [
        "pages scale with **BACKLOG**, which differs per arm\n",
        "the *BACKLOG* is long\n",
        "BACKLOG #1250 is the item\n",
    ],
)
def test_bold_markdown_around_the_word_is_not_a_glob(tmp_path: Path, prose: str) -> None:
    """MEASURED, NOT PREDICTED. The first version of the glob arm accepted a bare ``BACKLOG*``, and
    the real tree answered with ``docs/benchmarks/HANDOFF-enginebox-step2-step3.md`` -- prose whose
    closing bold marker read as a wildcard. One false positive in a population of four is a quarter
    of the one class this tool exists to surface, reported as a migration target.

    Found by LISTING the hits, never by reading the count, which is the only way this class is found.
    """
    repo = _synthetic_repo(tmp_path / "repo", {"note.md": prose})
    assert census_mod.run_census(repo).references == []


@pytest.mark.parametrize(
    "spelling",
    [
        "files: ^docs/(BACKLOG\\.md|archive/backlog/.*\\.md)$",
        "glob('BACKLOG*.md')",
        "re.compile(r'BACKLOG.*\\.md')",
    ],
)
def test_the_real_pattern_spellings_still_fire(tmp_path: Path, spelling: str) -> None:
    """The other half of the arm above. Tightening a pattern until it catches nothing is the easy
    way to make a false positive go away, and it is the failure this project keeps filing."""
    repo = _synthetic_repo(tmp_path / "repo", {"conf.yaml": spelling + "\n"})
    result = census_mod.run_census(repo)
    assert [ref.path for ref in result.references] == ["conf.yaml"]
    assert "path-pattern" in result.references[0].mechanisms


def test_a_broken_detector_reds_the_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control arm must be CAPABLE of going red, or it is a green tick over an assumption.

    ``never`` cannot match any text, so the path-literal class collapses to zero. Every count the
    census prints stays syntactically fine; only the control table says the instrument stopped
    working. That is the failure this whole design is aimed at.
    """
    broken = tuple(
        (name, re.compile(r"(?!x)x") if name == "path-literal" else pattern)
        for name, pattern in census_mod._DETECTORS
    )
    monkeypatch.setattr(census_mod, "_DETECTORS", broken)
    result = census_mod.run_census(_ROOT)
    assert result.control_failures, "a dead path-literal detector left the controls green"
    assert any("ledger_check.py" in failure for failure in result.control_failures)


def test_the_negative_arm_reds_when_a_detector_goes_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror of the test above. A pattern matching everything must also be caught.

    Without this, "all controls fired" is satisfied by a detector that reports the entire tree, and
    the census would hand a migration a blast radius of 2085 files with a full set of green ticks.
    """
    generic = tuple(
        (name, re.compile(r"") if name == "path-literal" else pattern)
        for name, pattern in census_mod._DETECTORS
    )
    monkeypatch.setattr(census_mod, "_DETECTORS", generic)
    result = census_mod.run_census(_ROOT)
    assert any("MUST-NOT-FIRE" in failure for failure in result.control_failures)


# --- the corpus -----------------------------------------------------------------------------------


def test_an_undecodable_file_is_recorded_rather_than_silently_skipped(tmp_path: Path) -> None:
    """A filtered scan that drops a file type reads as clean when it never looked."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")
    (repo / "a.md").write_text("docs/BACKLOG.md\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "main", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "seed"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    result = census_mod.run_census(repo)
    assert result.undecodable == ["blob.bin"]
    assert result.scanned == 2


def test_the_census_reads_the_checkout_it_lives_in_not_the_cwd(tmp_path: Path) -> None:
    """BACKLOG #1060's family. ``--root`` defaults to the script's own tree, never to ``getcwd``."""
    assert census_mod._DEFAULT_ROOT == _ROOT


# --- the parse_items half -------------------------------------------------------------------------


def test_the_asvs_heading_count_comes_from_parse_items_not_a_hand_scan(real: object) -> None:
    """CLAUDE.md section 11: ``parse_items`` DEFINES item status and a second scan drifts from it.

    Asserted on the OPEN population, because the item's aggregation argument is about the live map.
    """
    assert real.open_items > 0
    assert 0 < len(real.asvs_open_items) <= real.open_items


def test_a_heading_mention_counts_and_a_body_mention_does_not() -> None:
    ledger = (
        "## 10. an ASVS gap in the store\n"
        "\n"
        "> \U0001f522 **Re-scored.**\n"
        "\n"
        "body\n"
        "\n"
        "## 11. something else entirely\n"
        "\n"
        "> \U0001f522 **Re-scored.**\n"
        "\n"
        "this body mentions ASVS but the heading does not\n"
    )
    numbers, total_open = census_mod.asvs_open_items(ledger)
    assert (numbers, total_open) == ([10], 2)


# --- the historic arm ---------------------------------------------------------------------------


@pytest.mark.skipif(not _has_ref(_HISTORIC_REF), reason="shallow clone: the historic ref is absent")
def test_the_census_reproduces_the_asvs_count_the_item_recorded_at_its_own_ref(
    historic: object,
) -> None:
    """#1250 was filed on "103 open items carry ASVS in the heading". The census returns 103 there.

    This is the strongest control available: an independently written instrument, run against the
    exact commit the item names, landing on the number a human wrote down at the time. It also fixes
    the definition -- OPEN items, heading only -- which the item's prose left to be inferred.
    """
    assert len(historic.asvs_open_items) == 103


@pytest.mark.skipif(not _has_ref(_HISTORIC_REF), reason="shallow clone: the historic ref is absent")
def test_a_control_missing_at_a_historic_ref_means_the_wiring_was_younger_than_the_ref(
    historic: object,
) -> None:
    """Not a defect, and the census must not let a reader take it for one.

    At ``c2241cfe`` the ``backlog-parses`` pre-commit hook (BACKLOG #1259) had not landed, so
    ``.pre-commit-config.yaml`` carried no ledger dependency at all. Every OTHER control fires there,
    which is what tells a reader the detector is fine and the tree was different.
    """
    assert len(historic.control_failures) == 1
    assert ".pre-commit-config.yaml" in historic.control_failures[0]


# --- the wrapper ----------------------------------------------------------------------------------


def test_json_output_carries_the_ref_and_the_control_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A number without its ref is not a measurement, so the machine-readable form carries both."""
    assert census_mod.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["ref"]) == 40
    assert payload["control_failures"] == []
    assert payload["total"] == payload["naming"] + payload["parser_only"]


def test_the_blind_spots_print_on_a_clean_run_too(capsys: pytest.CaptureFixture[str]) -> None:
    """A caveat that only prints on the failure path is absent exactly when a reader concludes the
    picture is complete. The vault and the parked-deficit line are the two that must never be lost."""
    census_mod.main([])
    out = capsys.readouterr().out
    assert "WHAT THIS CENSUS CANNOT SEE" in out
    assert "VAULT" in out
    assert "PARKED DEFICIT ITEMS" in out
