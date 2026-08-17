# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pin the tooling partition against the tree, and against ci.yml.

``tests/tooling_manifest.txt`` decides which tests run on the engine legs and which move to the
path-gated ``tooling`` job. Nothing else does -- there is no filename pattern and no directory. That
makes the manifest load-bearing in a way a list of names usually is not, and it can rot in two
directions with opposite costs:

* A NEW HARNESS TEST NOBODY LISTS runs on every engine leg forever. Costs wall-clock on the critical
  path, which is the whole thing the partition exists to remove. Merely wasteful.
* A LISTED TEST WHOSE SUBJECT IS ENGINE SOURCE stops running on engine PRs. It goes on passing in the
  tooling job -- on a `scripts/**` path gate that an engine PR never trips -- so nothing reports a
  gap. That is a gate resting on a false premise (CLAUDE.md section 11), and it is why the rule for a
  new entry is "when ambiguous, leave it off".

The second is why ``_STAYS_WITHOUT_IMPORTING`` is an explicit list rather than an ``and not
name.startswith(...)`` escape hatch: every file that looks like harness but is not gets named here,
once, with the reason visible in review.

Three regex classifiers were tried before this file existed and each got a different obvious case
wrong. Relocating the tier into ``tests/tooling/`` was tried next and reverted -- the files are
coupled to their location in at least five ways. This test is the residue of both: keep the list
honest, and let the mechanism stay boring.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_TESTS = _ROOT / "tests"
_MANIFEST = _TESTS / "tooling_manifest.txt"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

_ENGINE_IMPORT = re.compile(r"^\s*(from|import)\s+(messagefoundry|harness|tee)\b", re.M)

# Tests that do NOT import the engine and nonetheless belong on the engine legs, because their
# SUBJECT is engine source: they read messagefoundry/** off disk and assert something about it. A
# scanner is still a guard on the thing it scans.
_STAYS_WITHOUT_IMPORTING = frozenset(
    {
        "test_asvs_apply.py",
        "test_asvs_residual_lint.py",
        "test_c901_delta.py",
        "test_cp1252_console_safety.py",
        "test_crypto_inventory_scanner.py",
        "test_dependency_boundaries.py",
        "test_ech_record_premise.py",
        "test_external_link_interstitial.py",
        "test_licence_header_gate.py",
        "test_packaging.py",
        "test_release_pipeline.py",
        "test_sandbox_worker_logging.py",
        "test_scan_forbidden.py",
        "test_scan_tokens_source.py",
        "test_seam_discovery.py",
        "test_security_static.py",
        # this file: it guards the partition, so it must run wherever the partition matters
        "test_tooling_partition.py",
    }
)


def _manifest_names() -> list[str]:
    return [
        line.strip().rsplit("/", 1)[-1]
        for line in _MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_every_manifest_entry_exists() -> None:
    """A stale entry silently un-marks a test back onto the engine legs."""
    missing = sorted(n for n in _manifest_names() if not (_TESTS / n).is_file())
    assert not missing, f"tooling_manifest.txt names files that do not exist: {missing}"


def test_manifest_has_no_duplicates() -> None:
    names = _manifest_names()
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"tooling_manifest.txt lists the same file twice: {dupes}"


def test_no_listed_test_imports_the_engine() -> None:
    """Importing the engine is sufficient proof the subject is the engine, so it cannot be harness."""
    wrong = sorted(
        n
        for n in _manifest_names()
        if _ENGINE_IMPORT.search((_TESTS / n).read_text(encoding="utf-8", errors="replace"))
    )
    assert not wrong, (
        "these are listed as tooling but import the engine, so they would stop running on the "
        f"engine legs that exercise what they test: {wrong}"
    )


def test_every_non_engine_test_is_classified() -> None:
    """The drift guard: a NEW harness test must land in the manifest or be named as staying.

    Without this, a new worktree-gate test quietly joins the engine legs and the tier grows back.
    """
    listed = set(_manifest_names())
    unclassified = sorted(
        p.name
        for p in _TESTS.glob("test_*.py")
        if p.name not in listed
        and p.name not in _STAYS_WITHOUT_IMPORTING
        and not _ENGINE_IMPORT.search(p.read_text(encoding="utf-8", errors="replace"))
    )
    assert not unclassified, (
        "these tests import no engine module, so they are unclassified: add them to "
        "tests/tooling_manifest.txt, or to _STAYS_WITHOUT_IMPORTING here if they read engine "
        f"source: {unclassified}"
    )


def test_stay_list_holds_only_real_files() -> None:
    missing = sorted(n for n in _STAYS_WITHOUT_IMPORTING if not (_TESTS / n).is_file())
    assert not missing, f"_STAYS_WITHOUT_IMPORTING names files that do not exist: {missing}"


def test_marker_is_registered() -> None:
    """An unregistered marker is a warning, not an error -- and `-m tooling` would still select 0."""
    cfg = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    markers = cfg["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("tooling:") for m in markers), (
        "the `tooling` marker must be declared in pyproject markers, or --strict-markers runs and "
        "typo'd selections fail open"
    )


@pytest.mark.parametrize(
    ("needle", "why"),
    [
        (
            "-m 'not tooling'",
            "the engine legs must DESELECT the harness tier -- without it the partition buys nothing",
        ),
        (
            "-m tooling",
            "the tooling job must SELECT it -- without it the tier stops running anywhere",
        ),
    ],
)
def test_ci_wires_both_halves(needle: str, why: str) -> None:
    """Both spellings must appear. Either one alone is a silent half-failure."""
    assert needle in _CI.read_text(encoding="utf-8"), f"{needle!r} missing from ci.yml: {why}"
