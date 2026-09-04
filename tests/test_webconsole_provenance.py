# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 15.2.4 (BACKLOG #1193): the engine verifies WHOSE code occupies the web-console import name.

``serve`` used to gate the in-process console mount on ``find_spec(...) is not None`` -- presence, not
provenance. Whatever occupied ``messagefoundry_webconsole`` on ``sys.path`` was then imported into the
engine process, and a wheel's payload executes AT IMPORT.

**The NEGATIVE controls are the point of this module.** A guard that has only ever been seen to pass is not
evidence -- this item's own defect class is a compensating control resting on a false premise. Every
refusal branch below is driven, and ``test_the_check_fires_before_the_payload_executes`` plants a real
package on ``sys.path`` that writes a marker file at import time, then asserts BOTH that the check
refuses AND that the marker was never written. That second assertion is what makes it a PRE-import
check rather than a post-mortem.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from messagefoundry.__main__ import (
    WEBCONSOLE_DISTRIBUTION,
    WEBCONSOLE_IMPORT_NAME,
    WEBCONSOLE_PROVENANCE_OPT_OUT,
    _editable_source_roots,
    _is_console_source_checkout,
    _measure_webconsole_provenance,
    _normalized_distribution,
    _webconsole_provenance_problem,
)

_ROOT = Path(__file__).resolve().parent.parent


def _plant_console_package(directory: Path, marker: Path) -> None:
    """A directory that OCCUPIES the console import name and proves it if imported.

    The payload writes ``marker`` from module top level, exactly as a squatted wheel's payload would
    run. Nothing here imports it; the assertions read whether the engine's check let it run.
    """
    package = directory / WEBCONSOLE_IMPORT_NAME
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f"import pathlib\npathlib.Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n",
        encoding="utf-8",
    )


# --- the pure classifier: one test per branch, refusals included ----------------------------------


def test_the_engines_own_source_checkout_verifies() -> None:
    """A checkout is the strongest case, not the weakest: no index resolved anything."""
    origin = _ROOT / WEBCONSOLE_IMPORT_NAME / "__init__.py"
    assert (
        _webconsole_provenance_problem(
            origin=origin,
            providers=[WEBCONSOLE_DISTRIBUTION],
            installed_roots=[],
            checkout_roots=[_ROOT],
        )
        is None
    )


def test_a_checkout_verifies_even_with_no_distribution_metadata_at_all() -> None:
    """The console runs from the repo root in this suite with nothing installed; that must pass."""
    assert (
        _webconsole_provenance_problem(
            origin=_ROOT / WEBCONSOLE_IMPORT_NAME / "_html.py",
            providers=[],
            installed_roots=[],
            checkout_roots=[_ROOT],
        )
        is None
    )


def test_the_installed_distributions_own_files_verify(tmp_path: Path) -> None:
    """The ordinary wheel install: the expected distribution claims the name AND owns the file."""
    root = tmp_path / "site-packages" / WEBCONSOLE_IMPORT_NAME
    assert (
        _webconsole_provenance_problem(
            origin=root / "__init__.py",
            providers=["MessageFoundry_WebConsole"],  # PEP 503 spelling variance must not matter
            installed_roots=[root],
            checkout_roots=[],
        )
        is None
    )


def test_a_foreign_distribution_claiming_the_import_name_is_REFUSED(tmp_path: Path) -> None:
    """NEGATIVE CONTROL. Someone else's wheel ships a top-level ``messagefoundry_webconsole``."""
    root = tmp_path / "site-packages" / WEBCONSOLE_IMPORT_NAME
    problem = _webconsole_provenance_problem(
        origin=root / "__init__.py",
        providers=["totally-not-evil"],
        installed_roots=[root],
        checkout_roots=[],
    )
    assert problem is not None
    assert "totally-not-evil" in problem, problem
    assert WEBCONSOLE_DISTRIBUTION in problem, problem


def test_a_second_distribution_alongside_the_real_one_is_REFUSED(tmp_path: Path) -> None:
    """NEGATIVE CONTROL. Ownership must be UNAMBIGUOUS -- the expected name being present is not
    enough when something else claims the same import name beside it."""
    root = tmp_path / "site-packages" / WEBCONSOLE_IMPORT_NAME
    problem = _webconsole_provenance_problem(
        origin=root / "__init__.py",
        providers=[WEBCONSOLE_DISTRIBUTION, "messagefoundry-webconsole-plus"],
        installed_roots=[root],
        checkout_roots=[],
    )
    assert problem is not None
    assert "messagefoundry-webconsole-plus" in problem, problem


def test_a_stray_directory_no_distribution_claims_is_REFUSED(tmp_path: Path) -> None:
    """NEGATIVE CONTROL. The exact hole ``find_spec`` left: a directory on ``sys.path`` that imports
    fine and belongs to nothing. Presence says yes; provenance says no."""
    stray = tmp_path / "somewhere-else" / WEBCONSOLE_IMPORT_NAME / "__init__.py"
    problem = _webconsole_provenance_problem(
        origin=stray,
        providers=[],
        installed_roots=[tmp_path / "site-packages" / WEBCONSOLE_IMPORT_NAME],
        checkout_roots=[tmp_path / "checkout"],
    )
    assert problem is not None
    assert "somewhere-else" in problem, problem
    assert "(none)" in problem, problem


def test_the_real_distribution_SHADOWED_by_an_earlier_path_entry_is_REFUSED(tmp_path: Path) -> None:
    """NEGATIVE CONTROL, and the subtlest one. The expected distribution IS installed, so a check
    that only asked ``packages_distributions()`` would return green -- while the module that actually
    imports comes from an earlier ``sys.path`` entry. Provenance is about the file that will run."""
    installed = tmp_path / "site-packages" / WEBCONSOLE_IMPORT_NAME
    shadow = tmp_path / "cwd" / WEBCONSOLE_IMPORT_NAME / "__init__.py"
    problem = _webconsole_provenance_problem(
        origin=shadow,
        providers=[WEBCONSOLE_DISTRIBUTION],
        installed_roots=[installed],
        checkout_roots=[],
    )
    assert problem is not None
    assert "cwd" in problem, problem


def test_a_namespace_package_with_no_module_file_is_REFUSED() -> None:
    """NEGATIVE CONTROL. ``origin is None`` is a bare directory with no ``__init__.py``."""
    problem = _webconsole_provenance_problem(
        origin=None, providers=[], installed_roots=[], checkout_roots=[]
    )
    assert problem is not None
    assert "namespace package" in problem, problem


# --- the checkout and editable-install recognisers -------------------------------------------------


def test_this_repository_is_recognised_as_a_console_source_checkout() -> None:
    """Liveness. Every checkout arm above is vacuous if this recogniser cannot find the real thing."""
    assert _is_console_source_checkout(_ROOT)


def test_a_directory_missing_either_marker_is_not_a_checkout(tmp_path: Path) -> None:
    """NEGATIVE CONTROL for the checkout arm: both markers are required, so a planted package
    directory alone cannot pass itself off as a checkout of this repository."""
    _plant_console_package(tmp_path, tmp_path / "unused-marker")
    assert not _is_console_source_checkout(tmp_path)  # package present, packaging/ absent

    packaging_only = tmp_path / "packaging-only"
    (packaging_only / "packaging" / WEBCONSOLE_DISTRIBUTION).mkdir(parents=True)
    (packaging_only / "packaging" / WEBCONSOLE_DISTRIBUTION / "pyproject.toml").write_text(
        "", encoding="utf-8"
    )
    assert not _is_console_source_checkout(packaging_only)  # packaging/ present, package absent


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (None, False),
        ("", False),
        ("{not json", False),
        ('{"url": "file:///c/repo/packaging/messagefoundry-webconsole"}', False),  # not editable
        ('{"url": "https://example.invalid/x", "dir_info": {"editable": true}}', False),
        ('{"url": "file:///c/repo/packaging/messagefoundry-webconsole", "dir_info": {}}', False),
        (
            '{"url": "file:///c/repo/packaging/messagefoundry-webconsole",'
            ' "dir_info": {"editable": true}}',
            True,
        ),
    ],
)
def test_only_a_local_editable_direct_url_yields_a_candidate_root(
    payload: str | None, expected: bool
) -> None:
    """Guard-the-guard. A PEP 610 record is a provenance statement the INSTALLER made; anything that
    is not a local editable directory must contribute no candidate at all."""
    assert bool(_editable_source_roots(payload)) is expected


def test_the_editable_root_is_the_checkout_two_levels_above_the_packaging_directory() -> None:
    """The recorded URL points at ``packaging/<dist>/``; the import package is at the repo root."""
    roots = _editable_source_roots(
        json.dumps(
            {
                "url": (_ROOT / "packaging" / WEBCONSOLE_DISTRIBUTION).as_uri(),
                "dir_info": {"editable": True},
            }
        )
    )
    assert roots == [_ROOT]


def test_the_name_normalizer_follows_pep_503() -> None:
    assert _normalized_distribution("MessageFoundry_Web.Console") == "messagefoundry-web-console"
    assert _normalized_distribution("  messagefoundry--webconsole ") == "messagefoundry-webconsole"


# --- end to end, against the live interpreter ------------------------------------------------------


def test_the_live_load_path_verifies_in_this_checkout() -> None:
    """POSITIVE CONTROL for the collector. Without this, every refusal below could be the collector
    being broken rather than the planted package being rejected."""
    assert importlib.util.find_spec(WEBCONSOLE_IMPORT_NAME) is not None, (
        "the console import name does not resolve at all, so this module measures nothing"
    )
    assert _measure_webconsole_provenance() is None


def test_the_check_fires_before_the_payload_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE negative control this item needs, end to end through the real collector.

    Plants a package that occupies the console import name and writes a marker file from its top
    level, puts it FIRST on ``sys.path``, and then asserts two things:

    1. ``_measure_webconsole_provenance`` returns a problem naming the planted location -- the guard
       fires against something the old ``find_spec`` presence test would have waved through; and
    2. the marker file does not exist -- so the refusal happened BEFORE the payload ran, which is the
       entire claim. A check that reported the same problem after the import would be worthless.
    """
    marker = tmp_path / "payload-executed.txt"
    planted = tmp_path / "planted"
    planted.mkdir()
    _plant_console_package(planted, marker)

    loaded = [
        name
        for name in sys.modules
        if name == WEBCONSOLE_IMPORT_NAME or name.startswith(f"{WEBCONSOLE_IMPORT_NAME}.")
    ]
    for name in loaded:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(planted))
    importlib.invalidate_caches()

    problem = _measure_webconsole_provenance()

    assert problem is not None, "the planted package was accepted -- the guard did not fire"
    assert "planted" in problem, problem
    assert not marker.exists(), (
        "the planted payload EXECUTED -- the provenance check ran after the import, not before it"
    )


def test_the_opt_out_is_named_and_uses_the_projects_environment_convention() -> None:
    """The escape hatch has to be visible in the process environment and greppable in shipped text."""
    assert WEBCONSOLE_PROVENANCE_OPT_OUT.startswith("MEFOR_")
    source = (_ROOT / "messagefoundry" / "__main__.py").read_text(encoding="utf-8")
    assert source.count(f'"{WEBCONSOLE_PROVENANCE_OPT_OUT}"') == 1, (
        "the opt-out's spelling must have ONE definition; a second literal is a second definition "
        "free to drift from it"
    )
    assert source.count("WEBCONSOLE_PROVENANCE_OPT_OUT") >= 4, (
        "the opt-out must be defined, consulted, and named in BOTH operator messages -- the refusal "
        "that tells them it exists and the warning that tells them it is in force"
    )
