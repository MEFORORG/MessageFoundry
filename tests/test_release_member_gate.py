# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The release-time member denylist (BACKLOG #1832), and the wiring that makes it fire.

Three parts, and the RULE is the least interesting of them. ``scripts/release/forbidden_members.py``
can be perfect and change nothing if a publishing job never calls it -- which is exactly what happened
to the sdist leak gate: it worked, and the harness and console wheel jobs simply had no member gate at
all. So the wiring tests derive the set of jobs that publish an artifact from ``release.yml`` itself
and require EVERY one of them to invoke the gate, rather than listing today's three job names and
passing forever after a fourth is added.

The third part is ``ci.yml``'s own positive control, EXECUTED rather than read. That control is what
makes ``packaging-build``'s four clean member gates mean anything, and it shipped deciding on the
gate's exit code alone -- which ``main`` returns for four different reasons, only one of them the gate
firing. Its three arms are run for real at the bottom of this file.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
RELEASE_YML = _REPO / ".github" / "workflows" / "release.yml"
CI_YML = _REPO / ".github" / "workflows" / "ci.yml"
GATE = _REPO / "scripts" / "release" / "forbidden_members.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_REPO / "scripts" / "release"))

from _bash_resolver import explain_returncode, probe_env, require_bash  # noqa: E402
from forbidden_members import (  # noqa: E402
    FORBIDDEN_BASENAMES,
    FORBIDDEN_PATH_COMPONENTS,
    KNOWN_DISTRIBUTIONS,
    RETIRED_ENGINE_PATHS,
    TEST_CONTENT_BASENAMES,
    TEST_CONTENT_PATH_COMPONENTS,
    TEST_TOOLING_DISTRIBUTIONS,
    development_content,
    distribution,
    escapes_root,
    filename_problem,
    forbidden,
    main,
    non_canonical,
    split_violation,
)

from tests._workflow_contexts import needs_of  # noqa: E402

#: hatchling names every sdist member ``<project>-<version>/...``. The fixtures carry it because the
#: denylist's whole claim is that a prefix cannot launder a basename, and a fixture with no prefix
#: would not test that claim.
_SDIST_PREFIX = "messagefoundry-0.3.0"

_CLEAN_SDIST = (
    "messagefoundry/__init__.py",
    "messagefoundry/py.typed",
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
)

_CLEAN_WHEEL = (
    "messagefoundry/__init__.py",
    "messagefoundry/py.typed",
    "messagefoundry-0.3.0.dist-info/METADATA",
    "messagefoundry-0.3.0.dist-info/RECORD",
)


def _write_sdist(path: Path, members: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for member in members:
            payload = b"fixture\n"
            info = tarfile.TarInfo(f"{_SDIST_PREFIX}/{member}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return path


def _write_wheel(path: Path, members: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for member in members:
            zf.writestr(member, "fixture\n")
    return path


# --------------------------------------------------------------------------------------------------
# The rule itself.
# --------------------------------------------------------------------------------------------------


def test_the_reported_leak_is_the_positive_control() -> None:
    """``messagefoundry/CLAUDE.md`` is what shipped on 0.1.0..0.2.15. If this passes, nothing below
    proves anything -- so it is asserted on its own, first, as the control for the whole module."""
    why = forbidden(f"{_SDIST_PREFIX}/messagefoundry/CLAUDE.md")
    assert why is not None, (
        "the exact member that shipped to PyPI on every release 0.1.0..0.2.15 is not forbidden"
    )
    assert "CLAUDE.md" in why


def test_a_clean_member_set_is_not_forbidden() -> None:
    """The negative control. A denylist that matched everything would pass every rejection test."""
    for member in (*_CLEAN_SDIST, *_CLEAN_WHEEL):
        assert forbidden(f"{_SDIST_PREFIX}/{member}") is None, member
        assert forbidden(member) is None, member


@pytest.mark.parametrize(
    "member",
    [
        # The location the allowlist trusted, which is the whole point of #1832.
        f"{_SDIST_PREFIX}/messagefoundry/CLAUDE.md",
        # The harness tree, force-included and unfilterable by hatchling's `exclude` (the #1702 case).
        "harness/CLAUDE.md",
        # Depth is irrelevant to a basename rule -- that is what makes it prefix-launder-proof.
        "messagefoundry/auth/data/CLAUDE.md",
        f"{_SDIST_PREFIX}/docs/{_SDIST_PREFIX}/CLAUDE.md",
        # Case folding: one file to the filesystem that committed it.
        "messagefoundry/claude.md",
        "messagefoundry/Claude.MD",
        # The next file of the same class, which is why this is a class rule and not one name.
        "messagefoundry/CLAUDE.local.md",
        "messagefoundry/AGENTS.md",
        "messagefoundry/GEMINI.md",
        "messagefoundry/.cursorrules",
        # Forbidden path components, at any depth, including a bare directory entry.
        "messagefoundry/.claude/settings.json",
        ".github/workflows/release.yml",
        f"{_SDIST_PREFIX}/.claude/",
        "a/b/.CLAUDE/c.json",
    ],
)
def test_forbidden_members_are_refused(member: str) -> None:
    assert forbidden(member) is not None, f"{member} passed the denylist"


@pytest.mark.parametrize(
    "member",
    [
        # Named LIKE a forbidden file but not one. A rule that fired here would red real releases.
        "messagefoundry_toolkit/generators/README.md",
        "messagefoundry/CLAUDE.md.txt",
        "messagefoundry/NOT-CLAUDE.md",
        "messagefoundry/claudemd",
        "messagefoundry/agents.py",
        "messagefoundry/claude/handler.py",
        # A forbidden component name as a FILE's basename in the middle of nothing -- `.github` as a
        # leaf file is still refused (the directory-entry arm), but `github` is not.
        "messagefoundry/github/client.py",
    ],
)
def test_lookalike_members_are_allowed(member: str) -> None:
    assert forbidden(member) is None, f"{member} was refused, which would red a real release"


def test_the_denylist_is_stored_casefolded() -> None:
    """The matcher casefolds the member, so a non-casefolded entry could never match anything.

    This is the silent-disarm shape: a contributor adds ``"AGENTS.md"``, every test that does not
    exercise that specific name stays green, and the entry is dead.

    Asserted against ``casefold()`` and not ``lower()`` (BACKLOG #1838). The two differ, the test
    was named for casefold while asserting lower, and the matcher used lower -- so the name was the
    only thing telling the truth.
    """
    for name in (*FORBIDDEN_BASENAMES, *FORBIDDEN_PATH_COMPONENTS):
        assert name == name.casefold(), f"{name!r} is not casefolded and can never match"


@pytest.mark.parametrize(
    "member",
    [
        # BACKSLASH SEPARATOR. `tarfile.getnames()` and `zipfile.namelist()` return STORED names
        # verbatim, so a writer that stored a backslash hands one back and a `/`-only split saw a
        # single component. Measured: all three passed before the fix.
        "pkg\\CLAUDE.md",
        ".claude\\settings.json",
        "C:\\repo\\CLAUDE.md",
        "a/b\\CLAUDE.md",
        # TRAILING DOT OR SPACE. Windows strips both on open, so each installs as the real file.
        "messagefoundry/CLAUDE.md ",
        "messagefoundry/CLAUDE.md.",
        ".claude./settings.json",
        ".claude /settings.json",
        # CASEFOLD, NOT lower(). U+017F casefolds to "s"; lower() leaves it alone.
        "messagefoundry/agent\u017f.md",
    ],
)
def test_normalisation_evasions_are_refused(member: str) -> None:
    """Each of these passed the first version of the rule (BACKLOG #1838)."""
    assert forbidden(member) is not None, f"{member!r} evaded the denylist"


@pytest.mark.parametrize(
    "member",
    [
        # The fix strips trailing dots and spaces, and must not eat a LEADING or INTERIOR one.
        "messagefoundry/.claudecfg/x.py",
        "messagefoundry/my.claude.py",
        "messagefoundry/claude.md.bak",
        # A backslash that is part of a legitimate name, not a separator, still must not match.
        "messagefoundry/not-claude.md",
    ],
)
def test_normalisation_does_not_overreach(member: str) -> None:
    """The control for the fix above. Stripping too much would red a real release."""
    assert forbidden(member) is None, f"{member!r} was refused and should not be"


# --------------------------------------------------------------------------------------------------
# The second rule: test and development content (BACKLOG #1938).
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "member",
    [
        # A tests/ tree at any depth, including a bare directory entry and inside an sdist prefix.
        "messagefoundry_webconsole/tests/test_ui.py",
        "messagefoundry/tests/",
        f"{_SDIST_PREFIX}/tests/conftest.py",
        "messagefoundry/pipeline/test/helper.py",
        "messagefoundry/fixtures/adt_a01.hl7",
        "messagefoundry/samples/config/IB_DEMO.py",
        # Module shapes, wherever they sit.
        "messagefoundry/conftest.py",
        "messagefoundry/api/test_app.py",
        "messagefoundry/api/app_test.py",
        # The same normalisation evasions the first rule closes.
        "messagefoundry\\Tests\\x.py",
        "messagefoundry/tests./x.py",
        "messagefoundry/CONFTEST.PY",
        "messagefoundry/conftest.py ",
    ],
)
def test_development_content_is_refused(member: str) -> None:
    assert development_content(member) is not None, f"{member!r} passed the test-content rule"


@pytest.mark.parametrize(
    "member",
    [
        # Every member of a clean engine wheel must pass, or the rule reds a real release.
        *_CLEAN_WHEEL,
        # Named LIKE test content but not test content.
        "messagefoundry/pipeline/dryrun.py",
        "messagefoundry/verify/smoke.py",
        "messagefoundry/attest.py",
        "messagefoundry/latest.py",
        "messagefoundry/contest.py",
        "messagefoundry/testament.py",
        "messagefoundry/test_data.json",
        "messagefoundry_toolkit/generators/README.md",
        "messagefoundry_webconsole/static/csp-probe.js",
        "messagefoundry/testing_notes/x.py",
    ],
)
def test_lookalike_members_pass_the_test_content_rule(member: str) -> None:
    assert development_content(member) is None, f"{member!r} was refused as test content"


def test_the_test_content_lists_are_stored_casefolded() -> None:
    """The same silent-disarm shape as the first rule: a non-casefolded entry never matches."""
    for name in (*TEST_CONTENT_BASENAMES, *TEST_CONTENT_PATH_COMPONENTS):
        assert name == name.casefold(), f"{name!r} is not casefolded and can never match"
    for dist in TEST_TOOLING_DISTRIBUTIONS:
        assert dist == distribution(Path(f"{dist.replace('-', '_')}-1.0-py3-none-any.whl")), (
            f"{dist!r} is not stored in the form distribution() returns, so it exempts nothing"
        )


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("messagefoundry_harness-0.4.0-py3-none-any.whl", "messagefoundry-harness"),
        ("messagefoundry_harness-0.4.0.tar.gz", "messagefoundry-harness"),
        ("messagefoundry_webconsole-0.3.0-py3-none-any.whl", "messagefoundry-webconsole"),
        ("messagefoundry-0.4.0-py3-none-any.whl", "messagefoundry"),
        ("messagefoundry-0.4.0.tar.gz", "messagefoundry"),
        ("Messagefoundry.Harness-0.4.0.tgz", "messagefoundry-harness"),
        # No version part: the whole stem is the name, so the ci.yml fixture is NOT the harness.
        ("poisoned.whl", "poisoned"),
    ],
)
def test_distribution_reads_the_name_from_the_filename(filename: str, expected: str) -> None:
    assert distribution(Path(filename)) == expected


def test_the_only_exemption_is_the_harness() -> None:
    """The exemption is a named decision. Widening it to the engine or console reopens #1938."""
    assert frozenset({"messagefoundry-harness"}) == TEST_TOOLING_DISTRIBUTIONS


def test_the_cli_refuses_a_console_wheel_carrying_tests(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE POSITIVE CONTROL FOR #1938: a synthetic console wheel with a tests/ member is refused."""
    wheel = _write_wheel(
        tmp_path / "webconsole-dist" / "messagefoundry_webconsole-0.3.0-py3-none-any.whl",
        (
            "messagefoundry_webconsole/__init__.py",
            "messagefoundry_webconsole/tests/test_planted.py",
        ),
    )
    assert main([str(wheel)]) == 1
    err = capsys.readouterr().err
    assert "ships messagefoundry_webconsole/tests/test_planted.py" in err
    assert "test or development content" in err


def test_the_cli_refuses_an_engine_wheel_and_sdist_carrying_a_conftest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_sdist(
        tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz", (*_CLEAN_SDIST, "conftest.py")
    )
    wheel = _write_wheel(
        tmp_path / "dist" / "messagefoundry-0.3.0-py3-none-any.whl",
        (*_CLEAN_WHEEL, "messagefoundry/api/test_app.py"),
    )
    assert main([str(sdist), str(wheel)]) == 1
    err = capsys.readouterr().err
    assert "conftest.py" in err
    assert "messagefoundry/api/test_app.py" in err


def test_the_harness_wheel_is_exempt_from_the_test_content_rule_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exemption, and its limit. Both halves use the harness's real filename shape."""
    harness = tmp_path / "harness-dist" / "messagefoundry_harness-0.3.0-py3-none-any.whl"
    _write_wheel(harness, ("harness/__init__.py", "harness/tests/test_load.py"))
    assert main([str(harness)]) == 0
    assert "test tooling by design" in capsys.readouterr().out

    # The maintainer-internal rule still applies in full to the exempt distribution.
    _write_wheel(
        harness, ("harness/__init__.py", "harness/tests/test_load.py", "harness/AGENTS.md")
    )
    assert main([str(harness)]) == 1
    err = capsys.readouterr().err
    assert "harness/AGENTS.md" in err
    assert "test_load.py" not in err


# --------------------------------------------------------------------------------------------------
# The CLI: it must fail loudly on every way of inspecting nothing.
# --------------------------------------------------------------------------------------------------


def test_the_cli_passes_clean_archives_and_prints_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_sdist(tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz", _CLEAN_SDIST)
    wheel = _write_wheel(tmp_path / "dist" / "messagefoundry-0.3.0-py3-none-any.whl", _CLEAN_WHEEL)
    assert main([str(sdist), str(wheel)]) == 0
    out = capsys.readouterr().out
    # A green line that does not say what was examined hides a gate that examined nothing.
    assert str(len(_CLEAN_SDIST)) in out
    assert str(len(_CLEAN_SDIST) + len(_CLEAN_WHEEL)) in out


def test_the_cli_fails_on_a_leaky_sdist(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sdist = _write_sdist(
        tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz",
        (*_CLEAN_SDIST, "messagefoundry/CLAUDE.md"),
    )
    assert main([str(sdist)]) == 1
    assert "CLAUDE.md" in capsys.readouterr().err


def test_the_cli_fails_on_a_leaky_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The harness wheel case. hatchling's ``exclude`` cannot filter a force-included tree, so this
    is the artifact with no build-time defence and therefore the one that most needs this gate."""
    wheel = _write_wheel(
        tmp_path / "harness-dist" / "messagefoundry_harness-0.3.0-py3-none-any.whl",
        ("harness/__init__.py", "harness/CLAUDE.md"),
    )
    assert main([str(wheel)]) == 1
    assert "harness/CLAUDE.md" in capsys.readouterr().err


def test_the_cli_fails_when_a_pattern_matches_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A misspelled or empty dist directory must not report a clean result.

    This is the gate's own version of the defect it exists to catch: zero archives inspected yields
    zero forbidden members, and without this arm that prints green.
    """
    assert main([str(tmp_path / "harness-dist" / "*.whl")]) == 1
    assert "no file matching" in capsys.readouterr().err


def test_the_cli_fails_on_a_zero_member_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _write_wheel(tmp_path / "dist" / "empty-0.3.0-py3-none-any.whl", ())
    assert main([str(wheel)]) == 1
    assert "ZERO members" in capsys.readouterr().err


def test_the_cli_fails_on_an_unreadable_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A truncated archive must fail rather than yield a short listing that reads as clean."""
    good = _write_sdist(tmp_path / "dist" / "good.tar.gz", _CLEAN_SDIST)
    bad = tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz"
    bad.write_bytes(good.read_bytes()[:40])
    good.unlink()
    assert main([str(bad)]) == 1
    assert "could not list" in capsys.readouterr().err


def test_the_cli_refuses_an_archive_shape_it_cannot_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An extension this gate does not understand must fail, not be skipped.

    Skipping is how a new artifact format (a ``.zst`` sdist, a conda package) would slip past a gate
    that still printed a clean line for the files it did recognise.
    """
    odd = tmp_path / "dist" / "messagefoundry-0.3.0.tar.zst"
    odd.parent.mkdir(parents=True, exist_ok=True)
    odd.write_bytes(b"not an archive this gate reads")
    assert main([str(odd)]) == 1
    assert "published uninspected" in capsys.readouterr().err


def test_the_cli_reports_every_archive_not_just_the_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two leaks must both be named. Bailing on the first hides the second from the release log."""
    _write_sdist(tmp_path / "d" / "a.tar.gz", (*_CLEAN_SDIST, "messagefoundry/CLAUDE.md"))
    _write_wheel(tmp_path / "d" / "b-py3-none-any.whl", ("harness/AGENTS.md",))
    assert main([str(tmp_path / "d" / "*")]) == 1
    err = capsys.readouterr().err
    assert "CLAUDE.md" in err
    assert "AGENTS.md" in err


# --------------------------------------------------------------------------------------------------
# The third rule: the engine and toolkit split (ADR 0201 AC-6, BACKLOG #1192). Planted archives in
# both the wheel and the sdist form, because the sdist's `<project>-<version>/` root is exactly what a
# prefix match would miss.
# --------------------------------------------------------------------------------------------------

_ENGINE_WHEEL = "messagefoundry-0.4.0-py3-none-any.whl"
_ENGINE_SDIST = "messagefoundry-0.4.0.tar.gz"
_TOOLKIT_WHEEL = "messagefoundry_toolkit-0.4.0-py3-none-any.whl"


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry/adr_analyze.py",  # the slice 2 retired path, wheel form
        "messagefoundry-0.4.0/messagefoundry/adr_analyze.py",  # sdist form
        "messagefoundry/ADR_Analyze.py",  # casefolded like every other rule
        "messagefoundry\\adr_analyze.py",  # a backslash separator
        # The slice 4 retired paths, wheel form and sdist form.
        "messagefoundry/scaffold.py",
        "messagefoundry/lens.py",
        "messagefoundry/lens_schema.py",
        "messagefoundry/corepoint_import.py",
        "messagefoundry-0.4.0/messagefoundry/scaffold.py",
        "messagefoundry-0.4.0/messagefoundry/lens.py",
        "messagefoundry-0.4.0/messagefoundry/lens_schema.py",
        "messagefoundry-0.4.0/messagefoundry/corepoint_import.py",
        # The slice 6 retired directory: every member under it, wheel form and sdist form.
        "messagefoundry/anon/__init__.py",
        "messagefoundry/anon/leak.py",
        "messagefoundry-0.4.0/messagefoundry/anon/keying.py",
        "messagefoundry/anon.py",  # a one-file module restoring the import name
        "messagefoundry-0.4.0/messagefoundry/anon.py",
        # The last component matches by stem: a sourceless .pyc or an extension module restores
        # the retired import name as well as a .py does.
        "messagefoundry/anon.pyc",
        "messagefoundry/anon.cp314-win_amd64.pyd",
        "messagefoundry/adr_analyze.pyc",
        # The slice 7 retired paths: every member under generators/, and the two schema emitters,
        # wheel form and sdist form.
        "messagefoundry/generators/__init__.py",
        "messagefoundry/generators/_hl7data.py",
        "messagefoundry/generators/README.md",
        "messagefoundry-0.4.0/messagefoundry/generators/adt.py",
        "messagefoundry/generators.py",  # a one-file module restoring the import name
        "messagefoundry/hl7schema.py",
        "messagefoundry/hl7structures.py",
        "messagefoundry-0.4.0/messagefoundry/hl7schema.py",
        "messagefoundry-0.4.0/messagefoundry/hl7structures.py",
        "messagefoundry/hl7structures.cpython-314.pyc",
        "messagefoundry_toolkit/__init__.py",  # the toolkit package inside the engine
        "messagefoundry-0.4.0/messagefoundry_toolkit/__main__.py",
        "messagefoundry_toolkit.py",  # the import name as a top-level module
        "messagefoundry-0.4.0.data/purelib/messagefoundry_toolkit.pth",
    ],
)
def test_an_engine_archive_carrying_toolkit_code_is_refused(member: str) -> None:
    assert split_violation(member, "messagefoundry") is not None


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry/__main__.py",
        "messagefoundry/cli_common.py",
        "messagefoundry-0.4.0/messagefoundry/config/impact.py",  # stays in the engine (ADR 0201)
        "messagefoundry/tools/adr_analyze.py",  # not the retired run: a different parent
        "adr_analyze.py",  # a run of one is not the two-component retired path
        "messagefoundry/redaction.py",  # the engine's own redactor, not the moved anon/ package
        "messagefoundry/anonymize.py",  # a near name is not the retired directory
        "messagefoundry/parsing/validate.py",  # the strict validator the schema emitters read
        "messagefoundry/hl7schemas.py",  # a near name is not the retired module
        "messagefoundry/verify/generators/x.py",  # the retired leaf under a different parent
    ],
)
def test_an_engine_archive_member_that_stays_is_allowed(member: str) -> None:
    assert split_violation(member, "messagefoundry") is None


def test_a_toolkit_archive_writing_into_the_engine_package_is_refused() -> None:
    assert split_violation("messagefoundry/adr_analyze.py", "messagefoundry-toolkit") is not None
    # PEP 427 installs every .data scheme outside the package: purelib and platlib into
    # site-packages, scripts over the engine's own console script, data under sys.prefix.
    for tail in (
        "purelib/messagefoundry/x.py",
        "platlib/messagefoundry/x.py",
        "scripts/messagefoundry",
        "data/lib/python3.14/site-packages/messagefoundry/x.py",
    ):
        member = f"messagefoundry_toolkit-0.4.0.data/{tail}"
        assert split_violation(member, "messagefoundry-toolkit") is not None, member
    assert (
        split_violation("messagefoundry_toolkit/adr_analyze.py", "messagefoundry-toolkit") is None
    )
    # The rule is keyed on the distribution: the same member in the engine is the engine's own.
    assert split_violation("messagefoundry/__init__.py", "messagefoundry") is None
    # And a distribution the rule does not name is untouched by it.
    assert split_violation("messagefoundry_toolkit/x.py", "messagefoundry-harness") is None


def test_the_retired_paths_are_stored_casefolded() -> None:
    """The same silent-disarm shape as the other rules: a non-casefolded entry never matches."""
    assert RETIRED_ENGINE_PATHS, "the retired-path list is empty, so the rule retires nothing"
    for run in RETIRED_ENGINE_PATHS:
        assert all(part == part.casefold() for part in run), run
    assert distribution(Path(_TOOLKIT_WHEEL)) == "messagefoundry-toolkit"


def test_the_cli_refuses_engine_archives_carrying_a_retired_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_sdist(
        tmp_path / "dist" / _ENGINE_SDIST, (*_CLEAN_SDIST, "messagefoundry/adr_analyze.py")
    )
    wheel = _write_wheel(
        tmp_path / "dist" / _ENGINE_WHEEL, (*_CLEAN_WHEEL, "messagefoundry_toolkit/__init__.py")
    )
    assert main([str(sdist), str(wheel)]) == 1
    err = capsys.readouterr().err
    assert "ships messagefoundry-0.3.0/messagefoundry/adr_analyze.py" in err
    assert "ships messagefoundry_toolkit/__init__.py" in err


def test_the_cli_refuses_a_toolkit_wheel_writing_into_the_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _write_wheel(
        tmp_path / "toolkit-dist" / _TOOLKIT_WHEEL,
        ("messagefoundry_toolkit/__init__.py", "messagefoundry/generators/__init__.py"),
    )
    assert main([str(wheel)]) == 1
    assert "ships messagefoundry/generators/__init__.py" in capsys.readouterr().err


def test_the_cli_passes_a_clean_toolkit_wheel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the two refusals above: the toolkit's own members pass every rule."""
    wheel = _write_wheel(
        tmp_path / "toolkit-dist" / _TOOLKIT_WHEEL,
        (
            "messagefoundry_toolkit/__init__.py",
            "messagefoundry_toolkit/__main__.py",
            "messagefoundry_toolkit/adr_analyze.py",
            "messagefoundry_toolkit-0.4.0.dist-info/METADATA",
        ),
    )
    assert main([str(wheel)]) == 0
    assert "inspected 4 members" in capsys.readouterr().out


@pytest.mark.parametrize(
    "filename",
    [
        "messagefoundry-toolkit-0.4.0.tar.gz",  # a hyphenated sdist name read as the engine
        "messagefoundry-toolkit-0.4.0-py3-none-any.whl",
        "messagefoundry_toolkit-0.4.0.tar.gz",
        "Messagefoundry.Toolkit-0.4.0rc1.tgz",
    ],
)
def test_distribution_reads_a_hyphenated_toolkit_filename_as_the_toolkit(filename: str) -> None:
    # BACKLOG #5470: splitting at the first hyphen named the engine, so the toolkit rule never ran.
    assert distribution(Path(filename)) == "messagefoundry-toolkit"


@pytest.mark.parametrize(
    "member",
    [
        # BACKLOG #5470: an sdist name-version root in front of the engine package.
        "messagefoundry_toolkit-0.4.0/messagefoundry/__init__.py",
        "messagefoundry-toolkit-0.4.0/messagefoundry/generators/adt.py",
        "messagefoundry-0.4.0/messagefoundry/x.py",
        # A leading or embedded dot segment.
        "./messagefoundry/__init__.py",
        "././messagefoundry/x.py",
        "messagefoundry_toolkit-0.4.0/./messagefoundry/x.py",
        # A parent segment an extractor resolves back to the engine package.
        "messagefoundry_toolkit/../messagefoundry/x.py",
        "messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/../messagefoundry/x.py",
        # An engine name-version directory, and a .data tree.
        "messagefoundry_toolkit-0.4.0.data/purelib/x.py",
        "./messagefoundry_toolkit-0.4.0.data/scripts/messagefoundry",
    ],
)
def test_a_prefixed_or_dotted_engine_member_in_a_toolkit_archive_is_refused(member: str) -> None:
    # The member's first written component as the root. That is the root inspect() derives for the
    # name-version cases; for a member with a ``..`` it derives the resolved first component, and
    # those cases are refused by the raw or resolved reading whatever the root is.
    first = [p for p in member.split("/") if p not in ("", ".")][0]
    assert split_violation(member, "messagefoundry-toolkit", first) is not None


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/__init__.py",
        "messagefoundry_toolkit-0.4.0/PKG-INFO",
        "./messagefoundry_toolkit/adr_analyze.py",
        "messagefoundry_toolkit-0.4.0.dist-info/METADATA",
        "messagefoundry_toolkit-0.4.0.dist-info/licenses/LICENSE",
        "messagefoundry_toolkit/templates/messagefoundry.toml",  # a near name, deeper
    ],
)
def test_the_toolkit_s_own_prefixed_members_still_pass(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit") is None
    # And with the sdist root inspect() derives, so a stripped reading is exercised too.
    assert split_violation(member, "messagefoundry-toolkit", "messagefoundry_toolkit-0.4.0") is None


def test_a_dot_segment_does_not_hide_a_retired_engine_path() -> None:
    assert split_violation("messagefoundry/./anon/__init__.py", "messagefoundry") is not None
    assert split_violation("messagefoundry/x/../hl7schema.py", "messagefoundry") is not None


def _write_tar(path: Path, entries: Sequence[tarfile.TarInfo]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for info in entries:
            payload = b"fixture\n" if info.isfile() else b""
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload) if payload else None)
    return path


def _link(name: str, target: str, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


@pytest.mark.parametrize(
    ("kind", "target"),
    [
        (tarfile.SYMTYPE, "../messagefoundry/__init__.py"),
        (tarfile.SYMTYPE, "real.py"),  # a link inside the toolkit's own tree is refused too
        (tarfile.SYMTYPE, ".."),  # the head of a chained-link escape
        (tarfile.SYMTYPE, "/usr/lib/python3.14/site-packages/messagefoundry/__init__.py"),
        (tarfile.LNKTYPE, "messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/real.py"),
        (tarfile.FIFOTYPE, ""),
    ],
)
def test_the_cli_refuses_every_tar_link_or_special_member(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: bytes, target: str
) -> None:
    # BACKLOG #5470: getnames() never read a link's target, and a target read as text cannot follow
    # a chain of links, so a published archive carrying any link is refused.
    sdist = _write_tar(
        tmp_path / "dist" / "messagefoundry_toolkit-0.4.0.tar.gz",
        [
            tarfile.TarInfo("messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/real.py"),
            _link("messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/h.py", target, kind),
        ],
    )
    assert main([str(sdist)]) == 1
    captured = capsys.readouterr()
    assert (
        "ships messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/h.py -- a link" in captured.err
    )
    assert "inspected 2 members" in captured.out


def test_the_cli_passes_a_tar_of_regular_files_and_directories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the refusal above: the same archive with no link passes."""
    folder = tarfile.TarInfo("messagefoundry_toolkit-0.4.0/messagefoundry_toolkit")
    folder.type = tarfile.DIRTYPE
    sdist = _write_tar(
        tmp_path / "dist" / "messagefoundry_toolkit-0.4.0.tar.gz",
        [folder, tarfile.TarInfo("messagefoundry_toolkit-0.4.0/messagefoundry_toolkit/real.py")],
    )
    assert main([str(sdist)]) == 0
    assert "inspected 2 members" in capsys.readouterr().out


def _toolkit_zip(path: Path, link_mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("messagefoundry_toolkit/__init__.py", "")
        entry = zipfile.ZipInfo("messagefoundry_toolkit/h.py")
        entry.external_attr = link_mode << 16
        zf.writestr(entry, "../messagefoundry/__init__.py")
    return path


def test_the_cli_refuses_a_zip_symlink_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _toolkit_zip(tmp_path / "toolkit-dist" / _TOOLKIT_WHEEL, 0o120777)
    assert main([str(wheel)]) == 1
    assert "ships messagefoundry_toolkit/h.py -- a link" in capsys.readouterr().err


def test_the_cli_passes_the_same_zip_entry_as_a_regular_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control: only the link mode bit differs from the refusal above."""
    wheel = _toolkit_zip(tmp_path / "toolkit-dist" / _TOOLKIT_WHEEL, 0o100644)
    assert main([str(wheel)]) == 0
    assert "inspected 2 members" in capsys.readouterr().out


@pytest.mark.parametrize(
    "root",
    ["messagefoundry_toolkit-main", "messagefoundry_toolkit-v0.4.0", "messagefoundry_toolkit"],
)
def test_the_cli_strips_whatever_single_root_a_toolkit_tar_has(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], root: str
) -> None:
    sdist = _write_tar(
        tmp_path / "dist" / "messagefoundry_toolkit-0.4.0.tar.gz",
        [tarfile.TarInfo(f"{root}/PKG-INFO"), tarfile.TarInfo(f"{root}/messagefoundry/x.py")],
    )
    assert main([str(sdist)]) == 1
    assert f"ships {root}/messagefoundry/x.py" in capsys.readouterr().err


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry.py",
        "messagefoundry.pth",
        "messagefoundry.cpython-314-x86_64-linux-gnu.so",
        "messagefoundry-0.4.0.dist-info/METADATA",
    ],
)
def test_a_toolkit_archive_may_not_carry_an_engine_named_module_or_dist_info(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit") is not None


def test_a_hyphenated_harness_filename_is_not_exempt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exemption is keyed on the name as the build writes it, so a rename only tightens."""
    wheel = _write_wheel(
        tmp_path / "harness-dist" / "messagefoundry-harness-0.4.0-py3-none-any.whl",
        ("harness/__init__.py", "harness/tests/test_x.py"),
    )
    assert main([str(wheel)]) == 1
    assert "test or development content" in capsys.readouterr().err


@pytest.mark.parametrize(
    "member",
    ["/messagefoundry_toolkit/x.py", "../x.py", "messagefoundry_toolkit/../../x.py", "C:/x.py"],
)
def test_a_member_outside_the_archive_is_refused(member: str) -> None:
    assert escapes_root(member) is not None


@pytest.mark.parametrize(
    "member",
    ["messagefoundry_toolkit/../messagefoundry_toolkit/x.py", "a/./b.py", "messagefoundry/x.py"],
)
def test_a_member_inside_the_archive_does_not_escape(member: str) -> None:
    assert escapes_root(member) is None


@pytest.mark.parametrize(
    ("member", "dist"),
    [
        # A trailing space on a dot segment is the same segment to the normaliser.
        (". /messagefoundry/x.py", "messagefoundry-toolkit"),
        ("messagefoundry_toolkit/.. /messagefoundry/x.py", "messagefoundry-toolkit"),
        ("messagefoundry/. /anon/x.py", "messagefoundry"),
        ("messagefoundry/.. /anon/__init__.py", "messagefoundry"),
    ],
)
def test_a_dot_segment_with_a_trailing_space_is_still_a_dot_segment(member: str, dist: str) -> None:
    assert split_violation(member, dist) is not None


def test_the_cli_refuses_a_hyphen_named_toolkit_sdist_carrying_the_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_tar(
        tmp_path / "dist" / "messagefoundry-toolkit-0.4.0.tar.gz",
        [
            tarfile.TarInfo("messagefoundry-toolkit-0.4.0/PKG-INFO"),
            tarfile.TarInfo("messagefoundry-toolkit-0.4.0/messagefoundry/__init__.py"),
        ],
    )
    assert main([str(sdist)]) == 1
    assert "ships messagefoundry-toolkit-0.4.0/messagefoundry/__init__.py" in (
        capsys.readouterr().err
    )


# The final review of BACKLOG #5470's repair: loosenings in the split rule's root handling and
# filename parsing. Each CLI case below passed the gate at cecd44aefba.

_TK_ROOT = "messagefoundry_toolkit-0.4.0"
_TK_SDIST = f"{_TK_ROOT}.tar.gz"


def _files(*names: str) -> list[tarfile.TarInfo]:
    return [tarfile.TarInfo(n) for n in names]


def _dot_entry() -> tarfile.TarInfo:
    """The ``./`` directory entry GNU tar writes first."""
    dot = tarfile.TarInfo("./")
    dot.type = tarfile.DIRTYPE
    return dot


def test_a_parent_segment_is_resolved_before_the_root_is_stripped() -> None:
    member = f"{_TK_ROOT}/../{_TK_ROOT}/messagefoundry/x.py"
    assert split_violation(member, "messagefoundry-toolkit", _TK_ROOT) is not None


def test_the_cli_refuses_a_root_climbing_back_into_itself(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    member = f"{_TK_ROOT}/../{_TK_ROOT}/messagefoundry/x.py"
    sdist = _write_tar(tmp_path / "dist" / _TK_SDIST, _files(f"{_TK_ROOT}/PKG-INFO", member))
    assert main([str(sdist)]) == 1
    assert f"ships {member}" in capsys.readouterr().err


@pytest.mark.parametrize(
    "stray",
    [
        "setup.py",  # a stray top-level file beside the root
        "other-0.1/PKG-INFO",  # a second root: a multi-root sdist
        f"{_TK_ROOT}/../elsewhere/x.py",  # a second top level reached through a parent segment
    ],
)
def test_the_cli_refuses_an_sdist_without_exactly_one_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], stray: str
) -> None:
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        _files(f"{_TK_ROOT}/PKG-INFO", f"{_TK_ROOT}/messagefoundry/x.py", stray),
    )
    assert main([str(sdist)]) == 1
    assert "top-level entries" in capsys.readouterr().err


def test_the_cli_refuses_an_sdist_with_no_root_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_tar(tmp_path / "dist" / _TK_SDIST, _files("PKG-INFO"))
    assert main([str(sdist)]) == 1
    assert "no top-level directory" in capsys.readouterr().err


@pytest.mark.parametrize("spelling", [_TK_ROOT.upper(), f"{_TK_ROOT}.", f"{_TK_ROOT} "])
def test_a_case_or_trailing_dot_spelling_of_the_root_is_the_same_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], spelling: str
) -> None:
    """Through the public path, so the root derivation itself is what is tested."""
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        _files(f"{spelling}/PKG-INFO", f"{_TK_ROOT}/messagefoundry/x.py"),
    )
    assert main([str(sdist)]) == 1
    err = capsys.readouterr().err
    assert f"ships {_TK_ROOT}/messagefoundry/x.py" in err
    assert "top-level" not in err


def test_gnu_tar_s_dot_entry_does_not_hide_the_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        [_dot_entry(), *_files(f"./{_TK_ROOT}/PKG-INFO", f"./{_TK_ROOT}/messagefoundry/x.py")],
    )
    assert main([str(sdist)]) == 1
    err = capsys.readouterr().err
    assert f"ships ./{_TK_ROOT}/messagefoundry/x.py" in err
    assert "top-level" not in err


def test_a_clean_rooted_toolkit_sdist_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the root refusals: one root, and nothing engine-named."""
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        _files(f"{_TK_ROOT}/PKG-INFO", f"{_TK_ROOT}/messagefoundry_toolkit/x.py"),
    )
    assert main([str(sdist)]) == 0, capsys.readouterr().err


def test_a_gnu_dot_entry_is_refused_as_non_canonical(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same clean sdist with GNU tar's ``./`` entry is refused: a ``.`` component is not a
    canonical name, and no build backend this gate is pointed at writes one."""
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        [
            _dot_entry(),
            *_files(f"./{_TK_ROOT}/PKG-INFO", f"./{_TK_ROOT}/messagefoundry_toolkit/x.py"),
        ],
    )
    assert main([str(sdist)]) == 1
    assert "is made only of dots and spaces" in capsys.readouterr().err


def test_a_zip_sdist_has_its_root_derived_and_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rooted = _write_wheel(
        tmp_path / "a" / f"{_TK_ROOT}.zip",
        (f"{_TK_ROOT}/PKG-INFO", f"{_TK_ROOT}/messagefoundry/x.py"),
    )
    assert main([str(rooted)]) == 1
    assert f"ships {_TK_ROOT}/messagefoundry/x.py" in capsys.readouterr().err
    two_roots = _write_wheel(
        tmp_path / "b" / f"{_TK_ROOT}.zip", (f"{_TK_ROOT}/PKG-INFO", "other-0.1/PKG-INFO")
    )
    assert main([str(two_roots)]) == 1
    assert "top-level entries" in capsys.readouterr().err


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry_toolkit-0.4.0.dist-info/METADATA",
        "messagefoundry_toolkit-0.4.0.data/purelib/x.py",
        "messagefoundry-0.4.0/messagefoundry-toolkit-0.4.0/x.py",
        "messagefoundry-toolkit/x.py",
    ],
)
def test_an_engine_archive_may_not_carry_a_toolkit_entry_in_any_spelling(member: str) -> None:
    assert split_violation(member, "messagefoundry") is not None


@pytest.mark.parametrize(
    "filename",
    [
        "messagefoundry-dev.whl",
        "messagefoundry-v0.4.0.tar.gz",
        "messagefoundry-foo-1.0-py3-none-any.whl",  # read as the engine before BACKLOG #5470
        "messagefoundryx-1.0-py3-none-any.whl",
        "mftoolkit-0.4.0-py3-none-any.whl",  # a renamed toolkit would get no split rule
        "unrelated-1.0-py3-none-any.whl",
        "poisoned.whl",
    ],
)
def test_a_filename_naming_no_known_distribution_is_refused(filename: str) -> None:
    assert filename_problem(Path(filename)) is not None


@pytest.mark.parametrize(
    "filename",
    [
        "messagefoundry-0.4.0-py3-none-any.whl",
        "messagefoundry-0.4.0.tar.gz",
        "messagefoundry_toolkit-0.4.0-py3-none-any.whl",
        "messagefoundry_harness-0.4.0-py3-none-any.whl",
        "messagefoundry_webconsole-0.4.0-py3-none-any.whl",
    ],
)
def test_a_filename_naming_a_known_distribution_is_placed(filename: str) -> None:
    assert filename_problem(Path(filename)) is None


@pytest.mark.parametrize(
    "filename", ["messagefoundry-dev.whl", "messagefoundry-v0.4.0-py3-none-any.whl"]
)
def test_the_cli_refuses_an_unparseable_filename_and_applies_both_split_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], filename: str
) -> None:
    wheel = _write_wheel(
        tmp_path / "dist" / filename,
        ("messagefoundry_toolkit/__init__.py", "messagefoundry/__init__.py"),
    )
    assert main([str(wheel)]) == 1
    err = capsys.readouterr().err
    assert f"refuses {filename}: its filename has no <name>-<version> shape" in err
    # The engine rule and the toolkit rule both still run on the members.
    assert "ships messagefoundry_toolkit/__init__.py" in err
    assert "ships messagefoundry/__init__.py" in err


@pytest.mark.parametrize(
    "filename",
    [
        "messagefoundry.harness-0.4.0-py3-none-any.whl",
        "Messagefoundry_Harness-0.4.0-py3-none-any.whl",
    ],
)
def test_only_the_exact_harness_spelling_is_exempt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], filename: str
) -> None:
    wheel = _write_wheel(
        tmp_path / "harness-dist" / filename, ("harness/__init__.py", "harness/tests/test_x.py")
    )
    assert main([str(wheel)]) == 1
    assert "test or development content" in capsys.readouterr().err


@pytest.mark.parametrize(
    "member",
    ["messagefoundry.toml", "messagefoundry.md", "MessageFoundry.TOML", "x/messagefoundry.py"],
)
def test_a_toolkit_doc_or_config_file_named_for_the_engine_passes(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit") is None


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry",  # a directory entry or an extensionless file
        "messagefoundry.toml.py",
        "messagefoundry.md/x.py",  # a directory, whatever its suffix
        "messagefoundry.pyi",
        "messagefoundry-0.4.0.md",  # an engine <name>-<version> entry, whatever follows
        f"{_TK_ROOT}/../messagefoundry.py",
    ],
)
def test_a_toolkit_code_member_named_for_the_engine_is_still_refused(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit", _TK_ROOT) is not None


@pytest.mark.parametrize("member", ["zz.pth", "messagefoundry_toolkit.pth", "X.PTH."])
def test_a_toolkit_archive_may_not_carry_a_top_level_pth_of_any_name(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit") is not None
    # A .pth below the top level is not on a site directory, so it runs nothing.
    assert split_violation(f"messagefoundry_toolkit/{member}", "messagefoundry-toolkit") is None


@pytest.mark.parametrize("member", ["./C:/x.py", "a/C:/x.py", "a\\c:\\x.py"])
def test_a_drive_letter_in_any_component_is_absolute(member: str) -> None:
    assert escapes_root(member) is not None


def test_an_empty_name_before_the_version_places_nothing() -> None:
    assert filename_problem(Path("-1.0-py3-none-any.whl")) is not None


def test_known_distributions_match_the_published_project_names() -> None:
    """A distribution added or renamed under packaging/ fails here, not on a release tag."""
    projects = [_REPO / "pyproject.toml", *sorted((_REPO / "packaging").glob("*/pyproject.toml"))]
    names = {
        re.sub(
            r"[-_.]+", "-", tomllib.loads(p.read_text(encoding="utf-8"))["project"]["name"]
        ).casefold()
        for p in projects
    }
    assert names == KNOWN_DISTRIBUTIONS


@pytest.mark.parametrize(
    ("member", "dist"),
    [
        ("   /messagefoundry/__init__.py", "messagefoundry-toolkit"),
        (".../messagefoundry/x.py", "messagefoundry-toolkit"),
        (". ./messagefoundry/x.py", "messagefoundry-toolkit"),
        ("messagefoundry/.../anon/__init__.py", "messagefoundry"),
    ],
)
def test_a_component_that_normalises_to_nothing_is_dropped(member: str, dist: str) -> None:
    """An extractor that strips trailing dots and spaces and drops the empty component writes the
    engine path the rule exists to stop, so the split rule's own reading drops them too."""
    assert split_violation(member, dist) is not None


@pytest.mark.parametrize(
    "member",
    ["sitecustomize.py", "usercustomize.py", "sitecustomize/__init__.py", "SiteCustomize.pyc"],
)
def test_a_toolkit_archive_may_not_carry_a_startup_module(member: str) -> None:
    assert split_violation(member, "messagefoundry-toolkit") is not None


@pytest.mark.parametrize(
    "member",
    [
        "MESSAG~1/__init__.py",
        "messagefoundry::$INDEX_ALLOCATION/__init__.py",
        "messagefoundry_toolkit/x.py:hidden",
    ],
)
def test_a_windows_alias_spelling_is_refused(member: str) -> None:
    assert escapes_root(member) is not None


def test_a_zip_entry_of_any_special_unix_type_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for mode, verdict in ((0o010644, 1), (0o020644, 1), (0o060644, 1), (0, 0), (0o040755, 0)):
        wheel = tmp_path / str(mode) / _TOOLKIT_WHEEL
        wheel.parent.mkdir(parents=True)
        with zipfile.ZipFile(wheel, "w") as zf:
            entry = zipfile.ZipInfo("messagefoundry_toolkit/h.py")
            entry.external_attr = mode << 16
            zf.writestr(entry, "")
        assert main([str(wheel)]) == verdict, oct(mode)
        assert ("-- a link" in capsys.readouterr().err) is bool(verdict), oct(mode)


def test_the_cli_passes_a_toolkit_sdist_with_an_engine_named_config_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_tar(
        tmp_path / "dist" / _TK_SDIST,
        _files(f"{_TK_ROOT}/PKG-INFO", f"{_TK_ROOT}/messagefoundry.toml"),
    )
    assert main([str(sdist)]) == 0, capsys.readouterr().err


@pytest.mark.parametrize(
    "filename",
    [
        "messagefoundry-webconsole-0.4.0-py3-none-any.whl",
        "messagefoundry-harness-0.4.0-py3-none-any.whl",
        "messagefoundry-toolkit-0.4.0-py3-none-any.whl",
    ],
)
def test_the_cli_refuses_a_hyphenated_wheel_and_applies_both_split_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], filename: str
) -> None:
    """A wheel name is written with underscores, so a hyphen places nothing. Before this the
    console spelling got the console's rule, where reading up to the first hyphen gave it the
    engine's."""
    assert filename_problem(Path(filename)) is not None
    wheel = _write_wheel(
        tmp_path / "dist" / filename,
        ("messagefoundry_toolkit/__init__.py", "messagefoundry/__init__.py"),
    )
    assert main([str(wheel)]) == 1
    err = capsys.readouterr().err
    assert f"refuses {filename}: it is a wheel whose distribution name contains a hyphen" in err
    assert "ships messagefoundry_toolkit/__init__.py" in err
    assert "ships messagefoundry/__init__.py" in err


def test_a_hyphenated_sdist_name_is_still_placed() -> None:
    """The hyphen refusal is the wheel spec's; an sdist built by an older backend may carry one."""
    assert filename_problem(Path("messagefoundry-toolkit-0.4.0.tar.gz")) is None


_NON_ENGINE_WHEELS = {
    "messagefoundry-toolkit": "messagefoundry_toolkit-0.4.0-py3-none-any.whl",
    "messagefoundry-harness": "messagefoundry_harness-0.4.0-py3-none-any.whl",
    "messagefoundry-webconsole": "messagefoundry_webconsole-0.4.0-py3-none-any.whl",
}


@pytest.mark.parametrize("dist", sorted(_NON_ENGINE_WHEELS))
@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry/__init__.py",
        "messagefoundry.py",
        "zz.pth",
        "sitecustomize.py",
        "usercustomize/__init__.py",
        "x-0.4.0.data/purelib/messagefoundry/x.py",
        "messagefoundry-0.4.0.dist-info/METADATA",
    ],
)
def test_no_non_engine_distribution_may_install_over_the_engine(dist: str, member: str) -> None:
    assert split_violation(member, dist) is not None


@pytest.mark.parametrize("dist", sorted(_NON_ENGINE_WHEELS))
def test_the_cli_refuses_any_non_engine_wheel_writing_into_the_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], dist: str
) -> None:
    wheel = _write_wheel(
        tmp_path / "dist" / _NON_ENGINE_WHEELS[dist], ("messagefoundry/__init__.py", "zz.pth")
    )
    assert main([str(wheel)]) == 1
    err = capsys.readouterr().err
    assert "ships messagefoundry/__init__.py" in err
    assert "ships zz.pth" in err


@pytest.mark.parametrize(
    ("dist", "member"),
    [
        ("messagefoundry-harness", "harness/__init__.py"),
        ("messagefoundry-harness", "harness/load/profile.toml"),
        ("messagefoundry-harness", "messagefoundry_harness-0.4.0.dist-info/METADATA"),
        ("messagefoundry-webconsole", "messagefoundry_webconsole/static/app.js"),
        ("messagefoundry-webconsole", "messagefoundry_webconsole-0.4.0.dist-info/RECORD"),
    ],
)
def test_harness_and_console_members_pass_the_split_rule(dist: str, member: str) -> None:
    assert split_violation(member, dist) is None


@pytest.mark.parametrize(
    ("dist", "member"),
    [
        ("messagefoundry-toolkit", "messagefoundry-dev.dist-info/METADATA"),
        ("messagefoundry-harness", "MessageFoundry-x.dist-info/entry_points.txt"),
        ("messagefoundry-webconsole", "messagefoundry.egg-info/PKG-INFO"),
        ("messagefoundry", "messagefoundry_toolkit-dev.dist-info/METADATA"),
        ("messagefoundry", "messagefoundry.toolkit.egg-info/PKG-INFO"),
    ],
)
def test_a_metadata_directory_is_placed_as_importlib_reads_it(dist: str, member: str) -> None:
    """importlib.metadata names a ``.dist-info`` or ``.egg-info`` directory by the text before its
    first hyphen, with no version needed, so a non-numeric version still declares the other
    distribution."""
    assert split_violation(member, dist) is not None


@pytest.mark.parametrize(
    "member",
    [
        "MESSAG~1/__init__.py",
        "messag~1.py",
        "MESSAG~12.PY",
        "a~1",
        "MES~1234/x.py",
        "MESSAG~1.PY./x",
        "x/MESSAG~1.HTM",
    ],
)
def test_an_8_3_short_name_is_refused(member: str) -> None:
    assert escapes_root(member) is not None


@pytest.mark.parametrize(
    "member",
    ["b~1c.txt", "messagefoundry~1/x.py", "messag~1.html", "x~/y.py", "a.b~1"],
)
def test_a_tilde_digit_outside_the_8_3_shape_is_not_an_alias(member: str) -> None:
    assert escapes_root(member) is None


def test_a_version_must_start_with_an_ascii_digit() -> None:
    """U+0663 (ARABIC-INDIC DIGIT THREE) passes ``str.isdigit``. It is named by escape rather than
    written, because the cp1252 console gate refuses the literal."""
    assert filename_problem(Path("messagefoundry_toolkit-\u0663.0-py3-none-any.whl")) is not None


def test_the_per_archive_line_says_an_archive_level_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refused filename or root with no forbidden member must not print "none forbidden"."""
    wheel = _write_wheel(
        tmp_path / "w" / "messagefoundry-webconsole-0.4.0-py3-none-any.whl",
        ("messagefoundry_webconsole/a.py",),
    )
    rootless = _write_tar(tmp_path / "s" / _TK_SDIST, _files("a.py", "b.py"))
    for archive in (wheel, rootless):
        assert main([str(archive)]) == 1
        out = capsys.readouterr().out
        assert f"in {archive.name}, ARCHIVE REFUSED, 0 members forbidden" in out
        assert "none forbidden" not in out


# --------------------------------------------------------------------------------------------------
# The wiring. A gate no publishing job calls is the gap that was reported.
# --------------------------------------------------------------------------------------------------

#: How a step invokes the gate. Matched against the step's `run:` text.
_GATE_INVOCATION = "scripts/release/forbidden_members.py"

#: A parsed workflow is arbitrary YAML, so the value type is `Any` by construction. Naming the shape
#: beats a bare `dict`, which mypy strict rejects for missing type arguments.
JobDict = dict[str, Any]
StepDict = dict[str, Any]


def _jobs() -> dict[str, JobDict]:
    # Imported in-function, matching tests/test_release_pipeline.py: PyYAML ships no stubs, and a
    # module-level import would put an untyped-import error in every mypy run over this directory.
    import yaml

    parsed = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))
    jobs = parsed.get("jobs")
    assert isinstance(jobs, dict) and jobs, "release.yml parsed to no jobs"
    return dict(jobs)


def _steps(job: JobDict) -> list[StepDict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def _publishing_jobs() -> dict[str, JobDict]:
    """Jobs that put an artifact somewhere a stranger can fetch it.

    DERIVED, NOT LISTED. The reported defect was a job with no gate, so a test naming today's three
    jobs would go green the day a fourth is added -- which is the same failure one layer up. A job
    qualifies if any step publishes to PyPI or uploads to a GitHub release.

    A PUBLISH-ONLY job (vault BACKLOG #2631, limb 1) builds nothing and so gates nothing itself: it
    publishes files another job gated, after checking them against that job's digests. Such a job
    is replaced here by the jobs that gated its files, which `_gating_jobs` finds and checks, so every
    test below grades the job where the gate has to be.
    """
    jobs = _jobs()
    out: dict[str, JobDict] = {}
    for jid, job in jobs.items():
        for step in _steps(job):
            uses = str(step.get("uses") or "")
            run = str(step.get("run") or "")
            if (
                "gh-action-pypi-publish" in uses
                or "gh release upload" in run
                or "gh release create" in run
            ):
                for gid in _gating_jobs(jid, job):
                    out[gid] = jobs[gid]
                break
    return out


#: How a publish-only job names the job whose digests it checks.
_DIGEST_SOURCE = re.compile(r"needs\.([\w-]+)\.outputs\.pypi-digests")


def _gating_jobs(jid: str, job: JobDict) -> list[str]:
    """``[jid]`` when the job runs the gate itself; else every job whose gated files it publishes.

    For a publish-only job this ASSERTS the chain that makes the substitution honest: one step
    checks the download against each `needs.<producer>.outputs.pypi-digests` before any publish
    step, and each `<producer>` is in the job's `needs:`. Every producer is returned, not the
    first: `publish-pypi` publishes files from `release` and `release-harness` (vault BACKLOG
    #2975), and keeping only one would drop the other from every test below.
    """
    steps = _steps(job)
    if any(_GATE_INVOCATION in str(s.get("run") or "") for s in steps):
        return [jid]
    checks = [
        (i, producers)
        for i, s in enumerate(steps)
        if (producers := _DIGEST_SOURCE.findall(str((s.get("env") or {}).get("EXPECTED") or "")))
    ]
    assert len(checks) == 1, f"{jid} publishes with no gate and no single digest check: {checks}"
    at, producers = checks[0]
    publish_at = [i for i, s in enumerate(steps) if "gh-action-pypi-publish" in str(s.get("uses"))]
    assert publish_at and at < min(publish_at), f"{jid} checks digests after it publishes"
    for producer in producers:
        assert producer in needs_of(job), (
            f"{jid} checks {producer}'s digests without needing {producer}"
        )
    return producers


def test_the_publishing_job_set_is_the_one_we_think_it_is() -> None:
    """Liveness for the derivation above. If it silently matched nothing, every test using it passes.

    Pinned as a FLOOR plus an identity check rather than an exact set: a new publishing job must not
    red this test, it must red the coverage test below, which is the one with something to say.
    """
    found = _publishing_jobs()
    assert set(found) >= {"release", "release-webconsole", "release-harness"}, (
        f"the publishing-job derivation lost a known job: {sorted(found)}"
    )


def test_every_publishing_job_invokes_the_member_gate() -> None:
    """THE TEST FOR THE REPORTED GAP. Before #1832 this failed for two of the three jobs."""
    missing = [
        jid
        for jid, job in _publishing_jobs().items()
        if not any(_GATE_INVOCATION in str(s.get("run") or "") for s in _steps(job))
    ]
    assert not missing, (
        f"these release jobs publish an artifact with no member gate: {sorted(missing)} -- "
        f"every one of them must run {_GATE_INVOCATION}"
    )


def test_the_gate_runs_before_anything_publishes() -> None:
    """A gate that fires after the upload has already leaked the file it was checking for."""
    for jid, job in _publishing_jobs().items():
        steps = _steps(job)
        gate_at = [i for i, s in enumerate(steps) if _GATE_INVOCATION in str(s.get("run") or "")]
        assert gate_at, f"{jid} has no member gate step"  # covered above; keeps this test honest
        publish_at = [
            i
            for i, s in enumerate(steps)
            if "gh-action-pypi-publish" in str(s.get("uses") or "")
            or "gh release upload" in str(s.get("run") or "")
            or "gh release create" in str(s.get("run") or "")
        ]
        assert min(gate_at) < min(publish_at), (
            f"{jid} runs its member gate at step {min(gate_at)}, after its first publishing step "
            f"at {min(publish_at)} -- the leak would already be public"
        )


def test_no_step_hands_out_an_archive_the_member_gate_refused() -> None:
    """ORDERING IS NOT ENOUGH: a later step with ``if: always()`` runs anyway (BACKLOG #1838).

    The test above asks whether the gate runs FIRST. That is necessary and not sufficient, because
    ``always()`` ignores an earlier failure entirely. Every publishing job ends with an
    ``actions/upload-artifact`` step carrying ``always()`` so a broken build still leaves something
    to inspect -- and as first shipped, two of the three would upload the very archive the gate had
    just refused, as a downloadable workflow artifact on a public repository.

    ``actions/upload-artifact`` is deliberately NOT in the publish set of the ordering test: that
    set is about *release* surfaces, and widening it there would say the upload must come after the
    gate, which is true but not the point. What matters here is the CONDITION, not the position.
    """
    offenders = []
    for jid, job in _publishing_jobs().items():
        for i, step in enumerate(_steps(job)):
            cond = str(step.get("if") or "")
            if "always()" not in cond:
                continue
            if "upload-artifact" not in str(step.get("uses") or ""):
                continue
            if "steps.member-gate.outcome" not in cond:
                offenders.append(f"{jid} step[{i}] {step.get('name')!r}: if: {cond}")
    assert not offenders, (
        "these steps run on always() and would hand out an archive the member gate refused -- "
        "each needs `&& steps.member-gate.outcome != 'failure'`:\n  " + "\n  ".join(offenders)
    )


def test_the_toolkit_gate_keeps_its_id_and_the_upload_reads_it() -> None:
    """The toolkit wheel rides the engine job (ADR 0201), so its gate needs its own id and the
    job's dry-run upload, which now carries ``toolkit-dist/``, must refuse to hand out what that
    gate refused. The generic guard above looks only for ``steps.member-gate.outcome``, which the
    engine gate satisfies alone, so without this a renamed id or a dropped clause stays green."""
    steps = _steps(_jobs()["release"])
    gates = [s for s in steps if "toolkit-dist/" in str(s.get("run") or "")]
    gates = [s for s in gates if _GATE_INVOCATION in str(s.get("run") or "")]
    # Two steps gate toolkit-dist/: the member gate before signing, and the bundle-move step after
    # it (BACKLOG #1192). Unlike the engine's dist-pub/ re-gate, toolkit-dist/ IS uploaded below, so
    # each needs its own id and the upload guard must read both.
    assert [s.get("id") for s in gates] == ["toolkit-member-gate", "toolkit-bundle-move"], gates
    uploads = [
        s
        for s in steps
        if "upload-artifact" in str(s.get("uses") or "")
        # The dry-run upload, by name: the PyPI hand-over (vault BACKLOG #2631) also carries
        # toolkit-dist/, but runs on the implicit success(), so no gate guard is needed there.
        and (s.get("with") or {}).get("name") == "release-artifacts"
        and "toolkit-dist/" in str((s.get("with") or {}).get("path") or "")
    ]
    assert len(uploads) == 1, "the release job's dry-run upload no longer carries toolkit-dist/"
    cond = str(uploads[0].get("if") or "")
    for gate_id in ("toolkit-member-gate", "toolkit-bundle-move"):
        assert f"steps.{gate_id}.outcome != 'failure'" in cond, cond


def test_the_member_gate_step_keeps_the_id_that_guard_depends_on() -> None:
    """The guard above is a string reference. Renaming or dropping the id disarms it silently."""
    for jid, job in _publishing_jobs().items():
        ids = [s.get("id") for s in _steps(job) if _GATE_INVOCATION in str(s.get("run") or "")]
        assert "member-gate" in ids, (
            f"{jid}'s member gate has no `id: member-gate`, so every "
            f"`steps.member-gate.outcome` reference in that job silently evaluates to empty"
        )


def test_each_job_gates_the_artifacts_it_actually_builds() -> None:
    """The gate must name the output directory its own job wrote.

    A step that inspected the wrong directory would find no archive; ``_resolve`` turns that into a
    failure rather than a green line, so this test is about the release staying GREEN for the right
    reason, not about the leak.
    """
    expected = {
        # The toolkit wheel is built and gated inside the engine job (ADR 0201); publish-pypi uploads it.
        "release": ("dist/", "toolkit-dist/"),
        "release-webconsole": ("webconsole-dist/",),
        "release-harness": ("harness-dist/",),
    }
    jobs = _jobs()
    for jid, needles in expected.items():
        gate_runs = [
            str(s.get("run") or "")
            for s in _steps(jobs[jid])
            if _GATE_INVOCATION in str(s.get("run") or "")
        ]
        assert gate_runs, f"{jid} has no member gate step"
        text = "\n".join(gate_runs)
        for needle in needles:
            assert needle in text, f"{jid}'s member gate does not inspect {needle}"


def test_the_engine_job_gates_its_wheel_as_well_as_its_sdist() -> None:
    """The sdist leak gate only ever read ``dist/*.tar.gz``. The engine wheel had no member gate."""
    gate_runs = "\n".join(
        str(s.get("run") or "")
        for s in _steps(_jobs()["release"])
        if _GATE_INVOCATION in str(s.get("run") or "")
    )
    assert "*.whl" in gate_runs, "the engine job's member gate does not inspect its wheel"
    assert "*.tar.gz" in gate_runs, "the engine job's member gate does not inspect its sdist"


def test_the_gate_script_is_tracked_and_executable_as_written() -> None:
    """The workflow calls a path. If it moves, every wiring test above still passes on the text."""
    assert GATE.is_file(), f"{GATE} does not exist, so every release job calls a missing script"


# --------------------------------------------------------------------------------------------------
# `ci.yml`'s positive control, RUN rather than read. The control is what makes the four clean member
# gates in `packaging-build` mean anything, so a control that cannot fail costs the whole job.
#
# It shipped deciding on the EXIT CODE alone, and `main` exits 1 for four different reasons: a refused
# member, a pattern that matched no file, an archive it could not open, and an archive that listed zero
# members. Only the first is the gate firing. So with the fixture renamed out from under it the step
# printed "control fired" having opened ZERO archives -- a control reporting the gate armed whether or
# not the gate saw anything, which is the empty-corpus defect the gate itself exists to prevent.
#
# The three tests below EXECUTE the step: the same script the runner runs, against a real wheel, once
# per arm. A text assertion could pin today's wording and still pass on a step that never fires.
# --------------------------------------------------------------------------------------------------

#: The job and step carrying the control. Named, not derived: there is exactly one, and a derivation
#: over "steps whose name says control" would silently follow a rename into inspecting nothing.
_CONTROL_JOB = "packaging-build"
_CONTROL_STEP = "Positive control"

#: The fixture the control poisons and the gate is pointed at.
_POISONED = "poisoned.whl"

#: A gate that ACCEPTS. Stands in for the denylist going empty, which is the failure the control was
#: built for; a stub says it in three lines and stays true whatever the real script's internals become.
_ACCEPTING_GATE = (
    "import sys\n"
    'print("member gate passed: inspected 5 members across 1 archive(s)")\n'
    "sys.exit(0)\n"
)


def _control_step_script(step_name: str = _CONTROL_STEP) -> str:
    """The control step's `run:` text, straight out of `ci.yml`."""
    import yaml

    parsed = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    job = (parsed.get("jobs") or {}).get(_CONTROL_JOB)
    assert isinstance(job, dict), f"ci.yml has no `{_CONTROL_JOB}` job"
    matches = [
        str(s.get("run") or "")
        for s in _steps(job)
        if step_name in str(s.get("name") or "") and str(s.get("run") or "")
    ]
    assert len(matches) == 1, (
        f"expected exactly one `{step_name}` step in `{_CONTROL_JOB}`, found {len(matches)} -- "
        "the extractor below would otherwise run the wrong script, or none"
    )
    return matches[0]


def _sandbox(tmp_path: Path, *, gate_source: str | None = None) -> Path:
    """The working tree the step expects: a built harness wheel, and the gate on its own path."""
    root = tmp_path / "job"
    (root / "scripts" / "release").mkdir(parents=True)
    _write_wheel(
        root / "harness-dist" / "messagefoundry_harness-0.3.0-py3-none-any.whl", _CLEAN_WHEEL
    )
    _write_wheel(
        root / "webconsole-dist" / "messagefoundry_webconsole-0.3.0-py3-none-any.whl",
        ("messagefoundry_webconsole/__init__.py",),
    )
    _write_wheel(root / "dist" / "messagefoundry-0.3.0-py3-none-any.whl", _CLEAN_WHEEL)
    target = root / "scripts" / "release" / GATE.name
    if gate_source is None:
        shutil.copy2(GATE, target)
    else:
        target.write_text(gate_source, encoding="utf-8")
    return root


def _run_control(tmp_path: Path, root: Path, script: str) -> subprocess.CompletedProcess[bytes]:
    """Run the step the way the runner does: bash, `-e`, from the job's working directory."""
    path = root / "control.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    bash = require_bash(tmp_path)
    # THE CHILD NEEDS REAL UTILITIES AND A `python`, NOT JUST THE INTERPRETER (BACKLOG #1373). The step
    # runs `cp` and `python`; a PATH without them fails the child at 127, which arm two would read as
    # its own success. `probe_env` appends bash's own directory, where `cp` ships; this process's own
    # interpreter directory is PREPENDED, so the step runs the python running the suite. Same call,
    # same reason, as tests/test_ci_tooling_gate.py.
    env = probe_env(Path(bash), dict(os.environ))
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    return subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv, tmp paths
        [bash, "-e", str(path)],
        cwd=str(root),
        env=env,
        capture_output=True,
        # UNDER the per-test watchdog, which is the only way this guard can ever fire. `addopts`
        # carries `--timeout=60 --timeout-method=thread`, and the CI legs override it at 60s (ubuntu)
        # / 120s (Windows) -- so a subprocess timeout at the 180 used elsewhere in this suite is
        # unreachable: pytest-timeout kills the whole session first and orphans the child. At 45 a
        # wedged step reds THIS test and the child is reaped. Measured: all three arms together run
        # in under 2 s on this box, so the margin is a hang backstop, not a tightness gate.
        timeout=45,
        check=False,
    )


def _output(proc: subprocess.CompletedProcess[bytes]) -> str:
    return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


def test_the_control_passes_when_the_gate_refuses_the_poisoned_member(tmp_path: Path) -> None:
    """ARM ONE. Without this the fix below is satisfied by a step that always fails."""
    script = _control_step_script()
    proc = _run_control(tmp_path, _sandbox(tmp_path), script)
    out = _output(proc)
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "ci.yml's positive control") + "\n" + out
    )
    assert f"{_POISONED} ships harness/CLAUDE.md" in out, (
        f"the gate never named the poisoned member, so the control passed without firing:\n{out}"
    )


def test_the_control_fails_when_the_gate_inspects_nothing(tmp_path: Path) -> None:
    """ARM TWO, THE REPORTED DEFECT. Rename the fixture out from under the gate's argument.

    The mutation is keyed on the INVOCATION, not on the step's prose: it rewrites the archive name on
    the one line that calls the gate, which is exactly what a later edit renaming the fixture on one
    line and not the other would do by accident.
    """
    lines = _control_step_script().splitlines(keepends=True)
    at = [i for i, line in enumerate(lines) if _GATE_INVOCATION in line]
    assert len(at) == 1, f"expected one gate invocation in the control step, found {len(at)}"
    assert _POISONED in lines[at[0]], (
        f"the gate invocation does not name {_POISONED}: {lines[at[0]]}"
    )
    lines[at[0]] = lines[at[0]].replace(_POISONED, "poisoned-renamed.whl")

    proc = _run_control(tmp_path, _sandbox(tmp_path), "".join(lines))
    out = _output(proc)
    assert "found no file matching" in out, (
        f"the mutation did not produce the empty-match condition it is meant to test:\n{out}"
    )
    assert proc.returncode != 0, (
        "THE REPORTED DEFECT: the control reported success having inspected ZERO members, so it "
        f"cannot fail and proves nothing about the member gates above it:\n{out}"
    )


def test_the_control_fails_when_the_gate_accepts_the_poisoned_member(tmp_path: Path) -> None:
    """ARM THREE. The failure the control was BUILT for must still red it after the fix above."""
    root = _sandbox(tmp_path, gate_source=_ACCEPTING_GATE)
    proc = _run_control(tmp_path, root, _control_step_script())
    out = _output(proc)
    assert proc.returncode != 0, (
        f"the control accepted a gate that shipped harness/CLAUDE.md:\n{out}"
    )
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"


# --------------------------------------------------------------------------------------------------
# `ci.yml`'s test-content control (BACKLOG #1938), RUN rather than read, for the same reason as the
# three arms above: a control that cannot fail proves nothing about the clean console result.
# --------------------------------------------------------------------------------------------------

_TEST_CONTENT_STEP = "Test-content control"


def test_the_test_content_control_passes_when_the_gate_refuses_the_planted_tests(
    tmp_path: Path,
) -> None:
    """ARM ONE. The real gate, a console wheel under its real filename, a planted tests/ member."""
    proc = _run_control(tmp_path, _sandbox(tmp_path), _control_step_script(_TEST_CONTENT_STEP))
    out = _output(proc)
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "ci.yml's test-content control") + "\n" + out
    )
    assert "ships messagefoundry_webconsole/tests/test_planted.py" in out, (
        f"the gate never named the planted member, so the control passed without firing:\n{out}"
    )


def test_the_test_content_control_fails_when_the_gate_accepts(tmp_path: Path) -> None:
    """ARM TWO. A gate that accepts everything must red the control, and say why."""
    root = _sandbox(tmp_path, gate_source=_ACCEPTING_GATE)
    proc = _run_control(tmp_path, root, _control_step_script(_TEST_CONTENT_STEP))
    out = _output(proc)
    assert proc.returncode != 0, f"the control accepted a gate that shipped a tests/ tree:\n{out}"
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"


def test_the_test_content_control_fails_when_the_console_is_exempted(tmp_path: Path) -> None:
    """ARM THREE. Widening the exemption to the console is the regression this control exists for."""
    real = GATE.read_text(encoding="utf-8")
    widened = real.replace(
        'frozenset({"messagefoundry-harness"})',
        'frozenset({"messagefoundry-harness", "messagefoundry-webconsole"})',
    )
    assert widened != real, "the exemption set is not spelled the way this mutation expects"
    root = _sandbox(tmp_path, gate_source=widened)
    proc = _run_control(tmp_path, root, _control_step_script(_TEST_CONTENT_STEP))
    out = _output(proc)
    assert proc.returncode != 0, f"the control passed with the console exempted:\n{out}"
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"


# --------------------------------------------------------------------------------------------------
# `ci.yml`'s retired-path control (ADR 0201 AC-6), RUN rather than read, for the same reason again.
# --------------------------------------------------------------------------------------------------

_RETIRED_PATH_STEP = "Retired-path control"


def test_the_retired_path_control_passes_when_the_gate_refuses_the_moved_module(
    tmp_path: Path,
) -> None:
    """ARM ONE. The real gate, an engine wheel under its real filename, the slice 2 retired path."""
    proc = _run_control(tmp_path, _sandbox(tmp_path), _control_step_script(_RETIRED_PATH_STEP))
    out = _output(proc)
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "ci.yml's retired-path control") + "\n" + out
    )
    assert "ships messagefoundry/adr_analyze.py" in out, (
        f"the gate never named the retired path, so the control passed without firing:\n{out}"
    )


def test_the_retired_path_control_fails_when_the_gate_accepts(tmp_path: Path) -> None:
    """ARM TWO. A gate that accepts everything must red the control, and say why."""
    root = _sandbox(tmp_path, gate_source=_ACCEPTING_GATE)
    proc = _run_control(tmp_path, root, _control_step_script(_RETIRED_PATH_STEP))
    out = _output(proc)
    assert proc.returncode != 0, f"the control accepted a gate that shipped a moved module:\n{out}"
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"


def test_the_retired_path_control_fails_when_the_rule_retires_nothing(tmp_path: Path) -> None:
    """ARM THREE. Emptying the retired-path list is the regression this control exists for."""
    real = GATE.read_text(encoding="utf-8")
    emptied = real.replace('    ("messagefoundry", "adr_analyze.py"),\n', "")
    assert emptied != real, "the retired-path list is not spelled the way this mutation expects"
    root = _sandbox(tmp_path, gate_source=emptied)
    proc = _run_control(tmp_path, root, _control_step_script(_RETIRED_PATH_STEP))
    out = _output(proc)
    assert proc.returncode != 0, f"the control passed with no retired path listed:\n{out}"
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"


# The third repair of BACKLOG #5470: a non-canonical name is refused before any rule reads it,
# because extractors disagree on it. ``zipfile.extractall`` drops a ``..`` component, so each engine
# wheel member below extracts as the retired path, and each passed the gate at 864942586c0.

_PARENT_HOPS = (
    "messagefoundry/../anon/__init__.py",
    "messagefoundry/../generators/adt.py",
    "messagefoundry/../hl7schema.py",
    "messagefoundry/../hl7structures.py",
)


@pytest.mark.parametrize("member", _PARENT_HOPS)
def test_the_cli_refuses_an_engine_wheel_whose_parent_segment_hides_a_retired_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], member: str
) -> None:
    wheel = _write_wheel(tmp_path / "dist" / _ENGINE_WHEEL, (*_CLEAN_WHEEL, member))
    assert main([str(wheel)]) == 1
    err = capsys.readouterr().err
    assert f"ships {member} -- component '..' is made only of dots and spaces" in err


@pytest.mark.parametrize("member", _PARENT_HOPS)
def test_zipfile_extracts_the_parent_hop_as_the_retired_path(tmp_path: Path, member: str) -> None:
    """The premise of the refusal, measured rather than asserted: the extracted path is retired."""
    wheel = _write_wheel(tmp_path / "w.whl", (member,))
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(tmp_path / "out")
    written = [p.relative_to(tmp_path / "out").as_posix() for p in (tmp_path / "out").rglob("*")]
    assert member.replace("/../", "/") in written


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry/../anon/__init__.py",
        "messagefoundry/./x.py",
        "./messagefoundry/x.py",
        ".",
        "messagefoundry//x.py",
        "/messagefoundry/x.py",
        "messagefoundry/x.py//",
        "",
        "messagefoundry\\anon\\__init__.py",
        "messagefoundry/.../anon/x.py",
        "messagefoundry/   /anon/x.py",
        "messagefoundry/.. /anon/x.py",
        "messagefoundry/. ./anon/x.py",
        "messagefoundry./x.py",
        "messagefoundry /x.py",
        "messagefoundry/x.py.",
        "messagefoundry/x.py ",
    ],
)
def test_a_non_canonical_name_is_refused(member: str) -> None:
    assert non_canonical(member) is not None


@pytest.mark.parametrize(
    "member",
    [
        "messagefoundry/__init__.py",
        "messagefoundry/",  # a zip directory entry's one trailing separator
        "messagefoundry-0.4.0.dist-info/METADATA",
        ".hidden/x.py",  # a leading dot is not a trailing one
        "a.b/c..d.py",
        "with space/x y.py",
    ],
)
def test_a_canonical_name_is_not_refused(member: str) -> None:
    assert non_canonical(member) is None


def test_the_cli_still_passes_a_clean_engine_wheel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the parent-hop cases: the same wheel without the hop passes."""
    wheel = _write_wheel(tmp_path / "dist" / _ENGINE_WHEEL, _CLEAN_WHEEL)
    assert main([str(wheel)]) == 0, capsys.readouterr().err


# Round 1 of that repair: on Windows ``zipfile`` rewrites each of ``:<>|"?*`` to ``_``, so each
# member below extracts there as a retired path or the toolkit package. Each passed the gate at
# 681c3ee898e.

_REWRITTEN = (
    "messagefoundry/lens?schema.py",
    "messagefoundry?toolkit/__init__.py",
    "messagefoundry/corepoint|import.py",
    "messagefoundry/adr*analyze.py",
    "messagefoundry/lens<schema.py",
    'messagefoundry/corepoint"import.py',
    "messagefoundry/adr>analyze.py",
)


@pytest.mark.parametrize("member", _REWRITTEN)
def test_the_cli_refuses_an_engine_wheel_member_zipfile_rewrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], member: str
) -> None:
    wheel = _write_wheel(tmp_path / "dist" / _ENGINE_WHEEL, (*_CLEAN_WHEEL, member))
    assert main([str(wheel)]) == 1
    assert f"ships {member} -- the name holds" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="zipfile rewrites these characters on Windows")
def test_zipfile_rewrites_the_character_to_an_underscore(tmp_path: Path) -> None:
    """The premise of the refusal, measured: the forged name extracts as the forbidden one."""
    wheel = _write_wheel(tmp_path / "w.whl", ("messagefoundry?toolkit/__init__.py",))
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(tmp_path / "out")
    assert (tmp_path / "out" / "messagefoundry_toolkit" / "__init__.py").is_file()


@pytest.mark.parametrize("char", [*':<>|"?*', "\x00", "\x1f", "\x7f"])
def test_a_rewritten_or_control_character_is_refused(char: str) -> None:
    assert non_canonical(f"messagefoundry_toolkit/a{char}b.py") is not None
