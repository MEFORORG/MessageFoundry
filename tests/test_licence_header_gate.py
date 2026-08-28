# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the licence-header gate (``scripts/quality/licence_header_check.py``).

THIS FILE IS THE GATE'S NEGATIVE CONTROL, AND IT SHIPS WITH THE GATE RATHER THAN AFTER IT. Per
BACKLOG #1000, a green gate is evidence only once it has been watched fail on the class it claims to
catch -- otherwise "no violations" and "cannot see violations" render identically, and the reassuring
one is the one nobody re-examines. Each planted class below was observed failing before the gate was
wired into pre-commit or CI.

The classes are deliberately four, not two. "Missing" and "wrong value" are the two the item names;
the other two are the ways a header can be PRESENT and still not be a header, and both would make the
gate pass a file it should fail:

  * a string LITERAL containing the tag -- ``messagefoundry/corepoint_import.py`` really does carry
    ``"# SPDX-License-Identifier: AGPL-3.0-or-later",`` because it generates headers for imported
    configuration, so a substring check reads a header-EMITTING file as a headered one;
  * a correct tag BURIED past the head window, which a whole-file grep accepts.

The last test is the one that matters operationally: it runs the checker against the **real** tracked
tree, so the invariant is enforced by the normal pytest job on every PR.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "licence_header_check.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("licence_header_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load()
_GOOD = f"{_MOD.SPDX_TAG} {_MOD.EXPECTED_IDENTIFIER}"


# --------------------------------------------------------------------------------------------------
# Positive control. If this ever reds, a failure below is the gate breaking, not the plant working.
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("clean.py", f"# {_GOOD}\nprint(1)\n"),
        ("clean.ts", f"// {_GOOD}\nexport const x = 1;\n"),
        ("clean.ps1", f"# {_GOOD}\nWrite-Output 1\n"),
        ("clean.sh", f"#!/bin/sh\n# {_GOOD}\necho 1\n"),
        ("clean.js", f"// {_GOOD}\nconst x = 1;\n"),
        ("clean.go", f"// {_GOOD}\npackage main\n"),
        # A shebang, an encoding line and a directive may all precede the header.
        ("shebang.py", f"#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n# {_GOOD}\n"),
        ("directive.ps1", f"# {_GOOD}\n#Requires -Version 7\n"),
    ],
)
def test_compliant_files_pass(tmp_path: Path, name: str, body: str) -> None:
    """Every in-scope language accepts a correctly-declared header."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    assert _MOD.check_file(path) is None


# --------------------------------------------------------------------------------------------------
# The four planted violation classes.
# --------------------------------------------------------------------------------------------------


def test_missing_header_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "missing.py"
    path.write_text("print(1)\n", encoding="utf-8")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.MISSING


@pytest.mark.parametrize("declared", ["Apache-2.0", "MIT", "AGPL-3.0-only", "GPL-3.0-or-later"])
def test_wrong_identifier_is_its_own_class(tmp_path: Path, declared: str) -> None:
    """A file affirmatively declaring the WRONG licence must not be folded into MISSING.

    This is the case a presence-only check blesses: five files in this repo declared ``Apache-2.0``
    in an AGPL project and ``grep -l SPDX-License-Identifier`` passed every one of them.
    ``AGPL-3.0-only`` is in the list on purpose -- it is one hyphenated word away from correct, and a
    prefix or substring comparison would accept it.
    """
    path = tmp_path / "wrong.py"
    path.write_text(f"# {_MOD.SPDX_TAG} {declared}\nprint(1)\n", encoding="utf-8")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.WRONG
    assert declared in result[1]


# --------------------------------------------------------------------------------------------------
# VENDORED_LICENCES (BACKLOG #1364): a named exception must still assert a value, not just skip.
# --------------------------------------------------------------------------------------------------


def test_vendored_override_accepts_its_own_licence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path listed in VENDORED_LICENCES is checked against ITS licence, not the project's."""
    path = tmp_path / "vendored.js"
    path.write_text("// SPDX-License-Identifier: Apache-2.0\nconsole.log(1);\n", encoding="utf-8")
    monkeypatch.setitem(_MOD.VENDORED_LICENCES, path.as_posix(), "Apache-2.0")
    assert _MOD.check_file(path) is None


def test_vendored_override_still_rejects_the_wrong_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The override asserts an exact value -- it does not just exempt the path entirely."""
    path = tmp_path / "vendored.js"
    path.write_text(f"// {_MOD.SPDX_TAG} MIT\nconsole.log(1);\n", encoding="utf-8")
    monkeypatch.setitem(_MOD.VENDORED_LICENCES, path.as_posix(), "Apache-2.0")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.WRONG
    assert "Apache-2.0" in result[1]


def test_an_unlisted_path_still_uses_the_project_licence(tmp_path: Path) -> None:
    """VENDORED_LICENCES is per-path, not global -- an unregistered file is unaffected."""
    path = tmp_path / "vendored.js"
    path.write_text("// SPDX-License-Identifier: Apache-2.0\nconsole.log(1);\n", encoding="utf-8")
    assert path.as_posix() not in _MOD.VENDORED_LICENCES  # sanity: never registered
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.WRONG


def test_the_real_vendored_cla_action_file_is_compliant() -> None:
    """The one real VENDORED_LICENCES entry (BACKLOG #1364) names an actual, compliant file."""
    assert _MOD.VENDORED_LICENCES, "no entries left to check -- update or remove this test"
    for rel_path in _MOD.VENDORED_LICENCES:
        real = _ROOT / rel_path
        assert real.is_file(), f"VENDORED_LICENCES entry {rel_path!r} does not exist"
        assert _MOD.check_file(real) is None


# --------------------------------------------------------------------------------------------------
# The lookup must not depend on HOW the path is addressed (BACKLOG #1364).
#
# VENDORED_LICENCES is keyed the way ``git ls-files`` emits paths -- repo-relative -- but nothing
# stops a caller handing ``check_file`` an absolute path. The two overrides above register an
# ABSOLUTE key, and that is correct there rather than sloppy: ``tmp_path`` lives outside the repo
# (the system temp dir), so no repo-relative key exists for it and ``as_posix()`` IS its key. The
# consequence is that until this section existed, every registry test reached the registry by a key
# that happened to equal ``path.as_posix()``, and the real repo-relative entry -- the only kind the
# shipped registry holds -- was never exercised through the lookup at all.
# --------------------------------------------------------------------------------------------------


@pytest.fixture
def inside_repo_js() -> Iterator[tuple[Path, str]]:
    """A throwaway ``.js`` file INSIDE the repo tree, plus its repo-relative registry key.

    Inside the repo on purpose: that is where the real vendored entry lives, and it is the only place
    a repo-relative key can be formed at all. The file stays untracked, so ``git ls-files`` never
    reports it and ``test_the_real_tracked_tree_is_clean`` is unaffected.
    """
    with tempfile.TemporaryDirectory(dir=_ROOT) as raw:
        path = Path(raw).resolve() / "vendored_probe.js"
        yield path, path.relative_to(_ROOT).as_posix()


def test_a_repo_relative_key_matches_an_absolutely_addressed_file(
    inside_repo_js: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real entry's exact shape: a repo-relative key, for a file addressed absolutely."""
    path, key = inside_repo_js
    path.write_text(f"// {_MOD.SPDX_TAG} Apache-2.0\nconsole.log(1);\n", encoding="utf-8")
    assert path.as_posix() != key  # the two addressings really are different strings
    monkeypatch.setitem(_MOD.VENDORED_LICENCES, key, "Apache-2.0")
    assert _MOD.check_file(path) is None


def test_a_repo_relative_key_still_rejects_the_wrong_value(
    inside_repo_js: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normalising the key must not turn a registry entry into a blanket exemption.

    The assertion is on WHICH licence is demanded, not merely that the file reds. Before the key was
    normalised this case ALSO returned WRONG -- but demanding the PROJECT's licence, because the
    lookup missed entirely. Naming the registered value is the only thing that tells the two apart,
    so a bare ``result[0] == WRONG`` here would be a test that cannot fail for the reason it claims.
    """
    path, key = inside_repo_js
    path.write_text(f"// {_MOD.SPDX_TAG} MIT\nconsole.log(1);\n", encoding="utf-8")
    monkeypatch.setitem(_MOD.VENDORED_LICENCES, key, "Apache-2.0")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.WRONG
    assert "Apache-2.0" in result[1]
    assert _MOD.EXPECTED_IDENTIFIER not in result[1]


def test_the_verdict_does_not_depend_on_how_the_path_is_addressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One file, one verdict, however the caller spells the path.

    Both shipped callers pass repo-relative paths -- CI goes through ``git ls-files`` and pre-commit
    forwards relative argv -- so only the first assertion held before this was fixed. An absolute
    path silently lost the exemption and demanded this project's AGPL identifier on third-party code,
    which is the affirmative misstatement the registry exists to prevent.
    """
    monkeypatch.chdir(_ROOT)
    for rel_path in _MOD.VENDORED_LICENCES:
        assert _MOD.check_file(Path(rel_path)) is None, f"{rel_path}: relative"
        assert _MOD.check_file(_ROOT / rel_path) is None, f"{rel_path}: absolute"


def test_tag_inside_a_string_literal_does_not_count(tmp_path: Path) -> None:
    """A header-emitting file is not a headered file."""
    path = tmp_path / "emitter.py"
    path.write_text(f'HEADER = "# {_GOOD}"\n', encoding="utf-8")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.MISSING


def test_header_buried_past_the_head_window_does_not_count(tmp_path: Path) -> None:
    path = tmp_path / "buried.py"
    path.write_text("\n" * (_MOD.HEAD_LINES + 5) + f"# {_GOOD}\n", encoding="utf-8")
    result = _MOD.check_file(path)
    assert result is not None
    assert result[0] == _MOD.MISSING


def test_comment_prefix_is_language_specific(tmp_path: Path) -> None:
    """A ``//`` header in a ``#``-comment language is not a valid header, and the reverse."""
    hash_lang = tmp_path / "wrongprefix.py"
    hash_lang.write_text(f"// {_GOOD}\nprint(1)\n", encoding="utf-8")
    assert (_MOD.check_file(hash_lang) or ("", ""))[0] == _MOD.MISSING

    slash_lang = tmp_path / "wrongprefix.ts"
    slash_lang.write_text(f"# {_GOOD}\nexport const x = 1;\n", encoding="utf-8")
    assert (_MOD.check_file(slash_lang) or ("", ""))[0] == _MOD.MISSING


# --------------------------------------------------------------------------------------------------
# Scope, and the end-to-end exit contract the two callers depend on.
# --------------------------------------------------------------------------------------------------


def test_out_of_scope_extensions_are_ignored() -> None:
    assert _MOD.in_scope("a.py") and _MOD.in_scope("a.ts") and _MOD.in_scope("a.go")
    for name in ("README.md", "pyproject.toml", "x.yaml", "x.json", "x.txt", "x"):
        assert not _MOD.in_scope(name)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=_ROOT,
    )


def test_exit_codes(tmp_path: Path) -> None:
    """0 clean / 1 violations / 2 usage error -- the contract pre-commit and CI both key on."""
    good = tmp_path / "good.py"
    good.write_text(f"# {_GOOD}\n", encoding="utf-8")
    bad = tmp_path / "bad.py"
    bad.write_text("print(1)\n", encoding="utf-8")

    assert _run(str(good)).returncode == 0
    assert _run(str(bad)).returncode == 1
    assert _run("--nonsense").returncode == 2


def test_violation_output_names_the_file_and_the_class(tmp_path: Path) -> None:
    """A gate that reds without naming what to fix costs the reader a second investigation."""
    bad = tmp_path / "bad.py"
    bad.write_text(f"# {_MOD.SPDX_TAG} Apache-2.0\n", encoding="utf-8")
    proc = _run(str(bad))
    assert proc.returncode == 1
    assert "WRONG" in proc.stderr or "wrong" in proc.stderr.lower()
    assert "bad.py" in proc.stderr
    assert _MOD.EXPECTED_IDENTIFIER in proc.stderr


# --------------------------------------------------------------------------------------------------
# The operational test: the real tree must satisfy the gate.
# --------------------------------------------------------------------------------------------------


def test_the_real_tracked_tree_is_clean() -> None:
    """Every in-scope tracked file declares the project licence.

    This is what makes the convention enforced rather than merely documented: it runs in the ordinary
    pytest job, so a new headerless file reds a PR even if the pre-commit hook was never installed.
    """
    proc = _run()
    assert proc.returncode == 0, f"licence-header violations on the tracked tree:\n{proc.stderr}"
