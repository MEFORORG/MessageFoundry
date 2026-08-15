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
