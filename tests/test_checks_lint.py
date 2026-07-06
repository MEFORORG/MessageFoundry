# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The advisory ``raise-fstring`` lint (SEC-023): an AST scan of the config-dir Router/Handler modules
that flags ``raise <Exc>(f"...{var}...")`` — the pattern that can carry free-text PHI past the
exception-path redaction. It only ever prints a heuristic reminder; it never blocks the gate."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.checks import _check_raise_fstring, run_checks


def _write(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def test_raise_fstring_flags_interpolated_raise(tmp_path: Path) -> None:
    _write(
        tmp_path / "handlers.py",
        "from messagefoundry import handler\n\n\n"
        "@handler(name='h')\n"
        "def h(msg, ctx):\n"
        "    x = msg.text\n"
        '    raise ValueError(f"bad {x}")\n',
    )
    result = _check_raise_fstring(tmp_path)
    assert result.name == "raise-fstring"
    assert result.required is False  # advisory — never blocks
    assert result.ok is True
    assert result.skipped is False
    assert "handlers.py:" in result.detail

    # And it is present in run_checks() output without flipping the report's overall ok.
    report = run_checks(tmp_path, run_lint=False)
    names = [r.name for r in report.results]
    assert "raise-fstring" in names
    rf = next(r for r in report.results if r.name == "raise-fstring")
    assert rf.required is False and rf.ok is True
    # The advisory lint must not block the gate; report.ok reflects only required checks.
    assert all(r.required is False or r.name != "raise-fstring" for r in report.results)


def test_raise_fstring_ignores_plain_and_constant_raise(tmp_path: Path) -> None:
    _write(
        tmp_path / "ok.py",
        "def f():\n"
        "    raise ValueError('static msg')\n"
        '    raise RuntimeError(f"no interpolation here")\n',
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert "no f-string raises" in result.detail


def test_raise_fstring_skips_malformed_module(tmp_path: Path) -> None:
    _write(tmp_path / "broken.py", "def f(:\n    raise ValueError(f'{x}')\n")
    result = _check_raise_fstring(tmp_path)
    # A syntactically invalid module must not crash the advisory check.
    assert result.ok is True and result.skipped is True


def test_raise_fstring_empty_dir(tmp_path: Path) -> None:
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert result.required is False
