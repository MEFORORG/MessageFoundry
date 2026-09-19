# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The advisory ``raise-fstring`` lint (SEC-023): an AST scan of the config-dir Router/Handler modules
that flags a ``raise`` whose message is built from a variable — at least the f-string, ``+``
concatenation, ``%`` formatting and ``.format(...)`` spellings, which carry the same free-text
payload past the exception-path redaction. It only ever prints a heuristic reminder; it never blocks
the gate, which is what pays for the over- and under-flags pinned in the tests below."""

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
    assert "no interpolated raises" in result.detail


def test_raise_fstring_skips_malformed_module(tmp_path: Path) -> None:
    _write(tmp_path / "broken.py", "def f(:\n    raise ValueError(f'{x}')\n")
    result = _check_raise_fstring(tmp_path)
    # A syntactically invalid module must not crash the advisory check.
    assert result.ok is True and result.skipped is True


def test_raise_fstring_empty_dir(tmp_path: Path) -> None:
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert result.required is False


def test_raise_fstring_flags_concatenated_raise(tmp_path: Path) -> None:
    """``raise ValueError("bad " + x)`` carries the same free-text payload as the f-string form."""
    _write(
        tmp_path / "concat.py",
        "def f(x):\n    raise ValueError('bad ' + x)\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is False
    assert "concat.py:2" in result.detail


def test_raise_fstring_flags_percent_formatted_raise(tmp_path: Path) -> None:
    """``raise ValueError("bad %s" % x)`` is the percent spelling of the same interpolation."""
    _write(
        tmp_path / "percent.py",
        "def f(x):\n    raise ValueError('bad %s' % x)\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is False
    assert "percent.py:2" in result.detail


def test_raise_fstring_flags_format_call_raise(tmp_path: Path) -> None:
    """``raise ValueError("bad {}".format(x))`` is the ``str.format`` spelling of the same shape."""
    _write(
        tmp_path / "fmt.py",
        "def f(x):\n    raise ValueError('bad {}'.format(x))\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is False
    assert "fmt.py:2" in result.detail


def test_raise_fstring_ignores_literal_only_concatenation(tmp_path: Path) -> None:
    """A ``+``/``%`` of literal *scalars* folds to a constant — no variable reaches the message.

    Scoped to the two spellings that actually fold. A literal-only ``.format`` and a literal *tuple*
    operand do NOT fold and are pinned as known over-flags below, so keeping them here would have
    made this test pass for a reason other than the one it asserts.
    """
    _write(
        tmp_path / "literal.py",
        "def f():\n    raise ValueError('a' + 'b')\n    raise RuntimeError('a %s' % 'b')\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert "no interpolated raises" in result.detail


def test_raise_fstring_ignores_bare_name_message(tmp_path: Path) -> None:
    """``raise ValueError(msg)`` stays unflagged: a bare ``Name`` is resolved nowhere.

    A deliberate false negative, pinned so it cannot move silently. Reaching the interpolation that
    built ``msg`` is scope resolution, a separate concern from which message shapes this check reads.
    """
    _write(
        tmp_path / "bare.py",
        "def f(x):\n    msg = f'bad {x}'\n    raise ValueError(msg)\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert "no interpolated raises" in result.detail


def test_raise_fstring_over_flags_nonfolding_literals_and_arithmetic(tmp_path: Path) -> None:
    """Three measured over-flags, pinned so the noise floor is a recorded choice, not a surprise.

    ``'%s' % ('b',)`` — the folding helper has no tuple case. ``'{}'.format('b')`` — the ``.format``
    branch counts arguments without inspecting them. ``retry + 1`` — the first constructor argument
    need not be a string. All three are literal or numeric and carry no PHI, and they are a sample,
    not the whole set; the check's docstring catalogues the rest.

    Tolerated because the check only ever prints. Narrowing the first two would mean changing the
    shared predicate the ADR 0144 lookup lint also reads, so it is not a local call. The arithmetic
    one is different and the distinction matters to whoever revisits this: it IS narrowable at this
    caller alone, by requiring a string anchor before consulting the predicate, with no reach into
    ``_unsafe_lookup_hit``. Left as noise here because it is out of this row's scope, not because it
    cannot be done.
    """
    _write(
        tmp_path / "noise.py",
        "def f(retry):\n"
        "    raise ValueError('a %s' % ('b',))\n"
        "    raise RuntimeError('a {}'.format('b'))\n"
        "    raise KeyError(retry + 1)\n",
    )
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is False
    for line in ("noise.py:2", "noise.py:3", "noise.py:4"):
        assert line in result.detail


def test_raise_fstring_ignores_argless_format_call(tmp_path: Path) -> None:
    """``'a {}'.format()`` is unflagged by the zero-argument guard, not by constant folding.

    The detail assertion is what separates this from a file the scanner never read: an unreadable
    or absent module skips with a different detail, so asserting the skip alone would pass for the
    wrong reason — the defect this whole test group was rewritten to remove.
    """
    _write(tmp_path / "argless.py", "def f():\n    raise ValueError('a {}'.format())\n")
    result = _check_raise_fstring(tmp_path)
    assert result.ok is True and result.skipped is True
    assert "no interpolated raises" in result.detail
