# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The static-analysis surfaces survive a module the parser refuses without a ``SyntaxError`` (BACKLOG #1858).

CPython's parser has two refusals that are not ``SyntaxError`` subclasses. A module too wide for the
PEG parser's stack raises ``MemoryError`` ("Parser stack overflowed"), and one too deep for the AST
conversion raises ``RecursionError``. Two ``ValueError`` leaves sit beside them: ``Path.read_text`` on
a file that is not UTF-8 raises ``UnicodeDecodeError``, and ``ast.parse`` on a string holding a lone
surrogate raises ``UnicodeEncodeError``. Every guard below was written for ``SyntaxError`` only, so
each of these used to escape as an uncaught traceback from ``check`` or ``lens``.

Each fixture carries its own control: the test first proves the source really does raise the class it
is named for, so a CPython that moves the parser wall turns the control red instead of letting the
guard test pass over a module that parses. The wall's exact width is never pinned.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.checks as checks
import messagefoundry.lens as lens
from messagefoundry.config.graph import _parse_module
from messagefoundry.config.impact import _scan_declaration_span
from messagefoundry.lens import LensParseError, LensRewriteError


def _elif_chain(branches: int = 8000) -> str:
    """A module whose ``if``/``elif`` chain is far wider than the parser stack allows."""
    lines = ["def wide(x):", "    if x == 0:", "        return 0"]
    for i in range(1, branches):
        lines += [f"    elif x == {i}:", f"        return {i}"]
    return "\n".join(lines) + "\n"


# Expression-shaped refusals, for the lens sites that parse a single expression or statement.
_WIDE_EXPR = "-" * 200_000 + "1"  # MemoryError: parser stack overflowed
_DEEP_EXPR = "a" + ".b" * 200_000  # RecursionError: stack overflow during compilation

# (module bytes, the class ``ast.parse(path.read_text(encoding="utf-8"))`` raises on them)
_MODULE_CASES: dict[str, tuple[bytes, type[BaseException]]] = {
    "syntax-error": (b"def broken(:\n", SyntaxError),  # the case every guard already handled
    "parser-memory": (_elif_chain().encode("utf-8"), MemoryError),
    "parser-recursion": (f"x = {_DEEP_EXPR}\n".encode(), RecursionError),
    "not-utf8": (b"x = '\xff\xfe'\n", UnicodeDecodeError),
}
_REFUSALS = ["parser-memory", "parser-recursion", "not-utf8"]
# (expression source, the class ``ast.parse`` raises on it, text the lens refusal must carry). The
# surrogate arm is the ValueError branch: a JSON ``"\ud800"`` escape in an edit decodes to exactly this.
_EXPR_CASES: dict[str, tuple[str, type[BaseException], str]] = {
    "parser-memory": (_WIDE_EXPR, MemoryError, "too complex"),
    "parser-recursion": (_DEEP_EXPR, RecursionError, "too complex"),
    "lone-surrogate": ("'\ud800'", UnicodeEncodeError, "UnicodeEncodeError"),
}


def _write_module(directory: Path, name: str, case: str) -> Path:
    content, expected = _MODULE_CASES[case]
    path = directory / name
    path.write_bytes(content)
    # Control: the fixture must still trip the parser the way its name says.
    with pytest.raises(expected):
        ast.parse(path.read_text(encoding="utf-8"))
    return path


def _config_with(tmp_path: Path, case: str) -> Path:
    """A loadable config (one inbound, one router, one handler that trips each advisory) beside a
    module the parser refuses. The good module proves each leg keeps scanning past the bad one."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "a_good.py").write_text(
        "import subprocess\n"
        "from messagefoundry import inbound, router, handler, File\n"
        "inbound('IB_A', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def h(m):\n"
        "    if m is None:\n"
        "        return []\n"
        "    subprocess.run(['x'])\n"
        "    raise ValueError(f'bad {m}')\n",
        encoding="utf-8",
    )
    _write_module(cfg, "z_refused.py", case)
    return cfg


# --- check: the three advisory legs that parse every *.py ---------------------------------------


@pytest.mark.parametrize("case", _REFUSALS)
def test_raise_fstring_skips_a_refused_module_and_still_scans_the_rest(
    tmp_path: Path, case: str
) -> None:
    result = checks._check_raise_fstring(_config_with(tmp_path, case))
    assert "a_good.py:" in result.detail, result.detail
    assert "z_refused.py" not in result.detail


@pytest.mark.parametrize("case", _REFUSALS)
def test_accepts_candidate_skips_a_refused_module_and_still_scans_the_rest(
    tmp_path: Path, case: str
) -> None:
    result = checks._check_accepts_candidate(_config_with(tmp_path, case))
    assert "a_good.py:" in result.detail, result.detail
    assert "z_refused.py" not in result.detail


@pytest.mark.parametrize("case", _REFUSALS)
def test_handler_security_skips_a_refused_module_and_still_scans_the_rest(
    tmp_path: Path, case: str
) -> None:
    result = checks._check_handler_security(_config_with(tmp_path, case))
    assert "a_good.py:" in result.detail, result.detail
    assert "z_refused.py" not in result.detail


_LATIN1_HANDLER = (
    b"# -*- coding: latin-1 -*-\n"
    b"import subprocess\n"
    b"from messagefoundry import inbound, router, handler, File\n"
    b"inbound('IB_A', File(directory='in'), router='r')\n"
    b"@router('r')\n"
    b"def r(m):\n"
    b"    return ['h']\n"
    b"@handler('h')\n"
    b"def h(m):\n"
    b"    label = '\xe9'\n"
    b"    subprocess.run(['x', label])\n"
    b"    raise ValueError(f'bad {m}')\n"
)


def test_a_module_with_a_coding_cookie_is_scanned_not_skipped(tmp_path: Path) -> None:
    """The loader honours a PEP 263 cookie, so a latin-1 module loads and runs. The legs must scan it.

    Reading it with ``read_text(encoding="utf-8")`` failed, and a leg that skipped on that failure let
    the module pass the handler-security gate unscanned, strict mode included. Parsing bytes reads the
    cookie the way the loader does."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    path = cfg / "latin.py"
    path.write_bytes(_LATIN1_HANDLER)
    with pytest.raises(UnicodeDecodeError):  # control: the old read path really does fail here
        path.read_text(encoding="utf-8")
    report = checks.run_checks(cfg, run_lint=False)
    validate = next(r for r in report.results if r.name == "validate")
    assert validate.ok, validate.detail  # the loader accepts it, so validate names nothing
    strict = checks._check_handler_security(cfg, strict=True)
    assert not strict.ok and strict.required, strict.detail
    assert "latin.py:" in strict.detail and "ambient-authority" in strict.detail
    assert "latin.py:" in checks._check_raise_fstring(cfg).detail


@pytest.mark.parametrize("case", ["syntax-error", *_REFUSALS])
def test_check_reports_the_refused_module_through_validate_instead_of_crashing(
    tmp_path: Path, case: str
) -> None:
    """Skipping at the three advisory sites is only honest because an earlier leg names the file.

    ``validate`` runs first and goes through the loader, whose broad catch turns any of these into a
    ``WiringError`` naming the module. The ``syntax-error`` arm is the parity control: a refused
    module is reported exactly where a module with a syntax error already was."""
    report = checks.run_checks(_config_with(tmp_path, case), run_lint=False)
    validate = next(r for r in report.results if r.name == "validate")
    assert not validate.ok and validate.required
    assert "z_refused.py" in validate.detail, validate.detail
    names = {r.name for r in report.results}
    assert {"raise-fstring", "accepts-candidate", "handler-security"} <= names


# --- lens: parse_source raises LensParseError; the rewrite sites keep LensRewriteError ----------


@pytest.mark.parametrize("case", list(_EXPR_CASES))
def test_lens_parse_source_raises_lens_parse_error(case: str) -> None:
    expr, expected, reason = _EXPR_CASES[case]
    source = f"x = {expr}\n"
    with pytest.raises(expected):
        ast.parse(source)
    with pytest.raises(LensParseError, match=reason):
        lens.parse_source(source, module="m.py")


def test_lens_parse_module_raises_lens_parse_error_on_a_wide_module(tmp_path: Path) -> None:
    path = _write_module(tmp_path, "wide.py", "parser-memory")
    with pytest.raises(LensParseError, match="wide.py"):
        lens.parse_module(path)


def test_lens_parse_module_raises_lens_parse_error_on_non_utf8(tmp_path: Path) -> None:
    path = _write_module(tmp_path, "latin.py", "not-utf8")
    with pytest.raises(LensParseError, match="latin.py"):
        lens.parse_module(path)


@pytest.mark.parametrize("case", list(_EXPR_CASES))
def test_lens_rewrite_source_refuses_with_lens_rewrite_error(case: str) -> None:
    expr, _expected, reason = _EXPR_CASES[case]
    edit: dict[str, Any] = {"op": "set_params", "line_start": 1, "line_end": 1, "params": {}}
    with pytest.raises(LensRewriteError, match=reason):
        lens.rewrite_source(f"x = {expr}\n", edit, module="m.py")


@pytest.mark.parametrize("case", list(_EXPR_CASES))
def test_lens_reparse_gate_refuses_with_lens_rewrite_error(case: str) -> None:
    expr, _expected, reason = _EXPR_CASES[case]
    with pytest.raises(LensRewriteError, match=reason):
        lens._assert_reparses(f"x = {expr}\n", "m.py")


@pytest.mark.parametrize("case", list(_EXPR_CASES))
def test_lens_expr_splice_refuses_with_lens_rewrite_error(case: str) -> None:
    expr, expected, reason = _EXPR_CASES[case]
    with pytest.raises(expected):
        ast.parse(expr, mode="eval")
    with pytest.raises(LensRewriteError, match=reason):
        lens._validated_expr(expr, "value")


def _widest_parseable_unary_chain() -> str:
    """The longest ``-...-1`` chain the parser accepts, found by bisection at test time.

    The wall is a compiled-in parser constant that may move between CPython builds, so it is measured
    here rather than pinned."""
    low, high = 1, 200_000  # the fixture above proves 200,000 trips the wall
    while high - low > 1:
        mid = (low + high) // 2
        try:
            ast.parse("-" * mid + "1", mode="eval")
        except MemoryError:
            high = mid
        else:
            low = mid
    return "-" * low + "1"


def test_lens_expr_splice_probe_refusal_is_a_lens_rewrite_error() -> None:
    """The second parse wraps the expr one call deeper, so it can trip the wall the first parse
    cleared. It must refuse for that reason, not as the extra-argument refusal after it."""
    expr = _widest_parseable_unary_chain()
    ast.parse(expr, mode="eval")  # control: the first parse clears the wall
    with pytest.raises(MemoryError):  # control: one call deeper does not
        ast.parse(f"_f({expr})", mode="eval")
    with pytest.raises(LensRewriteError, match="not a valid call argument") as refused:
        lens._validated_expr(expr, "value")
    assert expr not in str(refused.value)


@pytest.mark.parametrize("case", list(_EXPR_CASES))
def test_lens_paste_refuses_a_refused_block_with_lens_rewrite_error(case: str) -> None:
    expr, expected, _reason = _EXPR_CASES[case]
    block = f"    x = {expr}\n"
    with pytest.raises(expected):
        ast.parse("def _f():\n" + block)
    with pytest.raises(LensRewriteError, match="not valid Python"):
        lens._parse_pasted_block(block)


# --- config/impact.py and config/graph.py: best-effort scans skip the module ---------------------


@pytest.mark.parametrize("case", _REFUSALS)
def test_impact_declaration_scan_skips_a_refused_module(tmp_path: Path, case: str) -> None:
    _write_module(tmp_path, "a_refused.py", case)
    (tmp_path / "b_decl.py").write_text("Reference('OLD', {})\n", encoding="utf-8")
    file, span = _scan_declaration_span(tmp_path, frozenset({"Reference"}), "OLD")
    assert file is not None and file.endswith("b_decl.py")
    assert span is not None and span.start == 1


@pytest.mark.parametrize("case", _REFUSALS)
def test_graph_parse_module_returns_none_for_a_refused_module(tmp_path: Path, case: str) -> None:
    path = _write_module(tmp_path, "refused.py", case)
    cache: dict[str, Any] = {}
    assert _parse_module(str(path), cache) is None
    assert cache == {str(path): None}
