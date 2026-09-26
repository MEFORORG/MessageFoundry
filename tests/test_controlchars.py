# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared C0/DEL predicate (BACKLOG #1253).

#1239 asked for a test that "the two predicates agree across a shared character corpus, so a future
widening of one without the other fails". There is now ONE predicate, so that obligation becomes a
CHARACTERISATION test: pin the exact code-point set, over the whole of Latin-1 plus the neighbours
that tempt a widener, so a change to the shared definition has to be deliberate and cannot ride in
as a tidy-up. Seven call sites move together now -- that is the leverage and also the risk.
"""

from __future__ import annotations

import ast
import functools
import re
import warnings
from pathlib import Path

import pytest

from messagefoundry.controlchars import _is_control_char, has_control_char, strip_control_chars

#: The set the predicate is defined to catch. Written independently of the implementation, so this
#: is a second opinion rather than a restatement of the same expression.
_CONTROL = frozenset(chr(c) for c in range(0x00, 0x20)) | {chr(0x7F)}


@pytest.mark.parametrize("code", sorted(ord(c) for c in _CONTROL))
def test_every_c0_control_and_del_is_caught(code: int) -> None:
    assert has_control_char(f"a{chr(code)}b") is True


def test_the_predicate_matches_its_definition_across_all_of_latin1_and_beyond() -> None:
    """The characterisation. Any divergence here is a deliberate widening or a mistake, and either
    way it must not pass silently -- seven call sites share this now."""
    caught = {chr(c) for c in range(0x0000, 0x0300) if has_control_char(chr(c))}
    assert caught == set(_CONTROL)


def test_ordinary_text_is_not_flagged() -> None:
    assert has_control_char("") is False
    assert has_control_char("a normal value") is False
    assert has_control_char("punctuation!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~") is False


def test_the_boundaries_are_where_they_are_documented() -> None:
    """0x1F in, 0x20 out; 0x7E out, 0x7F in, 0x80 out. The off-by-one at each edge."""
    assert has_control_char(chr(0x1F)) is True
    assert has_control_char(chr(0x20)) is False  # space
    assert has_control_char(chr(0x7E)) is False  # tilde
    assert has_control_char(chr(0x7F)) is True  # DEL
    assert has_control_char(chr(0x80)) is False  # C1 starts here and is NOT covered


@pytest.mark.parametrize("code", [0x85, 0x9B, 0x2028, 0x2029, 0x200B, 0xFEFF])
def test_c1_and_unicode_separators_are_deliberately_NOT_caught(code: int) -> None:
    """Documented as deliberate, and pinned so nobody "fixes" it by accident. Every call site
    screens values bound for byte-oriented sinks where C0 and DEL are the injection alphabet.
    Widening this is a behaviour change at seven sites at once and must be made on purpose."""
    assert has_control_char(chr(code)) is False


# --- the two actions stay two actions ---------------------------------------------------------


def test_strip_removes_exactly_what_the_predicate_catches() -> None:
    noisy = "".join(sorted(_CONTROL)) + "keep me"
    assert strip_control_chars(noisy) == "keep me"
    assert has_control_char(strip_control_chars(noisy)) is False


def test_strip_is_a_no_op_on_clean_text() -> None:
    assert strip_control_chars("nothing to remove") == "nothing to remove"


def test_strip_preserves_order_and_the_rest_of_the_value() -> None:
    assert strip_control_chars("a\rb\nc\td") == "abcd"


def test_the_two_actions_disagree_on_purpose() -> None:
    """A regression that turned the strip into a reject (or vice versa) would show up here. #1253
    requires both arms to survive: six sites refuse, rest.py's header-VALUE path neutralises."""
    hostile = "value\r\nX-Injected: 1"
    assert has_control_char(hostile) is True
    assert strip_control_chars(hostile) == "valueX-Injected: 1"
    assert has_control_char(strip_control_chars(hostile)) is False


def test_the_strip_defeats_header_injection_which_is_why_it_exists() -> None:
    """CRLF is the whole point: a stripped value can no longer split a request line."""
    assert "\r" not in strip_control_chars("a\rb")
    assert "\n" not in strip_control_chars("a\nb")


# --- no site re-derives the alphabet (BACKLOG #1273) ----------------------------------------------
#
# The module above exists so the C0+DEL set is written once. Every copy found so far agreed with it,
# so no behaviour test could tell a copy from an import; only a scan of the source can. This one
# looks for the three spellings the repository has actually used:
#
#   * regex -- any string literal that compiles to a pattern whose single-character matches over
#     the domain below are exactly the set, or exactly its complement (the `[^...]` validator form).
#     Every literal is a candidate, not just a `re.compile` argument, so a hoisted constant or an
#     aliased `re` is still seen. Near sets are not copies -- an RFC or XML character rule is a
#     different set -- so this arm tests set EQUALITY, never overlap.
#   * range -- `range(0x20)` or `range(0, 0x20)` in a top-level statement that also names DEL.
#   * compare -- `x < 0x20 or x == 0x7F` (either operand order) over one operand.
#
# It matches both the live alphabet and C0+DEL as literally written, so after a deliberate widening
# an old narrow copy is still caught rather than falling out of view.

_PKG = Path(__file__).resolve().parent.parent / "messagefoundry"
_DOMAIN = range(0x0000, 0x0300)
_ALPHABET = frozenset(c for c in _DOMAIN if _is_control_char(chr(c)))
_C0_DEL = frozenset(range(0x20)) | {0x7F}
_TARGETS = (_ALPHABET, _C0_DEL)

#: Sites allowed to spell the set themselves, keyed by (path under messagefoundry/, top-level
#: symbol), with the detector kind each is expected to trip. controlchars.py's module docstring
#: gives the reasons; a stale entry fails test_every_exemption_is_still_live.
#:
#: ``transports/soap.py``'s ``_XML_ILLEGAL_RE`` is the other recorded carve-out, and it is
#: deliberately NOT listed here. It is a different set, so the detector does not flag it; listing it
#: would only suppress the one case that matters, where it is rewritten into a real copy. Its
#: exemption is test_the_soap_carve_out_is_the_xml_char_rule_and_not_this_alphabet instead.
_EXEMPT: dict[tuple[str, str], str] = {
    ("controlchars.py", "_is_control_char"): "compare",  # THE definition
    ("parsing/sniff.py", "nontext_upload_reason"): "compare",  # byte-wise density count
    ("spreadsheet.py", "_LEADING_NOISE"): "range",  # importer-droppable leads, harness-mirrored
}


def _int(node: ast.expr) -> int | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is int else None


def _top_level_symbol(stmt: ast.stmt) -> str:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return stmt.name
    targets: list[ast.expr] = []
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, ast.AnnAssign):
        targets = [stmt.target]
    names = [t.id for t in targets if isinstance(t, ast.Name)]
    return names[0] if names else f"<line {stmt.lineno}>"


def _is_regex_copy(text: str) -> bool:
    # Only a literal that could spell a character class holding NUL is worth compiling: it has a
    # bracket and a raw NUL or an escape that can name one. That keeps prose and docstrings out.
    if "[" not in text or not any(s in text for s in ("\x00", "\\x", "\\u", "\\0")):
        return False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # prose that happens to compile warns "nested set"
            pattern = re.compile(text)
    except re.error:
        return False
    matched = frozenset(c for c in _DOMAIN if pattern.fullmatch(chr(c)))
    unmatched = frozenset(_DOMAIN) - matched
    return any(target in (matched, unmatched) for target in _TARGETS)


def _names_del(stmt: ast.stmt) -> bool:
    return any(
        isinstance(n, ast.Constant) and (n.value == 0x7F or n.value == "\x7f")
        for n in ast.walk(stmt)
    )


def _c0_del_compare(value: ast.expr) -> tuple[str, str] | None:
    """``(role, operand)`` for ``x < 0x20`` / ``x <= 0x1F`` / ``x == 0x7F``, either order."""
    if not (isinstance(value, ast.Compare) and len(value.ops) == 1):
        return None
    left, op, right = value.left, value.ops[0], value.comparators[0]
    operand, bound = (left, _int(right)) if _int(right) is not None else (right, _int(left))
    flipped = operand is right
    below = (
        not flipped
        and (
            (isinstance(op, ast.Lt) and bound == 0x20)
            or (isinstance(op, ast.LtE) and bound == 0x1F)
        )
    ) or (
        flipped
        and (
            (isinstance(op, ast.Gt) and bound == 0x20)
            or (isinstance(op, ast.GtE) and bound == 0x1F)
        )
    )
    if below:
        return ("below", ast.dump(operand))
    if isinstance(op, ast.Eq) and bound == 0x7F:
        return ("del", ast.dump(operand))
    return None


def _kind(node: ast.AST, stmt: ast.stmt) -> str | None:
    """Which spelling of the alphabet ``node`` (inside top-level ``stmt``) is, if any."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "regex" if _is_regex_copy(node.value) else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "range"
        and [_int(a) for a in node.args] in ([0x20], [0, 0x20])
        and _names_del(stmt)
    ):
        return "range"
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        roles: dict[str, set[str]] = {"below": set(), "del": set()}
        for value in node.values:
            found = _c0_del_compare(value)
            if found is not None:
                roles[found[0]].add(found[1])
        if roles["below"] & roles["del"]:
            return "compare"
    return None


def _rederivations(source: str) -> list[tuple[str, str, int]]:
    """``(top-level symbol, kind, line)`` for every spelling of the alphabet in ``source``."""
    found = []
    for stmt in ast.parse(source).body:
        symbol = _top_level_symbol(stmt)
        for node in ast.walk(stmt):
            kind = _kind(node, stmt)
            if kind is not None:
                found.append((symbol, kind, getattr(node, "lineno", stmt.lineno)))
    return found


@functools.cache
def _scan_package() -> tuple[int, dict[tuple[str, str], list[tuple[str, int]]]]:
    """``(files scanned, hits by site)``. Cached: two tests read it and the scan is the cost."""
    hits: dict[tuple[str, str], list[tuple[str, int]]] = {}
    paths = sorted(_PKG.rglob("*.py"))
    for path in paths:
        rel = path.relative_to(_PKG).as_posix()
        for symbol, kind, line in _rederivations(path.read_text(encoding="utf-8")):
            hits.setdefault((rel, symbol), []).append((kind, line))
    return len(paths), hits


def test_no_site_under_messagefoundry_re_derives_the_alphabet() -> None:
    """Import :mod:`messagefoundry.controlchars` instead. If a site genuinely needs a different
    set, it is not a copy; if it needs this one for a stated reason, add it to ``_EXEMPT`` and give
    the reason in the controlchars module docstring."""
    scanned, hits = _scan_package()
    offenders = {site: found for site, found in hits.items() if site not in _EXEMPT}
    assert scanned > 0 and offenders == {}, (
        f"scanned {scanned} files under {_PKG}; re-derived C0+DEL set, import controlchars "
        f"instead: {offenders}"
    )


def test_every_exemption_is_still_live() -> None:
    _scanned, hits = _scan_package()
    for site, kind in _EXEMPT.items():
        assert kind in [k for k, _line in hits.get(site, [])], f"stale exemption: {site}"


def test_the_soap_carve_out_is_the_xml_char_rule_and_not_this_alphabet() -> None:
    """The soap carve-out is exempt by being a different set, not by a listing. Pin that
    difference, so a change turning it into a copy fails here as well as in the scan."""
    from messagefoundry.transports.soap import _XML_ILLEGAL_RE

    xml_c0_slice = frozenset(range(0x20)) - {0x09, 0x0A, 0x0D}
    assert frozenset(c for c in _DOMAIN if _XML_ILLEGAL_RE.fullmatch(chr(c))) == xml_c0_slice


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        # The pre-fold uploads.py line, verbatim: the copy this test was written to catch.
        ('_FILENAME_CTRL_RE = re.compile(r"[\\x00-\\x1f\\x7f]")', "regex"),
        ('X = re.sub(r"[\\x00-\\x1f\\x7f]+", "", v)', "regex"),
        ('_P = r"[\\x00-\\x1f\\x7f]"', "regex"),  # hoisted, whatever later compiles it
        ('X = _re.compile(pattern="[\\x00-\\x1f\\x7f]")', "regex"),  # aliased, keyword, non-raw
        ('X = re.compile(r"^[^\\x00-\\x1f\\x7f]*$")', "regex"),  # the complement validator
        ('X = frozenset(chr(c) for c in range(0x20)) | {"\\x7f"}', "range"),
        ("X = {*range(0, 32), 0x7F}", "range"),
        ("def f(ch):\n    return ord(ch) < 0x20 or ord(ch) == 0x7F", "compare"),
        ("def f(b):\n    return b <= 0x1F or b == 127", "compare"),
        ("def f(b):\n    return 0x20 > b or 0x7F == b", "compare"),
    ],
)
def test_the_detector_fires_on_each_spelling(source: str, kind: str) -> None:
    """The positive control. A scan that finds nothing is only evidence if it can find something."""
    assert [k for _s, k, _l in _rederivations(source)] == [kind]


@pytest.mark.parametrize(
    "source",
    [
        # Near sets are different sets: the XML rule, RFC 9110 field values, C0+DEL+C1, C0 alone.
        'X = re.compile(r"[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]")',
        'X = re.compile(r"[\\x00-\\x08\\x0a-\\x1f\\x7f]")',
        'X = re.compile(r"[\\x00-\\x1f\\x7f-\\x9f]")',
        'X = re.compile(r"[\\x00-\\x1f]")',
        'X = re.compile(r"^[^\\x00-\\x1f\\x7f-\\x9f]+$")',
        "X = range(0x100)",
        "X = frozenset(chr(c) for c in range(0x20))",  # C0 alone, no DEL
        "KEY = bytes(range(32))",  # a 32-byte vector is not a character set
        "def f(b):\n    return b < 0x20",
        "def f(a, b):\n    return a < 0x20 or b == 0x7F",  # two operands, not one set
    ],
)
def test_the_detector_does_not_fire_on_a_different_set(source: str) -> None:
    assert _rederivations(source) == []
