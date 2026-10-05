# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An unreadable ``anon.toml`` is refused with nothing of the file on the chain (BACKLOG #2310).

``load_rules`` used to raise ``RuleError(...) from exc`` inside the handler. A ``TOMLDecodeError``
keeps the whole document on ``.doc``, so the whole overlay rode ``__cause__``. A non-UTF-8 overlay
was worse in a different way: ``UnicodeDecodeError`` is a ``ValueError``, not an ``OSError``, so it
escaped the handler raw, with the file's bytes on ``.object``.

Both copies of ``rules.py`` are driven here. The source gate in
``tests/test_from_none_is_not_redaction.py`` scans ``messagefoundry/`` only, so it never saw the
tee's copy; these tests are what cover that one.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import rules as engine_rules
from tee.anon import rules as tee_rules

_BOTH = pytest.mark.parametrize("rules", [engine_rules, tee_rules], ids=["engine", "tee"])

#: Stands in for whatever the wrong file might hold. Letters only, so TOML accepts it as a key.
_PLANTED = "SYNTHETICPLANTED"


def _chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` by ``__cause__`` or ``__context__``, ``exc`` first."""
    seen: list[BaseException] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or any(cur is s for s in seen):
            continue
        seen.append(cur)
        stack += [cur.__cause__, cur.__context__]
    return seen


def _holders(exc: BaseException) -> list[str]:
    """The type names of every exception on the chain that holds the planted value anywhere."""
    hits = []
    for e in _chain(exc):
        fields = (str(e), repr(e.args), repr(getattr(e, "object", None)), repr(vars(e)))
        if any(_PLANTED in f for f in fields):
            hits.append(type(e).__name__)
    return hits


def _assert_bare(exc: BaseException) -> None:
    assert _chain(exc) == [exc], [type(e).__name__ for e in _chain(exc)]
    assert _holders(exc) == []


def _malformed(tmp_path: Path) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(f'[hl7]\n{_PLANTED} = "x"\nkeep = ["PID-5"\n', encoding="utf-8")
    return path


def _not_utf8(tmp_path: Path) -> Path:
    path = tmp_path / "anon.toml"
    path.write_bytes(b'[hl7]\nkeep = ["PID-5"]\n# \xff\xfe ' + _PLANTED.encode("ascii") + b"\n")
    return path


def test_the_walker_finds_both_pre_fix_shapes(tmp_path: Path) -> None:
    """Control: each shape this change removes is found, so a clean reading below means clean."""
    with pytest.raises(ValueError) as chained:
        try:
            tomllib.loads(_malformed(tmp_path).read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ValueError("cannot read it") from exc
    assert _holders(chained.value) == ["TOMLDecodeError"]
    with pytest.raises(AssertionError):
        _assert_bare(chained.value)

    with pytest.raises(UnicodeDecodeError) as raw:
        _not_utf8(tmp_path).read_text(encoding="utf-8")
    assert _holders(raw.value) == ["UnicodeDecodeError"]


@_BOTH
def test_a_malformed_overlay_keeps_the_file_off_the_chain(
    rules: ModuleType, tmp_path: Path
) -> None:
    overlay = _malformed(tmp_path)
    with pytest.raises(rules.RuleError) as caught:
        rules.load_rules(overlay)

    _assert_bare(caught.value)
    # The operator still gets the file and the place, which is all the fix needs.
    text = str(caught.value)
    assert str(overlay) in text
    assert "line 4, column 1" in text


@_BOTH
def test_a_non_utf8_overlay_is_a_rule_error_with_a_bare_chain(
    rules: ModuleType, tmp_path: Path
) -> None:
    overlay = _not_utf8(tmp_path)
    # A RuleError, where a raw UnicodeDecodeError used to escape.
    with pytest.raises(rules.RuleError) as caught:
        rules.load_rules(overlay)

    _assert_bare(caught.value)
    assert "UTF-8" in str(caught.value)


@_BOTH
def test_an_overlay_nested_past_the_parser_is_a_rule_error(
    rules: ModuleType, tmp_path: Path
) -> None:
    overlay = tmp_path / "anon.toml"
    overlay.write_text(f"{_PLANTED} = " + "[" * 5000, encoding="utf-8")
    with pytest.raises(rules.RuleError) as caught:
        rules.load_rules(overlay)

    _assert_bare(caught.value)
    assert "nests too deeply" in str(caught.value)


@_BOTH
def test_a_number_past_the_digit_limit_is_a_rule_error(rules: ModuleType, tmp_path: Path) -> None:
    # tomllib lets int()'s own ValueError through, so this one is not a TOMLDecodeError.
    overlay = tmp_path / "anon.toml"
    overlay.write_text(f"{_PLANTED} = " + "7" * 5000, encoding="utf-8")
    with pytest.raises(rules.RuleError) as caught:
        rules.load_rules(overlay)

    _assert_bare(caught.value)


@_BOTH
def test_a_missing_overlay_is_a_rule_error_naming_the_file(
    rules: ModuleType, tmp_path: Path
) -> None:
    overlay = tmp_path / "no-such-anon.toml"
    with pytest.raises(rules.RuleError) as caught:
        rules.load_rules(overlay)

    _assert_bare(caught.value)
    assert str(overlay) in str(caught.value)


@_BOTH
def test_a_readable_overlay_still_loads(rules: ModuleType, tmp_path: Path) -> None:
    overlay = tmp_path / "anon.toml"
    overlay.write_text('[hl7]\ndrop = ["PID-40"]\n', encoding="utf-8")

    loaded = {r.path: r.kind for r in rules.load_rules(overlay)}
    assert loaded["PID-40"] == rules.SurrogateKind.DROP
    assert loaded["PID-5"] == rules.SurrogateKind.NAME
