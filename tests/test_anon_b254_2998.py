# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``BHS`` or ``FHS`` rule reaches the field the leak-check counts (vault BACKLOG #2998).

Field 1 of ``BHS`` and ``FHS`` is the field separator, as ``MSH-1`` is, so field N sits at split
index N-1. The engine's parser already numbered all three that way. The leak-check and the tee
adapter shifted for ``MSH`` alone, so on a ``BHS`` or ``FHS`` line they counted one field to the
right of the field the engine rewrote. A dashed number next to a mapped field passed the
engine's check, and the tee rewrote a different field from the engine.

Three more things ride on the same numbering and are pinned here: the refusal of a rule on a
delimiter field, the refusal of a header line too short to hold its encoding characters, and
the site-code pass's date exemption.

Every value here is synthetic. The dashed number is the made-up shape the detector matches.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import messagefoundry.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.anon import keying as engine_keying
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon import rules as engine_rules
from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import leak as tee_leak
from tee.anon import rules as tee_rules
from tee.anon import surrogates as tee_surrogates

_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/security/scan_forbidden.py (absent on an installed wheel)",
)

_SALT = "b254-2998-salt-0123456789abcdef"
_SSN = "123-45-6789"
_MSH = r"MSH|^~\&|APP|FAC|RCV|RFAC|20260101120000||ADT^A01|M1|P|2.5.1"
_PID = "PID|1||1^^^H^MR||X^Y"

#: Each side with its own package's classes, as a real caller would hold them.
_ENGINE = SimpleNamespace(anon=engine_anon, rules=engine_rules, leak=engine_leak)
_TEE = SimpleNamespace(anon=tee_anon, rules=tee_rules, leak=tee_leak)
_SIDES = pytest.mark.parametrize("side", (_ENGINE, _TEE), ids=("engine", "tee"))
_HEADERS = pytest.mark.parametrize("seg", ("BHS", "FHS"))
_PLACES = pytest.mark.parametrize("place", ("later", "leading"))
_REWRITING_KINDS = tuple(k.value for k in engine_rules.SurrogateKind if k.value != "keep")


def _line(seg: str) -> str:
    """A batch or file header line with the dashed number in field 6, which is split index 5."""
    return rf"{seg}|^~\&|AAA3|BBB4|CCC5|{_SSN}|20260101"


def _message(line: str, place: str = "later") -> str:
    """``line`` after the message's segments, or leading the body as a batch header does."""
    return "\r".join((_MSH, _PID, line) if place == "later" else (line, _MSH, _PID))


def _rules(side: Any, path: str, kind: str) -> tuple[Any, ...]:
    return (*side.rules.DEFAULT_RULES, side.rules.FieldRule(path, kind))


def _fields(output: str, seg: str) -> list[str]:
    (line,) = (line for line in output.split("\r") if line.startswith(seg))
    return line.split("|")


def _unchecked(module: Any, path: str, kind: str) -> Any:
    """A rule built PAST the ``FieldRule`` path check, as ``tests/test_anon_b193_2265.py`` does:
    the only route to the adapter's own refusal for a spelling ``FieldRule`` will not build."""
    rule = object.__new__(module.FieldRule)
    object.__setattr__(rule, "path", path)
    object.__setattr__(rule, "kind", module.SurrogateKind(kind))
    return rule


# --- part 1: one numbering for the rule and the check ---------------------------------------------


@_HEADERS
def test_the_fixture_puts_the_number_in_field_6(seg: str) -> None:
    """The control for everything below: on a header line, field N sits at split index N-1."""
    fields = _line(seg).split("|")
    assert fields[5] == _SSN and fields[4] == "CCC5"
    assert _SSN not in _MSH


@_PLACES
@_HEADERS
@_SIDES
def test_a_drop_rule_blanks_the_field_it_names(side: Any, seg: str, place: str) -> None:
    """Before the fix the tee blanked split index 6, the field one to the right, and left the
    number in place (RED on the tee; the engine case was already green)."""
    out = side.anon.anonymize(
        _message(_line(seg), place), salt=_SALT, rules=_rules(side, f"{seg}-6", "drop")
    )
    assert _SSN not in out
    assert _fields(out, seg) == [seg, r"^~\&", "AAA3", "BBB4", "CCC5", "", "20260101"]


@_NO_SCANNER
@_PLACES
@_HEADERS
@_SIDES
def test_a_rule_one_field_lower_does_not_hide_the_number(side: Any, seg: str, place: str) -> None:
    """The reproduction. The rule names field 5, so field 6 is unmapped and holds the number.
    Before the fix the engine rewrote field 5, its check counted field 6 as mapped, and the
    number was emitted. The tee rewrote field 6 under the field 5 rule. Neither refused."""
    with pytest.raises(Exception, match=f"SSN-shaped value in {seg}-6") as exc:
        side.anon.anonymize_checked(
            _message(_line(seg), place), salt=_SALT, rules=_rules(side, f"{seg}-5", "id")
        )
    assert type(exc.value).__name__ == "LeakError"
    assert _SSN not in str(exc.value)


@_NO_SCANNER
@_PLACES
@_HEADERS
@_SIDES
def test_the_check_passes_the_rule_that_names_the_field(side: Any, seg: str, place: str) -> None:
    """The other half: the right rule removes the number, so the check has nothing to refuse.
    Before the fix the tee left the number and its check refused the message."""
    out = side.anon.anonymize_checked(
        _message(_line(seg), place), salt=_SALT, rules=_rules(side, f"{seg}-6", "drop")
    )
    assert _SSN not in out
    assert _fields(out, seg)[4] == "CCC5"  # the neighbour is untouched


@_HEADERS
@pytest.mark.parametrize("leak", (engine_leak, tee_leak), ids=("engine", "tee"))
def test_the_leak_check_numbers_a_header_line_the_header_way(leak: Any, seg: str) -> None:
    """The check itself: the encoding characters are field 2 and the first data field is 3."""
    text = _message(_line(seg))
    found = dict(leak.unmapped_field_values(text, set()))
    assert found[f"{seg}-2"] == r"^~\&"
    assert found[f"{seg}-3"] == "AAA3"
    assert found[f"{seg}-6"] == _SSN
    mapped = dict(leak.unmapped_field_values(text, {f"{seg}-6"}))
    assert f"{seg}-6" not in mapped and mapped[f"{seg}-7"] == "20260101"


_PARITY_LINES = {
    "the-fixture": r"{seg}|^~\&|AAA3|BBB4|CCC5|" + _SSN + "|20260101",
    "repetitions-and-escapes": r"{seg}|^~\&|A~B^C&D|F\T\G|CCC5|" + f"{_SSN}~{_SSN}" + "|2026",
    "three-fields": r"{seg}|^~\&|AAA3",
    "empty-fields": r"{seg}|^~\&||||" + _SSN + "|",
}


@_PLACES
@_HEADERS
@pytest.mark.parametrize("line", _PARITY_LINES.values(), ids=_PARITY_LINES.keys())
@pytest.mark.parametrize("number", (3, 4, 5, 6, 7, 30))
@pytest.mark.parametrize("kind", _REWRITING_KINDS)
def test_a_header_rule_gives_the_same_bytes_on_both_sides(
    kind: str, number: int, line: str, seg: str, place: str
) -> None:
    """Engine and tee output are equal byte for byte under a ``BHS`` or ``FHS`` rule. The parity
    file's own inputs run with the default rules, which name no such field."""
    message = _message(line.format(seg=seg), place)
    path = f"{seg}-{number}"
    engine = engine_anon.anonymize(message, salt=_SALT, rules=_rules(_ENGINE, path, kind))
    tee = tee_anon.anonymize(message, salt=_SALT, rules=_rules(_TEE, path, kind))
    assert engine == tee


@_HEADERS
def test_the_lowest_rewritable_header_field_is_three(seg: str) -> None:
    """The control for the refusal below: field 3 is rewritten, not refused, and it is the first
    field after the encoding characters on both sides."""
    for side in (_ENGINE, _TEE):
        out = side.anon.anonymize(
            _message(_line(seg)), salt=_SALT, rules=_rules(side, f"{seg}-3", "drop")
        )
        assert _fields(out, seg)[:4] == [seg, r"^~\&", "", "BBB4"]


@_SIDES
def test_the_default_rules_leave_a_header_line_alone(side: Any) -> None:
    """No default rule names a ``BHS`` or ``FHS`` field, so a caller with no such rule sees no
    change from the fix."""
    line = r"BHS|^~\&|AAA3|BBB4|CCC5|DDD6|20260101"
    out = side.anon.anonymize(_message(line), salt=_SALT)
    assert out.split("\r")[-1] == line


# --- the delimiter fields are refused, per message and at load -----------------------------------

_DELIMITER_PATHS = ("BHS-1", "BHS-2", "FHS-1", "FHS-2")


@pytest.mark.parametrize("path", _DELIMITER_PATHS)
@pytest.mark.parametrize("kind", _REWRITING_KINDS)
@_SIDES
def test_a_rule_that_would_rewrite_a_header_delimiter_is_refused(
    side: Any, kind: str, path: str
) -> None:
    """Before the fix a ``drop`` on ``BHS-1`` made the engine write the line with its separators
    missing, and the tee blanked the encoding characters (split index 1). Both now refuse, and
    the refusal carries no message text."""
    with pytest.raises(ValueError, match=f"a rule names {path},") as exc:
        side.anon.anonymize(_message(_line(path[:3])), salt=_SALT, rules=_rules(side, path, kind))
    assert isinstance(exc.value, side.rules.AnonError)
    assert _SSN not in str(exc.value) and "AAA3" not in str(exc.value)


@pytest.mark.parametrize(
    ("path", "named"),
    [("BHS-02", "BHS-2"), ("fhs-1", "fhs-1"), ("BHS-2\n", "BHS-2"), ("FHS-0", "FHS-0")],
    ids=repr,
)
@_SIDES
def test_the_field_number_decides_for_a_header_too(side: Any, path: str, named: str) -> None:
    """The number is read with ``int()`` and the id in any case, as for ``MSH``. These spellings
    are built past the ``FieldRule`` path check, which refuses each of them first."""
    with pytest.raises(ValueError, match=f"a rule names {named},"):
        side.rules._refuse_unwritable_rules((_unchecked(side.rules, path, "drop"),))


@_SIDES
def test_a_keep_on_a_header_delimiter_is_allowed(side: Any) -> None:
    """A KEEP rewrites nothing. The last line is the control: the same paths with a rewriting
    kind are refused, and every one is named."""
    refuse = side.rules._refuse_unwritable_rules
    refuse(tuple(side.rules.FieldRule(path, "keep") for path in _DELIMITER_PATHS))
    with pytest.raises(ValueError, match="a rule names BHS-1, BHS-2, FHS-1, FHS-2,"):
        refuse(tuple(side.rules.FieldRule(path, "drop") for path in _DELIMITER_PATHS))


def _overlay(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "anon.toml"
    path.write_text(body, encoding="utf-8")
    return path


@_SIDES
@pytest.mark.parametrize(
    ("body", "named"),
    [
        ('[hl7]\ndrop = ["BHS-1"]\n', "BHS-1"),
        ('[hl7]\ndrop = ["FHS-2"]\n', "FHS-2"),
        ('[hl7.fields]\n"BHS-2" = "id"\n', "BHS-2"),
        ('[hl7.fields]\n"FHS-1" = "freetext"\n"BHS-2" = "drop"\n', "BHS-2, FHS-1"),
        ('[hl7]\nkeep = ["BHS-2"]\ndrop = ["BHS-2"]\n', "BHS-2"),
    ],
    ids=["drop-bhs-1", "drop-fhs-2", "fields-bhs-2", "two-headers", "keep-then-drop"],
)
def test_an_overlay_rule_on_a_header_delimiter_is_refused_at_load(
    side: Any, body: str, named: str, tmp_path: Path
) -> None:
    """Before the fix this overlay loaded, and the tee wrote ``BHS||APP|FAC``."""
    overlay = _overlay(tmp_path, body)
    with pytest.raises(side.rules.RuleError) as exc:
        side.rules.load_rules(overlay)
    assert f"sets a rule on {named}, which no rule can rewrite" in str(exc.value)
    assert str(overlay) in str(exc.value)


@_SIDES
@pytest.mark.parametrize(
    ("body", "path", "kind"),
    [
        ('[hl7]\nkeep = ["BHS-1", "BHS-2", "FHS-1", "FHS-2"]\n', "FHS-1", "keep"),
        ('[hl7.fields]\n"BHS-2" = "keep"\n', "BHS-2", "keep"),
        ('[hl7.fields]\n"FHS-2" = "id"\n\n[hl7]\nkeep = ["FHS-2"]\n', "FHS-2", "keep"),
        ('[hl7]\ndrop = ["BHS-3", "FHS-3"]\n', "BHS-3", "drop"),
    ],
    ids=["keep-all-four", "fields-keep", "keep-over-fields", "drop-field-3"],
)
def test_a_keep_on_a_header_delimiter_still_loads(
    side: Any, body: str, path: str, kind: str, tmp_path: Path
) -> None:
    """The control: these loaded before the fix and must load after it."""
    rules = side.rules.load_rules(_overlay(tmp_path, body))
    assert {rule.path: rule.kind.value for rule in rules}[path] == kind


# --- part 2: a header line too short to hold its encoding characters -----------------------------

#: A header line with no separator after field 2. The engine's parser cannot find where the
#: encoding characters end on such a line.
_SHORT_LINES = {
    "bhs-number": f"BHS|{_SSN}",
    "fhs-number": f"FHS|{_SSN}",
    "bhs-text": "BHS|SECRETNAME",
    "bhs-encoding-characters-only": r"BHS|^~\&",
    "later-msh": r"MSH|^~\&",
}


def _anonymizers(side: Any) -> tuple[Callable[..., str], ...]:
    return (side.anon.anonymize, side.anon.anonymize_checked)


#: Every short line in both places, but for one: a leading ``MSH|^~\&`` IS the message header,
#: which this check does not walk. That line is the parser's to refuse, not the anonymizer's.
_SHORT_CASES = [
    pytest.param(line, place, id=f"{name}-{place}")
    for name, line in _SHORT_LINES.items()
    for place in ("later", "leading")
    if not (place == "leading" and line.startswith("MSH"))
]


@_NO_SCANNER
@pytest.mark.parametrize(("line", "place"), _SHORT_CASES)
@pytest.mark.parametrize("checked", (False, True), ids=("plain", "checked"))
@_SIDES
def test_a_short_header_line_is_refused(side: Any, checked: bool, line: str, place: str) -> None:
    """Before the fix the engine re-encoded ``BHS|TEXT`` as ``BHS|TEX|BHS|TEXT`` and its check
    passed a dashed number there. The tee emitted the line as it came. Both now refuse the
    message before any rule runs, with the refusal a bare header id already got."""
    seg = line[:3]
    anonymize = _anonymizers(side)[checked]
    with pytest.raises(ValueError, match="a line no rule can reach") as exc:
        anonymize(_message(line, place), salt=_SALT, rules=_rules(side, f"{seg}-3", "freetext"))
    assert isinstance(exc.value, side.rules.AnonError)
    assert _SSN not in str(exc.value) and "SECRETNAME" not in str(exc.value)


@_PLACES
@_HEADERS
def test_a_header_line_with_one_separator_after_its_encoding_characters_passes(
    seg: str, place: str
) -> None:
    """The control for the refusal: three split fields is enough, and the line comes back as it
    went in, the same on both sides."""
    line = rf"{seg}|^~\&|"
    message = _message(line, place)
    engine = engine_anon.anonymize(message, salt=_SALT)
    tee = tee_anon.anonymize(message, salt=_SALT)
    assert engine == tee
    assert line in engine.split("\r")


@pytest.mark.parametrize("leak", (engine_leak, tee_leak), ids=("engine", "tee"))
def test_the_short_line_rule_is_three_split_fields(leak: Any) -> None:
    """The boundary, at the check itself. A plain segment is the control: one field is a legal
    empty segment and two is an ordinary line."""
    defined = frozenset({"BHS", "FHS", "MSH", "PV2"})
    for seg in ("BHS", "FHS", "MSH"):
        assert leak._line_is_malformed([seg], defined)
        assert leak._line_is_malformed([seg, r"^~\&"], defined)
        assert not leak._line_is_malformed([seg, r"^~\&", ""], defined)
    assert not leak._line_is_malformed(["PV2"], defined)
    assert not leak._line_is_malformed(["PV2", "X"], defined)


# --- the site-code pass's date exemption ---------------------------------------------------------

# A filled year-and-month date. Its first two digits are the century, and an estate whose
# site-code prefix is that same pair turns it into the shape of a site code. The prefix is
# derived from the date so that no literal prefix sits in this scanned file.
_FILLED = "202601"


@pytest.fixture
def century_site_prefix(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A synthetic site-code prefix equal to the century, in BOTH copies of the module, as
    ``tests/test_anon_b193_2330.py`` sets it. The engine's scanner is loaded first, so it never
    reads the patched token source."""
    engine_leak._scanner()
    prefix = _FILLED[:2]
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", f"[site_prefix]\n{prefix}\n")
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()
    yield prefix
    monkeypatch.undo()  # restore the real source BEFORE recomputing
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()


@_NO_SCANNER
@_HEADERS
@pytest.mark.parametrize("module", (engine_surrogates, tee_surrogates), ids=("engine", "tee"))
def test_the_date_exemption_never_reaches_a_header_line(
    module: Any, seg: str, century_site_prefix: str
) -> None:
    """A ``DATE`` rule on field 7 writes split index 6. Before the fix the exemption matched the
    rule's path against the plain split index, so it skipped split index 7, the field one to the
    right: a site code there was neither scrubbed nor reported. A header line now earns no
    exemption, as an ``MSH`` line never did. The control is the same value under the same rule
    number in a segment the exemption does reach."""
    assert module.SITE_CODE_RE.fullmatch(_FILLED)
    date = engine_rules.SurrogateKind.DATE
    rules = (engine_rules.FieldRule(f"{seg}-7", date), engine_rules.FieldRule("ZPD-7", date))
    header_line = rf"{seg}|^~\&|A|B|C|D|E|{_FILLED}"
    assert header_line.split("|")[7] == _FILLED
    text = "\r".join((_MSH, _PID, header_line))
    assert module.message_has_site_code(text, rules)
    scrubbed = module.scrub_message_site_codes(text, engine_keying.Keyer(_SALT), rules)
    assert _fields(scrubbed, seg)[7] != _FILLED
    control = "\r".join((_MSH, _PID, f"ZPD|A|B|C|D|E|F|{_FILLED}"))
    assert not module.message_has_site_code(control, rules)
