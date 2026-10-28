# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An overlay that retargets a default path is refused unless it says the retarget is meant, and
a schema refusal is bounded (BACKLOG #3000, BACKLOG #3493).

Each test runs against both copies of the anonymizer:

* A retarget of a default path to a DIFFERENT kind is refused at load. Listed under
  ``[hl7].retarget_acknowledged`` it loads, is logged and is listed by ``retargeted_defaults``.
  The kinds rewrite different parts of a field, so each case also shows what an acknowledged
  retarget really leaves in the output. A retarget to the same kind, ``drop`` and ``freetext``
  are the controls that need no list and stay quiet.
* An entry on that list that is not such a retarget is refused, so a misspelt one cannot do
  nothing.
* The warnings are logged on every load. The anonymizer takes no overlay path, so a run loads
  once and the warnings come once.
* A ``RuleError`` quotes a bounded amount of overlay text, a field number has at most three
  digits, and the overlay's own file path is printed with its unprintable characters escaped.

Every value is synthetic. The tee's own console line is pinned in ``tests/test_anon_b193_2267.py``.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

import messagefoundry.anon as engine_anon
import tee.anon as tee_anon

_BOTH = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])

_SALT = "b254-salt-0123456789abcdef"
_ACK = "retarget_acknowledged"

# One synthetic patient. Each piece a narrower kind leaves behind is a distinct token below.
_MESSAGE = (
    "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
    "PID|1||999^^^H^MR||ZZTESTFAM^ZZTESTGIVEN^ZZTESTMID||19700315|M|||"
    "1 ZZ STREET^^FAKECITY^ZZ^99999||5550100^PRN^PH^zz@example.invalid\r"
    "PV1|1|I|||||1234^ZZDOCLAST^ZZDOCGIVEN"
)


def _overlay(tmp_path: Path, body: str, name: str = "anon.toml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _acknowledged(path: str, kind: str) -> str:
    return f'[hl7]\n{_ACK} = ["{path}"]\n[hl7.fields]\n"{path}" = "{kind}"\n'


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno == logging.WARNING:
            self.lines.append(record.getMessage())


@contextmanager
def _warnings(rules: ModuleType) -> Iterator[list[str]]:
    """The WARNING lines the module's own logger emits inside the block.

    A handler on the emitting logger, not ``caplog``: that fixture reads through the root logger,
    and ``tests/test_revocation_guard_remaining_hops.py`` records it losing records under xdist.
    """
    logger = logging.getLogger(rules.__name__)
    handler = _Collect()
    level, disabled, floor = logger.level, logger.disabled, logging.root.manager.disable
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.disabled = False
    logging.disable(logging.NOTSET)
    try:
        yield handler.lines
    finally:
        logging.disable(floor)
        logger.disabled = disabled
        logger.setLevel(level)
        logger.removeHandler(handler)


def _refusal(rules: ModuleType, overlay: Path) -> str:
    with pytest.raises(rules.RuleError) as exc:
        rules.load_rules(overlay)
    return str(exc.value)


# --- a retarget of a default path is refused, unless the overlay lists it ------------------------

_RETARGETS = pytest.mark.parametrize(
    ("path", "default", "kind", "left_behind"),
    [
        # id, mrn and ssn rewrite the first component only.
        ("PID-5", "name", "id", "^ZZTESTGIVEN^ZZTESTMID"),
        ("PID-5", "name", "mrn", "^ZZTESTGIVEN^ZZTESTMID"),
        ("PID-5", "name", "ssn", "^ZZTESTGIVEN^ZZTESTMID"),
        ("PID-11", "address", "id", "^^FAKECITY^ZZ^99999"),
        ("PID-11", "address", "ssn", "^^FAKECITY^ZZ^99999"),
        ("PID-13", "phone", "id", "^PRN^PH^zz@example.invalid"),
        ("PID-13", "phone", "ssn", "^PRN^PH^zz@example.invalid"),
        ("PV1-7", "provider", "id", "^ZZDOCLAST^ZZDOCGIVEN"),
        # date keeps the year, so on a date of birth it keeps the birth year.
        ("PID-7", "dob", "date", "|1970"),
    ],
)


@_BOTH
@_RETARGETS
def test_a_retarget_that_leaves_part_of_a_field_is_refused(
    anon: ModuleType, tmp_path: Path, path: str, default: str, kind: str, left_behind: str
) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, f'[hl7.fields]\n"{path}" = "{kind}"\n')
    with _warnings(rules) as lines:
        message = _refusal(rules, overlay)

    # The field, the kind it had, the kind it would have, and the two ways out.
    assert f"retargets {path} from its default {default} scrub to {kind}" in message
    assert f"[hl7].{_ACK}" in message
    assert "drop or freetext" in message
    assert lines == []


@_BOTH
@_RETARGETS
def test_an_acknowledged_retarget_loads_and_warns(
    anon: ModuleType, tmp_path: Path, path: str, default: str, kind: str, left_behind: str
) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, _acknowledged(path, kind))
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    (line,) = lines
    assert f"retargets {path} from its default {default} scrub to {kind}, as [hl7].{_ACK}" in line
    listed = [
        (was.path, was.kind.value, now.path, now.kind.value)
        for was, now in rules.retargeted_defaults(loaded)
    ]
    assert listed == [(path, default, path, kind)]
    assert rules.kept_defaults(loaded) == ()

    # What the warning is about: with this overlay that part of the value is in the output, and
    # with the default rules it is not.
    assert left_behind in anon.anonymize(_MESSAGE, salt=_SALT, rules=loaded)
    assert left_behind not in anon.anonymize(_MESSAGE, salt=_SALT)
    # A field address and kinds only: nothing of the message, which the loader never saw.
    assert "ZZTEST" not in line


@_BOTH
def test_a_retarget_that_leaves_nothing_today_still_needs_the_list(
    anon: ModuleType, tmp_path: Path
) -> None:
    # No ordering of the kinds says which retarget is safe, so every change of kind other than to
    # a constant needs the list. dob on a name leaves nothing of it today; the rule does not rest
    # on that.
    rules = anon.rules
    message = _refusal(rules, _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "dob"\n'))
    assert "retargets PID-5 from its default name scrub to dob" in message

    loaded = rules.load_rules(_overlay(tmp_path, _acknowledged("PID-5", "dob")))
    assert "ZZTEST" not in anon.anonymize(_MESSAGE, salt=_SALT, rules=loaded)


@_BOTH
def test_every_unlisted_retarget_is_named(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    body = f'[hl7]\n{_ACK} = ["PID-11"]\n[hl7.fields]\n"PID-5" = "id"\n"PID-11" = "id"\n'
    body += '"PID-13" = "ssn"\n'
    message = _refusal(rules, _overlay(tmp_path, body))

    assert "PID-5 from its default name scrub to id" in message
    assert "PID-13 from its default phone scrub to ssn" in message
    assert "PID-11" not in message  # listed, so not the cause


@_BOTH
@pytest.mark.parametrize(
    "body",
    [
        '[hl7.fields]\n"PID-5" = "name"\n"PID-7" = "dob"\n"PV1-7" = "provider"\n',
        '[hl7]\ndrop = ["PID-5", "PID-11"]\n',
        '[hl7.fields]\n"PID-5" = "drop"\n',
        # freetext writes a constant like drop, so it leaves nothing (BACKLOG #3493).
        '[hl7.fields]\n"PID-5" = "freetext"\n"PID-13" = "freetext"\n',
        '[hl7.fields]\n"ZPD-2" = "mrn"\n"EVN-1" = "id"\n',
        # A drop beats a retarget of the same path, so the field is blanked and nothing is left.
        '[hl7]\ndrop = ["PID-5"]\n[hl7.fields]\n"PID-5" = "id"\n',
    ],
    ids=[
        "same-kind",
        "drop-list",
        "drop-as-a-kind",
        "freetext",
        "not-a-default-path",
        "drop-beats-retarget",
    ],
)
def test_the_controls_load_without_the_list_and_do_not_warn(
    anon: ModuleType, tmp_path: Path, body: str
) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, body)
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    assert lines == []
    assert rules.retargeted_defaults(loaded) == ()
    assert "ZZTEST" not in anon.anonymize(_MESSAGE, salt=_SALT, rules=loaded)


# --- an entry on the list that is not a retarget is refused ---------------------------------------


@_BOTH
@pytest.mark.parametrize(
    "body",
    [
        # A misspelling of the retarget it meant: PID-31 for PID-13.
        f'[hl7]\n{_ACK} = ["PID-13", "PID-31"]\n[hl7.fields]\n"PID-13" = "id"\n',
        f'[hl7]\n{_ACK} = ["PID-13"]\n',
        f'[hl7]\n{_ACK} = ["ZPD-2"]\n[hl7.fields]\n"ZPD-2" = "mrn"\n',
        f'[hl7]\n{_ACK} = ["PID-5"]\n[hl7.fields]\n"PID-5" = "name"\n',
        f'[hl7]\n{_ACK} = ["PID-5"]\ndrop = ["PID-5"]\n',
        f'[hl7]\n{_ACK} = ["PID-5"]\n[hl7.fields]\n"PID-5" = "freetext"\n',
        f'[hl7]\n{_ACK} = ["PID-5"]\nkeep = ["PID-5"]\n',
        # A drop beats the retarget the entry was for, so the entry does nothing.
        f'[hl7]\n{_ACK} = ["PID-5"]\ndrop = ["PID-5"]\n[hl7.fields]\n"PID-5" = "id"\n',
    ],
    ids=[
        "misspelt",
        "no-rule",
        "not-a-default",
        "same-kind",
        "drop",
        "freetext",
        "keep",
        "drop-beats-retarget",
    ],
)
def test_an_entry_that_is_not_a_retarget_is_refused(
    anon: ModuleType, tmp_path: Path, body: str
) -> None:
    message = _refusal(anon.rules, _overlay(tmp_path, body))
    assert f"under [hl7].{_ACK}, but sets no rule" in message


@_BOTH
@pytest.mark.parametrize(
    ("body", "phrase"),
    [
        (f'[hl7]\n{_ACK} = ["PID-5.1"]\n', "not a whole-field HL7 address"),
        (f'[hl7]\n{_ACK} = "PID-5"\n', f"[hl7].{_ACK} must be a list of field paths"),
    ],
    ids=["component-path", "not-a-list"],
)
def test_the_list_has_the_same_schema_as_keep(
    anon: ModuleType, tmp_path: Path, body: str, phrase: str
) -> None:
    assert phrase in _refusal(anon.rules, _overlay(tmp_path, body))


@_BOTH
def test_a_long_list_of_stray_entries_is_quoted_bounded(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    entries = ", ".join(f'"ZP{chr(65 + n // 999)}-{n % 999 + 1}"' for n in range(3000))
    message = _refusal(rules, _overlay(tmp_path, f"[hl7]\n{_ACK} = [{entries}]\n"))
    assert "more characters not shown" in message
    assert len(message) <= len(str(tmp_path)) + _MESSAGE_BOUND


@_BOTH
def test_a_keep_is_listed_as_a_keep_and_not_as_a_retarget(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    overlay = _overlay(
        tmp_path, f'[hl7]\nkeep = ["PID-13"]\n{_ACK} = ["PID-5"]\n[hl7.fields]\n"PID-5" = "id"\n'
    )
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    assert len(lines) == 2
    assert sum("keeps PID-13" in line for line in lines) == 1
    assert sum("retargets PID-5" in line for line in lines) == 1
    assert [d.path for d, _ in rules.retargeted_defaults(loaded)] == ["PID-5"]
    assert [r.path for r in rules.kept_defaults(loaded)] == ["PID-13"]


@_BOTH
def test_the_default_rules_and_a_rule_set_built_in_code(anon: ModuleType) -> None:
    rules = anon.rules
    assert rules.retargeted_defaults(rules.DEFAULT_RULES) == ()
    built = (
        rules.FieldRule("PID-5", "ssn"),
        rules.FieldRule("PID-7", "dob"),
        rules.FieldRule("PID-13", "freetext"),
    )
    assert [(d.kind.value, now.kind.value) for d, now in rules.retargeted_defaults(built)] == [
        ("name", "ssn")
    ]
    # Every rule on a path runs. Appended to the defaults, the name rule still scrubs PID-5, so
    # nothing was replaced; the same rule alone is a retarget.
    appended = (*rules.DEFAULT_RULES, rules.FieldRule("PID-5", "id"))
    assert rules.retargeted_defaults(appended) == ()
    assert "ZZTEST" not in anon.anonymize(_MESSAGE, salt=_SALT, rules=appended)


@_BOTH
def test_the_sibling_is_exported(anon: ModuleType) -> None:
    assert anon.retargeted_defaults is anon.rules.retargeted_defaults
    assert "retargeted_defaults" in anon.__all__


# --- warned on every load, and the anonymizer never loads ----------------------------------------

_MESSAGES = 50
_TWO_LINES = f'[hl7]\nkeep = ["PID-13"]\n{_ACK} = ["PID-5"]\n[hl7.fields]\n"PID-5" = "id"\n'


@_BOTH
def test_every_load_warns(anon: ModuleType, tmp_path: Path) -> None:
    # Nothing is remembered between loads, so a second run in one process is told again
    # (BACKLOG #3493: a record of warnings kept for the process silenced every later run).
    rules = anon.rules
    overlay = _overlay(tmp_path, _TWO_LINES)
    with _warnings(rules) as lines:
        rules.load_rules(overlay)
        rules.load_rules(overlay)
    assert len(lines) == 4
    assert lines[:2] == lines[2:]


@_BOTH
@pytest.mark.parametrize("entry", ["anonymize", "anonymize_checked"])
def test_the_anonymizer_takes_no_overlay_path(anon: ModuleType, entry: str) -> None:
    # It used to load the overlay again for every message (BACKLOG #3493). A caller loads it once.
    function = getattr(anon, entry)
    assert "overlay" not in inspect.signature(function).parameters
    with pytest.raises(TypeError):
        function(_MESSAGE, salt=_SALT, overlay=Path("anon.toml"))


@_BOTH
@pytest.mark.parametrize("entry", ["anonymize", "anonymize_checked"])
def test_many_messages_with_one_load_warn_once(
    anon: ModuleType, tmp_path: Path, entry: str
) -> None:
    overlay = _overlay(tmp_path, _TWO_LINES)
    with _warnings(anon.rules) as lines:
        loaded = anon.rules.load_rules(overlay)
        for _ in range(_MESSAGES):
            getattr(anon, entry)(_MESSAGE, salt=_SALT, rules=loaded)

    # One keep line and one retarget line for the whole run.
    assert len(lines) == 2


@_BOTH
def test_two_overlay_files_each_warn(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    first = _overlay(tmp_path, _acknowledged("PID-5", "id"), "first.toml")
    second = _overlay(tmp_path, _acknowledged("PID-5", "id"), "second.toml")
    with _warnings(rules) as lines:
        rules.load_rules(first)
        rules.load_rules(second)

    assert len(lines) == 2
    assert "first.toml" in lines[0]
    assert "second.toml" in lines[1]


# --- the overlay's file path is printed with its unprintable characters escaped -----------------


@_BOTH
def test_a_nul_in_the_overlay_path_is_escaped_in_the_refusal(anon: ModuleType) -> None:
    message = _refusal(anon.rules, Path("no\x00such\nfile.toml"))
    assert "\x00" not in message
    assert "\n" not in message
    assert "no\\x00such\\nfile.toml" in message


@_BOTH
def test_a_printable_overlay_path_is_printed_as_it_is(anon: ModuleType, tmp_path: Path) -> None:
    # Control: the escape changes nothing an editor would show, a Windows backslash included.
    overlay = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "id"\n')
    assert f"anon overlay {overlay} retargets" in _refusal(anon.rules, overlay)


# --- a field number has at most three digits ----------------------------------------------------


@_BOTH
@pytest.mark.parametrize("path", ["ZPD-1000", "PID-0999", "ZPD-" + "1" * 5000])
def test_a_field_number_past_three_digits_is_refused(
    anon: ModuleType, tmp_path: Path, path: str
) -> None:
    rules = anon.rules
    message = _refusal(rules, _overlay(tmp_path, f'[hl7.fields]\n"{path}" = "id"\n'))
    assert "not a whole-field HL7 address" in message
    assert "a field number from 1 to 999" in message
    assert len(message) <= len(str(tmp_path)) + _MESSAGE_BOUND
    with pytest.raises(rules.RuleError):
        rules.FieldRule(path, "id")


@_BOTH
def test_a_three_digit_field_number_loads(anon: ModuleType, tmp_path: Path) -> None:
    # Control: the bound refuses no field a segment can have.
    rules = anon.rules
    loaded = rules.load_rules(_overlay(tmp_path, '[hl7.fields]\n"ZPD-999" = "id"\n'))
    assert ("ZPD-999", "id") in [(r.path, r.kind.value) for r in loaded]


# --- a schema refusal quotes a bounded amount of overlay text ----------------------------------

_LONG = 5000
# The longest fixed wording is the unknown-kind refusal, which lists every kind. Two quoted
# things at the limit, each with its cut marker, fit under this with room to spare.
_MESSAGE_BOUND = 500


_MANY_KEYS = "".join(f"k{n} = 1\n" for n in range(3000))
_BIG_LIST = "[" + ", ".join(f'"v{n}"' for n in range(3000)) + "]"


@_BOTH
@pytest.mark.parametrize(
    ("body", "phrase"),
    [
        (f'[hl7.fields]\n"PID-5" = "{"V" * _LONG}"\n', "unknown surrogate kind"),
        (f'[hl7.fields]\n"{"K" * _LONG}" = "name"\n', "not a whole-field HL7 address"),
        # The kind is read before the path, so this refusal quotes two long things at once.
        (f'[hl7.fields]\n"{"K" * _LONG}" = "{"V" * _LONG}"\n', "unknown surrogate kind"),
        (f'[hl7]\nkeep = ["{"K" * _LONG}"]\n', "not a whole-field HL7 address"),
        (f'[hl7]\ndrop = ["{"K" * _LONG}"]\n', "not a whole-field HL7 address"),
        (f'[hl7]\n{_ACK} = ["{"K" * _LONG}"]\n', "not a whole-field HL7 address"),
        (f'"{"K" * _LONG}" = 1\n', "unexpected top-level key(s)"),
        (f'[hl7]\n"{"K" * _LONG}" = 1\n', "[hl7] has unexpected key(s)"),
        # Many SHORT keys: a cap on each key alone would let this through.
        (_MANY_KEYS, "unexpected top-level key(s)"),
        ("[hl7]\n" + _MANY_KEYS, "[hl7] has unexpected key(s)"),
        # A value that is not a string is quoted by its repr, which is as long as the value.
        (f'[hl7.fields]\n"PID-5" = {_BIG_LIST}\n', "must name a surrogate kind as a string"),
    ],
    ids=[
        "long-kind",
        "long-path",
        "long-path-and-kind",
        "long-keep-entry",
        "long-drop-entry",
        "long-acknowledged-entry",
        "long-top-level-key",
        "long-hl7-key",
        "many-top-level-keys",
        "many-hl7-keys",
        "list-as-a-kind",
    ],
)
def test_a_schema_refusal_is_bounded(
    anon: ModuleType, tmp_path: Path, body: str, phrase: str
) -> None:
    rules = anon.rules
    message = _refusal(rules, _overlay(tmp_path, body))

    assert phrase in message
    assert len(message) <= _MESSAGE_BOUND
    # No run of the overlay's own text longer than the stated limit.
    assert "K" * (rules._QUOTE_LIMIT + 1) not in message
    assert "V" * (rules._QUOTE_LIMIT + 1) not in message
    assert "more characters not shown" in message


@_BOTH
def test_a_short_refusal_is_quoted_whole(anon: ModuleType, tmp_path: Path) -> None:
    # Control: the bound cuts nothing from an ordinary mistake.
    rules = anon.rules
    assert "'PID-5.1'" in _refusal(rules, _overlay(tmp_path, '[hl7]\nkeep = ["PID-5.1"]\n'))
    assert "['fhir', 'x12']" in _refusal(rules, _overlay(tmp_path, "[fhir]\n[x12]\n"))
    message = _refusal(rules, _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "nmae"\n'))
    assert "'PID-5'" in message
    assert "'nmae'" in message
    assert "not shown" not in message


@_BOTH
def test_a_rule_built_in_code_is_bounded_too(anon: ModuleType) -> None:
    rules = anon.rules
    with pytest.raises(rules.RuleError, match="not a whole-field HL7 address") as bad_path:
        rules.FieldRule("K" * _LONG, "name")
    with pytest.raises(rules.RuleError, match="unknown surrogate kind") as bad_kind:
        rules.FieldRule("PID-5", "V" * _LONG)
    with pytest.raises(rules.RuleError, match="as a string") as not_a_string:
        rules.FieldRule("PID-5", ["V"] * _LONG)

    for exc in (bad_path, bad_kind, not_a_string):
        assert len(str(exc.value)) <= _MESSAGE_BOUND
