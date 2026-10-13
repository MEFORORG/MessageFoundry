# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An overlay that retargets a default path warns, once, and a schema refusal is bounded (BACKLOG #3000).

Three things, each run against both copies of the anonymizer:

* A retarget of a default path to a DIFFERENT kind is logged and listed by
  ``retargeted_defaults``. The kinds rewrite different parts of a field, so each case here also
  shows what the retarget really leaves in the output. A retarget to the same kind, and a
  ``drop``, are the controls that stay quiet.
* The keep warning and the retarget warning are logged once for one set of lines, not once per
  message, when a caller passes ``overlay=`` on every call.
* A ``RuleError`` quotes a bounded amount of overlay text, however long the key, the value or the
  list of unknown keys.

Every value is synthetic. The tee's own console line is pinned in ``tests/test_anon_b193_2267.py``.
"""

from __future__ import annotations

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

# One synthetic patient. Each piece a narrower kind leaves behind is a distinct token below.
_MESSAGE = (
    "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
    "PID|1||999^^^H^MR||ZZTESTFAM^ZZTESTGIVEN^ZZTESTMID||19700315|M|||"
    "1 ZZ STREET^^FAKECITY^ZZ^99999||5550100^PRN^PH^zz@example.invalid\r"
    "PV1|1|I|||||1234^ZZDOCLAST^ZZDOCGIVEN"
)


@pytest.fixture(autouse=True)
def _fresh_warning_record() -> Iterator[None]:
    """Each test starts with nothing remembered, in both copies, and leaves nothing behind."""
    for package in (engine_anon, tee_anon):
        package.rules._forget_warnings()
    yield
    for package in (engine_anon, tee_anon):
        package.rules._forget_warnings()


def _overlay(tmp_path: Path, body: str, name: str = "anon.toml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


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


# --- a retarget of a default path warns -------------------------------------------------------


@_BOTH
@pytest.mark.parametrize(
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
def test_a_retarget_that_leaves_part_of_a_field_warns(
    anon: ModuleType, tmp_path: Path, path: str, default: str, kind: str, left_behind: str
) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, f'[hl7.fields]\n"{path}" = "{kind}"\n')
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    (line,) = lines
    # The field, the kind it had and the kind it has now.
    assert f"retargets {path} from its default {default} scrub to {kind}" in line
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
def test_a_retarget_that_leaves_nothing_still_warns(anon: ModuleType, tmp_path: Path) -> None:
    # No ordering of the kinds says which retarget is safe, so every change of kind is named.
    # dob on a name leaves nothing of it today; the warning does not depend on that.
    rules = anon.rules
    overlay = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "dob"\n')
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    (line,) = lines
    assert "retargets PID-5 from its default name scrub to dob" in line
    assert "ZZTEST" not in anon.anonymize(_MESSAGE, salt=_SALT, rules=loaded)


@_BOTH
@pytest.mark.parametrize(
    "body",
    [
        '[hl7.fields]\n"PID-5" = "name"\n"PID-7" = "dob"\n"PV1-7" = "provider"\n',
        '[hl7]\ndrop = ["PID-5", "PID-11"]\n',
        '[hl7.fields]\n"PID-5" = "drop"\n',
        '[hl7.fields]\n"ZPD-2" = "mrn"\n"EVN-1" = "id"\n',
        # A drop beats a retarget of the same path, so the field is blanked and nothing is left.
        '[hl7]\ndrop = ["PID-5"]\n[hl7.fields]\n"PID-5" = "id"\n',
    ],
    ids=["same-kind", "drop-list", "drop-as-a-kind", "not-a-default-path", "drop-beats-retarget"],
)
def test_the_controls_do_not_warn(anon: ModuleType, tmp_path: Path, body: str) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, body)
    with _warnings(rules) as lines:
        loaded = rules.load_rules(overlay)

    assert lines == []
    assert rules.retargeted_defaults(loaded) == ()
    assert "ZZTEST" not in anon.anonymize(_MESSAGE, salt=_SALT, rules=loaded)


@_BOTH
def test_a_keep_is_listed_as_a_keep_and_not_as_a_retarget(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-13"]\n[hl7.fields]\n"PID-5" = "id"\n')
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
    built = (rules.FieldRule("PID-5", "ssn"), rules.FieldRule("PID-7", "dob"))
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


# --- once for one set of lines, not once per message -------------------------------------------

_MESSAGES = 50
_TWO_LINES = '[hl7]\nkeep = ["PID-13"]\n[hl7.fields]\n"PID-5" = "id"\n'


@_BOTH
@pytest.mark.parametrize("entry", ["anonymize", "anonymize_checked"])
def test_many_messages_with_one_overlay_warn_once(
    anon: ModuleType, tmp_path: Path, entry: str
) -> None:
    overlay = _overlay(tmp_path, _TWO_LINES)
    with _warnings(anon.rules) as lines:
        for _ in range(_MESSAGES):
            getattr(anon, entry)(_MESSAGE, salt=_SALT, overlay=overlay)

    # One keep line and one retarget line for the whole run. It was two per message.
    assert len(lines) == 2

    # Control: the same loop does repeat them when the record is emptied between messages, so
    # the count above is the record's doing and not a quiet logger.
    with _warnings(anon.rules) as repeated:
        for _ in range(_MESSAGES):
            anon.rules._forget_warnings()
            getattr(anon, entry)(_MESSAGE, salt=_SALT, overlay=overlay)
    assert len(repeated) == 2 * _MESSAGES


@_BOTH
def test_an_edited_overlay_warns_again(anon: ModuleType, tmp_path: Path) -> None:
    # The record is keyed on what the warning says, not on the file, so the same path with a
    # different rule warns again in a process that stays up.
    rules = anon.rules
    overlay = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "id"\n')
    with _warnings(rules) as lines:
        rules.load_rules(overlay)
        rules.load_rules(overlay)
        assert len(lines) == 1

        overlay.write_text('[hl7.fields]\n"PID-5" = "ssn"\n', encoding="utf-8")
        rules.load_rules(overlay)
        rules.load_rules(overlay)
        assert len(lines) == 2
        assert "to ssn" in lines[1]

        # Adding a second field is a different set of lines, so both are named again.
        overlay.write_text('[hl7.fields]\n"PID-5" = "ssn"\n"PID-11" = "id"\n', encoding="utf-8")
        rules.load_rules(overlay)
        assert len(lines) == 4


@_BOTH
def test_two_overlay_files_each_warn(anon: ModuleType, tmp_path: Path) -> None:
    rules = anon.rules
    first = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "id"\n', "first.toml")
    second = _overlay(tmp_path, '[hl7.fields]\n"PID-5" = "id"\n', "second.toml")
    with _warnings(rules) as lines:
        for _ in range(3):
            rules.load_rules(first)
            rules.load_rules(second)

    assert len(lines) == 2
    assert sum("first.toml" in line for line in lines) == 1
    assert sum("second.toml" in line for line in lines) == 1


@_BOTH
def test_a_load_with_warnings_switched_off_is_not_remembered(
    anon: ModuleType, tmp_path: Path
) -> None:
    rules = anon.rules
    overlay = _overlay(tmp_path, _TWO_LINES)
    logger = logging.getLogger(rules.__name__)
    level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        rules.load_rules(overlay)
    finally:
        logger.setLevel(level)

    with _warnings(rules) as lines:
        rules.load_rules(overlay)
    assert len(lines) == 2


@_BOTH
def test_the_record_is_bounded(anon: ModuleType, tmp_path: Path) -> None:
    # A caller that writes a new overlay file per message must not grow the record without limit.
    rules = anon.rules
    with _warnings(rules) as lines:
        for n in range(rules._WARNED_LIMIT + 10):
            rules.load_rules(_overlay(tmp_path, '[hl7.fields]\n"PID-5" = "id"\n', f"o{n}.toml"))
    assert len(lines) == rules._WARNED_LIMIT + 10
    assert len(rules._warned) <= rules._WARNED_LIMIT


# --- a schema refusal quotes a bounded amount of overlay text ----------------------------------

_LONG = 5000
# The longest fixed wording is the unknown-kind refusal, which lists every kind. Two quoted
# things at the limit, each with its cut marker, fit under this with room to spare.
_MESSAGE_BOUND = 500


def _refusal(rules: ModuleType, tmp_path: Path, body: str) -> str:
    with pytest.raises(rules.RuleError) as exc:
        rules.load_rules(_overlay(tmp_path, body))
    return str(exc.value)


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
    message = _refusal(rules, tmp_path, body)

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
    assert "'PID-5.1'" in _refusal(rules, tmp_path, '[hl7]\nkeep = ["PID-5.1"]\n')
    assert "['fhir', 'x12']" in _refusal(rules, tmp_path, "[fhir]\n[x12]\n")
    message = _refusal(rules, tmp_path, '[hl7.fields]\n"PID-5" = "nmae"\n')
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
