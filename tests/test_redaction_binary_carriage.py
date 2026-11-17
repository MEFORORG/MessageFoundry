# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5378: an ``mfb64:v1:`` binary-carriage body quoted in a log record or exception is
withheld by the write-time log chain. The carriage pass runs after every label pass there, so a
labelled value is hidden at least as origin/main hid it. The support bundle is left as origin/main
has it, with its own ``_MFB64`` run first; the bundle tests here assert its main output. Synthetic
HL7 only (CLAUDE.md section 9)."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Callable

import pytest

from messagefoundry import logging_setup, redaction
from messagefoundry.parsing.binary import MARKER, encode
from messagefoundry.redaction import _BINARY_CARRIAGE, redact, redact_binary_carriage
from messagefoundry.support.redact import redact_log_line

_BODY = (
    b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5\r"
    b"PID|1||SYN123^^^H||ZZTEST^ALPHA\rNTE|1||A??>\r"
)
_CARRIAGE = encode(_BODY)
_PAYLOAD = _CARRIAGE.removeprefix(MARKER)
_KEPT = "mfb64:v1:[redacted]"
_BS = "\\"
_JSON_ESCAPED = _CARRIAGE.replace("/", _BS + "/")
_PERCENT_RUN = _CARRIAGE.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
_PERCENT_ALL = _PERCENT_RUN.replace(":", "%3A")
_UNICODE_ESCAPED = (
    _CARRIAGE.replace("+", _BS + "u002B").replace("/", _BS + "u002f").replace("=", _BS + "u003D")
).replace(":", _BS + "u003A")
_FORMS = {
    "plain": _CARRIAGE,
    "json-escaped": _JSON_ESCAPED,
    "percent-run": _PERCENT_RUN,
    "percent-marker": _PERCENT_ALL,
    "unicode-escaped": _UNICODE_ESCAPED,
    "upper": _CARRIAGE.upper(),
}


def _log_chain(text: str) -> str:
    """``text`` as the shipped handler chain renders it in a record's message."""
    record = logging.LogRecord("mf.test", logging.ERROR, __file__, 1, "%s", (text,), None)
    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    for flt in handler.filters:
        assert isinstance(flt, logging.Filter)
        assert flt.filter(record)
    return record.getMessage()


def _bundle(text: str) -> str:
    return redact_log_line(f"2026-01-01 00:00:00 ERROR {text}")


_CHAINS: dict[str, Callable[[str], str]] = {"log": _log_chain}
_LOG_CHAIN = pytest.mark.parametrize("chain", list(_CHAINS), ids=list(_CHAINS))


#: A carriage pattern that never matches. The empty group is load-bearing: the pass substitutes
#: ``\g<1>``, which needs a group 1 even where nothing matches.
_CARRIAGE_OFF = re.compile(r"(?!)()")


def _no_payload(out: str) -> None:
    for at in range(0, len(_PAYLOAD) - 8, 4):
        assert _PAYLOAD[at : at + 8] not in out, out


def test_the_payload_holds_every_character_the_run_reads_encoded() -> None:
    """Non-vacuity for the encoded forms: each has something to encode."""
    assert {"+", "/", "="} <= set(_PAYLOAD)


def test_the_literal_marker_is_the_carriage_marker() -> None:
    assert _BINARY_CARRIAGE.fullmatch(MARKER + "QQ==") is not None
    assert MARKER == "mfb64:v1:"


def test_redact_alone_does_not_read_the_carriage() -> None:
    """The pass is applied last by each chain, never inside :func:`redact`."""
    assert _CARRIAGE in redact(f"bad {_CARRIAGE} end")


@_LOG_CHAIN
@pytest.mark.parametrize("form", list(_FORMS), ids=list(_FORMS))
def test_a_carriage_payload_is_withheld_whole(chain: str, form: str) -> None:
    carriage = _FORMS[form]
    _no_payload(_CHAINS[chain](f"could not route {carriage} after retry"))
    _no_payload(_CHAINS[chain](repr(f'{{"raw": "{carriage}"}}')))


def test_the_log_chain_keeps_the_marker_and_the_text_around_it() -> None:
    assert _log_chain(f"could not route {_CARRIAGE} after retry") == (
        f"could not route {_KEPT} after retry"
    )


def test_the_traceback_is_withheld_too() -> None:
    record = logging.LogRecord("mf.test", logging.ERROR, __file__, 1, "body", (), None)
    try:
        raise ValueError(f"cannot decode {_CARRIAGE}")
    except ValueError:
        record.exc_info = sys.exc_info()
    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    for flt in handler.filters:
        assert isinstance(flt, logging.Filter)
        assert flt.filter(record)
    rendered = logging.Formatter().format(record)
    _no_payload(rendered)
    assert _KEPT in rendered


def test_scrub_log_text_withholds_a_carriage() -> None:
    _no_payload(logging_setup.scrub_log_text(f"bad {_CARRIAGE}"))


def test_prose_naming_the_marker_is_kept() -> None:
    text = "not a binary-carriage value (missing mfb64:v1: marker); check .is_binary first"
    assert redact_binary_carriage(text) == text


def test_the_pass_is_idempotent() -> None:
    once = redact_binary_carriage(f"bad {_CARRIAGE} end")
    assert redact_binary_carriage(once) == once


def test_a_placeholder_inside_the_run_does_not_cut_it() -> None:
    """A date-shaped piece between two ``/`` is scrubbed by the PHI pass before this pass runs; the
    run reads that placeholder as part of itself, so the tail after it is taken too."""
    text = f"{MARKER}QUJD/19800101/{_PAYLOAD}"
    out = _log_chain(text)
    _no_payload(out)
    assert out == _KEPT


def test_the_run_is_ascii_only() -> None:
    for letter in ("K", "ſ", "İ", "ı"):
        assert _BINARY_CARRIAGE.fullmatch(f"{MARKER}QUJD{letter}") is None


#: Each case found by code review on the first design, which read the carriage FIRST and printed
#: these values where origin/main hid them. The value must stay hidden in the log chain.
_LABELLED = {
    "mrn-slash": (f"bad {MARKER}QUJD/MRN: 12345678", "12345678"),
    "mrn-equals-aligned": (f"bad {MARKER}QUJ/MRN=12345678", "12345678"),
    "token-plus": (f"bad {MARKER}QUJD+token=zqsecretvalue", "zqsecretvalue"),
    "session-plus": (f"bad {MARKER}QUJD+session=zqsecretvalue", "zqsecretvalue"),
    "pwd-aligned": (f"bad {MARKER}QUJ+pwd=zqsecretvalue", "zqsecretvalue"),
    "token-double-equals": (f"bad {MARKER}QUJD/token==zqsecretvalue", "zqsecretvalue"),
    "api-key": (f"bad {MARKER}QUJD/api_key=zqsecretvalue", "zqsecretvalue"),
    "dicom": (f"bad {MARKER}QUJD/PatientID: 99887766", "99887766"),
    "dicom-aligned": (f"bad {MARKER}QU/PatientID=99887766", "99887766"),
    "camel-password": (f"bad {MARKER}QUJD/userPassword=zqsecretvalue", "zqsecretvalue"),
    "camel-token": (f"bad {MARKER}QUJD+accessToken=zqsecretvalue", "zqsecretvalue"),
    "compound-key": (f"bad {MARKER}QUJD/AccountKey=zqsecretvalue", "zqsecretvalue"),
    "dsn-slash": (f"bad {MARKER}QUJD/postgres://user:zqsecretvalue@host/db", "zqsecretvalue"),
    "dsn-plus": (f"bad {MARKER}QUJD+redis://user:zqsecretvalue@host/0", "zqsecretvalue"),
    "percent-slash": (f"bad {MARKER}QUJD%2Fpassword=zqsecretvalue", "zqsecretvalue"),
    "percent-plus": (f"bad {MARKER}QUJD%2Btoken=zqsecretvalue", "zqsecretvalue"),
    "label-whole-run-mrn": (f"bad {MARKER}MRN: 12345678", "12345678"),
    "label-whole-run-dicom": (f"bad {MARKER}PatientID=99887766", "99887766"),
    "spaces-password": (f"bad {MARKER}QUJD/password{' ' * 70}: zqsecretvalue", "zqsecretvalue"),
    "spaces-mrn": (f"bad {MARKER}QUJD/MRN{' ' * 70}12345678", "12345678"),
    "padded-slash-password": (f"bad {MARKER}QUJDRA==/Password: zqsecretvalue", "zqsecretvalue"),
    "repr-newline-password": (repr(f"{MARKER}QUJDRA==\nPassword: zqsecretvalue"), "zqsecretvalue"),
    "long-run-then-label": (f"bad {_CARRIAGE.removesuffix('=')}/MRN: 12345678", "12345678"),
}


@_LOG_CHAIN
@pytest.mark.parametrize("label", ["MRN: ", "MRN:", "mrn=", "MRN#", "patient MRN ", '"mrn": "'])
def test_a_carriage_that_is_a_labels_value_is_withheld(chain: str, label: str) -> None:
    """Found by code review: the MRN pass reads ``mfb64`` as the value and writes
    ``[redacted]:v1:``, so the pass after it must still read that head as a marker."""
    _no_payload(_CHAINS[chain](f"bad {label}{_CARRIAGE}"))
    _no_payload(_CHAINS[chain](f"bad {label}{MARKER}WlpURVNUXkFMUEhB"))
    assert "WlpURVNUXkFMUEhB" not in _CHAINS[chain](f"bad {label}{MARKER}WlpURVNUXkFMUEhB")


@_LOG_CHAIN
@pytest.mark.parametrize("case", list(_LABELLED), ids=list(_LABELLED))
def test_a_labelled_value_next_to_a_carriage_stays_hidden(chain: str, case: str) -> None:
    text, value = _LABELLED[case]
    out = _CHAINS[chain](text)
    assert value not in out, out
    assert "QUJD" not in out, out


def test_without_the_carriage_pass_the_log_chain_hides_the_same_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: with the carriage pass off, as on origin/main, each value is already hidden by
    its own label pass, so the green above is that pass's work and the carriage pass took nothing
    from it."""
    monkeypatch.setattr(redaction, "_BINARY_CARRIAGE", _CARRIAGE_OFF)
    for text, value in _LABELLED.values():
        assert value not in _log_chain(text), text


@_LOG_CHAIN
@pytest.mark.parametrize("joiner", ["/", "+", "%2F", "", " "])
def test_a_carriage_glued_after_another_is_withheld_too(chain: str, joiner: str) -> None:
    """Found by code review round 2: the first run took the second marker's head, so the second
    body printed after ``[redacted]:v1:``."""
    out = _CHAINS[chain](f"bad {MARKER}WlpURVNUXkFMUEhB{joiner}{_CARRIAGE} end")
    _no_payload(out)
    assert "WlpURVNUXkFMUEhB" not in out


def test_two_handlers_on_one_record_write_the_same_text() -> None:
    """Found by code review round 2: the placeholder is a run unit, so a second pass took text glued
    after the padding that the first had left; the pass now runs to its fixed point."""
    once = _log_chain(f"bad {MARKER}QUJD==Zq9Secret0x end")
    assert _log_chain(once) == once
    assert redact_binary_carriage(once) == once


@pytest.mark.parametrize(
    "glued",
    ["+code=zqsecretvalue", "/state=zqsecretvalue", "/sig=zqsecretvalue", "+jwt=zqsecretvalue"],
)
def test_the_bundle_hides_a_value_glued_after_a_run_as_main_did(glued: str) -> None:
    """Main's bundle pattern reads ``=`` anywhere in the run and takes such a value."""
    assert "zqsecretvalue" not in _bundle(f"?x={MARKER}QUJD{glued}")


def test_the_bundle_hides_a_word_glued_after_the_padding_as_main_did() -> None:
    assert "Zq9Secret" not in _bundle(f"bad {MARKER}QQ==Zq9Secret end")


def test_the_bundle_runs_no_part_of_the_carriage_pass() -> None:
    """The support bundle is left as origin/main has it: its own ``_MFB64`` at main's pattern, and
    no binding of the log chain's pattern or pass anywhere in the module."""
    from messagefoundry.support import redact as bundle_redact

    assert bundle_redact._MFB64.pattern == r"mfb64:v1:[A-Za-z0-9+/=]+"
    held = list(vars(bundle_redact).values())
    assert not any(value is redaction._BINARY_CARRIAGE for value in held)
    assert not any(value is redact_binary_carriage for value in held)
