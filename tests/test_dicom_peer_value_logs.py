# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What reaches the log of a value a DICOM peer sent that pynetdicom or pydicom refuses or flags as
non-conformant (owner ruling 2026-11-03, vault BACKLOG #5081): the line stays, with the element's
name and the reason, and the value is redacted. The SCP's own pre-read of each command set no longer
writes those lines a second time.

Every value here is synthetic: ``1.02.999.PLANTED`` is no real UID, and it is non-conformant twice
over, a component with a leading zero and one that is not a number. Every listener binds
``127.0.0.1`` on an ephemeral port.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import io
import logging
import socket
import struct
import sys
import threading
import time
import traceback
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

if TYPE_CHECKING:
    from pynetdicom.events import Event

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from tests.test_dicom_scp_admission import _running_scp  # noqa: E402
from tests.test_dicom_scp_pre_association import _a_held_association  # noqa: E402
from tests.test_dicom_scp_receipt_bounds import (  # noqa: E402
    _c_store_command,
    _first_bytes,
    _p_data,
)

_PLANTED = "1.02.999.PLANTED"
#: Under the DICOM root, so pynetdicom does not take it for a private UID, and non-conformant; the
#: length of the Explicit VR Big Endian UID it replaces in a captured request.
_PLANTED_ROOTED = "1.2.840.10008.PHI.9"
_NON_CONFORMANT = "Non-conformant 'Affected SOP Instance UID' value "


def _record(name: str, message: str, level: int = logging.WARNING) -> logging.LogRecord:
    return logging.LogRecord(name, level, __file__, 1, message, (), None)


def _filtered(name: str, message: str) -> str:
    record = _record(name, message)
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    return record.getMessage()


@contextlib.contextmanager
def _filter_removed() -> Iterator[None]:
    """The CONTROL's state: the redaction is off every logger it is on, the SCP's start does not put
    it back, and it is back on after."""
    install = dicom_module._redact_flagged_peer_values
    screen = dicom_module._screen_record
    for name in dicom_module._FILTERED_LOGGERS:
        logging.getLogger(name).removeFilter(dicom_module._PEER_VALUE_FILTER)
    dicom_module._redact_flagged_peer_values = lambda: None
    # The record factory stays installed and calls this by name, so this turns it off too.
    dicom_module._screen_record = lambda record: None
    try:
        yield
    finally:
        dicom_module._screen_record = screen
        dicom_module._redact_flagged_peer_values = install
        install()


# --- The line shapes -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "message", "expected"),
    [
        (
            "pynetdicom.utils",
            f"Non-conformant 'Affected SOP Instance UID' value '{_PLANTED}'",
            "Non-conformant 'Affected SOP Instance UID' value '[redacted]'",
        ),
        (
            "pynetdicom.utils",
            f"Invalid 'Affected SOP Instance UID' value '{_PLANTED}' - must not exceed 64 characters",
            "Invalid 'Affected SOP Instance UID' value '[redacted]' - must not exceed 64 characters",
        ),
        (
            # A value can hold a quote and the reason's own separator: none of it survives.
            "pynetdicom.utils",
            f"Invalid 'Move Originator AE Title' value 'A' - {_PLANTED}' - must not exceed 16 "
            "characters",
            "Invalid 'Move Originator AE Title' value '[redacted]' - must not exceed 16 characters",
        ),
        (
            "pydicom",
            f"Invalid value for VR UI: '{_PLANTED}'. Please see <https://dicom.nema.org/x> for "
            "allowed values for each VR.",
            "Invalid value for VR UI: [redacted]. Please see <https://dicom.nema.org/x> for "
            "allowed values for each VR.",
        ),
        (
            "pydicom",
            f"Invalid value for VR AE: '{_PLANTED}'.",
            "Invalid value for VR AE: [redacted]",
        ),
        (
            # pydicom joins its length and value messages into one line when a value fails both.
            "pydicom",
            "The value length (75) exceeds the maximum length of 64 allowed for VR UI. Invalid "
            f"value for VR UI: '{_PLANTED}'. Please see <https://dicom.nema.org/x> for allowed "
            "values for each VR.",
            "The value length (75) exceeds the maximum length of 64 allowed for VR UI. Invalid "
            "value for VR UI: [redacted]. Please see <https://dicom.nema.org/x> for allowed "
            "values for each VR.",
        ),
        (
            "pynetdicom._handlers",
            f"Their Implementation Class UID:    {_PLANTED}",
            "Their Implementation Class UID:    [redacted]",
        ),
        (
            "pynetdicom._handlers",
            f"      ={_PLANTED}",
            "      =[redacted]",
        ),
        (
            "pynetdicom.presentation",
            "The Transfer Syntax Name 'SMITH^JOHN MRN123' is non-conformant",
            "The Transfer Syntax Name '[redacted]' is non-conformant",
        ),
        (
            "pynetdicom.pdu_primitives",
            f"The Related General SOP Class UID '{_PLANTED}' is non-conformant",
            "The Related General SOP Class UID '[redacted]' is non-conformant",
        ),
        (
            # A title with more than one value is logged as its repr, which passes as a title.
            "pynetdicom._handlers",
            "Move Originator               : ['MRN1234', 'X']",
            "Move Originator               : [redacted]",
        ),
        (
            # A line of a known kind whose end the filter does not know loses all after the head.
            "pynetdicom.utils",
            f"Non-conformant 'Affected SOP Instance UID' value '{_PLANTED}' (a wording not seen)",
            "Non-conformant 'Affected SOP Instance UID' value '[redacted]",
        ),
        (
            "pynetdicom._handlers",
            f"Affected SOP Instance UID     : {_PLANTED}",
            "Affected SOP Instance UID     : [redacted]",
        ),
        (
            "pynetdicom._handlers",
            "Move Originator               : BAD\\AE",
            "Move Originator               : [redacted]",
        ),
        (
            # A DICOM-root UID that is not a transfer syntax: pynetdicom names it in a second line.
            "pynetdicom.presentation",
            "A UID has been added to 'transfer_syntax' that is not a transfer syntax: "
            f"'{_PLANTED_ROOTED}'",
            "A UID has been added to 'transfer_syntax' that is not a transfer syntax: '[redacted]'",
        ),
        (
            "pynetdicom._handlers",
            f"    Accepted Transfer Syntax: ={_PLANTED}",
            "    Accepted Transfer Syntax: =[redacted]",
        ),
        (
            "pynetdicom._handlers",
            "Calling Application Name:    BAD\\AE",
            "Calling Application Name:    [redacted]",
        ),
        (
            "pynetdicom._handlers",
            "Called Application Name:     BAD\\AE",
            "Called Application Name:     [redacted]",
        ),
        (
            "pynetdicom._handlers",
            "Their Implementation Version Name: BAD\\NAME",
            "Their Implementation Version Name: [redacted]",
        ),
        (
            "pynetdicom._handlers",
            f"Requested SOP Instance UID    : {_PLANTED}",
            "Requested SOP Instance UID    : [redacted]",
        ),
        (
            # A peer can send the word itself: it is no UID, so it is redacted like any other.
            "pynetdicom._handlers",
            "Affected SOP Instance UID     : None",
            "Affected SOP Instance UID     : [redacted]",
        ),
        (
            # pynetdicom prints "unknown" where a peer sent no class UID, and a peer can send that
            # word as its class UID; the line cannot say which, so it is redacted.
            "pynetdicom._handlers",
            "Their Implementation Class UID:    unknown",
            "Their Implementation Class UID:    [redacted]",
        ),
        (
            # The DUL logs the exception a PDU decode raised, and the refusal names the value.
            "pynetdicom.dul",
            f"Invalid 'Transfer Syntax Name' value '{_PLANTED}' - must not exceed 64 characters",
            "Invalid 'Transfer Syntax Name' value '[redacted]' - must not exceed 64 characters",
        ),
        (
            "pynetdicom.dul",
            "Unable to decode '31 2E 02 C3 A9' using the ascii codec(s)",
            "Unable to decode '[redacted]' using the ascii codec(s)",
        ),
    ],
    ids=[
        "non-conformant",
        "refused",
        "refused-with-a-quote",
        "pydicom",
        "pydicom-bare",
        "pydicom-joined",
        "association-dump",
        "transfer-syntax",
        "presentation",
        "pdu-primitives",
        "multi-valued-title",
        "unknown-end",
        "handler-uid",
        "handler-ae",
        "not-a-transfer-syntax",
        "accepted-transfer-syntax",
        "calling-ae",
        "called-ae",
        "version-name",
        "requested-instance",
        "peer-sent-none",
        "placeholder-word-from-a-peer",
        "dul-refused",
        "dul-undecodable",
    ],
)
def test_a_flagged_value_is_redacted_and_the_line_kept(
    name: str, message: str, expected: str
) -> None:
    assert _filtered(name, message) == expected


@pytest.mark.parametrize(
    ("name", "message"),
    [
        # Real UIDs and AE titles may be logged (owner ruling 2026-11-03): these are the CONTROL.
        ("pynetdicom._handlers", "Affected SOP Instance UID     : 1.2.826.0.1.3680043.2.1"),
        ("pynetdicom._handlers", "Affected SOP Class UID        : Comprehensive SR Storage"),
        ("pynetdicom._handlers", "Affected SOP Class UID        : 1.2.826.0.1.3680043.9.9"),
        ("pynetdicom._handlers", "Move Originator               : MODALITY1"),
        ("pydicom", "The value length (76) exceeds the maximum length of 64 allowed for VR UI."),
        (
            "pynetdicom.dimse_messages",
            "Non-conformant VM 2 for 'AffectedSOPInstanceUID', taking the first value",
        ),
        # A line that names no value keeps its reason.
        (
            "pynetdicom.utils",
            "Invalid 'Calling AE Title' value - must not consist entirely of spaces",
        ),
        ("pynetdicom._handlers", "    Abstract Syntax: =Verification SOP Class"),
        ("pynetdicom._handlers", "      =Implicit VR Little Endian"),
        ("pynetdicom._handlers", "    Accepted Transfer Syntax: =Implicit VR Little Endian"),
        ("pynetdicom._handlers", "Calling Application Name:    MODALITY1"),
        ("pynetdicom._handlers", "Their Implementation Version Name: PYNETDICOM_304"),
        # pynetdicom's placeholder where a peer sent no version name passes the title check, as the
        # same word sent by a peer would; and a title that spells "None" is still a title.
        ("pynetdicom._handlers", "Their Implementation Version Name:   unknown"),
        ("pynetdicom._handlers", "Move Originator               : None"),
        ("pynetdicom.presentation", "A non-conformant UID has been added to 'transfer_syntax'"),
        ("pynetdicom.dul", "Unable to decode the received PDU data"),
    ],
)
def test_a_conformant_value_and_a_line_with_no_value_pass_unchanged(
    name: str, message: str
) -> None:
    assert _filtered(name, message) == message


def test_a_traceback_the_filter_cannot_read_is_withheld_not_raised() -> None:
    class Unprintable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("no message")

    # The DUL's own shape: LOGGER.exception(exc), so the record's message is the exception too.
    unprintable = Unprintable()
    record = logging.LogRecord(
        "pynetdicom.dul",
        logging.ERROR,
        __file__,
        1,
        unprintable,
        (),
        (Unprintable, unprintable, None),
    )
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert record.exc_info is None
    assert record.exc_text is not None
    assert record.exc_text.endswith("Unprintable: [message withheld]")


def _refusal_from_a_codec_error() -> logging.LogRecord:
    """A DUL record whose exception is a refusal with the planted value, raised during a decode error,
    so ``safe_traceback`` rewrites the chain."""
    refusal = f"Invalid 'Transfer Syntax Name' value '{_PLANTED}' - must not exceed 64 characters"
    try:
        try:
            b"\xc3".decode("ascii")
        except UnicodeDecodeError:
            raise ValueError(refusal)  # noqa: B904 - the implicit context is the case under test
    except ValueError as exc:
        info = (ValueError, exc, exc.__traceback__)
        return logging.LogRecord("pynetdicom.dul", logging.ERROR, __file__, 1, exc, (), info)
    raise AssertionError("the refusal was not raised")


def test_a_rewritten_traceback_keeps_the_codec_error_protection() -> None:
    record = _refusal_from_a_codec_error()
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert record.exc_info is None and record.exc_text is not None
    assert "value '[redacted]' - must not exceed 64 characters" in record.exc_text
    # Rendered by safe_traceback, which names no byte a codec failed on (vault BACKLOG #3185).
    assert "UnicodeDecodeError" in record.exc_text
    assert _PLANTED not in record.exc_text and "0xc3" not in record.exc_text


def test_a_traceback_rendered_without_the_private_line_is_withheld(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A CPython with no TracebackException._str makes safe_traceback fall back to safe_exc's own
    # rewrite of the root line, which the filter's replace does not find; that must not leak the value.
    original = traceback.TracebackException.__init__

    def init(self: traceback.TracebackException, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.__dict__["_renamed"] = self.__dict__.pop("_str")

    monkeypatch.setattr(traceback.TracebackException, "__init__", init)
    record = _refusal_from_a_codec_error()
    passed = dicom_module._PEER_VALUE_FILTER.filter(record)
    monkeypatch.undo()  # before any assertion, so pytest can render a failure
    assert passed is True
    assert record.exc_info is None and record.exc_text is not None
    assert _PLANTED not in record.exc_text, record.exc_text
    assert record.exc_text == "ValueError (traceback withheld: it did not render)"


def test_a_message_that_will_not_format_is_withheld_with_its_args(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The handler's handleError prints a record's args to stderr, which the service writes to a file.
    record = _refusal_from_a_codec_error()
    record.msg, record.args = "Unable to decode %d", (_PLANTED,)
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert not record.args
    assert _PLANTED not in record.getMessage()
    stream = io.StringIO()
    logging.StreamHandler(stream).handle(record)
    written = stream.getvalue() + capsys.readouterr().err
    assert _PLANTED not in written, written
    assert "value '[redacted]' - must not exceed 64 characters" in written


def test_a_traceback_with_no_flagged_value_is_left_to_the_formatter() -> None:
    try:
        raise ValueError("Unable to decode the received PDU data")
    except ValueError as exc:
        info = (ValueError, exc, exc.__traceback__)
    record = logging.LogRecord("pynetdicom.dul", logging.ERROR, __file__, 1, "x", (), info)
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert record.exc_info == info and record.exc_text is None


def test_the_filter_is_on_each_logger_by_name() -> None:
    # A filter on a parent logger does not see a child's records, so each is named.
    for name in dicom_module._FILTERED_LOGGERS:
        assert dicom_module._PEER_VALUE_FILTER in logging.getLogger(name).filters, name


# --- The pre-read, and pydicom's warning copy ------------------------------------------------------


def _planted_command() -> bytes:
    return _c_store_command(instance_uid=_PLANTED.encode("ascii"))


def test_the_pre_read_writes_no_line_for_a_command_pynetdicom_will_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        assert dicom_module._read_command_set(_planted_command()) is not None
    assert caplog.records == [], [r.getMessage() for r in caplog.records]
    with caplog.at_level(logging.DEBUG), _filter_removed():  # CONTROL: the same capture sees them
        assert dicom_module._read_command_set(_planted_command()) is not None
    assert any(_PLANTED in r.getMessage() for r in caplog.records), caplog.text


def test_the_pre_read_writes_its_lines_once_redacted_when_the_message_ends_there(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A refused value ends the association, so pynetdicom never reads it: this copy is the only one.
    # Over 64 characters and not a valid UID either, so pydicom joins both its messages in one line.
    refused = "1.02." + "9" * 70
    with caplog.at_level(logging.DEBUG):
        assert (
            dicom_module._read_command_set(_c_store_command(instance_uid=refused.encode())) is None
        )
    lines = [r.getMessage() for r in caplog.records]
    redacted = (
        "Invalid 'Affected SOP Instance UID' value '[redacted]' - must not exceed 64 characters"
    )
    assert redacted in lines, lines
    # The bare assert is the guard tests/test_vacuous_absence_assert_lint.py reads.
    assert caplog.records
    assert not [line for line in lines if refused in line], lines


def test_pydicoms_warning_copy_is_ignored() -> None:
    with warnings.catch_warnings(record=True) as caught:
        # pytest put the warnings filters back after collecting this module, which is where the
        # import installed this one, so it is installed again here, as the SCP's start does.
        dicom_module._redact_flagged_peer_values()
        dicom_module._read_command_set(_planted_command())
    assert not [w for w in caught if _PLANTED in str(w.message)]
    with warnings.catch_warnings(record=True) as caught:  # CONTROL: unignored, it carries the value
        warnings.simplefilter("always")
        dicom_module._read_command_set(_planted_command())
    assert [w for w in caught if _PLANTED in str(w.message)]


# --- End to end, on an association ---------------------------------------------------------------


async def _store_planted(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Send one whole C-STORE whose command names the planted UID, and return every record logged
    until the SCP has answered it, which it does only after pynetdicom has read the message."""
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            with caplog.at_level(logging.DEBUG):
                sock.sendall(_p_data(0x03, _planted_command()) + _p_data(0x02, b"\x00" * 16))
                answer = await asyncio.to_thread(_first_bytes, sock, 1)
                assert answer, "the SCP did not answer the C-STORE"
        finally:
            sock.close()
    return list(caplog.records)


def _flagged(records: list[logging.LogRecord]) -> list[tuple[str, str]]:
    """Each pynetdicom non-conformant line for the instance UID, with the thread that wrote it."""
    return [
        (r.threadName or "", r.getMessage())
        for r in records
        if r.name.startswith("pynetdicom") and r.getMessage().startswith(_NON_CONFORMANT)
    ]


async def test_a_planted_uid_never_reaches_the_log_and_its_line_is_written_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    records = await _store_planted(caplog)
    assert records
    leaked = [f"{r.name}: {r.getMessage()}" for r in records if _PLANTED in r.getMessage()]
    assert leaked == []
    # Two copies are pynetdicom's own: its read of the message on the DUL thread, and the C-STORE
    # response it builds from the request on the Association thread. The pre-read's is gone.
    flagged = _flagged(records)
    assert [line for _, line in flagged] == [f"{_NON_CONFORMANT}'[redacted]'"] * 2, flagged


async def test_the_capture_sees_the_planted_uid_and_the_pre_reads_copy_without_the_filter(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The CONTROL for the test above: the same capture, without the filter, sees the value, and sees
    # the line a third time, from the SCP's pre-read, ahead of pynetdicom's two.
    with _filter_removed():
        records = await _store_planted(caplog)
    flagged = _flagged(records)
    assert [line for _, line in flagged] == [f"{_NON_CONFORMANT}'{_PLANTED}'"] * 3, flagged


# --- The pins ------------------------------------------------------------------------------------


def test_the_line_shapes_the_filter_reads_are_still_pynetdicoms_and_pydicoms() -> None:
    """Read against pynetdicom 3.0.4 and pydicom 3.0.2. A reworded line would pass the filter whole."""
    import inspect

    from pydicom import misc, valuerep
    from pynetdicom import _handlers, utils

    set_uid = inspect.getsource(utils.set_uid)
    assert "msg = f\"Invalid '{name}' value '{value}' - {reason}\"" in set_uid
    assert "LOGGER.warning(f\"Non-conformant '{name}' value '{value}'\")" in set_uid
    assert "msg = f\"Invalid '{name}' value '{value}' - {reason}\"" in inspect.getsource(
        utils.set_ae
    )
    assert 'f"Invalid value for VR {vr}: {value!r}."' in inspect.getsource(valuerep.validate_regex)
    assert "LOGGER.warning(msg)" in inspect.getsource(misc.warn_and_log)
    store_rq = inspect.getsource(_handlers._recv_c_store_rq)
    assert 'f"Affected SOP Instance UID     : {cs.AffectedSOPInstanceUID}"' in store_rq
    assert 'f"Move Originator               : {move_aet}"' in store_rq
    from pynetdicom import pdu_primitives, presentation

    presentation_source = inspect.getsource(presentation)
    assert "f\"The Transfer Syntax Name '{syntax}' is non-conformant\"" in presentation_source
    assert "\"A UID has been added to 'transfer_syntax' that is not a \"" in presentation_source
    assert "f\"transfer syntax: '{syntax}'\"" in presentation_source
    assert "f\"The Related General SOP Class UID '{uid}' is \"" in inspect.getsource(pdu_primitives)
    associate_ac = inspect.getsource(_handlers._receive_associate_ac)
    assert '"    Accepted Transfer Syntax: "' in associate_ac
    assert 'f"Their Implementation Version Name: {their_version}"' in associate_ac
    associate_rq = inspect.getsource(_handlers._receive_associate_rq)
    assert 'f"Calling Application Name:    {pdu.calling_ae_title}"' in associate_rq
    assert 'f"Called Application Name:     {pdu.called_ae_title}"' in associate_rq
    # The only placeholder pynetdicom prints on a line the filter reads; see _kept.
    assert 'their_class_uid: str | UID = "unknown"' in associate_rq
    assert 'f"Requested SOP Instance UID    : {cs.RequestedSOPInstanceUID}"' in inspect.getsource(
        _handlers._recv_n_get_rq
    )
    from pynetdicom import dul

    read_pdu = inspect.getsource(dul.DULServiceProvider._read_pdu_data)
    assert 'LOGGER.error("Unable to decode the received PDU data")\n' in read_pdu
    assert "f\"Unable to decode '{as_hex}' using the {', '.join(codecs)} codec(s)\"" in (
        inspect.getsource(utils.decode_bytes)
    )


def test_the_filter_was_read_against_these_library_versions() -> None:
    """The shapes are a list read from these two releases. A new release can add a line of a shape
    the list lacks, which would pass whole, so a version change fails here until it is read."""
    import pydicom
    import pynetdicom

    assert (pynetdicom.__version__, pydicom.__version__) == ("3.0.4", "3.0.2")


def test_the_phi_record_states_the_ruling() -> None:
    root = Path(__file__).resolve().parents[1]
    phi = (root / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert "third-party library loggers" in phi
    dicom = (root / "docs" / "DICOM.md").read_text(encoding="utf-8")
    assert "the value reads `[redacted]`" in dicom
    # Both say the filter is a list of known shapes, which a version pin guards; not a guarantee.
    assert "pin tests fail when either library's version changes" in " ".join(phi.split())
    assert "fail when either library's version changes" in " ".join(dicom.split())
    # The pins guard the tests' environment, never a site's install; both pages must say so.
    assert "not a site's own install" in " ".join(phi.split())
    assert "They do not reach a site's own install" in " ".join(dicom.split())


@pytest.mark.parametrize(
    ("value", "logged"),
    [
        (_PLANTED, "[redacted]"),
        ("1.2.826.0.1.3680043.2.1", "1.2.826.0.1.3680043.2.1"),  # CONTROL: a real UID may be logged
        ("", ""),
        (None, ""),
    ],
)
def test_the_engines_own_lines_name_an_object_uid_only_when_it_is_conformant(
    value: str | None, logged: str
) -> None:
    assert dicom_module._loggable_uid(value) == logged


def test_the_engines_uid_check_writes_no_line_of_its_own(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert dicom_module._loggable_uid("1.02." + "9" * 70) == "[redacted]"
    assert caplog.records == [] and caught == [], caplog.text


def test_pydicoms_joined_line_is_still_its_two_messages() -> None:
    """Read against pydicom 3.0.2: the shape the joined test case above stands for."""
    import inspect

    from pydicom import valuerep

    joined = inspect.getsource(valuerep.validate_length_and_type_and_regex)
    assert 'msg = " ".join([msg1, msg2]).strip()' in joined


#: A non-conformant implementation class UID the length of pynetdicom's own, so that it replaces
#: that UID in a captured request without changing a length field.
_PLANTED_IMPLEMENTATION = "1.02.999." + "9" * 23


async def _associate_planted(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    from pynetdicom import PYNETDICOM_IMPLEMENTATION_UID

    from tests.test_dicom_scp_pre_association import (
        _ASSOCIATE_AC,
        _a_real_association_request,
        _stall,
    )

    request = await asyncio.to_thread(_a_real_association_request)
    own = PYNETDICOM_IMPLEMENTATION_UID.encode("ascii")
    assert len(own) == len(_PLANTED_IMPLEMENTATION) and request.count(own) == 1
    planted = request.replace(own, _PLANTED_IMPLEMENTATION.encode("ascii"))
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        with caplog.at_level(logging.DEBUG):
            sock = await asyncio.to_thread(_stall, scp.sockport, planted)
            try:
                sock.settimeout(5.0)
                assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
            finally:
                sock.close()
    return list(caplog.records)


def _implementation_lines(records: list[logging.LogRecord]) -> list[str]:
    return [
        r.getMessage()
        for r in records
        if r.name == "pynetdicom.utils" and "'Implementation Class UID'" in r.getMessage()
    ]


async def test_the_association_request_check_writes_no_second_copy_and_no_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    filtered = await _associate_planted(caplog)
    caplog.clear()
    with _filter_removed():  # CONTROL: the same capture sees the value, and the pre-read's copy
        unfiltered = await _associate_planted(caplog)
    assert any(_PLANTED_IMPLEMENTATION in r.getMessage() for r in unfiltered)
    assert filtered
    assert not [r.getMessage() for r in filtered if _PLANTED_IMPLEMENTATION in r.getMessage()]
    assert _implementation_lines(unfiltered), "CONTROL: the planted UID was flagged"
    # The check decodes the request as the DUL does, so it wrote as many copies as the DUL writes.
    assert 2 * len(_implementation_lines(filtered)) == len(_implementation_lines(unfiltered))


def test_a_long_line_costs_one_pass() -> None:
    # A line that opens like pydicom's and never ends like it: a pattern that backtracked over the
    # value took seconds here at 40 KB, on whatever thread logged it.
    value = "'" + ("a. Please see <x" * 20000) + "'."
    started = time.monotonic()
    redacted = _filtered("pydicom", f"Invalid value for VR UR: {value}")
    assert time.monotonic() - started < 1.0
    assert redacted == "Invalid value for VR UR: [redacted]"


def test_a_hold_inside_another_hands_back_to_it() -> None:
    log = logging.getLogger("pynetdicom.utils")
    with dicom_module._logs_held() as outer:
        with dicom_module._logs_held() as inner:
            log.warning("inner")
        log.warning("outer")
    assert [r.getMessage() for r in inner] == ["inner"]
    assert [r.getMessage() for r in outer] == ["outer"]
    assert getattr(dicom_module._PRE_READ, "held", None) is None


# --- The shapes added for the transfer syntax, the dump labels and the DUL (vault BACKLOG #5081) ---

_REDACTED_MARK = "[redacted]"


def _read_pdu(sock: socket.socket) -> bytes:
    got = bytearray()
    while len(got) < 6 or len(got) < 6 + int.from_bytes(got[2:6], "big"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        got.extend(chunk)
    return bytes(got)


@functools.cache
def _captured_request() -> bytes:
    from tests.test_dicom_scp_pre_association import _a_real_association_request

    return _a_real_association_request()


@functools.cache
def _captured_ac() -> bytes:
    """The A-ASSOCIATE-AC a plain pynetdicom SCP sends for :func:`_captured_request`."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    ae = AE(ae_title="PLAINSCP")
    ae.add_supported_context(Verification)
    server = ae.start_server(("127.0.0.1", 0), block=False)
    assert server is not None  # block=False returns the server
    try:
        with socket.create_connection(server.server_address[:2], timeout=5.0) as sock:
            sock.sendall(_captured_request())
            ac = _read_pdu(sock)
            sock.sendall(b"\x07\x00\x00\x00\x00\x04\x00\x00\x00\x00")  # A-ABORT
    finally:
        server.shutdown()
    assert ac[:1] == b"\x02", ac[:1]
    return ac


def _formatted(records: list[logging.LogRecord]) -> list[str]:
    """Each record as a handler writes it, its traceback included."""
    formatter = logging.Formatter("%(name)s: %(message)s")
    return [formatter.format(r) for r in records]


def _associate_against(
    ac: bytes,
    caplog: pytest.LogCaptureFixture,
    then: Callable[[Any], None] | None = None,
    reply: bytes | None = None,
) -> list[logging.LogRecord]:
    """A pynetdicom SCU, as the engine's DICOM destination uses, asks a peer for an association and
    gets ``ac`` back, and does ``then`` on it if it is established. With ``reply``, the peer answers
    the next PDU with that command set. Every record logged meanwhile is returned."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    with socket.create_server(("127.0.0.1", 0)) as listener:

        def answer() -> None:
            conn, _ = listener.accept()
            with conn, contextlib.suppress(OSError):
                conn.settimeout(5.0)
                _read_pdu(conn)
                conn.sendall(ac)
                if reply is not None:
                    _read_pdu(conn)
                    conn.sendall(_p_data(0x03, reply))
                while conn.recv(4096):
                    pass

        peer = threading.Thread(target=answer)
        peer.start()
        ae = AE(ae_title="MODALITY1")
        ae.acse_timeout = 5
        ae.dimse_timeout = 5
        ae.add_requested_context(Verification)
        try:
            with caplog.at_level(logging.DEBUG):
                assoc = ae.associate("127.0.0.1", listener.getsockname()[1], ae_title="PLAINSCP")
                if assoc.is_established:
                    try:
                        if then is not None:
                            then(assoc)
                    finally:
                        if assoc.is_established:  # a refused reply has already ended it
                            assoc.abort()
        finally:
            peer.join(10.0)
    return list(caplog.records)


def _non_conformant_accepted_syntax() -> tuple[bytes, str]:
    planted = "1.02.999.PLANTED9"  # the length of the Implicit VR Little Endian UID it replaces
    accepted = b"\x40\x00\x00\x11" + b"1.2.840.10008.1.2"
    ac = _captured_ac()
    assert ac.count(accepted) == 1
    return ac.replace(accepted, b"\x40\x00\x00\x11" + planted.encode("ascii")), planted


def _over_long_accepted_syntax() -> tuple[bytes, str]:
    """An AC whose accepted transfer syntax pynetdicom refuses as it decodes the PDU."""
    from pydicom.uid import UID
    from pynetdicom.pdu import A_ASSOCIATE_AC

    planted = "1.02.999." + "9" * 70
    pdu = A_ASSOCIATE_AC()
    pdu.decode(_captured_ac())
    # Set past the setter, which would refuse it here as the peer's decoder refuses it there.
    pdu.presentation_context[0].transfer_syntax_sub_item[0]._transfer_syntax_name = UID(planted)
    return pdu.encode(), planted


@pytest.mark.parametrize(
    ("planting", "line_start"),
    [
        (_non_conformant_accepted_syntax, "    Accepted Transfer Syntax: "),
        (_over_long_accepted_syntax, "pynetdicom.dul: Invalid 'Transfer Syntax Name' value "),
    ],
    ids=["accepted-transfer-syntax", "dul-decode-failure"],
)
def test_a_peer_scps_flagged_value_never_reaches_the_scu_log(
    planting: Callable[[], tuple[bytes, str]], line_start: str, caplog: pytest.LogCaptureFixture
) -> None:
    ac, planted = planting()
    with _filter_removed():  # CONTROL: the same capture sees the value, on the line under test
        unfiltered = _formatted(_associate_against(ac, caplog))
    assert [line for line in unfiltered if planted in line and line_start in line], unfiltered
    caplog.clear()
    filtered = _formatted(_associate_against(ac, caplog))
    assert filtered
    assert not [line for line in filtered if planted in line], filtered
    assert [line for line in filtered if line_start in line and _REDACTED_MARK in line], filtered


async def test_a_proposed_non_transfer_syntax_never_reaches_the_scp_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from tests.test_dicom_scp_pre_association import _ASSOCIATE_AC, _stall

    big_endian = b"\x40\x00\x00\x13" + b"1.2.840.10008.1.2.2"
    request = _captured_request()
    assert request.count(big_endian) == 1
    planted = request.replace(big_endian, b"\x40\x00\x00\x13" + _PLANTED_ROOTED.encode("ascii"))

    async def associate() -> list[str]:
        async with _running_scp({"timeout_seconds": 30.0}) as scp:
            with caplog.at_level(logging.DEBUG):
                sock = await asyncio.to_thread(_stall, scp.sockport, planted)
                try:
                    sock.settimeout(5.0)
                    assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
                finally:
                    sock.close()
        return _formatted(list(caplog.records))

    with _filter_removed():  # CONTROL: unfiltered, pynetdicom's second line names the value
        unfiltered = await associate()
    assert [
        line for line in unfiltered if "not a transfer syntax" in line and _PLANTED_ROOTED in line
    ]
    caplog.clear()
    filtered = await associate()
    assert filtered
    assert not [line for line in filtered if _PLANTED_ROOTED in line], filtered
    assert [line for line in filtered if "not a transfer syntax: '[redacted]'" in line], filtered


def _request_dump(mutate: Callable[[Any], None]) -> None:
    """pynetdicom's own dump of a received association request, with one field set past its setter
    to a value its decoder would refuse on the wire."""
    from pynetdicom import _handlers
    from pynetdicom.pdu import A_ASSOCIATE_RQ

    pdu = A_ASSOCIATE_RQ()
    pdu.decode(_captured_request())
    mutate(pdu)
    _handlers._receive_associate_rq(cast("Event", SimpleNamespace(pdu=pdu)))


def _set_user_item(kind: str, attribute: str, value: str) -> Callable[[Any], None]:
    def mutate(pdu: Any) -> None:
        item = next(i for i in pdu.user_information.user_data if type(i).__name__ == kind)
        setattr(item, attribute, value)

    return mutate


def _command_dump(handler: str, **elements: Any) -> None:
    """pynetdicom's own dump of a received DIMSE command naming ``elements``."""
    from pydicom import Dataset
    from pynetdicom import _handlers

    command = Dataset()
    with warnings.catch_warnings():
        warnings.simplefilter(
            "ignore"
        )  # pydicom flags the planted UID as it is set; not under test
        for keyword, value in elements.items():
            setattr(command, keyword, value)
    message = SimpleNamespace(command_set=command, context_id=1, data_set=None)
    getattr(_handlers, handler)(SimpleNamespace(message=message))


_TITLE = "MRN\\4321"  # a backslash: no AE title may hold one


@pytest.mark.parametrize(
    ("dump", "planted", "line_start"),
    [
        (
            lambda: _request_dump(lambda pdu: setattr(pdu, "_calling_aet", _TITLE)),
            _TITLE,
            "Calling Application Name:",
        ),
        (
            lambda: _request_dump(lambda pdu: setattr(pdu, "_called_aet", _TITLE)),
            _TITLE,
            "Called Application Name:",
        ),
        (
            lambda: _request_dump(
                _set_user_item(
                    "ImplementationVersionNameSubItem", "_implementation_version_name", _TITLE
                )
            ),
            _TITLE,
            "Their Implementation Version Name:",
        ),
        (
            # A class UID a peer sends as the word pynetdicom prints where there is none.
            lambda: _request_dump(
                _set_user_item(
                    "ImplementationClassUIDSubItem", "_implementation_class_uid", "unknown"
                )
            ),
            "unknown",
            "Their Implementation Class UID:",
        ),
        (
            lambda: _command_dump(
                "_recv_n_get_rq",
                MessageID=1,
                RequestedSOPClassUID="1.2.840.10008.5.1.1.1",
                RequestedSOPInstanceUID=_PLANTED,
            ),
            _PLANTED,
            "Requested SOP Instance UID",
        ),
        (
            lambda: _command_dump(
                "_recv_c_store_rq",
                MessageID=1,
                Priority=0,
                AffectedSOPClassUID="1.2.840.10008.5.1.4.1.1.88.33",
                AffectedSOPInstanceUID="None",
            ),
            "None",
            "Affected SOP Instance UID",
        ),
    ],
    ids=[
        "calling-ae",
        "called-ae",
        "version-name",
        "placeholder-word-from-a-peer",
        "requested-instance",
        "peer-sent-none",
    ],
)
def test_pynetdicoms_dump_of_a_flagged_value_is_redacted(
    dump: Callable[[], None], planted: str, line_start: str, caplog: pytest.LogCaptureFixture
) -> None:
    def dumped() -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dump()
        return [r.getMessage() for r in caplog.records if r.name == "pynetdicom._handlers"]

    with _filter_removed():  # CONTROL: the dump names the planted value on its line
        unfiltered = dumped()
    assert [line for line in unfiltered if line.startswith(line_start) and line.endswith(planted)]
    filtered = dumped()
    lines = [line for line in filtered if line.startswith(line_start)]
    assert lines and all(line.endswith(_REDACTED_MARK) for line in lines), filtered


# --- A peer's credentials in the association dumps (vault BACKLOG #6637, item 6) -------------------

_PLANTED_USERNAME = "planted-user-6637"
_PLANTED_PASSWORD = "planted-pass-6637"


def _a_request_with_credentials() -> Any:
    """An A-ASSOCIATE-RQ whose user identity item is a username and password, decoded from bytes."""
    from pynetdicom.pdu import A_ASSOCIATE_RQ
    from pynetdicom.pdu_items import UserIdentitySubItemRQ

    pdu = A_ASSOCIATE_RQ()
    pdu.decode(_captured_request())
    item = UserIdentitySubItemRQ()
    item.user_identity_type = 2
    item.positive_response_requested = 0
    item.primary_field = _PLANTED_USERNAME.encode("ascii")
    item.secondary_field = _PLANTED_PASSWORD.encode("ascii")
    user_information = pdu.user_information
    assert user_information is not None
    user_information.user_data.append(item)
    decoded = A_ASSOCIATE_RQ()
    decoded.decode(pdu.encode())
    return decoded


@pytest.mark.parametrize("dump", ["_receive_associate_rq", "_send_associate_rq"])
def test_the_association_dump_never_writes_a_username_or_password(
    dump: str, caplog: pytest.LogCaptureFixture
) -> None:
    from pynetdicom import _handlers

    pdu = _a_request_with_credentials()

    def dumped() -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            getattr(_handlers, dump)(cast("Event", SimpleNamespace(pdu=pdu)))
        return _formatted(list(caplog.records))

    with _filter_removed():  # CONTROL: the dump names both, in cleartext
        unfiltered = dumped()
    assert [line for line in unfiltered if f"Username: [{_PLANTED_USERNAME}]" in line]
    assert [line for line in unfiltered if f"Password: [{_PLANTED_PASSWORD}]" in line]
    filtered = dumped()
    assert filtered
    assert not [line for line in filtered if _PLANTED_USERNAME in line], filtered
    assert not [line for line in filtered if _PLANTED_PASSWORD in line], filtered
    # The lines stay, so a reader can still see that an identity was negotiated, and of which kind.
    assert "pynetdicom._handlers:   Username: [redacted]" in filtered
    assert "pynetdicom._handlers:   Password: [redacted]" in filtered
    assert [line for line in filtered if "Authentication Mode: 2" in line]


async def test_a_peers_credentials_never_reach_the_scp_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from tests.test_dicom_scp_pre_association import _ASSOCIATE_AC, _stall

    request = _a_request_with_credentials().encode()

    async def associate() -> list[str]:
        async with _running_scp({"timeout_seconds": 30.0}) as scp:
            with caplog.at_level(logging.DEBUG):
                sock = await asyncio.to_thread(_stall, scp.sockport, request)
                try:
                    sock.settimeout(5.0)
                    assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
                finally:
                    sock.close()
        return _formatted(list(caplog.records))

    with _filter_removed():  # CONTROL: the same capture sees the password on the SCP's own path
        unfiltered = await associate()
    assert [line for line in unfiltered if _PLANTED_PASSWORD in line]
    caplog.clear()
    filtered = await associate()
    assert filtered
    leaked = [line for line in filtered if _PLANTED_PASSWORD in line or _PLANTED_USERNAME in line]
    assert leaked == []
    assert "pynetdicom._handlers:   Password: [redacted]" in filtered


def test_the_credential_lines_the_filter_reads_are_still_pynetdicoms() -> None:
    import inspect

    from pynetdicom import _handlers

    for dump in (_handlers._receive_associate_rq, _handlers._send_associate_rq):
        source = inspect.getsource(dump)
        assert "f\"  Username: [{primary.decode('utf-8')}]\"" in source
        assert "f\"  Password: [{secondary.decode('utf-8')}]\"" in source


# --- A refusal inside an exception, on any logger that logs one (vault BACKLOG #6637, item 5) ------

_REFUSAL = f"Invalid 'Affected SOP Instance UID' value '{_PLANTED}' - must not exceed 64 characters"
_PYDICOM_REFUSAL = (
    f"Invalid value for VR UI: '{_PLANTED}'. Please see <https://dicom.nema.org/x> for allowed "
    "values for each VR."
)


def _raised_from(inner: str) -> BaseException:
    """A plain error raised from a refusal, so only the traceback's chain names the value."""
    try:
        try:
            raise ValueError(inner)
        except ValueError as refusal:
            raise RuntimeError("the handler failed") from refusal
    except RuntimeError as exc:
        return exc


def _raised_during(inner: str) -> BaseException:
    try:
        try:
            raise ValueError(inner)
        except ValueError:
            raise RuntimeError("the handler failed")  # noqa: B904 - the implicit context is the case
    except RuntimeError as exc:
        return exc


def _raised_through_pydicoms_wrapper(inner: str) -> BaseException:
    """pydicom's ``tag_in_exception``, which builds a new message around the refusal and a copy of
    its traceback, the shape an encode failure has when ``pynetdicom.dsutils`` logs it."""
    from pydicom.tag import Tag, tag_in_exception

    try:
        with tag_in_exception(Tag(0x0000, 0x1000)):
            raise ValueError(inner)
    except ValueError as exc:
        return exc
    raise AssertionError("the refusal was not raised")


def _logged(name: str, exc: BaseException, caplog: pytest.LogCaptureFixture) -> list[str]:
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        # As pynetdicom's own `LOGGER.exception(exc)`, from inside the except block that caught it.
        logging.getLogger(name).exception(exc, exc_info=exc)
    return _formatted(list(caplog.records))


@pytest.mark.parametrize(
    "name",
    [
        "pynetdicom.acse",
        "pynetdicom.association",
        "pynetdicom.dimse",
        "pynetdicom.dsutils",
        "pynetdicom.dul",
        "pynetdicom.events",
        "pynetdicom.fsm",
        "pynetdicom.service_class",
        "pynetdicom.transport",
        "pynetdicom.utils",
    ],
)
@pytest.mark.parametrize("inner", [_REFUSAL, _PYDICOM_REFUSAL], ids=["pynetdicom", "pydicom"])
@pytest.mark.parametrize(
    "raising",
    [_raised_from, _raised_during, _raised_through_pydicoms_wrapper],
    ids=["cause", "context", "wrapped"],
)
def test_a_refusal_in_a_logged_exception_is_redacted_on_every_logger(
    name: str,
    inner: str,
    raising: Callable[[str], BaseException],
    caplog: pytest.LogCaptureFixture,
) -> None:
    exc = raising(inner)
    with _filter_removed():  # CONTROL: the handler's output names the value
        assert [line for line in _logged(name, exc, caplog) if _PLANTED in line]
    lines = _logged(name, exc, caplog)
    assert lines
    assert not [line for line in lines if _PLANTED in line], lines
    assert [line for line in lines if _REDACTED_MARK in line], lines


def test_every_pynetdicom_module_that_logs_an_exception_is_filtered() -> None:
    """A module that logs one and is not on the filter would write a chained refusal whole."""
    import pkgutil

    import pynetdicom

    logging_exceptions = {
        f"pynetdicom.{module.name}"
        for module in pkgutil.iter_modules(pynetdicom.__path__)
        if not module.ispkg
        and "LOGGER.exception("
        in (Path(pynetdicom.__path__[0]) / f"{module.name}.py").read_text(encoding="utf-8")
    }
    assert "pynetdicom.events" in logging_exceptions  # CONTROL: the scan finds a known one
    assert logging_exceptions <= set(dicom_module._FILTERED_LOGGERS)


def test_a_value_ahead_of_another_shape_in_one_message_is_redacted() -> None:
    # The first head in the text decides, whichever order the shapes are listed in.
    message = f"Unable to decode '{_PLANTED}' using the ascii codec(s): {_REFUSAL}"
    assert _PLANTED not in _filtered("pynetdicom.events", message)


# --- pydicom's character set and IS/DS lines, and "No presentation context" (#6637, item 7) --------


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            f"Incorrect value for Specific Character Set '{_PLANTED}' - assuming 'ISO_IR {_PLANTED}'",
            "Incorrect value for Specific Character Set '[redacted]",
        ),
        (
            f"Unknown encoding '{_PLANTED}' - using default encoding instead",
            "Unknown encoding '[redacted]' - using default encoding instead",
        ),
        (f"Unknown encoding '{_PLANTED}'", "Unknown encoding '[redacted]"),
        (
            f"Value 'ISO_IR 192' for Specific Character Set does not allow code extensions, "
            f"ignoring: {_PLANTED}, {_PLANTED}",
            "Value 'ISO_IR 192' for Specific Character Set does not allow code extensions, "
            "ignoring: [redacted]",
        ),
        (
            f'Value "{_PLANTED}" is not valid for elements with a VR of DS',
            'Value "[redacted]" is not valid for elements with a VR of DS',
        ),
        (
            f'Value "{_PLANTED}" is not valid for elements with a VR of IS\n'
            "Set reading_validation_mode to WARN or IGNORE to bypass",
            'Value "[redacted]" is not valid for elements with a VR of IS\n'
            "Set reading_validation_mode to WARN or IGNORE to bypass",
        ),
        (
            # A value can hold the line's own fixed text: none of it survives.
            f'Value "x" is not valid for elements with a VR of DS {_PLANTED}" is not valid for '
            "elements with a VR of DS",
            'Value "[redacted]" is not valid for elements with a VR of DS',
        ),
    ],
    ids=["incorrect", "unknown", "unknown-raised", "code-extension", "ds", "is-raised", "quoted"],
)
def test_pydicoms_character_set_and_number_lines_lose_the_value(
    message: str, expected: str
) -> None:
    assert _filtered("pydicom", message) == expected


def _pydicom_flags_planted_values() -> None:
    """pydicom's own calls for each line, each with the planted value or one carrying it."""
    from pydicom import charset, config
    from pydicom.valuerep import DSdecimal

    charset._warn_about_invalid_encoding(_PLANTED, "ISO_IR 192")
    charset._warn_about_invalid_encoding(_PLANTED)
    charset._handle_illegal_standalone_encodings(["ISO_IR 192", _PLANTED], ["utf8", "ascii"])
    DSdecimal(_PLANTED_NAN, validation_mode=config.WARN)


def _flags_from_inside_pydicom() -> None:
    """:func:`_pydicom_flags_planted_values`, its charset calls made from a frame in a pydicom
    module. They warn at stack level 2, so a warning is attributed to their caller, and the ignore
    is scoped by module."""
    from pydicom import charset, config
    from pydicom.valuerep import DSdecimal

    calls = (
        "charset._warn_about_invalid_encoding(planted, 'ISO_IR 192')\n"
        "charset._warn_about_invalid_encoding(planted)\n"
        "charset._handle_illegal_standalone_encodings(['ISO_IR 192', planted], ['utf8', 'ascii'])\n"
    )
    scope = {"__name__": "pydicom.charset", "charset": charset, "planted": _PLANTED}
    exec(calls, scope)  # noqa: S102 - a fixed string
    DSdecimal(_PLANTED_NAN, validation_mode=config.WARN)


#: A DS the decimal parser takes and the DS check refuses: the case that reaches pydicom's own line.
_PLANTED_NAN = "NaN"


def test_pydicoms_character_set_lines_never_reach_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with _filter_removed(), caplog.at_level(logging.DEBUG):  # CONTROL
            _pydicom_flags_planted_values()
        unfiltered = _formatted(list(caplog.records))
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            _pydicom_flags_planted_values()
        filtered = _formatted(list(caplog.records))
    assert len([line for line in unfiltered if _PLANTED in line]) == 3, unfiltered
    assert [line for line in unfiltered if f'Value "{_PLANTED_NAN}"' in line], unfiltered
    assert len(filtered) == len(unfiltered)
    assert not [line for line in filtered if _PLANTED in line], filtered
    assert not [line for line in filtered if f'Value "{_PLANTED_NAN}"' in line], filtered
    assert 'pydicom: Value "[redacted]" is not valid for elements with a VR of DS' in filtered


def test_pydicoms_warning_copies_of_those_lines_are_ignored() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")  # so only the filters installed next can ignore them
        dicom_module._redact_flagged_peer_values()
        _flags_from_inside_pydicom()
    assert not [w for w in caught if _PLANTED in str(w.message)], [str(w.message) for w in caught]
    assert not [w for w in caught if "is not valid for elements" in str(w.message)]
    with warnings.catch_warnings(record=True) as caught:  # CONTROL: unignored, they carry the value
        warnings.simplefilter("always")
        _flags_from_inside_pydicom()
    assert len([w for w in caught if _PLANTED in str(w.message)]) == 3


def test_the_character_set_and_number_lines_are_still_pydicoms() -> None:
    import inspect

    from pydicom import charset, valuerep

    source = inspect.getsource(charset)
    assert "f\"Incorrect value for Specific Character Set '{encoding}' - \"" in source
    assert "msg = f\"Unknown encoding '{encoding}' - using default encoding instead\"" in source
    assert "f\"Value '{encodings[0]}' for Specific Character Set does not \"" in source
    assert 'f"allow code extensions, ignoring: {' in source
    number = inspect.getsource(valuerep)
    assert "msg = f'Value \"{self}\" is not valid for elements with a VR of DS'" in number
    assert "msg = f'Value \"{self}\" is not valid for elements with a VR of IS'" in number
    assert 'msg += "\\nSet reading_validation_mode to WARN or IGNORE to bypass"' in number


def _no_context_store(sop_class: str) -> Callable[[Any], None]:
    """A C-STORE of a ``sop_class`` object on an association that accepted only Verification."""

    def send(assoc: Any) -> None:
        from pydicom import Dataset
        from pydicom.dataset import FileMetaDataset
        from pydicom.uid import ImplicitVRLittleEndian

        ds = Dataset()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # pydicom flags the planted UID as it is set
            ds.SOPClassUID = sop_class
            ds.SOPInstanceUID = "1.2.826.0.1.3680043.2.1"
        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
        with pytest.raises(ValueError, match="No presentation context"):
            assoc.send_c_store(ds)

    return send


def test_the_no_presentation_context_line_loses_a_flagged_sop_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _filter_removed():  # CONTROL: the line names the planted class
        unfiltered = _formatted(
            _associate_against(_captured_ac(), caplog, _no_context_store(_PLANTED))
        )
    assert [line for line in unfiltered if f"No presentation context for '{_PLANTED}'" in line]
    caplog.clear()
    filtered = _formatted(_associate_against(_captured_ac(), caplog, _no_context_store(_PLANTED)))
    assert filtered
    assert not [line for line in filtered if _PLANTED in line], filtered
    assert (
        "pynetdicom.association: No presentation context for '[redacted]' has been accepted by "
        "the peer with 'Implicit VR Little Endian' transfer syntax for the SCU role"
    ) in filtered


def test_the_no_presentation_context_line_keeps_a_real_sop_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The CONTROL for the redaction: a conformant class is what an operator needs from this line.
    lines = _formatted(
        _associate_against(_captured_ac(), caplog, _no_context_store("1.2.840.10008.5.1.4.1.1.2"))
    )
    assert (
        "pynetdicom.association: No presentation context for 'CT Image Storage' has been accepted "
        "by the peer with 'Implicit VR Little Endian' transfer syntax for the SCU role"
    ) in lines


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            f"No presentation context for 'CT Image Storage' has been accepted by the peer with "
            f"'{_PLANTED}' transfer syntax for the SCU role",
            "No presentation context for 'CT Image Storage' has been accepted by the peer with "
            "'[redacted]' transfer syntax for the SCU role",
        ),
        (
            f"No presentation context for '{_PLANTED}' has been accepted by the peer for the SCU "
            "role",
            "No presentation context for '[redacted]' has been accepted by the peer for the SCU "
            "role",
        ),
        (
            f"No presentation context for 'x' has been accepted by the peer {_PLANTED}",
            "No presentation context for '[redacted]",
        ),
        (
            f"No presentation context for 'it's {_PLANTED}' has been accepted by the peer for the "
            "SCU role",
            "No presentation context for '[redacted]",
        ),
    ],
    ids=["syntax", "class", "unknown-end", "quote"],
)
def test_a_no_presentation_context_line_with_any_flagged_part_loses_it(
    message: str, expected: str
) -> None:
    assert _filtered("pynetdicom.association", message) == expected


def test_the_no_presentation_context_line_is_still_pynetdicoms() -> None:
    import inspect

    from pynetdicom import association

    source = inspect.getsource(association.Association._get_valid_context)
    assert "f\"No presentation context for '{ab_syntax.name}' has been \"" in source
    assert 'f"accepted by the peer"' in source
    assert "msg += f\" with '{tr_syntax.name}' transfer syntax\"" in source
    assert 'msg += f" for the {role.upper()} role"' in source


# --- A codec error on a filtered logger, on a host with no engine log chain (#6637, item 15) -------


def test_a_codec_errors_byte_never_reaches_a_stock_handler(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # decode_bytes logs each UnicodeDecodeError it hits, and its str() names the byte.
    from pynetdicom import utils

    def decoded() -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.DEBUG), pytest.raises(ValueError):
            utils.decode_bytes(b"\xc3\x28")
        return _formatted(list(caplog.records))

    with _filter_removed():  # CONTROL: a stock formatter writes the byte, in the line and traceback
        assert [line for line in decoded() if line.count("0xc3") >= 2]
    lines = decoded()
    assert lines
    assert not [line for line in lines if "0xc3" in line], lines
    assert [line for line in lines if "UnicodeDecodeError" in line], lines


def test_a_codec_error_in_a_records_args_is_rendered_safely() -> None:
    try:
        b"\xc3\x28".decode("ascii")
    except UnicodeDecodeError as exc:
        record = logging.LogRecord(
            "pynetdicom.events", logging.ERROR, __file__, 1, "failed: %s", (exc,), None
        )
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert "0xc3" not in record.getMessage()


# --- The SCU's warnings filter, and the engine's own error text (#6637, items 11 and 14) -----------


def test_the_scu_puts_the_warnings_filter_back_on_a_host_that_reset_it() -> None:
    from tests.test_dicom_scu import _scu

    with warnings.catch_warnings(record=True) as caught:  # CONTROL: reset, the copy names the value
        warnings.simplefilter("always")
        dicom_module._read_command_set(_planted_command())
    assert [w for w in caught if _PLANTED in str(w.message)]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _scu(1)._build_ae()
        dicom_module._read_command_set(_planted_command())
    assert not [w for w in caught if _PLANTED in str(w.message)]


_CONTEXT_AWARE = bool(getattr(sys.flags, "context_aware_warnings", 0))


@pytest.mark.skipif(_CONTEXT_AWARE, reason="warnings.filters is not the list in force there")
def test_the_warnings_filters_are_not_reinstalled_while_they_are_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Each filterwarnings call resets every module's once-per-location record, so a reinstall per
    # send would repeat any other library's warning on stderr once per message.
    calls: list[str] = []
    original = warnings.filterwarnings

    def counted(*args: Any, **kwargs: Any) -> None:
        calls.append(str(kwargs.get("message")))
        original(*args, **kwargs)

    with warnings.catch_warnings():
        warnings.simplefilter("always")
        monkeypatch.setattr(warnings, "filterwarnings", counted)
        dicom_module._ignore_pydicom_value_warnings()
        assert len(calls) == len(dicom_module._PYDICOM_WARNING_MODULES)  # CONTROL: it installs them
        calls.clear()
        dicom_module._ignore_pydicom_value_warnings()
        assert calls == []
        warnings.simplefilter("always")  # now ahead of them, so they must go back in front
        dicom_module._ignore_pydicom_value_warnings()
        assert len(calls) == len(dicom_module._PYDICOM_WARNING_MODULES)
        monkeypatch.undo()


def test_no_warning_filter_nests_an_unbounded_scan_inside_a_leading_one() -> None:
    # Every UserWarning meets these filters, on text a peer can fill with a pattern's own opening
    # words, up to the 64 KiB command set cap. A leading `.*` with a second unbounded scan after it
    # is quadratic there. Read from the patterns, so a loaded machine cannot fail it.
    def nested(pattern: str) -> bool:
        return pattern.startswith(".*") and "*" in pattern[2:]

    assert nested(r'.*Value ".*" is not valid for elements with a VR of ')  # CONTROL
    assert dicom_module._PYDICOM_WARNING_MODULES
    assert not [p for p in dicom_module._PYDICOM_WARNING_MODULES if nested(p)]


def test_the_scu_ignores_pydicoms_copies_before_it_reads_the_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.parsing.dicom import DicomPeek
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _scu

    class Reached(Exception):
        """The read is over; the association is not under test."""

    def stop() -> Any:
        raise Reached

    data = make_sr_part10()
    uid = DicomPeek.parse(data).sop_instance_uid
    assert uid
    planted = ("1.02." + "7" * len(uid))[: len(uid)]
    scu = _scu(1)
    monkeypatch.setattr(scu, "_build_ae", stop)

    def warned() -> list[str]:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with pytest.raises(Reached):
                scu._store_object(data.replace(uid.encode(), planted.encode()))
        return [str(w.message) for w in caught if planted in str(w.message)]

    install = dicom_module._ignore_pydicom_value_warnings
    monkeypatch.setattr(dicom_module, "_ignore_pydicom_value_warnings", lambda: None)
    assert warned()  # CONTROL: uninstalled, the read warns with the value
    monkeypatch.setattr(dicom_module, "_ignore_pydicom_value_warnings", install)
    assert warned() == []


@pytest.mark.skipif(_CONTEXT_AWARE, reason="its control needs the flag off")
def test_context_aware_warnings_always_reinstall(monkeypatch: pytest.MonkeyPatch) -> None:
    # There, warnings.filters is not the list in force, so it cannot say the ignores are in place.
    calls: list[str] = []
    original = warnings.filterwarnings

    def counted(*args: Any, **kwargs: Any) -> None:
        calls.append(str(kwargs.get("message")))
        original(*args, **kwargs)

    with warnings.catch_warnings():
        dicom_module._ignore_pydicom_value_warnings()
        monkeypatch.setattr(warnings, "filterwarnings", counted)
        dicom_module._ignore_pydicom_value_warnings()
        assert calls == []  # CONTROL: without the flag, in place means no call
        flags = SimpleNamespace(context_aware_warnings=1)
        monkeypatch.setattr(dicom_module, "sys", SimpleNamespace(flags=flags))
        dicom_module._ignore_pydicom_value_warnings()
        assert len(calls) == len(dicom_module._PYDICOM_WARNING_MODULES)
        monkeypatch.undo()


@pytest.mark.parametrize("vr", ["UI", "CS", "IS", "DS"])
def test_the_engines_error_text_redacts_pydicoms_own_refusal(vr: str) -> None:
    # redact() rewrites this refusal's head, so the shapes must read the message before it does.
    from pydicom import config
    from pydicom.valuerep import validate_value

    value = "1.02.7777777^PLANTED"
    with pytest.raises(ValueError) as raised:
        validate_value(vr, value, config.RAISE)
    assert value in str(raised.value)  # CONTROL
    assert value not in dicom_module._safe_library_exc(raised.value)
    assert _REDACTED_MARK in dicom_module._safe_library_exc(raised.value)


def test_the_engines_error_text_keeps_a_codec_errors_byte_out() -> None:
    with pytest.raises(UnicodeDecodeError) as raised:
        b"\xc3\x28".decode("ascii")
    assert "0xc3" in str(raised.value)  # CONTROL
    assert "0xc3" not in dicom_module._safe_library_exc(raised.value)


def test_a_numeric_elements_raw_bytes_never_reach_the_log_or_the_error_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from pydicom.errors import BytesLengthException
    from pydicom.values import convert_numbers

    planted = b"S3CRETVAL"
    with pytest.raises(BytesLengthException) as raised:
        convert_numbers(planted, True, "H")
    exc = raised.value
    assert planted.decode() in str(exc)  # CONTROL
    text = dicom_module._safe_library_exc(exc)
    assert planted.decode() not in text
    assert "Instead received [redacted] with length 9 and struct format 'H'" in text
    lines = _logged("pynetdicom.dsutils", exc, caplog)
    assert lines
    assert not [line for line in lines if planted.decode() in line], lines


def test_a_message_that_holds_another_is_replaced_whole() -> None:
    # The outer message is short and sits inside its cause's, which also names a second value.
    outer = "Invalid 'A' value 'FIRSTVAL' - must not exceed 16 characters"
    inner = f"With tag (0000,1000): {outer}\nInvalid value for VR UI: 'SECONDVAL'."
    try:
        try:
            raise ValueError(inner)
        except ValueError as cause:
            raise ValueError(outer) from cause
    except ValueError as exc:
        info = (ValueError, exc, exc.__traceback__)
        record = logging.LogRecord("pynetdicom.dimse", logging.ERROR, __file__, 1, exc, (), info)
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    written = logging.Formatter("%(message)s").format(record)
    assert "FIRSTVAL" not in written and "SECONDVAL" not in written, written
    assert _REDACTED_MARK in written


@pytest.mark.parametrize("dump", ["_receive_associate_rq", "_send_associate_rq"])
def test_the_dump_of_extended_negotiation_writes_no_application_information(
    dump: str, caplog: pytest.LogCaptureFixture
) -> None:
    from pynetdicom import _handlers
    from pynetdicom.pdu import A_ASSOCIATE_RQ
    from pynetdicom.pdu_items import SOPClassExtendedNegotiationSubItem

    pdu = A_ASSOCIATE_RQ()
    pdu.decode(_captured_request())
    item = SOPClassExtendedNegotiationSubItem()
    item.sop_class_uid = "1.2.840.10008.1.1"
    item.service_class_application_information = b"S3CRETVAL"
    user_information = pdu.user_information
    assert user_information is not None
    user_information.user_data.append(item)
    hexed = "  ".join(format(byte, "02x") for byte in b"S3CRETVAL")

    def dumped() -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            getattr(_handlers, dump)(cast("Event", SimpleNamespace(pdu=pdu)))
        return [r.getMessage() for r in caplog.records]

    with _filter_removed():  # CONTROL: the dump writes the bytes as hex
        assert [line for line in dumped() if hexed in line]
    lines = dumped()
    assert lines
    assert not [line for line in lines if hexed in line], lines
    assert "    [redacted]" in lines


async def test_the_scp_puts_the_warning_ignores_back_at_each_c_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scp import _scu_cstore

    calls: list[str] = []
    install = dicom_module._ignore_pydicom_value_warnings

    def counted() -> None:
        calls.append(threading.current_thread().name)
        install()

    async with _running_scp({"timeout_seconds": 5.0}) as scp:
        monkeypatch.setattr(dicom_module, "_ignore_pydicom_value_warnings", counted)
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
    assert established and status == 0x0000
    assert calls, "the C-STORE callback did not put the ignores back"


def _with_a_note() -> BaseException:
    exc = RuntimeError("the handler failed")
    exc.add_note(f"while reading {_PLANTED}")
    return exc


@pytest.mark.parametrize(
    "build",
    [_with_a_note, lambda: ExceptionGroup("failed", [ValueError(_REFUSAL)])],
    ids=["note", "group-member"],
)
def test_a_traceback_with_a_note_or_group_member_is_withheld(
    build: Callable[[], BaseException], caplog: pytest.LogCaptureFixture
) -> None:
    exc = build()
    with _filter_removed():  # CONTROL: a stock formatter prints both
        assert [line for line in _logged("pynetdicom.dimse", exc, caplog) if _PLANTED in line]
    lines = _logged("pynetdicom.dimse", exc, caplog)
    assert lines
    assert not [line for line in lines if _PLANTED in line], lines
    assert [line for line in lines if "traceback withheld" in line], lines


async def test_the_scus_delivery_error_names_no_refused_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pynetdicom.association import Association

    from messagefoundry.transports.base import DeliveryError
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    def refuse(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(_REFUSAL)

    monkeypatch.setattr(Association, "send_c_store", refuse)
    with _storage_scp() as port, pytest.raises(DeliveryError) as raised:
        await _scu(port).send(_carry(make_sr_part10()))
    assert _PLANTED not in str(raised.value)
    assert "value '[redacted]' - must not exceed 64 characters" in str(raised.value)


async def test_the_scps_decode_error_line_names_no_refused_value(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from pydicom.dataset import Dataset

    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scp import _scu_cstore

    def refuse(self: Any, *args: Any, **kwargs: Any) -> None:
        raise ValueError(_REFUSAL)

    data = make_sr_part10()
    async with _running_scp({"timeout_seconds": 5.0}) as scp:
        monkeypatch.setattr(Dataset, "save_as", refuse)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.transports.dicom"):
            await asyncio.to_thread(_scu_cstore, scp.sockport, data)
    lines = [
        r.getMessage() for r in caplog.records if "could not be decoded/encoded" in r.getMessage()
    ]
    assert lines, caplog.text
    assert not [line for line in lines if _PLANTED in line], lines
    assert [line for line in lines if "value '[redacted]'" in line], lines


# --- A peer's DIMSE response that does not convert (vault BACKLOG #6637, item 4) -------------------

_PLANTED_REFUSED = "1.02." + "9" * 70  # over 64 characters, so set_uid raises rather than warns


def _c_echo_rsp_command(class_uid: str) -> bytes:
    """A whole C-ECHO-RSP command set, implicit VR little endian, naming ``class_uid``."""

    def element(tag: tuple[int, int], value: bytes) -> bytes:
        return struct.pack("<HHI", *tag, len(value)) + value

    uid = class_uid.encode("ascii")
    rest = (
        element((0x0000, 0x0002), uid + b"\x00" * (len(uid) % 2))
        + element((0x0000, 0x0100), struct.pack("<H", 0x8030))
        + element((0x0000, 0x0120), struct.pack("<H", 1))
        + element((0x0000, 0x0800), struct.pack("<H", 0x0101))
        + element((0x0000, 0x0900), struct.pack("<H", 0x0000))
    )
    return element((0x0000, 0x0000), struct.pack("<I", len(rest))) + rest


def _scu_echo_answered_with(command: bytes, caplog: pytest.LogCaptureFixture) -> list[str]:
    """A pynetdicom SCU sends a C-ECHO to a peer that answers with ``command``. Every record logged
    meanwhile is returned as a handler would write it, its traceback included."""
    records = _associate_against(
        _captured_ac(), caplog, then=lambda assoc: assoc.send_c_echo(), reply=command
    )
    return _formatted(records)


def test_a_refused_value_in_a_peers_dimse_response_never_reaches_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    command = _c_echo_rsp_command(_PLANTED_REFUSED)
    with (
        _filter_removed()
    ):  # CONTROL: pynetdicom.dimse logs the refusal, and its traceback repeats it
        unfiltered = _scu_echo_answered_with(command, caplog)
    assert [
        line
        for line in unfiltered
        if line.startswith("pynetdicom.dimse: Invalid 'Affected SOP Class UID' value ")
        and line.count(_PLANTED_REFUSED) >= 2
    ], unfiltered
    caplog.clear()
    filtered = _scu_echo_answered_with(command, caplog)
    assert filtered
    assert not [line for line in filtered if _PLANTED_REFUSED in line], filtered
    assert [
        line
        for line in filtered
        if line.startswith("pynetdicom.dimse: Invalid 'Affected SOP Class UID' value '[redacted]'")
        and "Traceback" in line
    ], filtered


# --- The no-service-class and private creator lines (vault BACKLOG #6637) --------------------------

_NO_SERVICE_TAIL = (
    "', please see the pynetdicom.sop_class.register_uid() function if you need to add support "
    "for a private, retired or otherwise unknown SOP Class UID"
)
#: The length of the class UID in ``_c_store_command``, so a replace keeps the command set's lengths.
_PLANTED_CLASS = (_PLANTED + ".9" * 7)[:30]


def _no_service_line(value: str) -> str:
    return f"No supported service class available for the SOP Class UID '{value}{_NO_SERVICE_TAIL}"


def test_the_no_service_class_line_keeps_only_a_conformant_class() -> None:
    assert _filtered("pynetdicom.association", _no_service_line(_PLANTED)) == _no_service_line(
        "[redacted]"
    )
    # The CONTROL: a real private class is what an operator needs from this line.
    real = _no_service_line("1.2.826.0.1.3680043.2.1")
    assert _filtered("pynetdicom.association", real) == real


def test_the_no_service_class_line_is_still_pynetdicoms() -> None:
    import inspect

    from pynetdicom import association

    source = inspect.getsource(association.Association._serve_request)
    assert '"No supported service class available for the SOP "' in source
    assert "f\"Class UID '{class_uid}', please see the \"" in source
    assert '"pynetdicom.sop_class.register_uid() function if you need to add "' in source
    assert '"support for a private, retired or otherwise unknown SOP Class UID"' in source


async def _store_of_a_class_no_service_serves(
    caplog: pytest.LogCaptureFixture,
) -> list[str]:
    """A C-STORE on an accepted context whose command names a class pynetdicom has no service for."""
    command = _c_store_command().replace(
        b"1.2.840.10008.5.1.4.1.1.88.11\x00", _PLANTED_CLASS.encode("ascii")
    )
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            with caplog.at_level(logging.DEBUG):
                sock.sendall(_p_data(0x03, command) + _p_data(0x02, b"\x00" * 16))
                assert await asyncio.to_thread(_first_bytes, sock, 1), "the SCP did not end it"
        finally:
            sock.close()
    return _formatted(list(caplog.records))


async def test_a_peers_class_with_no_service_never_reaches_the_scp_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _filter_removed():  # CONTROL: a peer's command reaches the line, with its value whole
        unfiltered = await _store_of_a_class_no_service_serves(caplog)
    assert [line for line in unfiltered if "No supported service" in line and _PLANTED in line]
    caplog.clear()
    filtered = await _store_of_a_class_no_service_serves(caplog)
    assert [line for line in filtered if "No supported service" in line], filtered
    assert not [line for line in filtered if _PLANTED in line], filtered


def _read_a_bad_private_creator() -> KeyError:
    """pydicom's own lookup of a private element whose creator has more than one value, and the
    error it raises."""
    from pydicom.datadict import get_private_entry
    from pydicom.multival import MultiValue
    from pydicom.tag import Tag

    with pytest.raises(KeyError) as raised:
        get_private_entry(Tag(0x0009, 0x1001), MultiValue(str, ["A", _PLANTED]))  # type: ignore[arg-type]
    return raised.value


def test_a_bad_private_creator_never_reaches_the_log(caplog: pytest.LogCaptureFixture) -> None:
    def lines() -> list[str]:
        caplog.clear()
        with warnings.catch_warnings(), caplog.at_level(logging.DEBUG):
            warnings.simplefilter("ignore")
            _read_a_bad_private_creator()
        return _formatted(list(caplog.records))

    with _filter_removed():  # CONTROL
        assert [line for line in lines() if _PLANTED in line]
    filtered = lines()
    assert filtered
    assert not [line for line in filtered if _PLANTED in line], filtered
    assert "pydicom: (0009,0010) '[redacted]' is not a valid private creator" in filtered


def test_a_bad_private_creators_warning_copy_is_ignored() -> None:
    with warnings.catch_warnings(record=True) as caught:  # CONTROL: unignored, it carries the value
        warnings.simplefilter("always")
        _read_a_bad_private_creator()
    assert [w for w in caught if _PLANTED in str(w.message)]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        dicom_module._redact_flagged_peer_values()
        _read_a_bad_private_creator()
    assert not [w for w in caught if _PLANTED in str(w.message)]


def test_a_bad_private_creator_in_a_raised_error_is_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        error = _read_a_bad_private_creator()
    assert _PLANTED in str(error)  # CONTROL
    assert _PLANTED not in dicom_module._safe_library_exc(error)
    lines = _logged("pynetdicom.events", error, caplog)
    assert lines
    assert not [line for line in lines if _PLANTED in line], lines


def test_a_tag_and_quote_on_any_other_line_are_withheld() -> None:
    # No library line reads this, so it matches no template: the screen is default-deny.
    line = "Element (0009,0010) 'LO' has no value"
    assert _filtered("pydicom", line) == (
        "pydicom WARNING line withheld: it matches no pinned template"
    )


def test_a_private_creator_holding_a_double_quote_is_redacted() -> None:
    # repr() of the KeyError's line then escapes each single quote, which moves the shape's head.
    creator = f"['{_PLANTED}\"X', 'B']"
    error = KeyError(f"(0009,0010) '{creator}' is not a valid private creator")
    assert _PLANTED in str(error)  # CONTROL
    assert _PLANTED not in dicom_module._safe_library_exc(error)


@pytest.mark.parametrize(
    "convert",
    ["DS", "IS", "DSfloat"],
)
def test_pythons_number_error_on_a_peers_text_loses_the_value(convert: str) -> None:
    from pydicom import valuerep

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(ValueError) as raised:
            getattr(valuerep, convert)("DOE^JANE")
    assert "DOE^JANE" in str(raised.value)  # CONTROL
    assert "DOE^JANE" not in dicom_module._safe_library_exc(raised.value)
    assert "DOE^JANE" not in _filtered("pynetdicom.events", str(raised.value))


def test_pydicoms_wrong_length_warning_copy_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydicom import config
    from pydicom.dataelem import RawDataElement, convert_raw_data_element
    from pydicom.tag import Tag

    monkeypatch.setattr(config, "convert_wrong_length_to_UN", True)
    element = RawDataElement(Tag(0x0028, 0x0010), "US", 3, b"SEC", 0, False, True)

    with warnings.catch_warnings(record=True) as caught:  # CONTROL: unignored, it quotes the bytes
        warnings.simplefilter("always")
        convert_raw_data_element(element)
    assert [w for w in caught if "b'SEC'" in str(w.message)]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        dicom_module._redact_flagged_peer_values()
        convert_raw_data_element(element)
    assert not [w for w in caught if "b'SEC'" in str(w.message)]


def test_the_private_creator_line_is_still_pydicoms() -> None:
    import inspect

    from pydicom import datadict

    source = inspect.getsource(datadict.get_private_entry)
    assert "f\"{tag.private_creator} '{private_creator}' \"" in source
    assert 'f"is not a valid private creator"' in source
    assert "warn_and_log(msg)" in source


# --- What the SCU refuses in an object before it associates (vault BACKLOG #6637) ------------------


def _object_with_class(sop_class: Any) -> bytes:
    from pydicom import dcmread

    from tests._dicom_sample import make_sr_part10

    dataset = dcmread(io.BytesIO(make_sr_part10()))
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dataset["SOPClassUID"].value = sop_class
        dataset.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()


def _object_whose_instance_uid_will_not_read() -> bytes:
    """Its SOP Instance UID is declared US with three bytes, which pydicom raises on when read."""
    from pydicom import dcmread

    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    found = data.find(b"\x08\x00\x18\x00UI")
    assert found > 0
    length = int.from_bytes(data[found + 6 : found + 8], "little")
    broken = (
        data[: found + 4]
        + b"US"
        + (3).to_bytes(2, "little")
        + b"\xff\xfe\xfd"
        + data[found + 8 + length :]
    )
    with pytest.raises(Exception, match="bytes per value"):  # CONTROL: this is what the SCU meets
        _ = dcmread(io.BytesIO(broken)).SOPInstanceUID
    return broken


def _object_with_instance(value: Any) -> bytes:
    """A synthetic object whose SOP Instance UID is ``value``, or absent where that is ``None``."""
    from pydicom import dcmread

    from tests._dicom_sample import make_sr_part10

    dataset = dcmread(io.BytesIO(make_sr_part10()))
    if value is None:
        del dataset.SOPInstanceUID
    else:
        dataset.SOPInstanceUID = value
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dataset.save_as(buffer)
    return buffer.getvalue()


def _object_with_two_transfer_syntaxes() -> bytes:
    """A synthetic object whose file meta names two transfer syntaxes, by editing its bytes, since
    pydicom will not write one. The group length moves with it."""
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    found = data.find(b"\x02\x00\x10\x00UI")
    assert found > 0
    length = int.from_bytes(data[found + 6 : found + 8], "little")
    first = data[found + 8 : found + 8 + length].rstrip(b"\x00")
    value = first + b"\\1.2.840.10008.1.2"
    value += b"\x00" * (len(value) % 2)
    grown = len(value) - length
    broken = (
        data[: found + 6] + len(value).to_bytes(2, "little") + value + data[found + 8 + length :]
    )
    meta_length_at = broken.find(b"\x02\x00\x00\x00UL") + 8
    meta_length = int.from_bytes(broken[meta_length_at : meta_length_at + 4], "little")
    return (
        broken[:meta_length_at]
        + (meta_length + grown).to_bytes(4, "little")
        + broken[meta_length_at + 4 :]
    )


def _object_with_transfer_syntax_as_lo() -> bytes:
    """A synthetic object whose (0002,0010) is encoded as LO, so it reads as a plain string."""
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    found = data.find(b"\x02\x00\x10\x00UI")
    assert found > 0
    return data[: found + 4] + b"LO" + data[found + 6 :]


def _object_with_instance_as_us() -> bytes:
    """A synthetic object whose (0008,0018) is encoded as US, so it reads as an int."""
    from tests._dicom_sample import make_sr_part10

    data = make_sr_part10()
    found = data.find(b"\x08\x00\x18\x00UI")
    assert found > 0
    length = int.from_bytes(data[found + 6 : found + 8], "little")
    return (
        data[: found + 4]
        + b"US"
        + (2).to_bytes(2, "little")
        + b"\x05\x00"
        + data[found + 8 + length :]
    )


@pytest.mark.parametrize(
    "build",
    [
        lambda: _object_with_class(_PLANTED_REFUSED),
        lambda: _object_with_class(["1.2", "1.3"]),
        _object_with_transfer_syntax_as_lo,
        _object_with_instance_as_us,
        _object_whose_instance_uid_will_not_read,
        lambda: _object_with_instance(None),
        lambda: _object_with_instance(""),
        lambda: _object_with_instance(["1.2.3", "1.2.4"]),
        _object_with_two_transfer_syntaxes,
    ],
    ids=[
        "refused-sop-class",
        "two-sop-classes",
        "transfer-syntax-as-lo",
        "instance-uid-as-us",
        "instance-uid-does-not-read",
        "no-instance-uid",
        "empty-instance-uid",
        "two-instance-uids",
        "two-transfer-syntaxes",
    ],
)
async def test_an_object_the_scu_cannot_propose_is_a_bad_object(
    build: Callable[[], bytes],
) -> None:
    from messagefoundry.transports.base import NegativeAckError
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    with _storage_scp() as port, pytest.raises(NegativeAckError) as raised:
        await _scu(port).send(_carry(build()))
    assert raised.value.code == "bad-object"
    assert raised.value.permanent is True
    assert _PLANTED_REFUSED not in str(raised.value)
    assert "xff" not in str(raised.value)
