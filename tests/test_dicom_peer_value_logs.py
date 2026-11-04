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
import logging
import time
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

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
    for name in dicom_module._FILTERED_LOGGERS:
        logging.getLogger(name).removeFilter(dicom_module._PEER_VALUE_FILTER)
    dicom_module._redact_flagged_peer_values = lambda: None
    try:
        yield
    finally:
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
        ("pynetdicom.dimse_messages", "Non-conformant VM 2 for 'AffectedSOPInstanceUID'"),
        # A line that names no value keeps its reason.
        (
            "pynetdicom.utils",
            "Invalid 'Calling AE Title' value - must not consist entirely of spaces",
        ),
        ("pynetdicom._handlers", "    Abstract Syntax: =Verification SOP Class"),
        ("pynetdicom._handlers", "      =Implicit VR Little Endian"),
        # pynetdicom's own placeholder where a peer sent nothing.
        ("pynetdicom._handlers", "Their Implementation Class UID:    unknown"),
    ],
)
def test_a_conformant_value_and_a_line_with_no_value_pass_unchanged(
    name: str, message: str
) -> None:
    assert _filtered(name, message) == message


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

    assert "f\"The Transfer Syntax Name '{syntax}' is non-conformant\"" in inspect.getsource(
        presentation
    )
    assert "f\"The Related General SOP Class UID '{uid}' is \"" in inspect.getsource(pdu_primitives)


def test_the_phi_record_states_the_ruling() -> None:
    root = Path(__file__).resolve().parents[1]
    phi = (root / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert "third-party library loggers" in phi
    dicom = (root / "docs" / "DICOM.md").read_text(encoding="utf-8")
    assert "the value reads `[redacted]`" in dicom


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
