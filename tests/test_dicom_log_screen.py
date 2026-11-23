# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fail-closed screen on pynetdicom's and pydicom's logs (vault BACKLOG #6637 item 10): a line is
written only if it is pinned, and anything else is withheld with its logger, level and exception
class. Every value here is synthetic. These tests assert on the formatted output, tracebacks
included, since that is what reaches a log file.

**These tests need the ``[dicom]`` extra and SKIP without it.**
"""

from __future__ import annotations

import ast
import asyncio
import functools
import io
import logging
import re
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM log tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM log tests need the [dicom] extra")

from messagefoundry.parsing.dicom.errors import DicomBombError  # noqa: E402
from messagefoundry.store.base import StoreAcquireTimeout  # noqa: E402
from messagefoundry.transports import _dicom_log_lines as lines  # noqa: E402
from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from tests import _dicom_log_census as census  # noqa: E402

_PLANTED = "DOE^JANE^PLANTED"
#: A refused UID, which the engine's general redaction does not recognise.
_UID = "1.02.999.PLANTED"
_REFUSAL = f"Invalid 'Affected SOP Instance UID' value '{_UID}' - must not exceed 64 characters"
_WITHHELD = "line withheld: it matches no pinned template"
_FORMAT = "%(name)s|%(levelname)s|%(message)s"


def _written(log: logging.Logger, emit: Callable[[logging.Logger], None]) -> str:
    """What a stock handler on ``log`` writes, with no ``logging_setup`` in the process's path."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter(_FORMAT))
    level, propagate = log.level, log.propagate
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    log.propagate = False
    try:
        emit(log)
    finally:
        log.removeHandler(handler)
        log.setLevel(level)
        log.propagate = propagate
    return stream.getvalue()


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR])
@pytest.mark.parametrize(
    "name", ["pydicom", "pynetdicom.association", "pynetdicom.dul", "pynetdicom.pdu"]
)
def test_an_unpinned_line_is_withheld_at_every_level(name: str, level: int) -> None:
    written = _written(
        logging.getLogger(name), lambda log: log.log(level, "Patient name %s", _PLANTED)
    )
    assert _PLANTED not in written
    assert written == f"{name}|{logging.getLevelName(level)}|{name} " + (
        f"{logging.getLevelName(level)} {_WITHHELD}\n"
    )


def test_an_info_dump_of_a_dataset_is_withheld() -> None:
    # pynetdicom logs a C-FIND identifier line by line at INFO, so INFO carries values too.
    written = _written(
        logging.getLogger("pynetdicom.service_class"),
        lambda log: log.info(f"(0010,0010) PN [{_PLANTED}]"),
    )
    assert _PLANTED not in written and _WITHHELD in written


@pytest.mark.parametrize(
    "message",
    [
        "Association Accepted",
        "Association Released",
        "Association Aborted",
        "Association Aborted (A-P-ABORT)",
        "Association Rejected",
        "Requesting Association",
        "Accepting Association",
        "Releasing Association",
        "Aborting Association",
        "Network timeout reached",
        "Connection closed before the entire PDU was received",
        "Sending Store Request: MsgID 7, (CT)",
        "Received Store Response (Status: 0x0000 - Success)",
        "Received Echo Request (MsgID 3)",
        "Result: Rejected Permanent, Source: Service User",
        "Reason: Called AE title not recognised",
    ],
)
def test_the_lines_an_operator_works_from_are_kept_whole(message: str) -> None:
    written = _written(logging.getLogger("pynetdicom.association"), lambda log: log.info(message))
    assert written == f"pynetdicom.association|INFO|{message}\n"


@pytest.mark.parametrize("field", ["Reason", "Result", "Status"])
def test_a_fixed_vocabulary_slot_refuses_a_word_outside_it(field: str) -> None:
    line = {
        "Reason": f"Reason: {_PLANTED}",
        "Result": f"Result: {_PLANTED}, Source: Service User",
        "Status": f"Received Store Response (Status: 0x0000 - {_PLANTED})",
    }[field]
    assert dicom_module._screened_line(line) is None


# --- Loggers a filter is not on ------------------------------------------------------------------


def test_a_logger_created_after_the_install_is_screened() -> None:
    name = "pynetdicom.created_after_install"
    assert name not in logging.root.manager.loggerDict  # CONTROL: it did not exist before this
    written = _written(logging.getLogger(name), lambda log: log.error("value %s", _PLANTED))
    assert _PLANTED not in written and _WITHHELD in written


def test_a_child_that_does_not_propagate_is_screened() -> None:
    log = logging.getLogger("pydicom.a.child")
    log.propagate = False
    written = _written(log, lambda child: child.warning("value %s", _PLANTED))
    assert _PLANTED not in written and _WITHHELD in written


def test_another_librarys_logger_is_left_alone() -> None:
    for name in ("pynetdicomish", "pydicomish.child", "messagefoundry.anything"):
        written = _written(logging.getLogger(name), lambda log: log.warning("kept %s", _PLANTED))
        assert written == f"{name}|WARNING|kept {_PLANTED}\n"


def test_a_host_record_factory_is_chained_and_put_back_under() -> None:
    original = logging.getLogRecordFactory()
    seen: list[str] = []

    def hosts(*args: object, **kwargs: object) -> logging.LogRecord:
        record = logging.LogRecord(*args, **kwargs)  # type: ignore[arg-type]
        seen.append(record.name)
        return record

    logging.setLogRecordFactory(hosts)
    try:
        dicom_module._install_record_screen()
        assert logging.getLogRecordFactory() is not hosts
        written = _written(
            logging.getLogger("pynetdicom.new_under_a_host"),
            lambda log: log.error("value %s", _PLANTED),
        )
        assert "pynetdicom.new_under_a_host" in seen  # the host's factory still ran
        assert _PLANTED not in written and _WITHHELD in written
        installed = logging.getLogRecordFactory()
        dicom_module._install_record_screen()
        assert logging.getLogRecordFactory() is installed  # CONTROL: installing is idempotent
    finally:
        logging.setLogRecordFactory(original)


def test_every_logger_the_libraries_create_has_the_filter() -> None:
    # The hold in _logs_held works through the filter, so it must be on each by name.
    created: set[str] = set()
    for module, logger, source in census.library_sources():
        if "getLogger(__name__)" in source:
            created.add(module)
        if 'getLogger("pydicom")' in source:
            created.add(logger)
    assert "pynetdicom.dul" in created and "pydicom" in created  # CONTROL
    assert created <= set(dicom_module._FILTERED_LOGGERS)
    for name in dicom_module._FILTERED_LOGGERS:
        assert dicom_module._PEER_VALUE_FILTER in logging.getLogger(name).filters, name


# --- Tracebacks --------------------------------------------------------------------------------


def _chained() -> BaseException:
    try:
        try:
            raise ValueError(f"inner {_PLANTED}")
        except ValueError as inner:
            raise RuntimeError(f"outer {_PLANTED}") from inner
    except RuntimeError as exc:
        return exc


def _during() -> BaseException:
    try:
        try:
            raise KeyError(_PLANTED)
        except KeyError:
            raise OSError(f"failed on {_PLANTED}")  # noqa: B904 - the implicit context is the case
    except OSError as exc:
        return exc


def _noted() -> BaseException:
    exc = RuntimeError("Unable to decode the received PDU data")
    exc.add_note(f"while reading {_PLANTED}")
    return exc


def _group() -> BaseException:
    return ExceptionGroup("failed", [ValueError(_PLANTED), TypeError(_PLANTED)])


def _codec() -> BaseException:
    try:
        f"{_PLANTED}\xe9".encode("ascii")
    except UnicodeEncodeError as exc:
        return exc
    raise AssertionError("no error")


@pytest.mark.parametrize(
    ("build", "class_name"),
    [
        (_chained, "RuntimeError"),
        (_during, "OSError"),
        (_noted, "RuntimeError"),
        (_group, "ExceptionGroup"),
        (_codec, "UnicodeEncodeError"),
    ],
    ids=["cause", "context", "note", "group", "codec"],
)
def test_nothing_of_an_exception_reaches_the_output_but_its_class(
    build: Callable[[], BaseException], class_name: str
) -> None:
    exc = build()
    written = _written(
        logging.getLogger("pynetdicom.events"), lambda log: log.exception(exc, exc_info=exc)
    )
    assert _PLANTED not in written, written
    assert class_name in written


def test_a_withheld_line_names_its_exception_class() -> None:
    exc = _chained()
    written = _written(
        logging.getLogger("pynetdicom.dul"), lambda log: log.exception(exc, exc_info=exc)
    )
    assert f"pynetdicom.dul ERROR {_WITHHELD} (RuntimeError)" in written


def test_a_chain_keeps_a_pinned_message_and_loses_the_rest() -> None:
    try:
        try:
            raise ValueError("Unable to decode the received PDU data")
        except ValueError as inner:
            raise RuntimeError(f"outer {_PLANTED}") from inner
    except RuntimeError as exc:
        caught = exc
    written = _written(
        logging.getLogger("pynetdicom.dul"), lambda log: log.exception(caught, exc_info=caught)
    )
    assert "ValueError: Unable to decode the received PDU data" in written
    assert "RuntimeError: [message withheld]" in written
    assert _PLANTED not in written


# --- A failure inside the screen -----------------------------------------------------------------


def test_a_failure_in_the_screen_withholds_the_line(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(text: str) -> str | None:
        raise RuntimeError(f"failed on {text}")

    monkeypatch.setattr(dicom_module, "_screened_line", broken)
    exc = _chained()
    written = _written(
        logging.getLogger("pynetdicom.dul"), lambda log: log.exception(exc, exc_info=exc)
    )
    assert _PLANTED not in written
    assert _WITHHELD in written and "traceback withheld" in written


def test_a_value_check_that_raises_redacts_the_field(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> frozenset[str]:
        raise RuntimeError("no dictionary")

    monkeypatch.setattr(dicom_module, "_uid_names", broken)
    assert (
        dicom_module._screened_line("Affected SOP Class UID        : Verification SOP Class")
        == "Affected SOP Class UID        : [redacted]"
    )


def test_a_message_whose_str_raises_is_withheld() -> None:
    class Unprintable:
        def __str__(self) -> str:
            raise RuntimeError(_PLANTED)

    written = _written(logging.getLogger("pynetdicom.dul"), lambda log: log.error(Unprintable()))
    assert _PLANTED not in written and _WITHHELD in written


def test_traceback_text_already_on_a_record_is_not_written() -> None:
    # A record that a formatter has seen, or one rebuilt from a queue, carries exc_text, which a
    # formatter writes in preference to exc_info.
    exc = RuntimeError("Unable to decode the received PDU data")
    info = (RuntimeError, exc, None)
    for exc_info in (info, None):
        record = logging.LogRecord(
            "pynetdicom.dul", logging.ERROR, __file__, 1, "Network timeout reached", (), exc_info
        )
        record.exc_text = f"Traceback naming {_PLANTED}"
        assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
        assert _PLANTED not in logging.Formatter("%(message)s").format(record)


@pytest.mark.parametrize(
    "exc_info", [(), (None, None, None), (ValueError, "not an exception", None)]
)
def test_a_malformed_exc_info_does_not_raise(exc_info: tuple[object, ...]) -> None:
    record = logging.LogRecord(
        "pynetdicom.dul",
        logging.ERROR,
        __file__,
        1,
        f"value {_PLANTED}",
        (),
        exc_info,  # type: ignore[arg-type]
    )
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    assert _PLANTED not in record.getMessage()


def test_a_note_added_after_the_screen_is_not_written() -> None:
    # A deferred handler formats later, so the record must not still hold the live exception.
    exc = ValueError("Network timeout reached")
    record = logging.LogRecord(
        "pynetdicom.dul", logging.ERROR, __file__, 1, "x", (), (ValueError, exc, None)
    )
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    exc.add_note(f"note {_PLANTED}")
    written = logging.Formatter("%(message)s").format(record)
    assert "ValueError: Network timeout reached" in written  # CONTROL: the traceback is written
    assert _PLANTED not in written


@pytest.mark.parametrize("name", sorted(lines.ELEMENT_NAMES))
def test_each_element_name_stays_on_its_refusal_line(name: str) -> None:
    assert dicom_module._screened_line(f"Invalid '{name}' value 'X' - must be str") == (
        f"Invalid '{name}' value '[redacted]' - must be str"
    )


@pytest.mark.parametrize(
    "line",
    [
        "The value length (20) exceeds the maximum length of 16 allowed for VR DS. Please see "
        "<https://dicom.nema.org/medical/dicom/current/output/html/part05.html#table_6.2-1> for "
        "allowed values for each VR.",
        "The PN component length (70) exceeds the maximum allowed length of 64.",
        "A value of type 'int' cannot be assigned to a tag with VR LT.",
        "Invalid A-ASSOCIATE 'Result Source' 9 and/or 'Diagnostic' 9 values",
        "Invalid A-ABORT 'Source' value '9'",
        "Invalid 'User Identity Type' None",
        "  Authentication Mode: 9 - (no value available)",
    ],
)
def test_a_value_free_diagnostic_line_stays(line: str) -> None:
    assert dicom_module._screened_line(line) == line


def test_a_private_creator_with_both_quotes_keeps_its_tag() -> None:
    error = KeyError(f"(0009,0010) '{_PLANTED}\"X' is not a valid private creator")
    assert dicom_module._screened_line(str(error)) == (
        "'(0009,0010) \\'[redacted]\\' is not a valid private creator'"
    )


def test_a_move_destination_holding_a_repr_is_redacted() -> None:
    assert dicom_module._screened_line("Move Destination              : ['AB', 'CD']") == (
        "Move Destination              : [redacted]"
    )


def test_a_number_slot_takes_ascii_digits_only() -> None:
    assert dicom_module._screened_line("Their Max PDU Receive Size:  \u0661\u0662") is None


def test_a_syntax_errors_source_text_is_not_written() -> None:
    # The stdlib prints a syntax error's text from its own fields, which no message screen reads.
    exc = SyntaxError("bad", ("peer.py", 1, 1, f"text {_PLANTED}", 1, 2))
    written = _written(
        logging.getLogger("pynetdicom.dul"), lambda log: log.error("x", exc_info=exc)
    )
    assert _PLANTED not in written
    assert "SyntaxError (traceback withheld: it did not render)" in written


def test_a_line_break_in_a_value_cannot_forge_a_second_line() -> None:
    # `.` stops at a line break, so the value slot does not span it and no template matches.
    forged = f"Calling Application Name:    A\nAssociation Accepted {_PLANTED}"
    assert dicom_module._screened_line(forged) is None


# --- Cost on a peer's text -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "a" * 200_000,
        "'" * 200_000,
        "' - " * 50_000,
        ". Please see <" * 15_000,
        'Value "' * 30_000,
    ],
    ids=["plain", "quotes", "tail", "see", "head"],
)
@pytest.mark.parametrize(
    "head",
    [
        "",
        "Invalid 'X' value '",
        "Invalid value for VR UI: ",
        "No presentation context for '",
        'Value "',
    ],
)
def test_matching_stays_linear_on_a_long_peer_value(head: str, value: str) -> None:
    started = time.monotonic()
    dicom_module._screened_line(head + value)
    assert time.monotonic() - started < 1.0


def test_no_template_has_two_unbounded_runs_that_can_overlap() -> None:
    def unbounded(template: str) -> list[str]:
        return [
            kind
            for kind in lines._SLOT.findall(template)
            # quoted_uid stops at the quote that follows it.
            if kind != "quoted_uid" and re.search(r"[*+]", lines._SLOT_PATTERNS[kind])
        ]

    assert len(unbounded("A {value} B {uid}")) == 2  # CONTROL
    over = [t for t in lines.TEMPLATES if len(unbounded(t)) > 1]
    # An indent of spaces and a dump of hex digits, which share no character.
    assert over == ["{indent}{hex_dump}"]


@pytest.mark.parametrize(
    "line",
    [
        "Affected SOP Class UID        : 1.2.3\r",
        "Affected SOP Class UID        : 1.2.3\x0b",
        "Affected SOP Class UID        : 1.2.3\u2028",
        "Affected SOP Class UID        : \x1c1.2.3",
        "Affected SOP Instance UID     : 1.2.3 ",
        "No presentation context for '1.2.3\n' has been accepted by the peer for the SCU role",
    ],
)
def test_a_uid_with_a_control_character_around_it_is_not_kept(line: str) -> None:
    screened = dicom_module._screened_line(line)
    assert screened is None or "1.2.3" not in screened, screened


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ("Invalid 'DOE JANE' value - must not be an empty str", "Invalid '[redacted]' value"),
        (
            "Non-conformant VM 2 for 'DOEJANE', taking the first value",
            "Non-conformant VM 2 for '[redacted]'",
        ),
        ("The DOE JANE 'x' is non-conformant", "The [redacted] '[redacted]'"),
        ("Unable to decode 'x' using the DOE JANE codec(s)", "using the [redacted] codec(s)"),
    ],
)
def test_a_library_word_outside_its_closed_list_is_redacted(line: str, kept: str) -> None:
    screened = dicom_module._screened_line(line)
    assert screened is not None and kept in screened and "DOE" not in screened


def test_the_element_names_are_the_ones_pynetdicom_passes() -> None:
    passed: set[str] = set()
    for module, _logger, source in census.library_sources():
        if not module.startswith("pynetdicom"):
            continue
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("set_uid", "set_ae")
                and len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
            ):
                passed.add(str(node.args[1].value))
    assert "Affected SOP Class UID" in passed  # CONTROL
    assert passed <= lines.ELEMENT_NAMES


@pytest.mark.parametrize("exc", [TimeoutError(), ConnectionResetError(), RuntimeError("")])
def test_an_exception_with_no_message_reads_as_its_class(exc: BaseException) -> None:
    assert dicom_module._safe_library_exc(exc) == type(exc).__name__


def test_where_an_engine_fault_was_raised_is_named_without_its_message() -> None:
    try:
        raise OSError(f"failed on {_PLANTED}")
    except OSError as exc:
        where = dicom_module._raised_at(exc)
        text = dicom_module._safe_library_exc(exc)
    assert where.startswith("test_dicom_log_screen.py:")
    assert where.endswith("in test_where_an_engine_fault_was_raised_is_named_without_its_message")
    assert text == f"OSError: [message withheld] (raised at {where})"
    assert dicom_module._raised_at(OSError()) == "an unknown place"


async def test_each_c_store_puts_a_replaced_record_factory_back() -> None:
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scp import _scu_cstore
    from tests.test_dicom_scp_admission import _running_scp

    original = logging.getLogRecordFactory()
    try:
        async with _running_scp({"timeout_seconds": 5.0}) as scp:
            logging.setLogRecordFactory(logging.LogRecord)
            established, status = await asyncio.to_thread(
                _scu_cstore, scp.sockport, make_sr_part10()
            )
            assert established and status == 0x0000
            assert isinstance(logging.getLogRecordFactory(), dicom_module._ScreeningRecordFactory)
    finally:
        logging.setLogRecordFactory(original)


# --- The guard: a library upgrade that changes a line fails here ---------------------------------


def test_the_census_is_the_installed_libraries() -> None:
    pinned = census.read_pinned()
    assert len(pinned) > 400  # CONTROL: the file holds a census, not an empty list
    found = census.census()
    added = sorted(set(found) - set(pinned))
    removed = sorted(set(pinned) - set(found))
    assert (added, removed) == ([], []), (
        "A library's log calls changed. Read each, pin it in messagefoundry/transports/"
        "_dicom_log_lines.py if an operator needs it, then run "
        "python -P tests/_dicom_log_census.py --write"
    )


@pytest.mark.parametrize(
    "planted",
    [
        'LOGGER.error(f"Patient {name} refused")',
        'LOGGER.info("Patient %s refused", name)',
        'LOGGER.warning(msg + " refused")',
        'warn_and_log(f"Patient {name} refused")',
        'logger.exception(f"Patient {name} refused")',
        'msg = "Patient value refused"\n    LOGGER.error(msg)',
    ],
)
def test_the_guard_sees_a_planted_library_line(planted: str) -> None:
    source = next(s for m, _l, s in census.library_sources() if m == "pynetdicom.dul")
    before = census.rows_in("pynetdicom.dul", "pynetdicom.dul", source)
    assert before <= set(census.read_pinned())  # CONTROL: the unplanted module is in the census
    after = census.rows_in(
        "pynetdicom.dul", "pynetdicom.dul", f"{source}\n\ndef planted():\n    {planted}\n"
    )
    assert after - set(census.read_pinned())


def test_the_value_free_lines_are_the_census_literals() -> None:
    pinned = census.read_pinned()
    assert "Association Accepted" in census.value_free_lines(pinned)  # CONTROL
    assert census.value_free_lines(pinned) == lines.VALUE_FREE_LINES


def test_each_template_still_has_its_text_in_a_library() -> None:
    # By its longest run of words: a library builds some of these lines from more than one literal.
    # CPython's own two number refusals are the exception, since no library holds their text.
    corpus = "\0".join(census.string_fragments())
    stale = []
    for template in lines.TEMPLATES:
        if template.startswith(("could not convert string", "invalid literal for int")):
            continue
        words = re.findall(r"[A-Za-z][A-Za-z ]{5,}", re.sub(r"\{[a-z_]+\}", "\0", template))
        if words and max(words, key=len).strip()[:16] not in corpus:
            stale.append(template)
    assert "Association Accepted" in corpus  # CONTROL
    assert "A wording no library has" not in corpus  # CONTROL
    assert stale == []


def test_each_slot_kind_is_defined_and_used() -> None:
    used = {kind for t in lines.TEMPLATES for kind in re.findall(r"\{([a-z_]+)\}", t)}
    assert used == set(lines._SLOT_PATTERNS)
    assert {
        "uid",
        "quoted_uid",
        "instance",
        "name",
        "keyword",
        "codecs",
        *dicom_module._TITLE_KINDS,
    } == lines.PEER_VALUE_KINDS - lines.ALWAYS_REDACTED_KINDS


# --- Warnings ------------------------------------------------------------------------------------


def test_only_charset_warns_with_a_raised_stack_level() -> None:
    # The ignore is by module, and a raised stack level attributes a warning to a caller: if one of
    # these reached code outside pydicom, its warning would no longer be ignored.
    sites: list[tuple[str, str]] = []
    for module, _logger, source in census.library_sources():
        if not module.startswith("pydicom"):
            continue
        tree = ast.parse(source)
        for function in ast.walk(tree):
            if not isinstance(function, ast.FunctionDef):
                continue
            for node in ast.walk(function):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "warn_and_log"
                    and any(k.arg == "stacklevel" for k in node.keywords)
                ):
                    sites.append((module, function.name))
    assert sorted(set(sites)) == [
        ("pydicom.charset", "_handle_illegal_standalone_encodings"),
        ("pydicom.charset", "_warn_about_invalid_encoding"),
    ]
    charset = next(s for m, _l, s in census.library_sources() if m == "pydicom.charset")
    for name in ("_handle_illegal_standalone_encodings", "_warn_about_invalid_encoding"):
        for module, _logger, source in census.library_sources():
            if module != "pydicom.charset":
                assert f"{name}(" not in source, (module, name)
        assert f"{name}(" in charset


_WARNINGS_PROBE = textwrap.dedent(
    """
    import sys, threading, warnings
    warnings.simplefilter("default")
    from messagefoundry.transports import dicom
    dicom._redact_flagged_peer_values()
    from pydicom import charset

    def run():
        charset.convert_encodings(["ISO_IR 192", "PLANTED-WARNING-VALUE"])

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    run()
    warnings.warn_explicit("ANOTHER-LIBRARY-WARNING", UserWarning, "other.py", 1, module="other")
    """
)


def _probe_stderr(script: str, *flags: str) -> str:
    done = subprocess.run(  # noqa: S603 - this interpreter, on a fixed script
        [sys.executable, *flags, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=Path(__file__).resolve().parents[1],
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return done.stderr


@pytest.mark.parametrize("context_aware", ["0", "1"])
def test_the_ignore_is_scoped_to_pydicom_under_either_warnings_mode(context_aware: str) -> None:
    stderr = _probe_stderr(_WARNINGS_PROBE, "-X", f"context_aware_warnings={context_aware}")
    assert "PLANTED-WARNING-VALUE" not in stderr, stderr
    assert "ANOTHER-LIBRARY-WARNING" in stderr, stderr  # another library's still shows


def test_the_probe_warns_with_the_value_when_the_ignore_is_off() -> None:
    # The CONTROL for the two above: the same call, with no ignore, puts the value on stderr.
    probe = _WARNINGS_PROBE.replace(
        "dicom._redact_flagged_peer_values()", "warnings.resetwarnings()"
    )
    assert "PLANTED-WARNING-VALUE" in _probe_stderr(probe)


def test_every_template_compiles_and_matches_its_own_shape() -> None:
    samples = {
        "int": "1",
        "number": "1",
        "hex": "00FF",
        "vr": "UI",
        "tag": "0009,0010",
        "name": "Some Name",
        "keyword": "Keyword",
        "message_type": "C-STORE",
        "role": "SCU",
        "roles": "SCU",
        "codecs": "ascii",
        "struct_format": "H",
        "see_url": "https://dicom.nema.org/x",
        "indent": "  ",
        "hex_dump": "00  ff",
        "status_word": "Success",
        "presence": "Present",
        "yes_none": "Yes",
        "priority": "Low",
        "standalone_charset": "GBK",
        "refusal_reason": "must be str",
        "assoc_result": "Accepted",
        "assoc_source": "Service User",
        "assoc_reason": "Reserved",
        "context_result": "Accepted",
        "identity_type": "SAML",
        "type_name": "int",
        "dataset_encoding": "Little Endian Implicit",
    }
    for text in lines.TEMPLATES:
        filled = re.sub(
            r"\{([a-z_]+)\}", lambda m: samples.get(m.group(1), "1.2.826.0.1.3680043.2.1"), text
        )
        assert dicom_module._screened_line(filled) is not None, text


# --- The repairs after the third review (BACKLOG #6637) --------------------------------------------


def test_a_line_in_a_hold_is_screened_when_a_host_removed_the_filter() -> None:
    log = logging.getLogger("pynetdicom.utils")
    line = f"Invalid 'Affected SOP Instance UID' value '{_PLANTED}' - must not exceed 64 characters"
    log.removeFilter(dicom_module._PEER_VALUE_FILTER)
    try:
        with dicom_module._logs_held() as held:
            written = _written(log, lambda logger: logger.error(line))
    finally:
        log.addFilter(dicom_module._PEER_VALUE_FILTER)
    assert held == []  # CONTROL: with no filter, nothing held it, so it went to the handler
    assert written  # CONTROL: the handler did write the line
    assert _PLANTED not in written


def test_a_held_line_is_still_held_and_screened_once_written() -> None:
    log = logging.getLogger("pynetdicom.utils")
    line = f"Invalid 'Affected SOP Instance UID' value '{_PLANTED}' - must not exceed 64 characters"

    def emit(logger: logging.Logger) -> None:
        with dicom_module._logs_held() as held:
            logger.error(line)
        assert len(held) == 1  # the filter still holds it
        dicom_module._write_held(held)

    written = _written(log, emit)
    assert "value '[redacted]' - must not exceed 64 characters" in written
    assert _PLANTED not in written


def test_a_host_factory_that_copied_the_marker_is_not_taken_for_the_screen() -> None:
    original = logging.getLogRecordFactory()

    @functools.wraps(original)
    def hosts(*args: Any, **kwargs: Any) -> logging.LogRecord:
        return logging.LogRecord(*args, **kwargs)

    logging.setLogRecordFactory(hosts)
    try:
        dicom_module._install_record_screen()
        assert logging.getLogRecordFactory() is not hosts
        written = _written(
            logging.getLogger("pynetdicom.new_under_a_wrapped_factory"),
            lambda log: log.error("value %s", _PLANTED),
        )
    finally:
        logging.setLogRecordFactory(original)
    assert _PLANTED not in written and _WITHHELD in written


class _FalsyNotes(list[str]):
    def __bool__(self) -> bool:
        return False


def test_notes_that_read_as_false_are_not_written() -> None:
    exc = ValueError("Network timeout reached")
    exc.__notes__ = _FalsyNotes([f"note {_PLANTED}"])
    record = logging.LogRecord(
        "pynetdicom.dul", logging.ERROR, __file__, 1, "x", (), (ValueError, exc, None)
    )
    assert dicom_module._PEER_VALUE_FILTER.filter(record) is True
    written = logging.Formatter("%(message)s").format(record)
    assert "ValueError: Network timeout reached" in written  # CONTROL: the traceback is written
    assert _PLANTED not in written


def _raiser(exc: BaseException) -> Callable[..., Any]:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise exc

    return fail


async def _worker_fault_text(
    fault: Exception, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, status: int = 0x0000
) -> str:
    """One object sent through the real delivery arm with every write of its failure to the store
    raising ``fault``, and what the worker's fault log then writes through the engine's
    ``RedactionFilter``. The caller patches the library failure; this undoes it."""
    from messagefoundry.config.models import RetryPolicy
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.config.wiring import Registry
    from messagefoundry.logging_setup import RedactionFilter
    from messagefoundry.pipeline.wiring_runner import RegistryRunner, _WorkerFaultLog
    from messagefoundry.store import MessageStore
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    async def locked(*args: Any, **kwargs: Any) -> Any:
        raise fault

    store = await MessageStore.open(tmp_path / "chain.db")
    try:
        payload = _carry(make_sr_part10())
        await store.enqueue_message(
            channel_id="IB", raw=payload, deliveries=[("OB_SCU", payload)], now=100.0
        )
        item = await store.claim_next_fifo("OB_SCU")
        assert item is not None
        with _storage_scp(status=status) as port:
            runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
            runner._destinations["OB_SCU"] = _scu(port)
            runner._retry["OB_SCU"] = RetryPolicy()
            runner._simulate["OB_SCU"] = False
            monkeypatch.setattr(store, "mark_failed", locked)
            monkeypatch.setattr(store, "dead_letter_now", locked)
            with pytest.raises(type(fault)) as raised:
                await runner._process_delivery_item("OB_SCU", item)
    finally:
        monkeypatch.undo()
        await store.close()

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(logging.Formatter("%(message)s"))
    log = logging.getLogger("messagefoundry.pipeline.wiring_runner")
    log.addHandler(handler)
    try:
        _WorkerFaultLog("delivery", "OB_SCU").failed(
            raised.value, "delivery worker %r: unexpected error"
        )
    finally:
        log.removeHandler(handler)
    return stream.getvalue()


@pytest.mark.parametrize(
    "fault",
    [
        StoreAcquireTimeout("sqlite: store pool acquire timed out after 5s"),
        # The CONTROL: the engine's log chain already withholds what is printed under a driver error.
        sqlite3.OperationalError("database is locked"),
    ],
    ids=["store-acquire-timeout", "driver-error"],
)
async def test_a_store_fault_on_a_failed_delivery_logs_no_library_text(
    fault: Exception, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The real delivery arm: the send fails, the arm's write of that failure to the store raises,
    # so the new error's context is the DeliveryError, and the worker's fault log prints the chain.
    from pynetdicom.association import Association

    monkeypatch.setattr(Association, "send_c_store", _raiser(RuntimeError(_REFUSAL)))
    written = await _worker_fault_text(fault, tmp_path, monkeypatch)
    assert type(fault).__name__ in written and "DeliveryError" in written  # CONTROL
    assert "RuntimeError" in written  # the cause is still named, by its class
    assert _UID not in written, written


def _release_that_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """The release fails where the library's own can: inside the negotiation, after ``release()``
    has paused the reactor, so the association stays up unless something ends it."""
    from pynetdicom.acse import ACSE

    monkeypatch.setattr(ACSE, "negotiate_release", _raiser(RuntimeError(_REFUSAL)))


def _live_associations() -> set[threading.Thread]:
    """Every association thread in this process: the SCU's and the in-process peer's."""
    from pynetdicom.association import Association

    return {t for t in threading.enumerate() if isinstance(t, Association) and t.is_alive()}


async def _associations_left(before: set[threading.Thread]) -> set[threading.Thread]:
    """The associations started since ``before`` that are still up after a short grace."""
    deadline = time.monotonic() + 3.0
    while (left := _live_associations() - before) and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    return left


@pytest.mark.parametrize("status", [0x0000, 0xC000], ids=["confirmed-store", "peer-refused"])
async def test_a_failed_release_aborts_the_association(
    status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.transports.base import NegativeAckError
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    _release_that_raises(monkeypatch)
    before = _live_associations()
    with _storage_scp(status=status) as port:
        scu = _scu(port)
        if status:
            with pytest.raises(NegativeAckError):
                await scu.send(_carry(make_sr_part10()))
        else:
            await scu.send(_carry(make_sr_part10()))
        # Inside the block: the server's shutdown would end the peer's side either way.
        left = await _associations_left(before)
    assert not left


async def test_an_abort_that_raises_after_a_failed_release_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from pynetdicom.association import Association

    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    _release_that_raises(monkeypatch)
    real_abort = Association._abort_blocking

    def abort(self: Any, block: bool = True) -> None:
        real_abort(self, block)  # ends the test's association, then the library raises
        if self.is_requestor:  # the in-process peer's own shutdown must not raise
            raise RuntimeError(_REFUSAL)

    # Not Association.abort: pynetdicom's event dispatch binds this method over it on the instance.
    monkeypatch.setattr(Association, "_abort_blocking", abort)
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.transports.dicom"),
        _storage_scp() as port,
    ):
        assert await _scu(port).send(_carry(make_sr_part10())) is None
    logged = [r.getMessage() for r in caplog.records if r.name == dicom_module.__name__]
    assert [entry for entry in logged if "abort failed" in entry and "RuntimeError" in entry]
    assert _UID not in caplog.text


@pytest.mark.parametrize("send_raises", [True, False], ids=["send-raised", "peer-refused"])
async def test_a_failed_release_puts_no_library_text_in_the_worker_fault_log(
    send_raises: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The release raises in the store's finally. Its error must not replace the delivery error,
    # whose chain is the one the SCU scrubs, or the fault log prints the refused UID.
    from pynetdicom.association import Association

    _release_that_raises(monkeypatch)
    if send_raises:
        monkeypatch.setattr(Association, "send_c_store", _raiser(RuntimeError(_REFUSAL)))
    written = await _worker_fault_text(
        StoreAcquireTimeout("sqlite: store pool acquire timed out after 5s"),
        tmp_path,
        monkeypatch,
        status=0xA700,  # out of resources: a failed delivery whichever arm is taken
    )
    assert "StoreAcquireTimeout" in written and "DeliveryError" in written  # CONTROL
    assert _UID not in written, written


@pytest.mark.parametrize(
    ("status", "line"),
    [(0x0000, "delivered"), (0xB007, "stored with warning")],
    ids=["success", "warning"],
)
async def test_a_confirmed_store_with_a_failed_release_is_delivered_once(
    status: int,
    line: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The peer's status decides delivery. Through the real delivery arm, so a retry would show as a
    # second stored object and the row would not read as done.
    from messagefoundry.config.models import RetryPolicy
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.config.wiring import Registry
    from messagefoundry.pipeline.wiring_runner import RegistryRunner
    from messagefoundry.store import MessageStore
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    _release_that_raises(monkeypatch)
    received: list[bytes] = []
    store = await MessageStore.open(tmp_path / "delivered.db")
    try:
        payload = _carry(make_sr_part10())
        await store.enqueue_message(
            channel_id="IB", raw=payload, deliveries=[("OB_SCU", payload)], now=100.0
        )
        item = await store.claim_next_fifo("OB_SCU")
        assert item is not None
        with (
            caplog.at_level(logging.INFO, logger="messagefoundry.transports.dicom"),
            _storage_scp(status=status, received=received) as port,
        ):
            runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
            runner._destinations["OB_SCU"] = _scu(port)
            runner._retry["OB_SCU"] = RetryPolicy()
            runner._simulate["OB_SCU"] = False
            await runner._process_delivery_item("OB_SCU", item)
        rows = await store.outbox_for(item.message_id)
        assert await store.claim_next_fifo("OB_SCU", now=1e12) is None  # nothing left to re-send
        assert await store.count_dead(allowed_channels=None) == 0
    finally:
        await store.close()
    assert [row["status"] for row in rows] == ["done"] and not rows[0]["last_error"]
    assert len(received) == 1
    logged = [r.getMessage() for r in caplog.records if r.name == dicom_module.__name__]
    assert [entry for entry in logged if line in entry]
    assert [entry for entry in logged if "release failed" in entry and "RuntimeError" in entry]
    assert _UID not in caplog.text


@pytest.mark.parametrize(
    ("status", "kind", "says"),
    [
        (0xA700, "DeliveryError", "out-of-resources"),
        (0xC000, "NegativeAckError", "0xC000"),
        (None, "DeliveryError", "no response status"),
    ],
    ids=["out-of-resources", "hard-refusal", "no-confirmed-status"],
)
async def test_a_failed_release_keeps_any_answer_that_is_not_a_confirmed_store(
    status: int | None,
    kind: str,
    says: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from pydicom.dataset import Dataset
    from pynetdicom.association import Association

    from messagefoundry.transports.base import DeliveryError
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    _release_that_raises(monkeypatch)
    if status is None:  # what pynetdicom returns for an abort or a timeout: an empty status
        monkeypatch.setattr(Association, "send_c_store", lambda *a, **k: Dataset())
    with (
        caplog.at_level(logging.INFO, logger="messagefoundry.transports.dicom"),
        _storage_scp(status=status or 0) as port,
        pytest.raises(DeliveryError) as raised,
    ):
        await _scu(port).send(_carry(make_sr_part10()))
    assert type(raised.value).__name__ == kind
    assert says in str(raised.value) and _UID not in str(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    logged = [r.getMessage() for r in caplog.records if r.name == dicom_module.__name__]
    assert not [entry for entry in logged if "delivered" in entry or "stored with" in entry]
    assert [entry for entry in logged if "release failed" in entry and "RuntimeError" in entry]
    assert _UID not in caplog.text


async def test_a_failed_release_after_a_good_c_echo_passes_the_test_and_aborts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from tests.test_dicom_scu import _scu, _storage_scp

    _release_that_raises(monkeypatch)
    before = _live_associations()
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.transports.dicom"),
        _storage_scp() as port,
    ):
        await _scu(port).test_connection()  # the peer answered Success, so the test passes
        left = await _associations_left(before)
    assert not left
    logged = [r.getMessage() for r in caplog.records if r.name == dicom_module.__name__]
    assert [entry for entry in logged if "release failed" in entry and "RuntimeError" in entry]
    assert _UID not in caplog.text


async def test_a_failed_release_does_not_replace_a_failed_c_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pydicom.dataset import Dataset
    from pynetdicom.association import Association

    from messagefoundry.redaction import safe_exc
    from messagefoundry.transports.base import DeliveryError
    from tests.test_dicom_scu import _scu, _storage_scp

    refused = Dataset()
    refused.Status = 0x0110
    _release_that_raises(monkeypatch)
    monkeypatch.setattr(Association, "send_c_echo", lambda *a, **k: refused)
    with _storage_scp() as port, pytest.raises(DeliveryError) as raised:
        await _scu(port).test_connection()
    assert "0x0110" in str(raised.value)  # CONTROL: the peer's answer, not the release's error
    assert _UID not in safe_exc(raised.value)  # what the Test Connection result would carry


def _assert_stands_for(cause: BaseException | None, name: str) -> None:
    """``cause`` is the engine's stand-in for a library class ``name``, and holds nothing else."""
    assert isinstance(cause, dicom_module._LibraryCause)
    assert cause.library_class == name
    assert name in type(cause).__qualname__  # what a traceback prints
    assert not cause.args and not vars(cause)


def _bomb_in_the_guard(patch: pytest.MonkeyPatch) -> None:
    patch.setattr(dicom_module, "guard_part10_deflate", _raiser(DicomBombError(_REFUSAL)))


def _unreadable_header(patch: pytest.MonkeyPatch) -> None:
    patch.setattr(dicom_module, "guard_part10_deflate", _raiser(ValueError(_REFUSAL)))


def _unparseable_object(patch: pytest.MonkeyPatch) -> None:
    patch.setattr(dicom_module, "load_dcmread", lambda: _raiser(ValueError(_REFUSAL)))


def _unproposable_context(patch: pytest.MonkeyPatch) -> None:
    from pynetdicom import AE

    patch.setattr(AE, "add_requested_context", _raiser(ValueError(_REFUSAL)))


def _unsendable(patch: pytest.MonkeyPatch) -> None:
    from pynetdicom.association import Association

    patch.setattr(Association, "send_c_store", _raiser(ValueError(_REFUSAL)))


def _no_instance_uid(patch: pytest.MonkeyPatch) -> None:
    from pynetdicom.association import Association

    from messagefoundry.parsing.dicom._deps import load_dcmread

    real = load_dcmread()

    def read(*args: Any, **kwargs: Any) -> Any:
        dataset = real(*args, **kwargs)
        del dataset.SOPInstanceUID
        return dataset

    patch.setattr(dicom_module, "load_dcmread", lambda: read)
    patch.setattr(Association, "send_c_store", _raiser(AttributeError(_REFUSAL)))


def _final_unanswered(patch: pytest.MonkeyPatch) -> None:
    from pynetdicom.association import Association

    patch.setattr(dicom_module, "_ENGINE_SCP_ABORT_PAST_BYTES", 0)
    patch.setattr(dicom_module, "_MAX_UNANSWERED_SENDS_OVER_CEILING", 1)
    patch.setattr(Association, "send_c_store", _raiser(RuntimeError(_REFUSAL)))


def _transient_send_fault(patch: pytest.MonkeyPatch) -> None:
    from pynetdicom.association import Association

    patch.setattr(Association, "send_c_store", _raiser(RuntimeError(_REFUSAL)))


#: One case for each ``raise ... from`` in ``_store_object``; the census test below holds the count.
_CHAINED_REFUSALS: list[tuple[str, Callable[[pytest.MonkeyPatch], None], str | None, type]] = [
    ("deflate-bomb", _bomb_in_the_guard, "deflate-bomb", DicomBombError),
    ("unreadable-header", _unreadable_header, "bad-object", ValueError),
    ("unparseable", _unparseable_object, "bad-object", ValueError),
    ("unproposable", _unproposable_context, "bad-object", ValueError),
    ("unsendable", _unsendable, "cstore-unsendable", ValueError),
    ("no-instance-uid", _no_instance_uid, "bad-object", AttributeError),
    ("final-unanswered", _final_unanswered, "unanswered-over-ceiling", RuntimeError),
    ("transient", _transient_send_fault, None, RuntimeError),
]


def test_every_chained_raise_in_the_scu_has_a_refusal_case() -> None:
    tree = ast.parse(Path(dicom_module.__file__).read_text(encoding="utf-8"))
    body = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_store_object"
    )
    chained = [n for n in ast.walk(body) if isinstance(n, ast.Raise) and n.cause is not None]
    assert len(chained) == len(_CHAINED_REFUSALS)


@pytest.mark.parametrize(
    ("arrange", "code", "library"),
    [case[1:] for case in _CHAINED_REFUSALS],
    ids=[case[0] for case in _CHAINED_REFUSALS],
)
async def test_each_refusal_the_scu_raises_carries_no_library_text_on_its_chain(
    arrange: Callable[[pytest.MonkeyPatch], None],
    code: str | None,
    library: type,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.transports.base import DeliveryError, NegativeAckError
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    arrange(monkeypatch)
    with _storage_scp() as port, pytest.raises(DeliveryError) as raised:
        await _scu(port).send(_carry(make_sr_part10()))
    if code is None:
        assert not isinstance(raised.value, NegativeAckError)
    else:  # CONTROL: this case reached the arm it names
        assert isinstance(raised.value, NegativeAckError) and raised.value.code == code
    link: BaseException | None = raised.value
    seen = 0
    while link is not None:
        assert _UID not in str(link)
        seen += 1
        link = link.__cause__ or link.__context__
    assert seen == 2  # CONTROL: the cause is still there, by its class
    assert _UID not in "".join(traceback.format_exception(raised.value))
    cause = raised.value.__cause__
    _assert_stands_for(cause, library.__name__)


def _exception_whose_bare_new(gives: Callable[[Any], Any]) -> Exception:
    """A library-style exception holding the refusal, whose ``__new__`` with no arguments returns
    what ``gives`` does, and counts the call: the chain scrub must not make it."""

    class Odd(Exception):
        raised: Exception
        bare_calls = 0

        def __new__(cls, *args: Any) -> Any:
            if args:
                return super().__new__(cls, *args)
            cls.bare_calls += 1
            return gives(cls)

    Odd.raised = Odd(_REFUSAL)
    return Odd.raised


def _with_text_on_an_attribute(kind: Any) -> Any:
    bare = Exception.__new__(kind)
    bare.detail = _REFUSAL
    return bare


@pytest.mark.parametrize(
    "gives",
    [
        lambda kind: _REFUSAL,
        lambda kind: ValueError(_REFUSAL),
        lambda kind: kind(_REFUSAL),
        lambda kind: kind.raised,
        lambda kind: type("Sub", (kind,), {})(_REFUSAL),
        _with_text_on_an_attribute,
        _raiser(TypeError(_REFUSAL)),
        _raiser(SystemExit(_REFUSAL)),
    ],
    ids=[
        "a-string",
        "another-exception",
        "a-populated-instance",
        "the-raised-instance",
        "a-subclass",
        "text-on-an-attribute",
        "raises",
        "raises-a-base-exception",
    ],
)
def test_the_chain_scrub_never_raises_and_keeps_no_library_text(
    gives: Callable[[Any], Any],
) -> None:
    from messagefoundry.transports.base import DeliveryError

    library = _exception_whose_bare_new(gives)
    error = DeliveryError("the screened line")
    error.__cause__ = library
    dicom_module._drop_library_text_from_chain(error)
    assert error.__context__ is None
    written = "".join(traceback.format_exception(error))
    assert "the screened line" in written  # CONTROL
    assert _UID not in written, written
    assert type(library).bare_calls == 0  # type: ignore[attr-defined]  # no library code ran
    _assert_stands_for(error.__cause__, "Odd")


def test_a_slot_on_a_library_exception_cannot_carry_text_onto_the_chain() -> None:
    from messagefoundry.transports.base import DeliveryError

    class Slotted(Exception):
        __slots__ = ("detail",)
        detail: str

        def __new__(cls, *args: Any) -> Any:
            made = super().__new__(cls, *args)
            made.detail = _REFUSAL
            return made

        def __str__(self) -> str:
            return str(self.detail)

    error = DeliveryError("the screened line")
    error.__cause__ = Slotted()
    assert _UID in "".join(traceback.format_exception(error))  # CONTROL: the slot prints
    dicom_module._drop_library_text_from_chain(error)
    assert _UID not in "".join(traceback.format_exception(error))
    _assert_stands_for(error.__cause__, "Slotted")


def test_the_chain_scrub_reads_the_class_name_with_no_library_code() -> None:
    from messagefoundry.transports.base import DeliveryError

    meta = type("Meta", (type,), {"__name__": property(_raiser(RuntimeError(_REFUSAL)))})
    named: Any = meta("Named", (Exception,), {})
    error = DeliveryError("the screened line")
    error.__cause__ = named(_REFUSAL)
    dicom_module._drop_library_text_from_chain(error)
    _assert_stands_for(error.__cause__, "Named")


def test_a_delivery_error_with_no_chain_keeps_none() -> None:
    from messagefoundry.transports.base import DeliveryError

    error = DeliveryError("the screened line")
    dicom_module._drop_library_text_from_chain(error)
    assert error.__cause__ is None and error.__context__ is None


async def test_a_library_class_that_cannot_be_rebuilt_still_fails_as_a_delivery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pynetdicom.association import Association

    from messagefoundry.transports.base import DeliveryError
    from tests._dicom_sample import make_sr_part10
    from tests.test_dicom_scu import _carry, _scu, _storage_scp

    library = _exception_whose_bare_new(lambda kind: _REFUSAL)
    monkeypatch.setattr(Association, "send_c_store", _raiser(library))
    with _storage_scp() as port, pytest.raises(DeliveryError) as raised:
        await _scu(port).send(_carry(make_sr_part10()))
    assert _UID not in "".join(traceback.format_exception(raised.value))
