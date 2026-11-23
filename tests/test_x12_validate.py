# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict X12 validation (messagefoundry.parsing.x12.validate) — the opt-in pyx12 slow path behind the
tolerant X12Peek/X12Message hot path (ADR 0012, BACKLOG #32).

Covers: a clean interchange validates; a conformance-violating interchange reports structural errors +
emits a 999 ack; non-X12 input raises X12ValidationError (not a generic crash); and the PHI guard —
an offending element *value* does not appear in the surfaced errors, and a segment id is kept only
when pyx12's bundled maps define it. A sender value equal to a real id (``LIN``) is still kept."""

from __future__ import annotations

import importlib
import io
import logging
import threading
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("pyx12")

from messagefoundry.parsing.x12 import (  # noqa: E402 - after importorskip
    X12SegmentError,
    X12ValidationError,
    X12ValidationResult,
    validate,
)
from messagefoundry.parsing.x12._deps import (  # noqa: E402
    _read_map_segment_ids,
    load_x12_code_resolver,
    load_x12_map_segment_ids,
)
from messagefoundry.redaction import safe_traceback  # noqa: E402
from tests._content_free import assert_chain_severed  # noqa: E402

_ISA = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*060501*1200*^*00501*000000001*0*P*:~"
)
_GS = "GS*HC*SENDERAPP*RECVAPP*20060501*1200*1*X*005010X222A1~"
_GE = "GE*1*1~"
_IEA = "IEA*1*000000001~"


def _interchange(*body: str) -> str:
    return _ISA + _GS + "".join(body) + _GE + _IEA


# A fully IG-conformant 270 eligibility inquiry (004010X092A1) — its map ships in the pyx12 wheel, and
# it is simple enough to hand-build to zero-violation conformance (the 5010 X279 map is not bundled).
# ISA11 is the 4010 repetition separator 'U'; ISA12/GS08 select the 004010X092A1 implementation guide.
_ISA_270 = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*060501*1200*U*00401*000000001*0*P*:~"
)
_GS_270 = "GS*HS*SENDERAPP*RECVAPP*20060501*1200*1*X*004010X092A1~"


def _conformant_270(*, dob: str = "19430519", iea: str = "IEA*1*000000001~") -> str:
    """The conformant 004010 270 eligibility inquiry, with slots left open to break exactly one thing."""
    return (
        _ISA_270 + _GS_270 + "ST*270*0001~"
        "BHT*0022*13*10001234*20060501*1319~"
        "HL*1**20*1~"
        "NM1*PR*2*ABC COMPANY*****PI*842610001~"
        "HL*2*1*21*1~"
        "NM1*1P*1*JONES*MARCUS****SV*0202034~"
        "HL*3*2*22*0~"
        "TRN*1*93175-012547*9877281234~"
        "NM1*IL*1*SMITH*ROBERT****MI*11122333301~"
        f"DMG*D8*{dob}*M~"
        "DTP*307*D8*20060101~"
        "EQ*30~"
        "SE*13*0001~GE*1*1~" + iea
    )


def test_valid_conformant_interchange_validates_true() -> None:
    # A conformant 270 must validate with valid=True and zero surfaced errors (the positive case the
    # existing suite lacked). The negative-ack side is exercised by the conformance-error test above.
    result = validate(_conformant_270())
    assert isinstance(result, X12ValidationResult)
    assert result.valid is True
    assert result.errors == ()


def test_element_error_code_is_the_x12_number() -> None:
    # pyx12 4.0.1 moved the X12 number from err_cde (now a pyx12 name such as
    # "ELE_8_invalid_date_range") to x12_code; ``code`` must stay the X12 number (data element error 8,
    # "Invalid Date").
    result = validate(_conformant_270(dob="19431399"))
    assert result.valid is False
    element = [e for e in result.errors if e.element_position is not None]
    assert [(e.segment_id, e.element_position, e.code) for e in element] == [("DMG", 2, "8")]
    assert all(e.code.isdigit() for e in result.errors)


def test_envelope_error_code_is_the_x12_number() -> None:
    # IEA01 counts two groups but the interchange holds one: TA1 note code 021 ("Invalid Number of
    # Included Groups Value"), not pyx12's "ISA_021_invalid_group_count".
    result = validate(_conformant_270(iea="IEA*2*000000001~"))
    assert result.valid is False
    assert [(e.message, e.code) for e in result.errors] == [("interchange error", "021")]


def test_validate_reports_conformance_errors_and_emits_999() -> None:
    # An 837 stub missing mandatory loops + a wrong SE count — pyx12 finds real violations.
    msg = _interchange(
        "ST*837*0001*005010X222A1~",
        "BHT*0019*00*0123*20060501*1200*CH~",
        "SE*4*0001~",
    )
    result = validate(msg)
    assert isinstance(result, X12ValidationResult)
    assert result.valid is False
    assert result.errors, "expected at least one conformance error"
    assert all(isinstance(e, X12SegmentError) for e in result.errors)
    # The 999 Functional Acknowledgment is generated for free off the 005010 walk.
    assert result.ack is not None
    assert result.ack_transaction == "999"
    assert "ST*999" in result.ack


def test_validate_bytes_input_is_decoded() -> None:
    result = validate(_interchange("ST*837*0001*005010X222A1~", "SE*2*0001~").encode("utf-8"))
    assert isinstance(result, X12ValidationResult)
    assert result.valid is False  # incomplete 837


def test_non_x12_input_raises_validation_error() -> None:
    with pytest.raises(X12ValidationError):
        validate("this is not an X12 interchange at all")


def _rendered(result: X12ValidationResult) -> str:
    """Every surfaced field of every error, as one string to search for a leaked value."""
    return "\n".join(
        f"{e.code}|{e.message}|{e.segment_id}|{e.element_position}|{e.element_name}|{e.loop}"
        for e in result.errors
    )


def test_errors_never_leak_the_offending_value() -> None:
    """PHI guard: a bad data-element value (here a fake date) must NOT appear anywhere in the surfaced
    errors — only the structural locators (code, segment id, element position, schema type name)."""
    secret = "NOTADATE99"
    msg = _interchange(
        "ST*837*0001*005010X222A1~",
        f"BHT*0019*00*0123*{secret}*1200*CH~",  # BHT04 invalid/too-long date
        "SE*4*0001~",
    )
    result = validate(msg)
    assert result.valid is False
    assert secret not in _rendered(result), "the offending data value leaked into a surfaced error"


_LEAKY = "LEAKYVALUE"
_LEAKY_837 = _interchange(
    "ST*837*0001*005010X222A1~",
    f"BHT*0019*00*0123*{_LEAKY}*1200*CH~",
    "SE*4*0001~",
)


# The package re-exports the function under the module's own name, so a plain `import ... as`
# binds the function; importlib returns the module.
_X12_VALIDATE = importlib.import_module("messagefoundry.parsing.x12.validate")


def _pyx12_tree() -> list[logging.Logger]:
    logging.getLogger("pyx12")  # make sure the parent itself is in the manager's dict
    return [
        logger
        for name, logger in logging.Logger.manager.loggerDict.copy().items()
        if (name == "pyx12" or name.startswith("pyx12.")) and isinstance(logger, logging.Logger)
    ]


@pytest.fixture
def unmuted_pyx12_logger() -> Iterator[logging.Logger]:
    """Put the ``pyx12`` logger tree back to logging's defaults for one test, and restore it after.

    ``validate`` mutes the tree for the life of the process, so an earlier test would otherwise
    have muted it already, and a test of the mute would pass without ``validate`` doing anything."""
    parent = logging.getLogger("pyx12")
    saved_levels = {logger: logger.level for logger in _pyx12_tree()}
    saved = (parent.propagate, list(parent.handlers))
    for logger in saved_levels:
        logger.setLevel(logging.NOTSET)
    parent.propagate = True
    for handler in list(parent.handlers):
        parent.removeHandler(handler)
    try:
        yield parent
    finally:
        for logger in _pyx12_tree():
            logger.setLevel(saved_levels.get(logger, logging.NOTSET))
        parent.propagate = saved[0]
        for handler in list(parent.handlers):
            parent.removeHandler(handler)
        for handler in saved[1]:
            parent.addHandler(handler)


def _leaky_validator() -> tuple[Any, Callable[[], Any]]:
    """pyx12's validator with value logging turned back on.

    pyx12 4.1.0 leaves the error message and the offending value out of its log records unless
    ``log_data_values`` is set; 4.0.1 always logged them and ignores the parameter. The engine never
    sets it, so with it off the mute tests below would pass even if the engine muted nothing."""
    from messagefoundry.parsing.x12._deps import load_x12_validator

    x12n_document, make_params = load_x12_validator()

    def leaky_params() -> Any:
        params = make_params()
        params.set("log_data_values", True)
        return params

    return x12n_document, leaky_params


def test_pyx12_itself_logs_the_value_when_unmuted(
    unmuted_pyx12_logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    """Control for the next test: pyx12, run as the next test runs it, really does put the value
    in the log. Without this, the next test's "not in the log" would also pass if pyx12 simply
    stopped logging it."""
    x12n_document, make_params = _leaky_validator()
    with caplog.at_level(logging.DEBUG):
        x12n_document(make_params(), io.StringIO(_LEAKY_837), io.StringIO(), None, None, None)
    assert _LEAKY in caplog.text


def test_validation_silences_the_value_bearing_pyx12_logger(
    unmuted_pyx12_logger: logging.Logger,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pyx12 logs raw, value-bearing error strings at ERROR; the pass must suppress them so the
    secret never reaches the general log, and must leave the tree muted afterwards."""
    # The pass runs with value logging on, as the control above does, so the secret is in what
    # pyx12 logs and only the engine's mute keeps it out.
    monkeypatch.setattr(_X12_VALIDATE, "load_x12_validator", _leaky_validator)
    # Capture at the root (where pyx12's records would propagate); do NOT force the pyx12 logger level
    # -- the validator's own suppression must win on its own.
    with caplog.at_level(logging.DEBUG):
        validate(_LEAKY_837)
        validate(_LEAKY_837)
    assert _LEAKY not in caplog.text
    # Muted for good: nothing restores it, so a concurrent pass cannot unmute it (BACKLOG #1603).
    assert unmuted_pyx12_logger.propagate is False
    assert unmuted_pyx12_logger.level > logging.CRITICAL
    # Exactly one sink after two passes: each pass re-asserts the mute without stacking handlers.
    assert unmuted_pyx12_logger.handlers == [_X12_VALIDATE._PYX12_SINK]


def test_a_child_logger_pinned_to_debug_is_muted_too(
    unmuted_pyx12_logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    """``pyx12.error_997``, ``error_999`` and ``error_html`` pin their own level to DEBUG at import,
    so a level on the ``pyx12`` parent does not reach them.

    The pass sets every existing ``pyx12`` logger above CRITICAL. A logger that pins itself to DEBUG
    again after the pass is still held, because the parent stops propagation."""
    pinned = logging.getLogger("pyx12.error_999")
    pinned.setLevel(logging.DEBUG)  # what pyx12's import does; the fixture had reset it
    validate(_LEAKY_837)
    assert pinned.level > logging.CRITICAL
    pinned.setLevel(logging.DEBUG)  # a re-pin after the pass
    with caplog.at_level(logging.DEBUG):
        pinned.error("value %s", _LEAKY)
        logging.getLogger("control.not_pyx12").error("control %s", "SEEN")
    assert _LEAKY not in caplog.text
    assert "control SEEN" in caplog.text  # the capture sees an ordinary record from here


def test_an_overlapping_pass_cannot_unmute_the_logger_for_another(
    unmuted_pyx12_logger: logging.Logger,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two passes on two threads: the first finishes while the second is still inside pyx12.

    The removed context manager restored the saved level when a pass ended. Here the first pass
    would have restored NOTSET mid-way through the second, and the second's ERROR record would
    have reached the root log. The second thread also logs to a non-pyx12 logger at the same
    moment: that record must arrive, so the capture is shown to work from that thread."""
    first_inside = threading.Event()
    second_inside = threading.Event()
    first_done = threading.Event()

    def fake_document(
        _params: object,
        _src: object,
        _ack: object,
        _html: object,
        _xml: object,
        fd_json: io.StringIO,
    ) -> bool:
        if threading.current_thread().name == "first":
            first_inside.set()
            assert second_inside.wait(10)
        else:
            second_inside.set()
            assert first_done.wait(10)
            logging.getLogger("pyx12.error_handler").error("value %s", _LEAKY)
            logging.getLogger("control.not_pyx12").error("control %s", "SEEN")
        fd_json.write("{}")
        return True

    monkeypatch.setattr(_X12_VALIDATE, "load_x12_validator", lambda: (fake_document, object))
    results: dict[str, bool] = {}

    def run() -> None:
        results[threading.current_thread().name] = validate(_LEAKY_837).valid

    # The FIRST pass must be the first to enter: it is the one whose saved state predates both
    # passes, so it is the one whose restore would have unmuted the logger under the second.
    with caplog.at_level(logging.DEBUG):
        first = threading.Thread(target=run, name="first")
        second = threading.Thread(target=run, name="second")
        first.start()
        assert first_inside.wait(10)
        second.start()
        first.join(10)
        first_done.set()
        second.join(10)

    assert results == {"first": True, "second": True}
    assert "control SEEN" in caplog.text
    assert _LEAKY not in caplog.text
    # And the tree is left muted, not restored to the level the first pass saw on entry.
    assert unmuted_pyx12_logger.propagate is False


def test_segment_error_is_frozen_dataclass() -> None:
    err = X12SegmentError(code="3", message="segment NM1: error 3", segment_id="NM1")
    with pytest.raises(Exception):  # noqa: B017
        err.code = "9"  # type: ignore[misc]


def test_codes_follow_the_ack_version_and_fall_back_to_the_pyx12_name() -> None:
    # pyx12's own x12_code field is 999-first whatever the version; a pass that generated a 997 (a
    # 004010 GS08) reports a not-used segment as AK304 "2", not the 999's IK304 "I4". A raw X12 number
    # passes through, and a name pyx12 maps to no X12 code (an HL count mismatch) stands in as itself.
    def report(vriic: str) -> dict[str, object]:
        seg = {"seg_id": "REF", "errors": [{"err_cde": "SEG_2_segment_not_used"}], "elements": []}
        hl = {"seg_id": "HL", "errors": [{"err_cde": "SEG_8_hl_count_mismatch"}], "elements": []}
        txn = {"errors": [], "segments": [seg, hl]}
        group = {"vriic": vriic, "errors": [{"err_cde": "5"}], "transactions": [txn]}
        return {"interchanges": [{"errors": [], "groups": [group]}]}

    resolve = load_x12_code_resolver()
    flatten = _X12_VALIDATE._flatten_errors
    codes_4010 = [e.code for e in flatten(report("004010X092A1"), resolve, prefer_5010=False)]
    codes_5010 = [e.code for e in flatten(report("005010X222A1"), resolve, prefer_5010=True)]
    assert codes_4010 == ["5", "2", "SEG_8_hl_count_mismatch"]
    assert codes_5010 == ["5", "I4", "SEG_8_hl_count_mismatch"]


def test_validate_resolves_codes_against_the_ack_it_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The 004010 270 is acked with a 997, so its codes resolve AK-first; the 005010 837 gets a 999.
    real = load_x12_code_resolver()
    seen: list[bool] = []

    def recording(err_cde: str, prefer_5010: bool = True) -> str | None:
        seen.append(prefer_5010)
        return real(err_cde, prefer_5010=prefer_5010)

    monkeypatch.setattr(_X12_VALIDATE, "load_x12_code_resolver", lambda: recording)
    result = validate(_conformant_270(dob="19431399"))
    assert result.ack_transaction == "997" and seen and not any(seen)
    seen.clear()
    result = validate(_interchange("ST*837*0001*005010X222A1~", "SE*2*0001~"))
    assert result.ack_transaction == "999" and seen and all(seen)


def test_a_997_whose_sender_text_holds_999_is_still_a_997(monkeypatch: pytest.MonkeyPatch) -> None:
    # The 997 echoes GS03 "TEST" then GS02 "999APP", so its GS line holds the text "ST*999"; only the ST
    # segment's own ST01 names the ack.
    msg = _conformant_270(dob="19431399").replace("GS*HS*SENDERAPP*RECVAPP*", "GS*HS*999APP*TEST*")
    real = load_x12_code_resolver()
    seen: list[bool] = []

    def recording(err_cde: str, prefer_5010: bool = True) -> str | None:
        seen.append(prefer_5010)
        return real(err_cde, prefer_5010=prefer_5010)

    monkeypatch.setattr(_X12_VALIDATE, "load_x12_code_resolver", lambda: recording)
    result = validate(msg)
    assert result.ack is not None and "ST*999" in result.ack
    assert result.ack_transaction == "997"
    assert seen and not any(seen)


def test_a_4010_pass_with_no_ack_reports_the_4010_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    # An inbound 004010 997 (GS01 FA) gets no ack, so the code list comes from the group's GS08. A
    # not-used segment is spliced into pyx12's real report: 004010 says "2", only the 999 says "I4".
    isa = _ISA_270
    gs = "GS*FA*SENDERAPP*RECVAPP*20060501*1200*1*X*004010~"
    msg = isa + gs + "ST*997*0001~AK1*HS*1~AK9*A*1*1*1~SE*4*0001~GE*1*1~IEA*1*000000001~"
    real_loads = _X12_VALIDATE.json_loads_or_refusal

    def splice(raw: str) -> tuple[object, object]:
        report, refused = real_loads(raw)
        txn = report["interchanges"][0]["groups"][0]["transactions"][0]
        bad = {"seg_id": "REF", "errors": [{"err_cde": "SEG_2_segment_not_used"}], "elements": []}
        txn["segments"].append(bad)
        return report, refused

    monkeypatch.setattr(_X12_VALIDATE, "json_loads_or_refusal", splice)
    result = validate(msg)
    assert result.ack is None and result.ack_transaction is None
    assert [e.code for e in result.errors if e.segment_id == "REF"] == ["2"]


def test_sender_separators_cannot_forge_the_acks_st_segment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With "|" and newline as the sender's separators, a GS03 of "X~ST" and a GS02 of "999" are
    # echoed into the 997's GS line, ahead of its real ST*997. pyx12 4.0.1 copied them as-is, a whole
    # "~ST*999" segment boundary; 4.1.0, the floor, writes "?" for the "~", leaving the text "?ST*999".
    msg = _conformant_270(dob="19431399").replace("GS*HS*SENDERAPP*RECVAPP*", "GS*HS*999*X#ST*")
    msg = msg.replace("*", "|").replace("~", chr(10)).replace("#", "~")
    real = load_x12_code_resolver()
    seen: list[bool] = []

    def recording(err_cde: str, prefer_5010: bool = True) -> str | None:
        seen.append(prefer_5010)
        return real(err_cde, prefer_5010=prefer_5010)

    monkeypatch.setattr(_X12_VALIDATE, "load_x12_code_resolver", lambda: recording)
    result = validate(msg)
    # pyx12 escapes the echoed "~", so no segment boundary is forged; a pyx12 that stopped escaping
    # fails here. Positive control: the text "ST*999" still sits in the ack ahead of the real "ST*997",
    # so an ack type read from the ack's text would come out as 999.
    assert result.ack is not None and "ST*997" in result.ack
    assert "GS*FA*X?ST*999*" in result.ack and "~ST*999" not in result.ack
    assert result.ack.index("ST*999") < result.ack.index("ST*997")
    assert result.ack_transaction == "997"
    assert seen and not any(seen)


def test_a_997_pass_never_reports_a_999_only_code() -> None:
    # NM110 is not used in this 004010 270. pyx12 maps that error to the 999's I10 alone, with no 997
    # AK code, so on a 997 pass the code is pyx12's own name rather than a code no 997 carries.
    result = validate(_conformant_270().replace("MI*11122333301~", "MI*11122333301*X~"))
    assert result.ack_transaction == "997"
    element = [
        (e.segment_id, e.element_position, e.code) for e in result.errors if e.element_position
    ]
    assert element == [("NM1", 10, "ELE_I10_NOT_USED")]
    import pyx12.error_codes

    ik_only = {s.ik_code for s in pyx12.error_codes.ERROR_CODES.values() if s.ak_code is None}
    assert not [e.code for e in result.errors if e.code in ik_only]


def test_a_fragment_from_an_ack_writer_that_failed_is_not_returned(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # An ST with no ST02 makes pyx12's 997 writer raise after its AK1, and pyx12 swallows the error;
    # the fragment it leaves has no closing IEA, so it is no 997 and is not returned to send.
    with caplog.at_level(logging.WARNING, logger=_X12_VALIDATE.__name__):
        result = validate(_conformant_270().replace("ST*270*0001~", "ST*270~"))
    assert result.ack is None
    assert result.ack_transaction is None
    assert "before the closing IEA" in caplog.text


def test_sender_text_cannot_forge_the_closing_iea_of_a_fragment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With "|" and newline as the sender's separators, a GS06 of "1~IEA*1*000000001" is echoed into
    # the fragment's AK1, so the fragment's text ends in "IEA*1*000000001~", which pyx12 never wrote
    # as an IEA. pyx12 4.0.1 copied the "~" as-is, a whole IEA segment; 4.1.0, the floor, writes "?"
    # for it, and its 997 writer still splits the "*"s into elements, so the text ends the same way.
    pipes = _conformant_270().replace("ST*270*0001~", "ST*270~").replace("*", "|")
    pipes = pipes.replace("|1200|1|X|", "|1200|1#IEA*1*000000001|X|")
    pipes = pipes.replace("GE|1|1~", "GE|1|1#IEA*1*000000001~")
    msg = pipes.replace("~", chr(10)).replace("#", "~")
    buffers: list[io.StringIO] = []
    real_buffer = _X12_VALIDATE._AckBuffer

    def keep() -> io.StringIO:
        buffers.append(real_buffer())
        return buffers[-1]

    monkeypatch.setattr(_X12_VALIDATE, "_AckBuffer", keep)
    result = validate(msg)
    # pyx12 escapes the echoed "~", so the forged text is no whole IEA segment; a pyx12 that stopped
    # escaping fails here. Positive control: the fragment's text still ends in the forged IEA text, so
    # a check that the text ends in an IEA's text would take the fragment for a finished ack.
    tail = buffers[0].getvalue().rstrip()
    assert tail.endswith("AK1*HS*1?IEA*1*000000001~")
    assert result.ack is None
    assert result.ack_transaction is None


# A bad BHT04 that holds all four of the ack writer's own delimiters ("~ * : ^"). The sender uses
# "|", newline, ">" and "{" as its separators, so to the sender these are data, and pyx12 echoes the
# bad value into the 999's IK404.
_DELIMITED_VALUE = "20*6:5^1~2"
_DELIMITED_837 = (
    _interchange(
        "ST*837*0001*005010X222A1~",
        "BHT*0019*00*0123*#VALUE#*1200*CH~",
        "SE*4*0001~",
    )
    .replace("*^*00501*", "*{*00501*")
    .replace("*:~", "*>~")
    .replace("*", "|")
    .replace("~", chr(10))
    .replace("#VALUE#", _DELIMITED_VALUE)
)


def test_a_value_holding_the_ack_writers_delimiters_is_a_validation_result() -> None:
    # pyx12 4.1.0's X12Writer.Write raises EngineError on a value holding one of its delimiters. Its
    # 999 writer replaces those characters in an echoed value with "?" first, so the 999 completes.
    result = validate(_DELIMITED_837)
    assert result.valid is False
    assert [(e.segment_id, e.element_position) for e in result.errors if e.element_position] == [
        ("BHT", 4),
        ("BHT", 4),
    ]
    assert result.ack is not None and result.ack_transaction == "999"
    assert "IK4*4*373*8*20?6?5?1?2~" in result.ack
    # Every segment of the 999 starts with an ack segment ID. That catches an echoed "~" only where
    # the text after it is not an ack segment ID, so a raw "1~IK5" would pass it.
    ack_ids = {"ISA", "GS", "ST", "AK1", "AK2", "IK3", "IK4", "IK5", "AK9", "SE", "GE", "IEA"}
    segments = [seg.strip() for seg in result.ack.split("~") if seg.strip()]
    assert {seg.split("*", 1)[0] for seg in segments} <= ack_ids
    # So also pin the IK4 segments whole: an echoed "~" or "*" anywhere in the value would cut one
    # or add an element.
    assert [seg for seg in segments if seg.startswith("IK4*")] == [
        "IK4*4*373*5*20?6?5?1?2",
        "IK4*4*373*8*20?6?5?1?2",
    ]
    assert _DELIMITED_VALUE not in _rendered(result)


def test_an_ack_writer_that_raises_on_a_delimiter_ends_as_a_validation_result(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    unmuted_pyx12_logger: logging.Logger,
) -> None:
    # Take the "?" replacement away, so the raw value reaches X12Writer.Write. The writer raises,
    # pyx12 catches it inside x12n_document and leaves a fragment, and the pass still returns a
    # result: no ack, the errors, and nothing of the value in them or in the log.
    import pyx12.error_visitor
    import pyx12.errors
    import pyx12.x12file

    raised: list[Exception] = []
    real_check = pyx12.x12file.X12Writer._check_delimiters

    def spy(self: Any, seg_data: Any) -> None:
        try:
            real_check(self, seg_data)
        except pyx12.errors.EngineError as exc:
            raised.append(exc)
            raise

    monkeypatch.setattr(pyx12.x12file.X12Writer, "_check_delimiters", spy)
    monkeypatch.setattr(pyx12.error_visitor, "sanitize_ack_segment", lambda seg_data: None)

    # Positive control first: with the engine's mute taken away and the pyx12 tree at logging's
    # defaults, the same pass logs the value, in the exception pyx12 logs for its failed 999 writer.
    # So the absence below is the mute's doing, not a pass that logs nothing.
    real_mute = _X12_VALIDATE._mute_pyx12_logger
    monkeypatch.setattr(_X12_VALIDATE, "_mute_pyx12_logger", lambda: None)
    with caplog.at_level(logging.DEBUG):
        validate(_DELIMITED_837)
    failures = [r for r in caplog.records if r.getMessage() == "Failed to create 999 response"]
    assert len(failures) == 1 and failures[0].exc_info is not None
    assert "20*6" in str(failures[0].exc_info[1])
    assert "20*6" in caplog.text  # the instrument the log negative below reads
    assert raised

    monkeypatch.setattr(_X12_VALIDATE, "_mute_pyx12_logger", real_mute)
    raised.clear()
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        result = validate(_DELIMITED_837)
    # Positive control: the writer really did raise on the value.
    assert raised
    assert result.valid is False and result.errors
    assert result.ack is None and result.ack_transaction is None
    assert "before the closing IEA" in caplog.text
    assert "20*6" not in caplog.text and "20*6" not in _rendered(result)


def test_an_unterminated_segment_past_pyx12s_limit_is_a_validation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pyx12 4.1.0 can raise X12Error on a segment longer than about 1,040,000 characters, as it
    # does on this unterminated one; 4.0.1 could stop reading at a much shorter segment. The pass
    # raises X12ValidationError, and neither its message nor the pyx12 error's message shows the
    # segment's text. The pyx12 error is read from a spy, because it is no longer chained (#5370).
    import pyx12.errors

    seen: list[Exception] = []
    monkeypatch.setattr(_X12_VALIDATE, "load_x12_validator", _spying_validator(seen))
    body = "Q" * (1024 * 1024 + 100)
    with pytest.raises(X12ValidationError) as caught:
        validate(_ISA + _GS + "ST*837*0001*005010X222A1~BHT*0019*00*" + body)
    assert len(seen) == 1
    assert isinstance(seen[0], pyx12.errors.X12Error) and "terminator" in str(seen[0])
    assert "QQQQ" not in str(caught.value) and "QQQQ" not in str(seen[0])
    assert_chain_severed(caught.value)


# --- BACKLOG #5370: no interchange text through the exception chain, the repr or a segment id. ---

_PLANT = "PLANTEDNAME"
_PLANT_ISA02 = "AUTHPLANT1"
_PLANT_ISA04 = "SECPLANT22"
# 17 elements inside ISA's fixed 106 characters: ISA06 gives up padding for one more separator, so
# pyx12 finds its terminators, reads the segment, and refuses it with the whole segment quoted.
_ISA_17_ELEMENTS = (
    f"ISA*00*{_PLANT_ISA02}*00*{_PLANT_ISA04}*ZZ*SENDER*X       *ZZ*RECEIVER       "
    "*060501*1200*U*00401*000000001*0*P*:~"
)
_TAIL_270 = "ST*270*0001~SE*2*0001~GE*1*1~IEA*1*000000001~"
# Each makes pyx12 raise an exception that quotes the planted values: X12Error, EngineError
# ("Map not found", which quotes GS08) and ValueError (int() of GE01).
_RAISING_INTERCHANGES = {
    "isa17": (_ISA_17_ELEMENTS + _GS_270 + _TAIL_270, (_PLANT_ISA02, _PLANT_ISA04)),
    "gs08": (
        _ISA_270 + "GS*HS*SENDERAPP*RECVAPP*20060501*1200*1*X*PLANTGS08~" + _TAIL_270,
        ("PLANTGS08",),
    ),
    "ge01": (
        _ISA_270 + _GS_270 + "ST*270*0001~SE*2*0001~GE*PLANTGE01*1~IEA*1*000000001~",
        ("PLANTGE01",),
    ),
}


def _spying_validator(seen: list[Exception]) -> Callable[[], tuple[Any, Callable[[], Any]]]:
    """A ``load_x12_validator`` whose walk records what pyx12 raised. The engine no longer chains it,
    so this is how a test proves the fixture really made pyx12 quote the planted text."""
    from messagefoundry.parsing.x12._deps import load_x12_validator

    def load() -> tuple[Any, Callable[[], Any]]:
        x12n_document, make_params = load_x12_validator()

        def spy(*args: Any) -> Any:
            try:
                return x12n_document(*args)
            except Exception as exc:
                seen.append(exc)
                raise

        return spy, make_params

    return load


@pytest.mark.parametrize(
    ("raw", "plants"), list(_RAISING_INTERCHANGES.values()), ids=list(_RAISING_INTERCHANGES)
)
def test_a_refused_interchange_chains_no_pyx12_text(
    raw: str, plants: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Exception] = []
    monkeypatch.setattr(_X12_VALIDATE, "load_x12_validator", _spying_validator(seen))
    with pytest.raises(X12ValidationError) as caught:
        validate(raw)

    # Control: pyx12's own message holds the values, so their absence below is the engine's doing.
    assert len(seen) == 1
    assert all(plant in str(seen[0]) for plant in plants)

    exc = caught.value
    assert_chain_severed(exc)
    for text in (
        safe_traceback((type(exc), exc, exc.__traceback__)),
        "".join(traceback.format_exception(exc)),
    ):
        assert not any(plant in text for plant in plants)
    # What is kept of the pyx12 error is its class name, so a refusal can still be told apart.
    assert type(seen[0]).__name__ in str(exc)


def _270_with(segment: str) -> str:
    """The conformant 270 with one extra segment ahead of the subscriber's NM1."""
    return _conformant_270().replace("NM1*IL*", f"{segment}NM1*IL*", 1)


def test_the_repr_of_a_result_leaves_out_the_ack_that_echoes_a_value() -> None:
    result = validate(_270_with(f"NM1|IL|1|{_PLANT}|ROBERT~"))
    assert result.ack is not None and _PLANT in result.ack  # control: this ack echoes the value
    assert _PLANT not in repr(result)
    # Exact, so a field added to the result later has to be read for the same exposure.
    assert repr(result) == (
        f"X12ValidationResult(valid=False, errors={result.errors!r}, "
        f"ack_transaction={result.ack_transaction!r})"
    )


@pytest.mark.parametrize(
    "segment",
    [
        f"NM1|IL|1|{_PLANT}|ROBERT~",  # the wrong element separator
        f"NM1{_PLANT}~",  # no separator after the id
        f"{_PLANT}~",  # the value alone
        f"{_PLANT}*IL*1~",  # a value where the id goes
    ],
)
def test_a_wrongly_delimited_segment_puts_no_value_in_an_error(segment: str) -> None:
    result = validate(_270_with(segment))
    assert result.valid is False
    assert _PLANT not in repr(result)  # holds every field of every error
    # The violation is still reported and located, without the id it could not trust.
    dropped = [e for e in result.errors if e.segment_id is None and e.line is not None]
    assert dropped, "the bad segment must still be reported"
    assert all(e.message.startswith("segment ?: error ") for e in dropped)


def test_a_well_delimited_unknown_segment_shows_no_id() -> None:
    result = validate(_270_with(f"ZZZ*{_PLANT}*ROBERT~"))
    assert "ZZZ" not in {e.segment_id for e in result.errors}
    assert "segment ?: error 1" in [e.message for e in result.errors]
    assert _PLANT not in _rendered(result)


@pytest.mark.parametrize("template", ["NM1*IL*1*O~{}*A*B~", "{}~", "{}*A~"])
@pytest.mark.parametrize("name", ["LEE", "KIM", "WU", "NG", "ZZZ", "DOE"])
def test_sender_text_shaped_like_an_id_is_not_kept(
    name: str, template: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _270_with(template.format(name))
    # Control: with the name in the map set it is kept, so pyx12 really put it where the id goes.
    with monkeypatch.context() as patched:
        patched.setattr(_X12_VALIDATE, "load_x12_map_segment_ids", lambda: frozenset({name}))
        assert name in {e.segment_id for e in validate(raw).errors}

    errors = validate(raw).errors
    assert name not in {e.segment_id for e in errors}
    assert not any(e.message.startswith((f"segment {name}:", f"element {name}")) for e in errors)
    assert any(e.message.startswith("segment ?: error ") for e in errors)


def test_a_sender_value_equal_to_a_real_id_is_still_kept() -> None:
    # The known limit: the set is the union of every indexed map, so LIN is kept here although the
    # 270's own map does not define it.
    assert "LIN" in {e.segment_id for e in validate(_270_with("LIN*A~")).errors}


def test_no_id_is_kept_when_the_map_set_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_X12_VALIDATE, "load_x12_map_segment_ids", frozenset)
    assert _X12_VALIDATE._structural_segment_id({"seg_id": "NM1"}) is None


def test_the_bundled_index_gives_real_ids_of_the_id_shape() -> None:
    ids = load_x12_map_segment_ids()
    assert {"ISA", "GS", "ST", "NM1", "N1", "SE", "GE", "IEA"} <= ids
    assert all(_X12_VALIDATE._SEGMENT_ID.fullmatch(seg_id) for seg_id in ids)


def test_a_failed_map_read_is_not_kept_and_is_retried_after_a_pause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deps = importlib.import_module("messagefoundry.parsing.x12._deps")
    results = iter([frozenset[str](), frozenset({"NM1"})])
    reads: list[object] = []
    start = 1000.0
    now = [start]

    def read(map_dir: object) -> frozenset[str]:
        reads.append(map_dir)
        return next(results)

    monkeypatch.setattr(deps, "_read_map_segment_ids", read)
    monkeypatch.setattr(deps, "_map_ids", frozenset())
    monkeypatch.setattr(deps, "_map_ids_retry_at", 0.0)
    # A clock only this module sees. The test moves the clock and never the deadline, so the
    # deadline the failed read wrote is what decides whether the retry fires.
    monkeypatch.setattr(deps, "time", SimpleNamespace(monotonic=lambda: now[0]))
    pause = deps._MAP_IDS_RETRY_SECONDS
    assert pause > 0

    assert load_x12_map_segment_ids() == frozenset()
    now[0] = start + pause - 0.001
    assert load_x12_map_segment_ids() == frozenset()  # inside the pause: no second read
    assert len(reads) == 1

    now[0] = start + pause  # the pause is over
    assert load_x12_map_segment_ids() == {"NM1"}
    assert load_x12_map_segment_ids() == {"NM1"}  # a good read is kept
    assert len(reads) == 2


_MAP_INDEX = "<maps><version><map>a.xml</map><map>b.xml</map></version></maps>"


def test_the_map_reader_reads_only_the_maps_the_index_lists(tmp_path: Path) -> None:
    (tmp_path / "maps.xml").write_text(_MAP_INDEX, encoding="utf-8")
    (tmp_path / "a.xml").write_text("<map><segment xid='NM1'/></map>", encoding="utf-8")
    (tmp_path / "b.xml").write_text("<map><segment xid='N1'/><loop xid='X1'/></map>", "utf-8")
    (tmp_path / "unlisted.xml").write_text("<map><segment xid='ZZZ'/></map>", encoding="utf-8")
    assert _read_map_segment_ids(tmp_path) == {"NM1", "N1"}


@pytest.mark.parametrize(
    "contents",
    [
        None,
        {},
        {"maps.xml": "<maps/>"},
        {"maps.xml": "<maps"},
        {"maps.xml": _MAP_INDEX, "a.xml": "<map><segment xid='NM1'/></map>"},
        {"maps.xml": _MAP_INDEX, "a.xml": "<map><segment xid='NM1'/></map>", "b.xml": "<map"},
        {"maps.xml": _MAP_INDEX, "a.xml": "<map/>", "b.xml": "<map/>"},
        {"maps.xml": "<?xml version='1.0' encoding='no-such-codec'?><maps/>"},  # LookupError
        {"maps.xml": "<?xml version='1.0' encoding='utf-7'?><maps/>"},  # plain ValueError
    ],
    ids=[
        "no-directory",
        "no-index",
        "empty-index",
        "unparseable-index",
        "listed-map-missing",
        "listed-map-unparseable",
        "no-segment",
        "unknown-encoding",
        "multibyte-encoding",
    ],
)
def test_maps_that_cannot_be_read_give_no_ids(
    contents: dict[str, str] | None, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    map_dir = tmp_path / "map"
    if contents is not None:
        map_dir.mkdir()
        for name, text in contents.items():
            (map_dir / name).write_text(text, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert _read_map_segment_ids(map_dir) == frozenset()
    assert "no segment id" in caplog.text


@pytest.mark.parametrize(
    ("seg_id", "kept"),
    [
        ("NM1", "NM1"),
        ("N1", "N1"),
        ("ZZZ", None),  # the shape of an id, but no map defines it
        ("TST", None),  # only in comp_test.xml, which pyx12's index does not list
        ("UNU", None),  # likewise
        ("nm1", None),  # lower case
        ("A", None),  # too short
        ("NM1X", None),  # too long
        ("1NM", None),  # pyx12's own check requires a leading letter
        ("N1\n", None),  # ``$`` would match before this newline
        ("NM" + chr(0x661), None),  # a non-ASCII digit
        ("", None),
        (None, None),
        (7, None),
    ],
)
def test_only_a_segment_id_the_maps_define_is_kept(seg_id: Any, kept: str | None) -> None:
    seg = {"seg_id": seg_id, "cur_line": 3, "name": "Subscriber Name"}
    seg_err = _X12_VALIDATE._segment_error("1", seg, {})
    ele_err = _X12_VALIDATE._element_error("8", seg, {"ele_pos": 2, "name": "Date"})
    shown = kept or "?"
    assert (seg_err.segment_id, seg_err.message) == (kept, f"segment {shown}: error 1")
    assert (ele_err.segment_id, ele_err.message) == (kept, f"element {shown}02: error 8")
