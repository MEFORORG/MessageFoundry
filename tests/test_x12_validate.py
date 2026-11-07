# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict X12 validation (messagefoundry.parsing.x12.validate) — the opt-in pyx12 slow path behind the
tolerant X12Peek/X12Message hot path (ADR 0012, BACKLOG #32).

Covers: a clean interchange validates; a conformance-violating interchange reports structural errors +
emits a 999 ack; non-X12 input raises X12ValidationError (not a generic crash); and the PHI guard —
the offending data *value* never appears in the surfaced errors (only schema-label locators)."""

from __future__ import annotations

import importlib
import io
import logging
import threading
from collections.abc import Iterator

import pytest

pytest.importorskip("pyx12")

from messagefoundry.parsing.x12 import (  # noqa: E402 - after importorskip
    X12SegmentError,
    X12ValidationError,
    X12ValidationResult,
    validate,
)
from messagefoundry.parsing.x12._deps import load_x12_code_resolver  # noqa: E402

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
    rendered = "\n".join(
        f"{e.code}|{e.message}|{e.segment_id}|{e.element_position}|{e.element_name}|{e.loop}"
        for e in result.errors
    )
    assert secret not in rendered, "the offending data value leaked into a surfaced error"


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


def test_pyx12_itself_logs_the_value_when_unmuted(
    unmuted_pyx12_logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    """Control for the next test: pyx12 really does put the value in the log. Without this, the
    next test's "not in the log" would also pass if pyx12 simply stopped logging it."""
    from messagefoundry.parsing.x12._deps import load_x12_validator

    x12n_document, make_params = load_x12_validator()
    with caplog.at_level(logging.DEBUG):
        x12n_document(make_params(), io.StringIO(_LEAKY_837), io.StringIO(), None, None, None)
    assert _LEAKY in caplog.text


def test_validation_silences_the_value_bearing_pyx12_logger(
    unmuted_pyx12_logger: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:
    """pyx12 logs raw, value-bearing error strings at ERROR; the pass must suppress them so the
    secret never reaches the general log, and must leave the tree muted afterwards."""
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
    # With "|" and newline as the sender's separators, a GS03 of "X~ST" and a GS02 of "999" put a
    # whole "~ST*999" segment boundary into the 997's GS line, ahead of its real ST*997.
    msg = _conformant_270(dob="19431399").replace("GS*HS*SENDERAPP*RECVAPP*", "GS*HS*999*X#ST*")
    msg = msg.replace("*", "|").replace("~", chr(10)).replace("#", "~")
    real = load_x12_code_resolver()
    seen: list[bool] = []

    def recording(err_cde: str, prefer_5010: bool = True) -> str | None:
        seen.append(prefer_5010)
        return real(err_cde, prefer_5010=prefer_5010)

    monkeypatch.setattr(_X12_VALIDATE, "load_x12_code_resolver", lambda: recording)
    result = validate(msg)
    assert result.ack is not None and "~ST*999" in result.ack and "ST*997" in result.ack
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


def test_sender_text_cannot_forge_the_closing_iea_of_a_fragment() -> None:
    # With "|" and newline as the sender's separators, a GS06 of "1~IEA*1*000000001" is echoed into
    # the fragment's AK102, so the fragment's text ends in an IEA segment pyx12 never wrote.
    pipes = _conformant_270().replace("ST*270*0001~", "ST*270~").replace("*", "|")
    pipes = pipes.replace("|1200|1|X|", "|1200|1#IEA*1*000000001|X|")
    pipes = pipes.replace("GE|1|1~", "GE|1|1#IEA*1*000000001~")
    msg = pipes.replace("~", chr(10)).replace("#", "~")
    result = validate(msg)
    assert result.ack is None
    assert result.ack_transaction is None
