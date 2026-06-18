# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0016 — synchronous X12 request/response (real-time eligibility 270/271, TA1 classification).

Covers the TA1 classification matrix (TA1*A/E/R, business-response-instead-of-TA1, unparseable, the
capturing-vs-non-capturing branch), a real-socket capture round-trip, byte-identical-when-off,
ta1_required, and the X12 wiring-validation arm.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import messagefoundry.parsing.x12.message as x12_message_mod
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import X12, WiringError, build_outbound_connection
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, NegativeAckError
from messagefoundry.transports.x12 import X12Destination, X12Source


def _isa(*, control: str = "000000001") -> str:
    el = "*"
    segment = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + "SENDERID".ljust(15)
        + el
        + "ZZ"
        + el
        + "RECEIVERID".ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + "^"
        + el
        + "00501"
        + el
        + control
        + el
        + "0"
        + el
        + "P"
        + el
        + ":"
    )
    assert len(segment) == 105
    return segment + "~"


def _270() -> str:
    return (
        _isa()
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~BHT*0022*13*10001234*20240101*1200~HL*1**20*1~SE*4*0001~GE*1*1~"
        + "IEA*1*000000001~"
    )


def _271() -> bytes:
    return (
        _isa()
        + "GS*HB*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*271*0001~BHT*0022*11*10001234*20240101*1200~SE*3*0001~GE*1*1~"
        + "IEA*1*000000001~"
    ).encode()


def _ta1(code: str) -> bytes:
    """A TA1-only interchange with TA1-04 = ``code`` (A/E/R)."""
    return (_isa() + f"TA1*000000001*240101*1200*{code}*000~" + "IEA*1*000000001~").encode()


EDI = _270()


def _dest(port: int = 9, **settings: object) -> X12Destination:
    base: dict[str, object] = {"host": "127.0.0.1", "port": port, "timeout_seconds": 5}
    base.update(settings)
    return X12Destination(Destination(name="out", type=ConnectorType.X12, settings=base))


def _source() -> X12Source:
    return X12Source(Source(type=ConnectorType.X12, settings={"host": "127.0.0.1", "port": 0}))


# --- TA1 classification matrix (direct _check_ta1 unit tests) ----------------


def test_ta1_accepted_capturing() -> None:
    r = _dest(capture_response=True)._check_ta1(_ta1("A"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted" and r.detail == "TA1*A"


def test_ta1_accepted_non_capturing_returns_none() -> None:
    assert _dest(capture_response=False)._check_ta1(_ta1("A")) is None


def test_ta1_reject_is_permanent_both_modes() -> None:
    for capturing in (True, False):
        with pytest.raises(NegativeAckError) as ei:
            _dest(capture_response=capturing)._check_ta1(_ta1("R"))
        assert ei.value.permanent is True and ei.value.code == "AR"


def test_ta1_error_is_accepted_with_warning_not_retried() -> None:
    # Resolved decision (ADR 0016): TA1*E = accepted-with-warning, NOT a retry (the interchange WAS
    # accepted). Capturing → accepted reply; non-capturing → None. Never a NegativeAckError.
    r = _dest(capture_response=True)._check_ta1(_ta1("E"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    assert "E" in (r.detail or "")
    assert _dest(capture_response=False)._check_ta1(_ta1("E")) is None


def test_business_response_instead_of_ta1_is_accepted() -> None:
    r = _dest(capture_response=True)._check_ta1(_271())
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    assert "271" in r.body  # the application response is carried back for re-ingress


def test_unparseable_reply_capturing_vs_not() -> None:
    r = _dest(capture_response=True)._check_ta1(b"NOT-AN-INTERCHANGE~")
    assert isinstance(r, DeliveryResponse) and r.outcome == "unparseable"
    with pytest.raises(DeliveryError):  # non-capturing: a retryable transport error
        _dest(capture_response=False)._check_ta1(b"NOT-AN-INTERCHANGE~")


# --- real-socket integration -------------------------------------------------


async def _round_trip(reply: bytes | None, **dest_kw: object) -> DeliveryResponse | None:
    async def handler(raw: bytes) -> str | None:
        return reply.decode() if reply is not None else None

    source = _source()
    await source.start(handler)
    try:
        return await _dest(source.sockport, **dest_kw).send(EDI)
    finally:
        await source.stop()


async def test_capture_271_round_trip() -> None:
    resp = await _round_trip(_271(), capture_response=True)
    assert resp is not None and resp.outcome == "accepted" and "ST*271" in resp.body


async def test_send_returns_none_when_not_capturing() -> None:
    # Byte-identical when off: fire-and-forget returns None even though a reply is sent.
    assert await _round_trip(_271()) is None


async def test_ta1_required_reject_fails_fast() -> None:
    with pytest.raises(NegativeAckError) as ei:
        await _round_trip(_ta1("R"), ta1_required=True)
    assert ei.value.permanent is True


async def test_ta1_required_no_reply_retries() -> None:
    with pytest.raises(DeliveryError):
        await _round_trip(None, ta1_required=True, timeout_seconds=0.3)


# --- wiring validation (check / dry-run, no store) ---------------------------


def test_x12_capture_requires_expect_reply() -> None:
    with pytest.raises(WiringError, match="expect_reply"):
        build_outbound_connection("OB", X12(host="h", port=5, capture_response=True))


def test_x12_reingress_forces_capture_still_requires_expect_reply() -> None:
    with pytest.raises(WiringError, match="expect_reply"):
        build_outbound_connection("OB", X12(host="h", port=5, reingress_to="IB_LOOP"))


def test_x12_capture_with_expect_reply_ok() -> None:
    oc = build_outbound_connection(
        "OB", X12(host="h", port=5, capture_response=True, expect_reply=True)
    )
    assert oc.spec.settings["capture_response"] is True


def test_x12_reingress_with_expect_reply_forces_capture() -> None:
    oc = build_outbound_connection(
        "OB", X12(host="h", port=5, reingress_to="IB_LOOP", expect_reply=True)
    )
    assert oc.spec.settings["capture_response"] is True  # forced by reingress_to (ADR 0013)


# --- codec purity ------------------------------------------------------------


def test_x12_codec_stays_pure() -> None:
    # ADR 0016: _check_ta1 lives in transports/x12.py and uses the existing X12Message API; the codec
    # gains nothing and imports no engine module (parsing/ purity carve-out, CLAUDE.md §4).
    src = Path(x12_message_mod.__file__).read_text(encoding="utf-8")
    for banned in ("messagefoundry.transports", "messagefoundry.pipeline", "messagefoundry.store"):
        assert banned not in src
