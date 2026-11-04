# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2827: the SOAP fault-code scan is linear in the reply, and it runs off the event loop.

The former ``_FAULTCODE_RE`` and ``_CODEVALUE_RE`` ended ``[^>]*>(.*?)</`` under DOTALL, so every
start tag with no close after it rescanned to the end of the reply. A partner reply of repeated start
tags then cost the square of its length, and on the 2xx path that cost ran on the event loop.

Three things are pinned here: the new extraction returns what the old patterns returned, its time
grows linearly, and the 2xx classification runs in the worker thread. The old patterns are kept
below, verbatim, as the reference for the first and the positive control for the second.
"""

from __future__ import annotations

import gc
import random
import re
import threading
from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Soap
from messagefoundry.transports import build_destination, soap
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.soap import SoapDestination, _classify_soap, _fault_code
from tests._growth import _growth_between

# The patterns as they stood at engine origin/main 7051dbc552, before BACKLOG #2827.
_OLD_FAULTCODE_RE = re.compile(
    r"<\s*(?:[\w.\-]+:)?faultcode\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL
)
_OLD_CODEVALUE_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Value\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)


def _old_fault_code(body: str) -> str:
    m = _OLD_FAULTCODE_RE.search(body) or _OLD_CODEVALUE_RE.search(body)
    return m.group(1) if m else ""


# --- the same capture as before ---------------------------------------------------------------

_NAMED_SHAPES = {
    "soap11": "<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>",
    "soap12": "<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault>",
    "soap12-subcode": (
        "<Fault><Code><Value>env:Receiver</Value><Subcode><Value>m:Busy</Value></Subcode>"
        "</Code></Fault>"
    ),
    "SOAP-ENV": "<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode></SOAP-ENV:Fault>",
    "dotted-prefix": "<a.b:Fault><a.b:faultcode>a.b:Client</a.b:faultcode></a.b:Fault>",
    "spaced": "< soap:Fault >< soap:faultcode  xmlns:q='u' >q:Client</ soap:faultcode>",
    "upper": "<FAULT><FAULTCODE>CLIENT</FAULTCODE></FAULT>",
    "attr-with-gt": '<Fault><faultcode a="x>y">soap:Client</faultcode></Fault>',
    "cdata": "<Fault><faultcode><![CDATA[soap:Server]]></faultcode></Fault>",
    "comment": "<Fault><faultcode><!-- c -->soap:Server</faultcode></Fault>",
    "nested": "<Fault><faultcode><b>soap:Client</b></faultcode></Fault>",
    "multiline": "<Fault><faultcode>\n  soap:Client\n</faultcode></Fault>",
    "empty": "<Fault><faultcode></faultcode><Value>x:Sender</Value></Fault>",
    "faultcode-unclosed-then-value": "<Fault><Value>x:Sender</Value><faultcode>y",
    "name-only-prefix-match": "<faultcodeX>a</faultcodeX><Value>v</Value>",
    "no-gt": "<Fault><faultcode",
    "no-close": "<Fault><faultcode>soap:Client",
    "self-closing": "<Fault><faultcode/>x</y>",
    "no-fault": "<soap:Body>ok</soap:Body>",
    "blank": "",
}


@pytest.mark.parametrize("body", list(_NAMED_SHAPES.values()), ids=list(_NAMED_SHAPES))
def test_each_named_shape_yields_what_the_old_patterns_did(body: str) -> None:
    assert _fault_code(body) == _old_fault_code(body)


#: Fragments a random reply is built from: the delimiters the scan looks for, both names, legal and
#: illegal prefixes, whitespace, and text.
_FRAGMENTS = (
    "<", ">", "</", "/>", " ", "\n", "faultcode", "FaultCode", "Value", "VALUE", "Fault",
    "soap:", "SOAP-ENV:", "a.b:", ":", "x", "Client", "Receiver", '"', "'", "=", "<!--", "-->",
    "<![CDATA[", "]]>", "faultcodes", "Values",
)  # fmt: skip


def test_random_replies_yield_what_the_old_patterns_did() -> None:
    """The proof of equivalence is in ``_code_text``'s docstring; this samples it. Seeded, so a
    failure replays."""
    rng = random.Random(2827)
    for _ in range(5_000):
        body = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(0, 16)))
        assert _fault_code(body) == _old_fault_code(body), repr(body)


# --- linear growth, with a positive control -----------------------------------------------------

#: The time ratio between an input four times as long and the base one. A linear scan gives about
#: 4 and a quadratic one about 16, so 8 splits them with room for runner noise either way. The same
#: line and attempt rule as tests/test_ad_group_dn_only.py.
_MAX_LINEAR_RATIO = 8.0

#: Replies shaped to make the old tail rescan: many start tags, none of them closed.
_PATHOLOGICAL_REPLIES: dict[str, Callable[[int], str]] = {
    "faultcode-start-tags": lambda k: "<soap:Fault>" + "<faultcode>" * (k // 11),
    "value-start-tags": lambda k: "<soap:Fault>" + "<soap:Value>" * (k // 12),
    "unterminated-faultcode-tags": lambda k: "<Fault>" + "<faultcode " * (k // 11),
    "unterminated-value-tags": lambda k: "<Fault>" + "<Value " * (k // 7),
    "long-prefixes": lambda k: "<Fault>" + ("<" + "a." * 50) * (k // 101),
}


def _attempt_ratio(scan: Callable[[str], object], small: str, large: str) -> float:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        return _growth_between(scan, small, large, rounds=3)
    finally:
        if was_enabled:
            gc.enable()


def _scaling_ratios(
    scan: Callable[[str], object], make: Callable[[int], str], k: int
) -> list[float]:
    """Time on a ``4 * k`` reply over time on a ``k`` one, re-measured up to three times while a
    reading is at or over the line, so one preemption cannot fake a curve. The lowest is the
    verdict for both the linear checks and the control."""
    small, large = make(k), make(4 * k)
    readings: list[float] = []
    for _ in range(3):
        readings.append(_attempt_ratio(scan, small, large))
        if readings[-1] < _MAX_LINEAR_RATIO:
            break
    return readings


def _attempts(readings: list[float]) -> str:
    return "attempts: " + ", ".join(f"{reading:.2f}x" for reading in readings)


def _classify_2xx(body: str) -> object:
    return _classify_soap(200, body)


@pytest.mark.parametrize(
    "make", list(_PATHOLOGICAL_REPLIES.values()), ids=list(_PATHOLOGICAL_REPLIES)
)
def test_a_pathological_reply_is_classified_in_linear_time(make: Callable[[int], str]) -> None:
    """The whole 2xx classification, every regex in it, on a reply up to 400,000 characters."""
    readings = _scaling_ratios(_classify_2xx, make, 100_000)
    ratio = min(readings)
    assert ratio < _MAX_LINEAR_RATIO, (
        f"4x the reply took {ratio:.2f}x the time ({_attempts(readings)})"
    )


@pytest.mark.parametrize("shape", ["faultcode-start-tags", "unterminated-value-tags"])
def test_the_linear_check_fails_the_old_patterns(shape: str) -> None:
    """Positive control: the check above must fail the patterns #2827 replaced, or its pass proves
    nothing. It asserts exactly the negation of that pass condition, once per old pattern and once
    per tail (``(.*?)</`` and ``[^>]*>``). The old patterns took about 0.4 s at 44,000 characters,
    so this runs at 4,000 and 16,000."""
    readings = _scaling_ratios(_old_fault_code, _PATHOLOGICAL_REPLIES[shape], 4_000)
    ratio = min(readings)
    assert ratio >= _MAX_LINEAR_RATIO, (
        f"the old patterns scaled by only {ratio:.2f}x ({_attempts(readings)})"
    )


# --- the 2xx classification runs off the event loop ---------------------------------------------


class _Resp:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else self._body[:amt]

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Opener:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        return _Resp(self._body)


def _dest() -> SoapDestination:
    d = build_destination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings=Soap(url="https://api.example.com/svc").settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


async def test_a_2xx_reply_is_classified_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: classify in ``send`` after the thread returns, as before #2827. Red: the recorded
    thread is the loop's."""
    threads: list[int] = []

    def recording(status: int, body: str) -> DeliveryError | None:
        threads.append(threading.get_ident())
        return _classify_soap(status, body)

    monkeypatch.setattr(soap, "_classify_soap", recording)
    dest = _dest()
    fault = b"<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>"
    dest._opener = _Opener(fault)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError):
        await dest.send("<env/>")
    assert len(threads) == 1
    assert threads[0] != threading.get_ident()
