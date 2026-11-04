# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2827: the SOAP fault-code scan is linear in the reply, and it runs off the event loop.

The former ``_FAULTCODE_RE`` and ``_CODEVALUE_RE`` ended ``[^>]*>(.*?)</`` under DOTALL, so every
start tag with no close after it rescanned to the end of the reply. A partner reply of repeated start
tags then cost the square of its length, and on the 2xx path that cost ran on the event loop.

Three things are pinned here: what the new extraction reads, its time grows linearly, and the 2xx
classification runs in the worker thread. The old patterns are kept below, verbatim, as the positive
control for the second, and inside the reference for the first.

The new extraction is NOT the old one everywhere. The old patterns read the first code anywhere in
the reply, the Header included, and an empty ``<faultcode/>`` took the next element's text as its
code. Both could make a permanent fault read as a Receiver one and retry for ever; the named tests
below pin each, with a control.

The third is about which thread runs the scan, not about the loop staying responsive.
``SoapDestination._post_and_classify`` says why the two differ, and what bounds the difference.
"""

from __future__ import annotations

import asyncio
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


def _old_fault_code(body: str, fault: object = None) -> str:
    m = _OLD_FAULTCODE_RE.search(body) or _OLD_CODEVALUE_RE.search(body)
    return m.group(1) if m else ""


# The reference reading: the old patterns, run on the text between the first Fault start tag and
# its close tag, the earlier of the two names taken, with an element that cannot hold a code read
# as empty. It reuses the production close-tag and nested-tag patterns, so it re-checks the
# str.find bounds and captures, not those patterns; the named shapes pin what they read.
_REF_FAULT_RE = re.compile(
    r"<\s*(?:[\w.\-]+:)?Fault[\s/>](.*?)(?:</\s*(?:[\w.\-]+:)?Fault\s*>|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_REF_START_TAG_RE = re.compile(r"[^>]*>")


def _ref_fault_code(body: str) -> str:
    fault = _REF_FAULT_RE.search(body)
    if fault is None:
        return ""
    fault_tag = _REF_START_TAG_RE.match(body, fault.start(1) - 1)
    if fault_tag is None or fault_tag.group().endswith("/>"):
        return ""
    inner = fault.group(1)
    found = [
        (m, close)
        for m, close in (
            (_OLD_FAULTCODE_RE.search(inner), soap._FAULTCODE_END_RE),
            (_OLD_CODEVALUE_RE.search(inner), soap._CODEVALUE_END_RE),
        )
        if m is not None
    ]
    if not found:
        return ""
    m, own_close = min(found, key=lambda pair: pair[0].start())
    code = m.group(1)
    self_closing = inner[m.start(1) - 2] == "/"
    holds_an_element = soap._TAG_OPEN_RE.search(code) is not None
    if self_closing or holds_an_element or not own_close.match(inner, m.end() - 2):
        return ""
    return code


# --- what the extraction reads ------------------------------------------------------------------

#: Each shape, and the code read from it.
_NAMED_SHAPES = {
    "soap11": ("<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>", "soap:Client"),
    "soap12": ("<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault>", "s:Sender"),
    "soap12-subcode": (
        "<Fault><Code><Value>env:Receiver</Value><Subcode><Value>m:Busy</Value></Subcode>"
        "</Code></Fault>",
        "env:Receiver",
    ),
    "SOAP-ENV": (
        "<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode></SOAP-ENV:Fault>",
        "SOAP-ENV:Server",
    ),
    "dotted-prefix": (
        "<a.b:Fault><a.b:faultcode>a.b:Client</a.b:faultcode></a.b:Fault>",
        "a.b:Client",
    ),
    "spaced": (
        "< soap:Fault >< soap:faultcode  xmlns:q='u' >q:Client</ soap:faultcode>",
        "q:Client",
    ),
    "upper": ("<FAULT><FAULTCODE>CLIENT</FAULTCODE></FAULT>", "CLIENT"),
    "attr-with-gt": ('<Fault><faultcode a="x>y">soap:Client</faultcode></Fault>', 'y">soap:Client'),
    "cdata": (
        "<Fault><faultcode><![CDATA[soap:Server]]></faultcode></Fault>",
        "<![CDATA[soap:Server]]>",
    ),
    "comment": (
        "<Fault><faultcode><!-- c -->soap:Server</faultcode></Fault>",
        "<!-- c -->soap:Server",
    ),
    "multiline": ("<Fault><faultcode>\n  soap:Client\n</faultcode></Fault>", "\n  soap:Client\n"),
    "faultcode-unclosed-then-value": ("<Fault><Value>x:Sender</Value><faultcode>y", "x:Sender"),
    "name-only-prefix-match": ("<Fault><faultcodeX>a</faultcodeX><Value>v</Value></Fault>", "v"),
    # The first code element decides: an empty one is not passed over for the Value after it.
    "empty": ("<Fault><faultcode></faultcode><Value>x:Sender</Value></Fault>", ""),
    "nested": ("<Fault><faultcode><b>soap:Client</b></faultcode></Fault>", ""),
    "self-closing": ("<Fault><faultcode/>x</y>", ""),
    "foreign-close": ("<Fault><faultcode>soap:Server</faultstring></Fault>", ""),
    "no-gt": ("<Fault><faultcode", ""),
    "no-close": ("<Fault><faultcode>soap:Client", ""),
    "code-outside-any-fault": ("<faultcode>soap:Server</faultcode>", ""),
    "no-fault": ("<soap:Body>ok</soap:Body>", ""),
    "blank": ("", ""),
}


@pytest.mark.parametrize(("body", "code"), list(_NAMED_SHAPES.values()), ids=list(_NAMED_SHAPES))
def test_each_named_shape_yields_its_code(body: str, code: str) -> None:
    assert _fault_code(body) == code
    assert _ref_fault_code(body) == code


# Defect 1: the code was the first faultcode, else the first Value, anywhere in the reply, so a
# Header element, or a faultcode in a SOAP 1.2 Detail, decided the Fault.
_OUTSIDE_THE_CODE = {
    "soap12-header-value": (
        "<env:Envelope><env:Header><x:Value>Receiver</x:Value></env:Header><env:Body>"
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value></env:Code></env:Fault>"
        "</env:Body></env:Envelope>",
        "env:Sender",
    ),
    "soap11-header-faultcode": (
        "<soap:Envelope><soap:Header><x:faultcode>Server</x:faultcode></soap:Header>"
        "<soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault></soap:Body>"
        "</soap:Envelope>",
        "soap:Client",
    ),
    "soap12-detail-faultcode": (
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value></env:Code><env:Detail>"
        "<app:faultcode>SERVER_ERROR</app:faultcode></env:Detail></env:Fault>",
        "env:Sender",
    ),
}


@pytest.mark.parametrize(
    ("body", "code"), list(_OUTSIDE_THE_CODE.values()), ids=list(_OUTSIDE_THE_CODE)
)
def test_a_code_in_the_header_does_not_decide_a_sender_fault(body: str, code: str) -> None:
    """Red on the old reading, which took the Header's, or the Detail's, Receiver code and retried
    a Sender fault."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the defect"
    assert _fault_code(body) == code
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.permanent
    assert failure.code == "soap-sender"


_AFTER_THE_FAULT = {
    "after-the-close-tag": (
        "<Fault><faultstring>bad</faultstring></Fault><Value>env:Receiver</Value>"
    ),
    "after-a-self-closing-fault": "<env:Body><x:Fault/><r><Value>Receiver</Value></r></env:Body>",
}


@pytest.mark.parametrize("body", list(_AFTER_THE_FAULT.values()), ids=list(_AFTER_THE_FAULT))
def test_a_code_after_the_fault_does_not_decide_it(body: str) -> None:
    """The read stops at the Fault's close tag, and a self-closing Fault holds no code."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the bound"
    assert _fault_code(body) == ""
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.code == "soap-fault"


# Defect 2: an element that cannot hold a code read the next element's text as its code.
_EMPTY_CODE = {
    "self-closing-faultcode": (
        "<soap:Fault><faultcode/><faultstring>Server busy</faultstring></soap:Fault>"
    ),
    "faultcode-holding-an-element": (
        "<soap:Fault><faultcode><faultstring>Server busy</faultstring></faultcode></soap:Fault>"
    ),
    "self-closing-value": (
        "<env:Fault><env:Code><env:Value/><env:Subcode><env:Value>m:Server</env:Value>"
        "</env:Subcode></env:Code></env:Fault>"
    ),
}


@pytest.mark.parametrize("body", list(_EMPTY_CODE.values()), ids=list(_EMPTY_CODE))
def test_an_empty_code_element_yields_no_code(body: str) -> None:
    """Red on the old reading, which took ``<faultstring>Server busy`` as a Receiver code. With no
    code the fault reads as the empty-code path reads it: permanent, as ``soap-fault``."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the defect"
    assert _fault_code(body) == ""
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.permanent
    assert failure.code == "soap-fault"


_STILL_RECEIVER = {
    "header-sender-fault-receiver": (
        "<env:Envelope><env:Header><x:Value>Sender</x:Value></env:Header><env:Body>"
        "<env:Fault><env:Code><env:Value>env:Receiver</env:Value></env:Code></env:Fault>"
        "</env:Body></env:Envelope>"
    ),
    "faultcode-then-faultstring": (
        "<soap:Fault><faultcode>soap:Server</faultcode><faultstring>Client busy</faultstring>"
        "</soap:Fault>"
    ),
}


@pytest.mark.parametrize("body", list(_STILL_RECEIVER.values()), ids=list(_STILL_RECEIVER))
def test_a_receiver_code_in_the_fault_still_retries(body: str) -> None:
    """Control for both defects: a real Receiver code inside the Fault still reads as transient, so
    the two tests above do not pass by reading every fault as permanent."""
    failure = _classify_soap(200, body)
    assert isinstance(failure, DeliveryError) and not isinstance(failure, NegativeAckError)


#: Fragments a random reply is built from: the delimiters the scan looks for, both names, legal and
#: illegal prefixes, whitespace, and text.
_FRAGMENTS = (
    "<", ">", "</", "/>", " ", "\n", "faultcode", "FaultCode", "Value", "VALUE", "Fault",
    "soap:", "SOAP-ENV:", "a.b:", ":", "x", "Client", "Receiver", '"', "'", "=", "<!--", "-->",
    "<![CDATA[", "]]>", "faultcodes", "Values",
)  # fmt: skip


def test_random_replies_yield_the_reference_reading() -> None:
    """The argument is in ``_code_text``'s docstring; this samples it against the regex reference.
    Seeded, so a failure replays."""
    rng = random.Random(2827)
    for _ in range(5_000):
        body = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(0, 16)))
        assert _fault_code(body) == _ref_fault_code(body), repr(body)


# --- linear growth, with a positive control -----------------------------------------------------

#: The time ratio between an input four times as long and the base one. A linear scan gives about
#: 4 and a quadratic one about 16, so 8 splits them with room for runner noise either way. The same
#: line and attempt rule as tests/test_ad_group_dn_only.py.
_MAX_LINEAR_RATIO = 8.0

#: Replies shaped to make the old tails rescan: many start tags, none of them closed. ``long-prefixes``,
#: ``lt-run`` and ``long-close-prefixes`` name neither element, so they never reached the old tails;
#: the last two reach the checks on a code element that has a close. ``long-prefixes`` is here for the
#: name regexes' ``[\w.\-]+:`` prefix class, which backtracks over each run that has no colon, and
#: ``long-close-prefixes`` for the same class in the Fault close-tag scan, ``_FAULT_END_RE``.
#: ``lt-run`` is the shape measured in ``SoapDestination._post_and_classify``'s docstring.
_PATHOLOGICAL_REPLIES: dict[str, Callable[[int], str]] = {
    "faultcode-start-tags": lambda k: "<soap:Fault>" + "<faultcode>" * (k // 11),
    "value-start-tags": lambda k: "<soap:Fault>" + "<soap:Value>" * (k // 12),
    "unterminated-faultcode-tags": lambda k: "<Fault>" + "<faultcode " * (k // 11),
    "unterminated-value-tags": lambda k: "<Fault>" + "<Value " * (k // 7),
    "long-prefixes": lambda k: "<Fault>" + ("<" + "a." * 50) * (k // 101),
    "lt-run": lambda k: "<Fault>" + "<" * k,
    # The Fault close-tag scan's prefix class, over close tags with no colon.
    "long-close-prefixes": lambda k: "<Fault>" + ("</" + "a." * 50) * (k // 102),
    # A code element's own close-tag check, over one long prefix run with no colon, and its scan
    # for a nested start tag, over a long run of comment openers.
    "long-code-close-prefix": lambda k: "<Fault><faultcode>x</" + "a." * (k // 2),
    "long-code-text": lambda k: "<Fault><faultcode>" + "<!x" * (k // 3) + "</faultcode>",
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
    """The whole 2xx classification, every regex in it, on a reply up to 400,000 characters. Each
    shape is first shown to read as a fault, so the timing covers the fault-code extraction rather
    than a fault-less fall-through to the status."""
    assert isinstance(_classify_2xx(make(1_000)), NegativeAckError)
    readings = _scaling_ratios(_classify_2xx, make, 100_000)
    ratio = min(readings)
    assert ratio < _MAX_LINEAR_RATIO, (
        f"4x the reply took {ratio:.2f}x the time ({_attempts(readings)})"
    )


@pytest.mark.parametrize(
    ("shape", "k"), [("faultcode-start-tags", 2_000), ("unterminated-value-tags", 8_000)]
)
def test_the_linear_check_fails_the_old_patterns(
    shape: str, k: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the check above must fail the patterns #2827 replaced, or its pass proves
    nothing. It times the same subject, the 2xx classification, with the old extraction patched
    in, and asserts exactly the negation of that pass condition, once per old pattern and once per
    tail (``(.*?)</`` and ``[^>]*>``).

    The old patterns took about 0.4 s at 44,000 characters, so this runs far below the linear
    check's sizes. Each ``k`` is where the old curve read well clear of the line in 12 runs on one
    workstation (2026-11-03): 13.8x to 15.8x and 12.9x to 15.9x. The ``(.*?)</`` tail is the
    costlier one, so its ``k`` is smaller; at 4,000 it read once at 9.6x and took 1.6 s a run."""
    monkeypatch.setattr(soap, "_fault_code", _old_fault_code)
    readings = _scaling_ratios(_classify_2xx, _PATHOLOGICAL_REPLIES[shape], k)
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


def _dest(*, capture_response: bool) -> SoapDestination:
    d = build_destination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings=Soap(
                url="https://api.example.com/svc", capture_response=capture_response
            ).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


_SECRET = "an-echoed-credential"


@pytest.mark.parametrize("capture_response", [False, True], ids=["raising", "capturing"])
async def test_a_2xx_reply_is_classified_off_the_event_loop(
    capture_response: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The POST, the classification and the capture scrub run in one ``to_thread`` hop, on a
    thread that is not the loop's.

    Mutation: classify, or scrub, in ``send`` after the thread returns, as before #2827. Red: that
    recorded thread is the loop's. Mutation: a second ``to_thread`` hop for either. Red: the hop
    count. The thread ids alone cannot see that one, since the pool may hand both hops to the same
    idle worker."""
    threads: dict[str, list[int]] = {"post": [], "classify": [], "scrub": []}
    hops: list[object] = []
    to_thread = asyncio.to_thread

    async def counting_to_thread[T](func: Callable[..., T], /, *args: object) -> T:
        hops.append(func)
        return await to_thread(func, *args)

    monkeypatch.setattr(asyncio, "to_thread", counting_to_thread)

    def classify(status: int, body: str) -> DeliveryError | None:
        threads["classify"].append(threading.get_ident())
        return _classify_soap(status, body)

    monkeypatch.setattr(soap, "_classify_soap", classify)
    dest = _dest(capture_response=capture_response)
    # A secret the partner echoes in its Fault, which a capturing connection must mask.
    dest._body_secrets = (("{{TOKEN}}", _SECRET),)
    post, scrub = dest._post, dest._scrub_body_secrets

    def recording_post(payload: str) -> tuple[str, int, dict[str, str]]:
        threads["post"].append(threading.get_ident())
        return post(payload)

    def recording_scrub(text: str) -> str:
        threads["scrub"].append(threading.get_ident())
        return scrub(text)

    monkeypatch.setattr(dest, "_post", recording_post)
    monkeypatch.setattr(dest, "_scrub_body_secrets", recording_scrub)
    fault = f"<soap:Fault><faultcode>soap:Client</faultcode>{_SECRET}</soap:Fault>"
    dest._opener = _Opener(fault.encode())  # type: ignore[assignment]
    if capture_response:
        response = await dest.send("<env>{{TOKEN}}</env>")
        assert response is not None and response.outcome == "rejected"
        assert _SECRET not in response.body and "***" in response.body
        assert threads["scrub"], "a capturing connection with body_secrets scrubs the reply"
    else:
        with pytest.raises(NegativeAckError, match="Sender fault"):
            await dest.send("<env>{{TOKEN}}</env>")
        assert not threads["scrub"]
    assert len(hops) == 1, f"one to_thread hop, not {len(hops)}"
    (worker,) = threads["post"]
    assert worker != threading.get_ident()
    assert threads["classify"] == [worker]
    assert set(threads["scrub"]) <= {worker}
