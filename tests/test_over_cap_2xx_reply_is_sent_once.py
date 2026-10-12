# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An over-cap reply body after a 2xx is not sent again (vault BACKLOG #2180).

Before this, a 2xx whose body was over the byte bound raised ``ResponseTooLargeError``, a retryable
``DeliveryError``. The partner had already answered 2xx, so on a first deployment each retry would
have sent the request again, and the message would then have dead-lettered when the retries ran out.

The owner ruling of 2026-10-05 judges such a reply by who reads the body:

* nothing looks inside it: the message is delivered and the body is dropped. The message gets a
  ``reply_dropped`` event, and then a WARNING is logged (vault BACKLOG #3040 items 2 and 5). REST
  with capture off, and a plain FHIR write with capture off;
* the engine reads it to know the outcome, or passes it on: a permanent refusal, and no
  re-send. SOAP, DICOMweb and REST with capture on.

Two FHIR cases are a refusal on the same principle: an update the engine wraps in a transaction,
whose reply it reads for the entry status, in either capture mode; and any FHIR write with capture
on, whose reply is passed on. The ruling names the principle and not these FHIR refusals. Refusing
them is a reading of it made when this was built, and the owner may reverse that reading. If that
happens, the FHIR rows of ``_RULED`` that say ``_REFUSED`` are the ones to change.

Three layers:

* **The helper**, with a small bound, including the two arms it must leave alone.
* **Each destination's ``_post``**, against a peer whose body never ends.
* **The delivery worker, on the wire.** A loopback partner counts the requests it receives while
  the worker is given the row again and again. This is the layer the item is about: one send, and
  the recorded status the ruling names. The same harness shows a 500 IS sent again, so a count of
  one is not something it reports for every reply.

Synthetic data only.
"""

from __future__ import annotations

import contextlib
import http.server
import inspect
import json
import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import FHIR, Registry, build_outbound_connection
from messagefoundry.parsing import RawMessage
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports.base import NegativeAckError, ReplyBodyDropped
from messagefoundry.transports.bounded_read import (
    DEFAULT_MAX_RESPONSE_BYTES,
    REPLY_TOO_LARGE_CODE,
    ResponseTooLargeError,
    TruncatedResponseError,
    read_2xx_reply_text,
)
from tests.test_bounded_egress_reads import _ExactResp, _FakeOpener, _UnboundedResp
from tests.test_digest_refusal_classification import (
    _FACTORY,
    _LABEL,
    _build,
    _Stops,
)

#: The name ``_build`` gives every destination, and so the name a WARNING or refusal carries.
CONNECTION = "OB"
CHANNEL = "IB_TEST"
DEST = "OB_PARTNER"
RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"
#: In the URL so a test can see that no part of the URL reaches a log line or a stored error.
_URL_MARKER = "SITE-QUERY-MARKER"
#: In every outgoing payload, for the same reason.
_PAYLOAD_MARKER = "PAYLOAD-MARKER-7f3a"
#: The byte an over-cap reply is made of on the wire. A run of it must never reach a log line.
_REPLY_FILL = b"Z"
#: The delivery worker's WARNING for a dropped body, which it logs after the row is recorded.
_RECORDED_AS_DELIVERED = "the row is recorded as delivered with a reply_dropped event"
#: The logger that WARNING comes from.
_WORKER_LOGGER = "messagefoundry.pipeline.wiring_runner"


# --- the helper -----------------------------------------------------------------------------------


def test_an_unused_over_cap_body_is_reported_dropped_and_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The helper says what happened and logs nothing. The WARNING is the delivery worker's,
    after its store write (vault BACKLOG #3040 item 2), so a line here would come first."""
    with caplog.at_level(logging.DEBUG):
        got = read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=201),
            limit=64,
            connector="REST connection 'OB_X'",
            encoding="utf-8",
            body_is_needed=False,
        )
    assert got == ReplyBodyDropped(status=201, limit=64)
    assert caplog.records == []


def test_a_used_over_cap_body_is_a_permanent_refusal() -> None:
    with pytest.raises(NegativeAckError) as ei:
        read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=201),
            limit=64,
            connector="SOAP connection 'OB_X'",
            encoding="utf-8",
            body_is_needed=True,
        )
    err = ei.value
    assert err.code == REPLY_TOO_LARGE_CODE == "reply-too-large"
    # Not a credential or configuration fault: those stop the lane, and this is one reply.
    assert (err.permanent, err.credential_fault, err.config_fault) == (True, False, False)
    assert str(err) == (
        "reply-too-large, not sent again. A 2xx reply body is over the 64-byte bound and is "
        "needed here. Check the partner before a replay (SOAP connection 'OB_X')"
    )
    assert _REPLY_FILL.decode() * 4 not in str(err)
    # Neither chain reaches the frame that holds the bytes read so far.
    assert err.__context__ is None
    assert err.__cause__ is None


@pytest.mark.parametrize("body_is_needed", [False, True])
def test_a_body_at_the_bound_comes_back_whole(
    body_is_needed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """THE CONTROL: the helper changes nothing at or under the bound."""
    with caplog.at_level(logging.WARNING):
        text = read_2xx_reply_text(
            _ExactResp(b"y" * 64),
            limit=64,
            connector="c",
            encoding="utf-8",
            body_is_needed=body_is_needed,
        )
    assert text == "y" * 64
    assert caplog.records == []


class _ShortResp(_ExactResp):
    """A reply that stopped 9 bytes short of the length it declared."""

    length = 9


@pytest.mark.parametrize("body_is_needed", [False, True])
def test_a_truncated_body_is_still_raised_as_it_was(body_is_needed: bool) -> None:
    """Only the byte bound is handled. A truncated reply after a 2xx is still a retryable
    ``TruncatedResponseError``, in both modes: that is a different question, left alone."""
    with pytest.raises(TruncatedResponseError):
        read_2xx_reply_text(
            _ShortResp(b"y" * 5),
            limit=64,
            connector="c",
            encoding="utf-8",
            body_is_needed=body_is_needed,
        )


@pytest.mark.parametrize("body_is_needed", [False, True])
@pytest.mark.parametrize("status", [199, 300, 404, 500])
def test_an_over_cap_body_on_another_status_is_left_to_the_caller(
    status: int, body_is_needed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """The helper is for a 2xx. Handed a reply with any other status it changes nothing, so a
    wrong call cannot record a refused request as delivered, or claim a 2xx that never came."""
    with caplog.at_level(logging.WARNING), pytest.raises(ResponseTooLargeError) as ei:
        read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=status),
            limit=64,
            connector="c",
            encoding="utf-8",
            body_is_needed=body_is_needed,
        )
    assert not isinstance(ei.value, NegativeAckError)
    assert caplog.records == []


class _BareReader:
    """A reader with no ``status`` of its own, as a binary file handle has none."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else self._body[:amt]


_ABSENT = object()


@pytest.mark.parametrize("body_is_needed", [False, True])
@pytest.mark.parametrize(
    "status", [_ABSENT, None, "200", 200.0], ids=["absent", "None", "str", "float"]
)
def test_an_over_cap_body_with_no_status_to_show_fails_closed(
    status: object, body_is_needed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """The guard fails closed. A reader that cannot show an integer 2xx is not taken for one, so
    an over-cap body is never recorded as delivered on a guess."""
    reader = _BareReader(_REPLY_FILL * 65)
    if status is not _ABSENT:
        reader.status = status  # type: ignore[attr-defined]
    with caplog.at_level(logging.WARNING), pytest.raises(ResponseTooLargeError) as ei:
        read_2xx_reply_text(
            reader, limit=64, connector="c", encoding="utf-8", body_is_needed=body_is_needed
        )
    assert not isinstance(ei.value, NegativeAckError)
    assert caplog.records == []


@pytest.mark.parametrize("status", [200, 204, 299])
def test_the_status_guard_lets_every_2xx_through(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    """THE CONTROL for the two tests above: the guard refuses nothing inside 200 to 299."""
    with caplog.at_level(logging.DEBUG):
        got = read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=status),
            limit=64,
            connector="c",
            encoding="utf-8",
            body_is_needed=False,
        )
    assert got == ReplyBodyDropped(status=status, limit=64)
    assert caplog.records == []


def test_the_stored_refusal_keeps_its_code_and_advice_under_a_long_connection_name() -> None:
    """A dead-lettered row keeps the error text, cut at 200 characters, and not the code. So the
    code, "not sent again" and the advice come first, and the connection last, where a long name
    can push out only itself (vault BACKLOG #3040 items 4 and 6). DICOMweb has the longest label, so with the
    connection first the advice went there first, from about 23 characters of name."""
    name = "OB_" + "LONGPARTNER_" * 5 + "ADT"
    assert len(name) > 60
    with pytest.raises(NegativeAckError) as ei:
        read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65),
            limit=64,
            connector=f"DICOMweb connection {name!r}",
            encoding="utf-8",
            body_is_needed=True,
        )
    # What the worker does with it: safe_exc, then the store's own safe_text.
    stored = safe_text(safe_exc(ei.value))
    # The control: the text really was cut, and what the cut took is the name at the end.
    assert name in str(ei.value)
    assert name not in stored
    assert f"{REPLY_TOO_LARGE_CODE}, not sent again" in stored
    assert "Check the partner before a replay (DICOMweb connection" in stored


# --- each destination's _post, against a body that never ends -------------------------------------


def _payload(ctype: ConnectorType, over: dict[str, Any] | None = None) -> str:
    if ctype is ConnectorType.FHIR:
        patient = {
            "resourceType": "Patient",
            "id": "p1",
            "meta": {"versionId": "3"},  # if-match sends it; the other forms ignore it
            "note": _PAYLOAD_MARKER,
        }
        interaction = (over or {}).get("interaction")
        if interaction in ("transaction", "batch"):
            # What a Handler hands over for this interaction: its own Bundle, sent as it is.
            entry = {"resource": patient, "request": {"method": "POST", "url": "Patient"}}
            return json.dumps({"resourceType": "Bundle", "type": interaction, "entry": [entry]})
        return json.dumps(patient)
    if ctype is ConnectorType.DICOMWEB:
        return RawMessage.from_bytes(
            b"\x00" * 128 + b"DICM" + _PAYLOAD_MARKER.encode(), "dicom"
        ).encode()
    if ctype is ConnectorType.SOAP:
        return f"<x>{_PAYLOAD_MARKER}</x>"
    return json.dumps({"note": _PAYLOAD_MARKER})


#: vault #2804 (engine PR 2244, open when these rows were added) makes a FHIR ``transaction`` or
#: ``batch`` connection list the methods its entries may use, and refuses one that does not. Until
#: it lands the setting does not exist, so it is passed only where ``FHIR()`` takes it. Once
#: that PR is on main, pass the setting outright and drop this probe.
_ENTRY_SCREEN: dict[str, Any] = (
    {"allowed_entry_methods": ["POST"]}
    if "allowed_entry_methods" in inspect.signature(FHIR).parameters
    else {}
)

#: At least these destinations and modes, as (connector, extra settings) -> the delivered or the
#: refused side.
_DELIVERED = "delivered"
_REFUSED = "refused"
_RULED: list[tuple[ConnectorType, dict[str, Any], str]] = [
    (ConnectorType.REST, {"capture_response": False}, _DELIVERED),
    (ConnectorType.REST, {"capture_response": True}, _REFUSED),
    (ConnectorType.SOAP, {"capture_response": False}, _REFUSED),
    (ConnectorType.SOAP, {"capture_response": True}, _REFUSED),
    (ConnectorType.DICOMWEB, {"capture_response": False}, _REFUSED),
    (ConnectorType.DICOMWEB, {"capture_response": True}, _REFUSED),
    # A plain FHIR write with capture off has no reader. THE CONTROL for the three rows after it.
    (ConnectorType.FHIR, {"capture_response": False}, _DELIVERED),
    # With capture on the reply is passed on, as a REST reply is.
    (ConnectorType.FHIR, {"capture_response": True}, _REFUSED),
    # An update goes out wrapped in a transaction, and the engine reads
    # the reply for the entry status. So the outcome is unknown without it, in either mode.
    (ConnectorType.FHIR, {"capture_response": False, "interaction": "update"}, _REFUSED),
    (ConnectorType.FHIR, {"capture_response": True, "interaction": "update"}, _REFUSED),
    # THE CONTROL for the two rows above: the same update sent as a plain PUT is not wrapped, so
    # nothing reads its reply. It is the wrap that decides, and not the word update.
    (
        ConnectorType.FHIR,
        {"capture_response": False, "interaction": "update", "update_url_form": "path"},
        _DELIVERED,
    ),
    # THE CONTROL: a transaction Bundle the Handler built is not the engine's wrap. The engine
    # never looks inside that reply, so nothing reads the body.
    (
        ConnectorType.FHIR,
        {
            "capture_response": False,
            "interaction": "transaction",
            "allowed_entry_methods": ["POST"],
        },
        _DELIVERED,
    ),
    # The other way a write becomes a wrapped update: if-match, whatever the interaction says.
    (ConnectorType.FHIR, {"capture_response": False, "conditional": "if-match"}, _REFUSED),
    # THE CONTROL: the other conditional forms are not wrapped, even under interaction="update".
    (
        ConnectorType.FHIR,
        {
            "capture_response": False,
            "interaction": "update",
            "conditional": "conditional-update",
            "conditional_query": "identifier=synthetic-1",
        },
        _DELIVERED,
    ),
    # vault BACKLOG #3040 item 3: the cells engine PR 2041 left without a row. Capture off, the last forms that
    # are not wrapped: a conditional create, and a batch Bundle the Handler built.
    (
        ConnectorType.FHIR,
        {
            "capture_response": False,
            "conditional": "if-none-exist",
            "conditional_query": "identifier=synthetic-1",
        },
        _DELIVERED,
    ),
    (
        ConnectorType.FHIR,
        {"capture_response": False, "interaction": "batch", **_ENTRY_SCREEN},
        _DELIVERED,
    ),
    # Capture on refuses every FHIR form, wrapped or not, because the reply is passed on.
    (
        ConnectorType.FHIR,
        {"capture_response": True, "interaction": "transaction", **_ENTRY_SCREEN},
        _REFUSED,
    ),
    (ConnectorType.FHIR, {"capture_response": True, "conditional": "if-match"}, _REFUSED),
    (
        ConnectorType.FHIR,
        {"capture_response": True, "interaction": "update", "update_url_form": "path"},
        _REFUSED,
    ),
    (
        ConnectorType.FHIR,
        {
            "capture_response": True,
            "interaction": "update",
            "conditional": "conditional-update",
            "conditional_query": "identifier=synthetic-1",
        },
        _REFUSED,
    ),
    # REST decides by capture alone, whatever the method.
    (ConnectorType.REST, {"capture_response": False, "method": "PATCH"}, _DELIVERED),
    # reingress_to forces capture on at wiring, over an explicit capture_response=False. So the
    # reply is passed on and the refusal holds. See _dest for why this row is wired first.
    (ConnectorType.REST, {"capture_response": False, "reingress_to": "LB_REPLY"}, _REFUSED),
]


def _dest(ctype: ConnectorType, url: str, over: dict[str, Any]) -> Any:
    """``_build``, after the wiring step a real config passes through, where a case needs it.

    ``_build`` hands the factory's settings straight to the connector. ``reingress_to`` forces
    ``capture_response`` on in ``build_outbound_connection``, a step ``_build`` skips, so the
    re-ingress row takes its capture setting from that step."""
    if "reingress_to" not in over:
        return _build(ctype, url, **over)
    wired = build_outbound_connection(
        "OB",
        _FACTORY[ctype](url=url, **over),
        cleartext_accepted=url.startswith("http://"),
        cleartext_reason="test peer has no TLS" if url.startswith("http://") else None,
    )
    forced = wired.spec.settings["capture_response"]
    assert forced is True  # the wiring step this row is about
    return _build(ctype, url, **{**over, "capture_response": forced})


def _case_id(case: tuple[ConnectorType, dict[str, Any], str]) -> str:
    ctype, over, _ = case
    capture = "capture-on" if over.get("capture_response") else "capture-off"
    interaction = f"-{over['interaction']}" if "interaction" in over else ""
    form = f"-{over['update_url_form']}" if "update_url_form" in over else ""
    conditional = f"-{over['conditional']}" if "conditional" in over else ""
    method = f"-{over['method']}" if "method" in over else ""
    reingress = "-reingress" if "reingress_to" in over else ""
    return f"{ctype.value}-{capture}{interaction}{form}{conditional}{method}{reingress}"


def test_every_ruled_case_has_its_own_id() -> None:
    """A repeated id would let pytest run two cases under one name, and a later edit could drop
    one unseen."""
    ids = [_case_id(case) for case in _RULED]
    assert len(ids) >= 20
    assert len(set(ids)) == len(ids)
    # The framing test's rows: the plain capture pair of REST, one delivered and one refused.
    assert [side for _, _, side in _FRAMING_ROWS] == [_DELIVERED, _REFUSED]


@pytest.mark.parametrize("case", _RULED, ids=_case_id)
async def test_send_follows_the_ruling_and_keeps_the_byte_bound(
    case: tuple[ConnectorType, dict[str, Any], str], caplog: pytest.LogCaptureFixture
) -> None:
    ctype, over, side = case
    dest = _dest(ctype, f"https://partner.example.com/x?site={_URL_MARKER}", over)
    resp = _UnboundedResp()
    opener = _FakeOpener(resp)
    dest._opener = opener
    # Only what send() logs: building a path-form FHIR destination logs its own WARNING.
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        if side == _DELIVERED:
            dropped = await dest.send(_payload(ctype, over))
            assert dropped == ReplyBodyDropped(status=200, limit=DEFAULT_MAX_RESPONSE_BYTES)
        else:
            with pytest.raises(NegativeAckError) as ei:
                await dest.send(_payload(ctype, over))
            assert ei.value.code == REPLY_TOO_LARGE_CODE
            assert ei.value.permanent is True
            refusal = str(ei.value)
            identity = f"{_LABEL[ctype]} connection {CONNECTION!r}"
            assert refusal.startswith(f"{REPLY_TOO_LARGE_CODE}, not sent again")
            assert refusal.endswith(f"Check the partner before a replay ({identity})")
            assert _URL_MARKER not in refusal
            assert "partner.example.com" not in refusal
    # The bound is still enforced on the read: one byte past it, and never the whole body.
    assert resp.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]
    assert len(opener.requests) == 1
    # send() logs nothing on either side. The delivered side's WARNING is the delivery worker's,
    # after its store write (vault BACKLOG #3040 item 2); the wire tests below show it is logged
    # and that this capture would see it.
    assert caplog.records == []


# --- the delivery worker, on the wire -------------------------------------------------------------


@pytest.fixture(scope="module")
def over_cap_body() -> Iterator[bytes]:
    """One byte past the bound. A module fixture, so the 16 MiB is built on first use and let go
    when this module is done."""
    yield _REPLY_FILL * (DEFAULT_MAX_RESPONSE_BYTES + 1)


class _Partner:
    """A loopback partner that answers every request with ``status`` and ``body``, and counts them.

    ``framing`` is how the body's end is marked: ``"length"`` (``Content-Length``), ``"chunked"``
    (an HTTP/1.1 chunked body) or ``"close"`` (no length; the partner closes after the body)."""

    def __init__(self, status: int, body: bytes, framing: str = "length") -> None:
        self.requests: list[str] = []
        outer = self
        wire = body
        if framing == "chunked":
            step = 1 << 20
            pieces = [body[at : at + step] for at in range(0, len(body), step)]
            wire = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in pieces) + b"0\r\n\r\n"

        class _Handler(http.server.BaseHTTPRequestHandler):
            # HTTP/1.1 only for chunked: the engine refuses Transfer-Encoding on an HTTP/1.0 reply.
            protocol_version = "HTTP/1.1" if framing == "chunked" else "HTTP/1.0"

            def _serve(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(self.command)
                self.send_response(status)
                if framing == "length":
                    self.send_header("Content-Length", str(len(body)))
                elif framing == "chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                # A destination that classifies a non-2xx on the status alone closes without
                # reading the body, so the rest of the write has nowhere to go.
                with contextlib.suppress(OSError):
                    self.wfile.write(wire)

            # PATCH for the REST method row, which needs a verb other than POST.
            do_POST = do_PUT = do_PATCH = _serve

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    def __enter__(self) -> _Partner:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@dataclass(frozen=True)
class _Delivery:
    """What the store holds after the worker was offered one row ``_OFFERS`` times."""

    message_id: str
    outcomes: list[_ItemOutcome]
    row_status: str
    last_error: str
    message_status: str
    captured: list[tuple[str, str | None]]
    stopped: list[str]
    #: Every ``reply_dropped`` row on the message: (destination, detail).
    dropped_events: list[tuple[str | None, str]]
    #: The ``mark_done`` calls, and the worker's dropped-body WARNING, in the order they
    #: happened. A call is entered once it has returned.
    order: list[str]


class _OrderLog(logging.Handler):
    """Appends ``"WARNING"`` to ``order`` when the worker logs its dropped-body line."""

    def __init__(self, order: list[str]) -> None:
        super().__init__(logging.WARNING)
        self._order = order

    def emit(self, record: logging.LogRecord) -> None:
        if _RECORDED_AS_DELIVERED in record.getMessage():
            self._order.append("WARNING")


def _spy_on_mark_done(store: MessageStore, order: list[str], done: str) -> None:
    """Wrap ``mark_done`` so each call enters ``order`` once it returns, as ``"mark_done"`` or,
    when it carries a drop, ``"mark_done+reply_dropped"``. ``done="raise"`` makes it raise before
    it writes anything, as a store fault would, and enters ``"raised"``. ``done="noop"`` makes it
    write nothing and return ``False``, as a vanished row or a fenced write does, and enters
    ``"noop"``."""
    real_mark_done = store.mark_done

    async def mark_done(*args: Any, **kwargs: Any) -> bool:
        if done == "raise":
            order.append("raised")
            raise OSError("synthetic store fault")
        if done == "noop":
            order.append("noop")
            return False
        wrote = await real_mark_done(*args, **kwargs)
        order.append("mark_done+reply_dropped" if kwargs.get("reply_dropped") else "mark_done")
        return wrote

    store.mark_done = mark_done  # type: ignore[method-assign]


#: How often the worker is offered the row. Each offer is past any backoff, so a row that is still
#: pending is claimed and sent again. Three is enough to tell one send from a send per offer.
_OFFERS = 3


async def _deliver(tmp_path: Path, dest: Any, payload: str, *, done: str = "real") -> _Delivery:
    """Queue one outbound row for ``dest`` and offer it to the delivery worker ``_OFFERS`` times."""
    outcomes: list[_ItemOutcome] = []
    order: list[str] = []
    order_log = _OrderLog(order)
    worker_logger = logging.getLogger(_WORKER_LOGGER)
    store = await MessageStore.open(tmp_path / "overcap.db")
    try:
        mid = await store.enqueue_ingress(channel_id=CHANNEL, raw=RAW, now=0.0)
        ing = await store.claim_next_fifo(CHANNEL, stage=Stage.INGRESS.value, now=0.0)
        assert ing is not None
        await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id=CHANNEL,
            handlers=[("h1", RAW)],
            disposition=MessageStatus.ROUTED,
            now=0.0,
        )
        routed = await store.claim_next_fifo(CHANNEL, stage=Stage.ROUTED.value, now=0.0)
        assert routed is not None
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id=CHANNEL,
            deliveries=[(DEST, payload)],
            now=0.0,
        )
        sink = _Stops()
        runner = RegistryRunner(
            Registry(),
            store,
            alert_sink=sink,
            egress=EgressSettings(deny_by_default=False),
        )
        runner._destinations[DEST] = dest
        _spy_on_mark_done(store, order, done)
        worker_logger.addHandler(order_log)
        for offer in range(1, _OFFERS + 1):
            # A day further on each time: past any backoff the last attempt set.
            item = await store.claim_next_fifo(DEST, now=time.time() + offer * 86400.0)
            if item is None:
                break
            try:
                outcome, _ = await runner._process_delivery_item(DEST, item)
            except OSError:
                # Only done="raise" raises. The worker's caller would re-pend the row; this stops.
                if done != "raise":
                    raise
                break
            outcomes.append(outcome)
        events = await store.events_for(mid)
        cur = await store._db.execute(
            "SELECT status, last_error FROM queue WHERE message_id=? AND stage=?",
            (mid, Stage.OUTBOUND.value),
        )
        row = await cur.fetchone()
        assert row is not None
        message = await store.get_message(mid)
        assert message is not None
        return _Delivery(
            message_id=mid,
            outcomes=outcomes,
            row_status=str(row["status"]),
            # Plaintext here: the test store has the default identity cipher.
            last_error="" if row["last_error"] is None else str(row["last_error"]),
            message_status=str(message["status"]),
            captured=[(c.outcome, c.body) for c in await store.correlate_response(mid)],
            stopped=[name for name, _ in sink.stopped],
            dropped_events=[
                (e["destination"], str(e["detail"] or ""))
                for e in events
                if e["event"] == "reply_dropped"
            ],
            order=order,
        )
    finally:
        worker_logger.removeHandler(order_log)
        await store.close()


@pytest.mark.parametrize("case", _RULED, ids=_case_id)
async def test_an_over_cap_2xx_is_sent_once_and_recorded_as_ruled(
    case: tuple[ConnectorType, dict[str, Any], str],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    over_cap_body: bytes,
) -> None:
    ctype, over, side = case
    with _Partner(200, over_cap_body) as partner:
        dest = _dest(ctype, f"{partner.url}/x?site={_URL_MARKER}", over)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over))
    # THE ITEM: the partner answered 2xx, so it must never see the request twice.
    assert len(partner.requests) == 1, partner.requests
    if "method" in over:
        # The row is about the verb, so show the verb reached the wire.
        assert partner.requests == [over["method"]]
    assert got.outcomes == [_ItemOutcome.PROCESSED]
    assert got.stopped == [], "one over-cap reply must not stop the lane"
    assert got.captured == []
    if side == _DELIVERED:
        assert got.row_status == OutboxStatus.DONE.value
        assert got.message_status == MessageStatus.PROCESSED.value
        assert got.last_error == ""
        # vault BACKLOG #3040 item 5: the message itself says its reply was dropped.
        bound = DEFAULT_MAX_RESPONSE_BYTES
        assert got.dropped_events == [(DEST, f"HTTP 200; reply body over the {bound}-byte bound")]
        # Item 2: the row is recorded, then the drop, and only then the WARNING.
        assert got.order == ["mark_done+reply_dropped", "WARNING"]
        (warning,) = [r for r in caplog.records if _RECORDED_AS_DELIVERED in r.getMessage()]
        assert warning.levelno == logging.WARNING
        assert warning.name == _WORKER_LOGGER
        line = warning.getMessage()
        assert line.startswith(f"delivery worker {DEST!r}: outbox row ")
        assert f"(message {got.message_id}) answered" in line
        assert f"answered with status 200 and a response body over the {bound}-byte" in line
        assert line.endswith(_RECORDED_AS_DELIVERED)
    else:
        # A refusal writes no reply_dropped row and no dropped-body WARNING. The delivered side
        # of this same test shows both are seen when they are written.
        assert got.dropped_events == []
        assert "WARNING" not in got.order
        assert got.row_status == OutboxStatus.DEAD.value
        assert got.message_status == MessageStatus.ERROR.value
        # The stored error is the fixed text: the connection, the bound, and nothing of the URL,
        # the payload or the reply.
        identity = f"{_LABEL[ctype]} connection {CONNECTION!r}"
        # The code is in the text, because the row keeps the text and not the code. The
        # connection is the last thing in it, so seeing it whole shows the 200-character cut
        # took nothing.
        assert f"{REPLY_TOO_LARGE_CODE}, not sent again" in got.last_error
        assert got.last_error.endswith(f"Check the partner before a replay ({identity})")
        for leaked in (_URL_MARKER, "127.0.0.1", _PAYLOAD_MARKER, "ZZZZ"):
            assert leaked not in got.last_error
    for record in caplog.records:
        for leaked in (_URL_MARKER, _PAYLOAD_MARKER, "ZZZZ"):
            assert leaked not in record.getMessage()


#: The framing is read by shared code, not by each destination, so one delivered and one
#: refused row cover it.
_FRAMING_ROWS = [
    case
    for case in _RULED
    if case[0] is ConnectorType.REST and set(case[1]) == {"capture_response"}
]


@pytest.mark.parametrize("framing", ["chunked", "close"])
@pytest.mark.parametrize("case", _FRAMING_ROWS, ids=_case_id)
async def test_an_over_cap_2xx_in_another_framing_is_sent_once(
    case: tuple[ConnectorType, dict[str, Any], str],
    framing: str,
    tmp_path: Path,
    over_cap_body: bytes,
) -> None:
    """vault BACKLOG #3040 item 7: the wire layer above frames each reply with ``Content-Length``. A chunked or
    close-framed over-cap body after a 2xx takes the same arm, with one request."""
    ctype, over, side = case
    with _Partner(200, over_cap_body, framing=framing) as partner:
        dest = _build(ctype, f"{partner.url}/x", **over)
        got = await _deliver(tmp_path, dest, _payload(ctype, over))
    assert len(partner.requests) == 1, partner.requests
    assert got.outcomes == [_ItemOutcome.PROCESSED]
    if side == _DELIVERED:
        assert (got.row_status, got.last_error) == (OutboxStatus.DONE.value, "")
        assert len(got.dropped_events) == 1
        assert got.order == ["mark_done+reply_dropped", "WARNING"]
    else:
        assert got.row_status == OutboxStatus.DEAD.value
        assert f"{REPLY_TOO_LARGE_CODE}, not sent again" in got.last_error
        assert got.dropped_events == []


#: A reply each destination takes as a plain success.
_IN_CAP_BODY = {
    ConnectorType.REST: b'{"ok": true}',
    ConnectorType.SOAP: (
        b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        b"<soap:Body><ok/></soap:Body></soap:Envelope>"
    ),
    ConnectorType.FHIR: b'{"resourceType": "Patient", "id": "p1"}',
    ConnectorType.DICOMWEB: b'{"00081199": {"vr": "SQ", "Value": [{}]}}',
}


@pytest.mark.parametrize("case", _RULED, ids=_case_id)
async def test_an_in_cap_2xx_is_delivered_as_before(
    case: tuple[ConnectorType, dict[str, Any], str],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """THE CONTROL: a reply under the bound is delivered once in every case, the refused ones
    included, and with capture on its body is stored whole. No new WARNING is logged for it.
    So what refuses a case above is the size of its reply, and not the case."""
    ctype, over, _ = case
    body = _IN_CAP_BODY[ctype]
    with _Partner(200, body) as partner:
        dest = _dest(ctype, f"{partner.url}/x", over)
        # Read off the connector, so a reingress_to that forced capture on counts.
        capture = bool(dest.capture_response)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over))
    assert len(partner.requests) == 1
    assert got.outcomes == [_ItemOutcome.PROCESSED]
    assert got.row_status == OutboxStatus.DONE.value
    assert got.message_status == MessageStatus.PROCESSED.value
    assert got.captured == ([("accepted", body.decode())] if capture else [])
    assert not any("over the" in r.getMessage() for r in caplog.records)
    assert got.dropped_events == []
    assert "WARNING" not in got.order


@pytest.mark.parametrize("case", [c for c in _RULED if c[2] == _DELIVERED], ids=_case_id)
async def test_no_dropped_body_warning_when_the_store_write_fails(
    case: tuple[ConnectorType, dict[str, Any], str],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    over_cap_body: bytes,
) -> None:
    """Vault BACKLOG #3040 item 2: the WARNING says the row is recorded as delivered, so it must
    not be logged when the write that records it fails. The delivered side of the matrix above
    shows the same capture sees the line when the write succeeds."""
    ctype, over, _ = case
    with _Partner(200, over_cap_body) as partner:
        dest = _dest(ctype, f"{partner.url}/x", over)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over), done="raise")
    assert len(partner.requests) == 1, partner.requests
    assert got.order == ["raised"]
    assert got.row_status == OutboxStatus.INFLIGHT.value
    assert got.dropped_events == []
    assert _RECORDED_AS_DELIVERED not in caplog.text


@pytest.mark.parametrize("case", [c for c in _RULED if c[2] == _DELIVERED], ids=_case_id)
async def test_the_warning_says_so_when_the_store_recorded_nothing(
    case: tuple[ConnectorType, dict[str, Any], str],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    over_cap_body: bytes,
) -> None:
    """``mark_done`` returns ``False`` for a vanished row or a fenced write, and writes nothing.
    The WARNING follows what it returned, so it does not claim a record (vault BACKLOG #3040
    item 2). The matrix above is the control: there it returns ``True`` and the line says so."""
    ctype, over, _ = case
    with _Partner(200, over_cap_body) as partner:
        dest = _dest(ctype, f"{partner.url}/x", over)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over), done="noop")
    assert len(partner.requests) == 1, partner.requests
    assert got.order == ["noop"]
    assert got.dropped_events == []
    (warning,) = [r for r in caplog.records if r.name == _WORKER_LOGGER]
    line = warning.getMessage()
    assert f"(message {got.message_id}) answered with status 200" in line
    assert line.endswith("the store recorded nothing: the row was gone or the write was fenced")
    assert _RECORDED_AS_DELIVERED not in line


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
@pytest.mark.parametrize("capture", [False, True], ids=["capture-off", "capture-on"])
async def test_an_over_cap_body_on_a_500_is_retried_as_before(
    ctype: ConnectorType, capture: bool, tmp_path: Path, over_cap_body: bytes
) -> None:
    """THE CONTROL, and the proof the harness can see a re-send. A 500 says the partner did not
    take the request, so it is sent again on every offer, whatever the size of its body. A harness
    that reported one request for every reply would fail here."""
    with _Partner(500, over_cap_body) as partner:
        dest = _build(ctype, f"{partner.url}/x", capture_response=capture)
        got = await _deliver(tmp_path, dest, _payload(ctype))
    assert len(partner.requests) == _OFFERS
    assert got.outcomes == [_ItemOutcome.PROCESSED] * _OFFERS
    assert got.row_status == OutboxStatus.PENDING.value
    assert "HTTP 500" in got.last_error
    assert REPLY_TOO_LARGE_CODE not in got.last_error
    assert got.captured == []
