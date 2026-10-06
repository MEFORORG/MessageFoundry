# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An over-cap reply body after a 2xx is not sent again (vault BACKLOG #2180).

Before this, a 2xx whose body was over the byte bound raised ``ResponseTooLargeError``, a retryable
``DeliveryError``. The partner had already answered 2xx, so on a first deployment each retry would
have sent the request again, and the message would then have dead-lettered when the retries ran out.

The owner ruling of 2026-10-05 judges such a reply by who reads the body:

* nothing looks inside it: the message is delivered, the body is dropped, and a WARNING is logged.
  REST with capture off, and a plain FHIR write with capture off;
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
from messagefoundry.config.wiring import Registry
from messagefoundry.parsing import RawMessage
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.bounded_read import (
    DEFAULT_MAX_RESPONSE_BYTES,
    REPLY_TOO_LARGE_CODE,
    ResponseTooLargeError,
    TruncatedResponseError,
    read_2xx_reply_text,
)
from tests.test_bounded_egress_reads import _ExactResp, _FakeOpener, _UnboundedResp
from tests.test_digest_refusal_classification import _FACTORY, _LABEL, _build, _Stops

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


# --- the helper -----------------------------------------------------------------------------------


def test_an_unused_over_cap_body_reads_as_empty_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        text = read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=201),
            limit=64,
            connector="REST connection 'OB_X'",
            encoding="utf-8",
            body_is_needed=False,
        )
    assert text == ""
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert message.startswith("REST connection 'OB_X' answered with status 201 and")
    assert "64-byte bound" in message
    assert "recorded as delivered" in message
    assert _REPLY_FILL.decode() * 4 not in message


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
        "SOAP connection 'OB_X': reply-too-large, not sent again. A 2xx reply body is over the "
        "64-byte bound and is needed here. Check the partner before a replay"
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
    with caplog.at_level(logging.WARNING):
        text = read_2xx_reply_text(
            _ExactResp(_REPLY_FILL * 65, status=status),
            limit=64,
            connector="c",
            encoding="utf-8",
            body_is_needed=False,
        )
    assert text == ""
    (record,) = caplog.records
    assert f"answered with status {status} and" in record.getMessage()


def test_the_stored_refusal_keeps_its_code_under_a_long_connection_name() -> None:
    """A dead-lettered row keeps the error text, cut at 200 characters, and not the code. So the
    code and "not sent again" come first, where a long connection name cannot push them out."""
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
    # The control: the text really was cut, and what the cut took is the advice at the end.
    assert "Check the partner before a replay" in str(ei.value)
    assert "Check the partner before a replay" not in stored
    assert f"{name!r}: {REPLY_TOO_LARGE_CODE}, not sent again" in stored


# --- each destination's _post, against a body that never ends -------------------------------------


def _payload(ctype: ConnectorType, over: dict[str, Any] | None = None) -> str:
    if ctype is ConnectorType.FHIR:
        patient = {
            "resourceType": "Patient",
            "id": "p1",
            "meta": {"versionId": "3"},  # if-match sends it; the other forms ignore it
            "note": _PAYLOAD_MARKER,
        }
        if (over or {}).get("interaction") == "transaction":
            # What a Handler hands over for this interaction: its own Bundle, sent as it is.
            entry = {"resource": patient, "request": {"method": "POST", "url": "Patient"}}
            return json.dumps({"resourceType": "Bundle", "type": "transaction", "entry": [entry]})
        return json.dumps(patient)
    if ctype is ConnectorType.DICOMWEB:
        return RawMessage.from_bytes(
            b"\x00" * 128 + b"DICM" + _PAYLOAD_MARKER.encode(), "dicom"
        ).encode()
    if ctype is ConnectorType.SOAP:
        return f"<x>{_PAYLOAD_MARKER}</x>"
    return json.dumps({"note": _PAYLOAD_MARKER})


#: At least these destinations and modes, as (connector, extra settings) -> the delivered or the
#: refused side. Not here: ``interaction="batch"``, which takes the path ``"transaction"`` takes.
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
    (ConnectorType.FHIR, {"capture_response": False, "interaction": "transaction"}, _DELIVERED),
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
]


def _case_id(case: tuple[ConnectorType, dict[str, Any], str]) -> str:
    ctype, over, _ = case
    capture = "capture-on" if over.get("capture_response") else "capture-off"
    interaction = f"-{over['interaction']}" if "interaction" in over else ""
    form = f"-{over['update_url_form']}" if "update_url_form" in over else ""
    conditional = f"-{over['conditional']}" if "conditional" in over else ""
    return f"{ctype.value}-{capture}{interaction}{form}{conditional}"


@pytest.mark.parametrize("case", _RULED, ids=_case_id)
async def test_send_follows_the_ruling_and_keeps_the_byte_bound(
    case: tuple[ConnectorType, dict[str, Any], str], caplog: pytest.LogCaptureFixture
) -> None:
    ctype, over, side = case
    dest = _build(ctype, f"https://partner.example.com/x?site={_URL_MARKER}", **over)
    resp = _UnboundedResp()
    opener = _FakeOpener(resp)
    dest._opener = opener
    with caplog.at_level(logging.WARNING):
        if side == _DELIVERED:
            assert await dest.send(_payload(ctype, over)) is None
        else:
            with pytest.raises(NegativeAckError) as ei:
                await dest.send(_payload(ctype, over))
            assert ei.value.code == REPLY_TOO_LARGE_CODE
            assert ei.value.permanent is True
            refusal = str(ei.value)
            identity = f"{_LABEL[ctype]} connection {CONNECTION!r}"
            assert refusal.startswith(f"{identity}: {REPLY_TOO_LARGE_CODE}, not sent again")
            assert _URL_MARKER not in refusal
            assert "partner.example.com" not in refusal
    # The bound is still enforced on the read: one byte past it, and never the whole body.
    assert resp.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]
    assert len(opener.requests) == 1
    if side == _DELIVERED:
        (warning,) = [r.getMessage() for r in caplog.records if "over the" in r.getMessage()]
        assert warning.startswith(f"{_LABEL[ctype]} connection {CONNECTION!r} answered")
        for leaked in (_URL_MARKER, "partner.example.com", _PAYLOAD_MARKER, "\x00\x00"):
            assert leaked not in warning
    else:
        # A refusal is not also logged as a delivery. The delivered cases of this same test show
        # the capture sees that WARNING when it is logged.
        assert "recorded as delivered" not in caplog.text


# --- the delivery worker, on the wire -------------------------------------------------------------


@pytest.fixture(scope="module")
def over_cap_body() -> Iterator[bytes]:
    """One byte past the bound. A module fixture, so the 16 MiB is built on first use and let go
    when this module is done."""
    yield _REPLY_FILL * (DEFAULT_MAX_RESPONSE_BYTES + 1)


class _Partner:
    """A loopback partner that answers every request with ``status`` and ``body``, and counts them."""

    def __init__(self, status: int, body: bytes) -> None:
        self.requests: list[str] = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(self.command)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                # A destination that classifies a non-2xx on the status alone closes without
                # reading the body, so the rest of the write has nowhere to go.
                with contextlib.suppress(OSError):
                    self.wfile.write(body)

            do_POST = do_PUT = _serve

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

    outcomes: list[_ItemOutcome]
    row_status: str
    last_error: str
    message_status: str
    captured: list[tuple[str, str | None]]
    stopped: list[str]


#: How often the worker is offered the row. Each offer is past any backoff, so a row that is still
#: pending is claimed and sent again. Three is enough to tell one send from a send per offer.
_OFFERS = 3


async def _deliver(tmp_path: Path, dest: Any, payload: str) -> _Delivery:
    """Queue one outbound row for ``dest`` and offer it to the delivery worker ``_OFFERS`` times."""
    outcomes: list[_ItemOutcome] = []
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
        for offer in range(1, _OFFERS + 1):
            # A day further on each time: past any backoff the last attempt set.
            item = await store.claim_next_fifo(DEST, now=time.time() + offer * 86400.0)
            if item is None:
                break
            outcome, _ = await runner._process_delivery_item(DEST, item)
            outcomes.append(outcome)
        cur = await store._db.execute(
            "SELECT status, last_error FROM queue WHERE message_id=? AND stage=?",
            (mid, Stage.OUTBOUND.value),
        )
        row = await cur.fetchone()
        assert row is not None
        message = await store.get_message(mid)
        assert message is not None
        return _Delivery(
            outcomes=outcomes,
            row_status=str(row["status"]),
            # Plaintext here: the test store has the default identity cipher.
            last_error="" if row["last_error"] is None else str(row["last_error"]),
            message_status=str(message["status"]),
            captured=[(c.outcome, c.body) for c in await store.correlate_response(mid)],
            stopped=[name for name, _ in sink.stopped],
        )
    finally:
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
        dest = _build(ctype, f"{partner.url}/x?site={_URL_MARKER}", **over)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over))
    # THE ITEM: the partner answered 2xx, so it must never see the request twice.
    assert len(partner.requests) == 1, partner.requests
    assert got.outcomes == [_ItemOutcome.PROCESSED]
    assert got.stopped == [], "one over-cap reply must not stop the lane"
    assert got.captured == []
    if side == _DELIVERED:
        assert got.row_status == OutboxStatus.DONE.value
        assert got.message_status == MessageStatus.PROCESSED.value
        assert got.last_error == ""
        assert any("recorded as delivered" in r.getMessage() for r in caplog.records)
    else:
        assert got.row_status == OutboxStatus.DEAD.value
        assert got.message_status == MessageStatus.ERROR.value
        # The stored error is the fixed text: the connection, the bound, and nothing of the URL,
        # the payload or the reply.
        identity = f"{_LABEL[ctype]} connection {CONNECTION!r}"
        # The code is in the text, because the row keeps the text and not the code. The advice
        # is the last thing in it, so seeing it shows the 200-character cut took nothing.
        assert f"{identity}: {REPLY_TOO_LARGE_CODE}, not sent again" in got.last_error
        assert got.last_error.endswith("Check the partner before a replay")
        for leaked in (_URL_MARKER, "127.0.0.1", _PAYLOAD_MARKER, "ZZZZ"):
            assert leaked not in got.last_error
    for record in caplog.records:
        for leaked in (_URL_MARKER, _PAYLOAD_MARKER, "ZZZZ"):
            assert leaked not in record.getMessage()


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
    capture = bool(over["capture_response"])
    body = _IN_CAP_BODY[ctype]
    with _Partner(200, body) as partner:
        dest = _build(ctype, f"{partner.url}/x", **over)
        with caplog.at_level(logging.WARNING):
            got = await _deliver(tmp_path, dest, _payload(ctype, over))
    assert len(partner.requests) == 1
    assert got.outcomes == [_ItemOutcome.PROCESSED]
    assert got.row_status == OutboxStatus.DONE.value
    assert got.message_status == MessageStatus.PROCESSED.value
    assert got.captured == ([("accepted", body.decode())] if capture else [])
    assert not any("over the" in r.getMessage() for r in caplog.records)


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
