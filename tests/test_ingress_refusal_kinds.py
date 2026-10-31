# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How the Http() listener answers a body refused at ingress, by kind (BACKLOG #2105).

Owner ruling 2026-09-30, recorded as ADR 0154's amendment of 2026-10-30: a TEMPORARY refusal is
answered ``503`` with ``Retry-After``, an over-size one ``413`` on every over-size path, and any other
``422``. Each carries the ``ERROR`` row's ``message_id``. The strict-validation timeout stays ``422``.

Every case drives the real runner's receipt handler behind a real listener socket, so the answer is
the one a partner would read. The engine-to-engine pair at the bottom sends from the engine's own REST
outbound to that listener and reads how the outbound classifies each answer.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    Validation,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    Registry,
    Rest,
)
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _source_config
from messagefoundry.store.store import MessageStatus, MessageStore
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError, build_source
from messagefoundry.transports.http_listener import (
    TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS,
    HttpSource,
)
from messagefoundry.transports.receipt import IngressReceipt, RefusalKind
from messagefoundry.transports.rest import RestDestination
from tests.test_inbound_http_source import _http, _Response

HL7 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


def _hl7_with_doc(nbytes: int) -> str:
    """An MDM^T02 carrying one OBX-5 ED base64 document, so a streaming inbound detaches it."""
    b64 = base64.b64encode(b"P" * nbytes).decode("ascii")
    return (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{b64}||||||F\r"
    )


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "refusal.db")
    yield s
    await s.close()


def _ic(content_type: ContentType = ContentType.HL7V2, **over: Any) -> InboundConnection:
    settings: dict[str, Any] = {"port": 0}
    settings.update(over.pop("settings", {}))
    return InboundConnection(
        name="IB_HTTP",
        spec=ConnectionSpec(ConnectorType.HTTP, settings),
        router="r",
        content_type=content_type,
        **over,
    )


async def _post_through_runner(
    store: MessageStore, ic: InboundConnection, body: bytes, **runner_kw: Any
) -> _Response:
    """POST ``body`` once to a real listener bound to the real runner's receipt handler."""
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False), **runner_kw)
    cfg = _source_config(ic, "127.0.0.1", {})
    cfg.settings["port"] = 0
    source = build_source(cfg, egress=EgressSettings(deny_by_default=False))
    assert isinstance(source, HttpSource)
    await source.start(runner._make_http_handler(ic))
    try:
        return await _http(source.sockport, body=body)
    finally:
        await source.stop()


async def _the_one_error_row(store: MessageStore) -> dict[str, Any]:
    """The single ``messages`` row, which must be ``ERROR``, with nothing on the ingress stage."""
    cur = await store._db.execute("SELECT id, status, error FROM messages")
    rows = [dict(r) for r in await cur.fetchall()]
    assert len(rows) == 1, rows
    assert rows[0]["status"] == MessageStatus.ERROR.value
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue")
    queued = await cur.fetchone()
    assert queued is not None and queued["n"] == 0, "a refused body reached the ingress stage"
    return rows[0]


def _assert_names_the_row(resp: _Response, row: dict[str, Any]) -> None:
    assert resp.json() == {"error": "message was not accepted", "message_id": row["id"]}


# --- temporary: 503 + Retry-After -----------------------------------------------------------------


async def test_the_stream_budget_refusal_is_503_with_retry_after_and_names_its_row(
    store: MessageStore,
) -> None:
    # The streaming detach's in-flight budget is the engine's own and clears as concurrent detaches
    # finish, so the same body may be taken on a re-send. Base answered 422, which a sender and the
    # engine's own REST outbound both treat as final.
    ic = _ic(stream_threshold_bytes=500)
    resp = await _post_through_runner(
        store, ic, _hl7_with_doc(2000).encode("ascii"), stream_inflight_budget_bytes=10
    )
    assert resp.status == 503
    assert resp.headers["retry-after"] == str(TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS) == "5"
    row = await _the_one_error_row(store)
    assert "in-flight budget exceeded" in row["error"]
    _assert_names_the_row(resp, row)


async def test_an_unsupported_streaming_backend_stays_a_permanent_422(store: MessageStore) -> None:
    # Control for the case above: the same detach arm, but a backend that cannot stream refuses the
    # same body every time, so it must not invite a re-send.
    store.supports_streaming_attachments = False
    ic = _ic(stream_threshold_bytes=500)
    resp = await _post_through_runner(store, ic, _hl7_with_doc(2000).encode("ascii"))
    assert resp.status == 422
    assert "retry-after" not in resp.headers
    _assert_names_the_row(resp, await _the_one_error_row(store))


async def test_the_strict_validation_timeout_stays_a_permanent_422(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deliberately NOT temporary (ADR 0154 amendment 2026-10-30): the same pathological body times
    # out on every re-send, and each attempt orphans another hl7apy thread the listener cannot kill,
    # so inviting a retry would multiply the load the timeout bounds.
    def _slow_validate(text: str, **_: Any) -> Any:
        time.sleep(0.3)
        raise AssertionError("the timeout must have answered first")

    monkeypatch.setattr(wiring_runner, "validate", _slow_validate)
    monkeypatch.setattr(wiring_runner, "_strict_validate_timeout", lambda ic: 0.01)
    ic = _ic(validation=Validation(strict=True))
    resp = await _post_through_runner(store, ic, HL7.encode("ascii"))
    assert resp.status == 422
    assert "retry-after" not in resp.headers
    row = await _the_one_error_row(store)
    assert "strict-validation timed out" in row["error"]
    _assert_names_the_row(resp, row)


# --- over-size: 413 on every path -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("content_type", "body", "error"),
    [
        (ContentType.JSON, b'{"mrn": "100", "type": "obs"}', "exceeds"),
        (ContentType.BINARY, b"\x00\x01" * 16, "exceeds"),
    ],
    ids=["text_engine_ceiling", "binary_engine_ceiling"],
)
async def test_a_body_over_the_engine_ceiling_is_413_and_names_its_row(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    content_type: ContentType,
    body: bytes,
    error: str,
) -> None:
    # Under the listener's max_body_bytes, so the listener reads it; over the engine's ingress
    # ceiling, so the runner refuses it. Base answered 422 here and 413 for max_body_bytes.
    monkeypatch.setattr(ingress_guards, "INGRESS_MAX_BYTES", 8)
    resp = await _post_through_runner(store, _ic(content_type), body)
    assert resp.status == 413
    row = await _the_one_error_row(store)
    assert error in row["error"]
    _assert_names_the_row(resp, row)


async def test_an_hl7_body_over_the_peek_ceiling_is_413_and_names_its_row(
    store: MessageStore,
) -> None:
    # The HL7 ceiling is Peek.parse's max_bytes, which a streaming inbound sets from its own
    # max_message_bytes. The parse refuses it as HL7MessageTooLarge, so it answers as over-size.
    ic = _ic(stream_threshold_bytes=500, max_message_bytes=1000)
    body = _hl7_with_doc(4000).encode("ascii")
    assert len(body) > 1000
    resp = await _post_through_runner(store, ic, body)
    assert resp.status == 413
    row = await _the_one_error_row(store)
    assert "exceeds max size" in row["error"]
    _assert_names_the_row(resp, row)


async def test_an_hl7_parse_failure_that_is_not_size_stays_422(store: MessageStore) -> None:
    # Control for the case above: the same Peek.parse arm, refusing for a reason that is not size.
    resp = await _post_through_runner(store, _ic(), b"NOT-HL7|at all")
    assert resp.status == 422
    _assert_names_the_row(resp, await _the_one_error_row(store))


async def test_a_body_over_max_body_bytes_is_413_before_any_row(store: MessageStore) -> None:
    # The listener's own cap, refused before the body is read, already answered 413. Kept beside the
    # engine-side cases so the one-code claim is pinned on every over-size path in one place.
    ic = _ic(ContentType.JSON, settings={"max_body_bytes": 16})
    resp = await _post_through_runner(store, ic, b'{"mrn": "100", "type": "obs"}')
    assert resp.status == 413
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    counted = await cur.fetchone()
    assert counted is not None and counted["n"] == 0


# --- the classifier itself ------------------------------------------------------------------------


async def test_a_size_phase_guard_is_oversize_and_every_other_phase_is_permanent(
    store: MessageStore,
) -> None:
    reg = Registry()
    ic = _ic(ContentType.JSON)
    reg.add_inbound(ic)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    kinds = {}
    for phase in ("size", "decode", "type", "parse", "strict"):
        receipt = await runner._refuse_guarded(
            ic, b"x", None, ingress_guards.IngressGuardError("r", phase=phase), message_type=None
        )
        assert isinstance(receipt, IngressReceipt) and receipt.message_id
        kinds[phase] = receipt.refusal
    assert kinds == {
        "size": RefusalKind.OVERSIZE,
        "decode": RefusalKind.PERMANENT,
        "type": RefusalKind.PERMANENT,
        "parse": RefusalKind.PERMANENT,
        "strict": RefusalKind.PERMANENT,
    }


# --- engine to engine: the REST outbound reads each answer ----------------------------------------


async def _send_from_rest_to_a_listener_that_refuses(kind: RefusalKind) -> None:
    """Start a listener whose receipt handler refuses with ``kind`` and deliver to it over REST."""
    listener = HttpSource(
        Source(type=ConnectorType.HTTP, settings={"host": "127.0.0.1", "port": 0})
    )

    async def handler(raw: bytes) -> IngressReceipt:
        return IngressReceipt.refused(kind, "err-1")

    await listener.start(handler)
    try:
        url = f"http://127.0.0.1:{listener.sockport}/ingest"
        dest = build_destination(
            Destination(name="OB_HOP", type=ConnectorType.REST, settings=Rest(url=url).settings),
            egress=EgressSettings(deny_by_default=False),
        )
        assert isinstance(dest, RestDestination)
        await dest.send('{"a": 1}')
    finally:
        await listener.stop()


async def test_a_503_from_an_engine_hop_is_retried() -> None:
    # A temporary refusal at the next engine is a retryable DeliveryError at this one, so the delivery
    # worker re-pends the row under its RetryPolicy instead of dead-lettering it.
    with pytest.raises(DeliveryError) as raised:
        await _send_from_rest_to_a_listener_that_refuses(RefusalKind.TEMPORARY)
    assert not isinstance(raised.value, NegativeAckError)
    assert "HTTP 503" in str(raised.value)


@pytest.mark.parametrize("kind", [RefusalKind.PERMANENT, RefusalKind.OVERSIZE])
async def test_a_permanent_answer_from_an_engine_hop_is_dead_lettered(kind: RefusalKind) -> None:
    # A permanent or over-size refusal is a permanent NegativeAckError, which dead-letters the row
    # rather than re-sending a body the next engine will refuse the same way.
    with pytest.raises(NegativeAckError) as raised:
        await _send_from_rest_to_a_listener_that_refuses(kind)
    assert raised.value.permanent is True
    assert raised.value.code == {RefusalKind.PERMANENT: "422", RefusalKind.OVERSIZE: "413"}[kind]
