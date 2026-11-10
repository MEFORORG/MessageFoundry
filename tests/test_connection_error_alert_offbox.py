# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The notifier's ``connection_error`` alert keeps its reason on the box (BACKLOG #5021).

The reason is a ``safe_exc`` text, which can echo a partner's reply. The webhook JSON and the
default email body carry the connection, the kind and the exception class, never that reason; the
stored alert instance still keeps it as its masked, revealable reason (BACKLOG #2443). Every value
here is synthetic."""

from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any

import pytest

from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.pipeline.alert_sinks import EmailTransport, NotifierAlertSink, WebhookTransport
from tests.test_alert_state import _RecordingStore

#: An obviously synthetic MRN, standing in for message content a partner's reply echoed.
_ECHO = "FAKE-MRN-ZZ0000099"
_DETAIL = f"partner replied: unknown patient {_ECHO}"


class _Resp:
    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def read(self, amt: int = -1) -> bytes:
        return b""


def _wire(monkeypatch: pytest.MonkeyPatch) -> tuple[list[bytes], list[str]]:
    posts: list[bytes] = []
    bodies: list[str] = []

    def fake_open(req: Any, timeout: float | None = None) -> _Resp:
        posts.append(req.data)
        return _Resp()

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            pass

        def __enter__(self) -> _FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def starttls(self, context: ssl.SSLContext | None = None) -> None:
            pass

        def send_message(self, msg: Any, **envelope: Any) -> None:
            bodies.append(msg.get_body(preferencelist=("plain",)).get_content())

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks._NO_REDIRECT_OPENER.open", fake_open)
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _FakeSMTP)
    return posts, bodies


async def _fire(store: _RecordingStore, *, error_class: str | None) -> None:
    web = WebhookTransport("https://hooks.example/x", posture=HopPosture(enforcing=False))
    email = EmailTransport(
        host="smtp.example", port=587, sender="mf@example", recipients=["ops@example"]
    )
    sink = NotifierAlertSink([web, email], store=store)
    sink.connection_error(
        "OB_FAKE", kind="connection_lost", detail=_DETAIL, error_class=error_class
    )
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    await sink.drain_state(1.0)


async def test_the_reason_never_leaves_the_box(monkeypatch: pytest.MonkeyPatch) -> None:
    posts, bodies = _wire(monkeypatch)
    store = _RecordingStore()
    await _fire(store, error_class="DeliveryError")

    assert len(posts) == 1 and len(bodies) == 1
    wire = posts[0].decode("utf-8")
    assert _ECHO not in wire and _ECHO not in bodies[0]
    payload = json.loads(wire)
    assert set(payload) == {"type", "connection", "kind", "error_class", "severity", "ts"}
    assert (payload["connection"], payload["kind"], payload["error_class"]) == (
        "OB_FAKE",
        "connection_lost",
        "DeliveryError",
    )
    for line in ("connection: OB_FAKE", "kind: connection_lost", "error_class: DeliveryError"):
        assert line in bodies[0].splitlines()
    # The stored instance keeps the reason, masked until an operator reveals it.
    assert [u["reason"] for u in store.upserts] == [_DETAIL]


@pytest.mark.parametrize("error_class", [None, "", "Bad Class", f"Err_{_ECHO}-x", "Erré"])
async def test_a_class_that_is_not_a_plain_identifier_is_a_fixed_token(
    monkeypatch: pytest.MonkeyPatch, error_class: str | None
) -> None:
    posts, bodies = _wire(monkeypatch)
    await _fire(_RecordingStore(), error_class=error_class)

    assert json.loads(posts[0])["error_class"] == "unnamed error"
    assert "error_class: unnamed error" in bodies[0].splitlines()
    assert _ECHO not in posts[0].decode("utf-8") and _ECHO not in bodies[0]


class _RecordingTransport:
    name = "custom"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_: Any) -> None:
        self.events.append(dict(event))


async def test_no_transport_or_observer_is_handed_the_reason() -> None:
    # A transport that keeps _-prefixed keys still never sees the reason: _handle pops it.
    transport = _RecordingTransport()
    observed: list[dict[str, Any]] = []
    store = _RecordingStore()
    sink = NotifierAlertSink([transport], store=store)
    sink.set_delivery_observer(lambda _name, event: observed.append(dict(event)))
    sink.connection_error("OB_FAKE", kind="connection_lost", detail=_DETAIL, error_class="X")
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    await sink.drain_state(1.0)

    assert len(transport.events) == 1 and len(observed) == 1
    for event in (transport.events[0], observed[0]):
        assert _ECHO not in repr(event)
        assert "_detail" not in event and "detail" not in event
    assert [u["reason"] for u in store.upserts] == [_DETAIL]
