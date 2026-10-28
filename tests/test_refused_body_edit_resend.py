# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2608: edit-and-resubmit refuses a refused body stored only as its head.

Past the refused-body allowance a refused row stores only the head of its body;
:func:`head_only_resubmit_refusal` says why such a row must not be resubmitted. Both
edit-and-resubmit modes, re-route and direct, refuse it with 409 before anything is written. A
whole-stored refusal and every other row behave exactly as before.

The rows are seeded through :meth:`RefusedBodyAllowance.bound`, so the metadata the guard reads is
the metadata the runner writes. Synthetic HL7 only; no real PHI.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
    head_only_resubmit_refusal,
)
from messagefoundry.store import MessageStatus

EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"
#: A refused body of short segments, so its head still opens as HL7.
_REFUSED = b"MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r" + b"".join(
    b"NTE|%d||synthetic note %d\r" % (i, i) for i in range(200)
)
_HEAD_BYTES = 256


def _registry(tmp_path: Path) -> Registry:
    for d in ("o1", "o2"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            # A listener, not a poll source: only a listener's refusals are ever stored as a head.
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    for name, d in (("OB1", "o1"), ("OB2", "o2")):
        reg.add_outbound(
            OutboundConnection(
                name, ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / d)})
            )
        )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    return reg


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    eng.add_registry(_registry(tmp_path))
    await eng.start()
    try:
        yield eng
    finally:
        await eng.stop()


async def _seed_refused(engine: Engine, *, allowance_bytes: int) -> str:
    """Record ``_REFUSED`` as a refused row the way the runner does, under an allowance of
    ``allowance_bytes``: 0 stores only its head, a large one stores it whole."""
    allowance = RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=allowance_bytes, head_bytes=_HEAD_BYTES)
    )
    bounded = allowance.bound(
        "in1", _REFUSED, _REFUSED.decode(), ContentType.HL7V2.value, "parse error: synthetic"
    )
    return await engine.store.record_received(
        channel_id="in1",
        raw=bounded.raw,
        status=MessageStatus.ERROR,
        error=bounded.error,
        source_type="mllp",
        metadata=bounded.metadata,
    )


async def _message_ids(engine: Engine) -> set[str]:
    return {m["id"] for m in await engine.store.list_messages(limit=1000, allowed_channels=None)}


async def _edit_resend_audits(engine: Engine) -> int:
    """How many edit-and-resubmit audit rows the store holds."""
    return len(await engine.store.list_audit(action="message_edit_resend", limit=1000))


def _client(engine: Engine) -> httpx.AsyncClient:
    from messagefoundry.api import create_app

    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


@pytest.mark.parametrize("to", [None, "OB2"], ids=["reroute", "direct"])
async def test_edit_resend_refuses_a_head_only_refused_row(engine: Engine, to: str | None) -> None:
    mid = await _seed_refused(engine, allowance_bytes=0)
    stored = await engine.store.get_message(mid)
    assert stored is not None
    # The precondition: a cut copy that still opens as HL7, which is why it must not be resubmitted.
    assert json.loads(stored["metadata"])[METADATA_KEY]["stored"] == "head"
    assert stored["raw"].startswith("MSH|") and len(stored["raw"]) < len(_REFUSED)
    before = await _message_ids(engine)

    payload: dict[str, object] = {"raw": stored["raw"], "idempotency_key": f"k-{to}"}
    if to is not None:
        payload["to"] = to
    async with _client(engine) as c:
        r = await c.post(f"/messages/{mid}/edit-resend", json=payload)

    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert f"the head of this {len(_REFUSED):,}-byte refused body" in detail
    assert f"cut to a {_HEAD_BYTES:,}-byte head bound" in detail
    assert "have the sender send its own copy again" in detail
    assert "NTE|" not in detail  # lengths and ids only, never the body
    # Nothing was re-ingressed or delivered, and nothing was recorded as an edit-and-resubmit.
    assert await _message_ids(engine) == before
    assert await engine.store.outbox_for(mid) == []
    assert await _edit_resend_audits(engine) == 0
    # The refused row itself is untouched.
    assert await engine.store.get_message(mid) == stored


@pytest.mark.parametrize("to", [None, "OB2"], ids=["reroute", "direct"])
async def test_edit_resend_still_resubmits_a_whole_stored_refused_row(
    engine: Engine, to: str | None
) -> None:
    mid = await _seed_refused(engine, allowance_bytes=1 << 20)
    stored = await engine.store.get_message(mid)
    assert stored is not None
    assert json.loads(stored["metadata"])[METADATA_KEY]["stored"] == "whole"
    assert stored["raw"] == _REFUSED.decode()

    payload: dict[str, object] = {"raw": EDITED, "idempotency_key": f"k-{to}"}
    if to is not None:
        payload["to"] = to
    async with _client(engine) as c:
        r = await c.post(f"/messages/{mid}/edit-resend", json=payload)

    assert r.status_code == 200, r.text
    assert r.json()["status"] == ("resubmitted" if to is None else "resent")
    assert await _edit_resend_audits(engine) == 1


def test_only_a_head_record_refuses() -> None:
    head = json.dumps({METADATA_KEY: {"bytes": 9000, "stored": "head", "head_bytes": 512}})
    reason = head_only_resubmit_refusal("m1", head)
    assert reason is not None
    assert reason.startswith("message m1 stored only the head of this 9,000-byte refused body")
    assert ", cut to a 512-byte head bound, so" in reason
    # A head record missing its counts still refuses, naming what it has.
    bare = head_only_resubmit_refusal("m1", json.dumps({METADATA_KEY: {"stored": "head"}}))
    assert bare is not None and "the head of this refused body, so" in bare
    for metadata in (
        None,
        "",
        "not json",
        "[1, 2]",
        json.dumps({"correlation_id": "x"}),
        json.dumps({METADATA_KEY: "head"}),
        json.dumps({METADATA_KEY: {"bytes": 9000, "stored": "whole"}}),
    ):
        assert head_only_resubmit_refusal("m1", metadata) is None, metadata
