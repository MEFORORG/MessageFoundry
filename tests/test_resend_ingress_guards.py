# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An operator resubmission meets the ingress guards a sender would meet (BACKLOG #1911).

``POST /uploads/{file_id}/resend`` puts one message from an uploaded file onto a chosen inbound's
ingress stage, and ``POST /messages/{id}/edit-resend`` re-ingresses an edited body on the origin's
channel. Neither passed through the inbound's listener, so neither met its size ceiling (the engine
16 MiB default, or the inbound's own ``max_message_bytes``) or its declared-type sniff. Each test below
drives one guard and was red on the code before this change: the resubmission was committed.

The refusal is a 4xx plus an audit row, and nothing is committed. That keeps count-and-log whole: no
body is accepted and then dropped, because none is accepted.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.binary import encode as carry
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.ingress_guards import (
    IngressGuardError,
    admit_resubmitted_body,
)
from messagefoundry.store.store import Stage

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN123^^^H^MR||DOE^JANE\r"
EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"
TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rZXF|sent\r"
#: A unique marker inside a refused body. It must reach neither the 4xx detail nor any audit row.
PHI_MARKER = "MRN7777SECRET"


def _inbound(
    tmp_path: Path,
    *,
    content_type: ContentType = ContentType.HL7V2,
    max_message_bytes: int | None = None,
) -> InboundConnection:
    (tmp_path / "in").mkdir(exist_ok=True)
    return InboundConnection(
        "in1",
        ConnectionSpec(
            ConnectorType.FILE,
            {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
        ),
        router="r",
        content_type=content_type,
        max_message_bytes=max_message_bytes,
    )


def _registry(tmp_path: Path, ic: InboundConnection) -> Registry:
    for d in ("o1", "o2"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB2", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o2")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    return reg


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    e = await Engine.create(tmp_path / "guards.db", poll_interval=0.02)
    try:
        yield e
    finally:
        await e.stop()


async def _operator(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    return service


async def _login(c: httpx.AsyncClient) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": "op", "password": PW, "provider": "local"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def _message_count(engine: Engine, channel: str) -> int:
    return len(await engine.store.list_messages(channel_id=channel, limit=1000))


async def _actions(engine: Engine, action: str) -> list[dict[str, object]]:
    return [a for a in await engine.store.list_audit() if a["action"] == action]


async def _upload_then_resend(
    engine: Engine,
    tmp_path: Path,
    body: str,
    *,
    max_upload_bytes: int = 1_000_000,
) -> httpx.Response:
    """Upload ``body`` as a one-message ``.hl7`` file and resend message 0 into ``in1``."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    await engine.start()
    service = await _operator(engine)
    settings = StoreSettings(
        uploads_dir=str(tmp_path / "uploads"), max_upload_bytes=max_upload_bytes
    )
    app = create_app(engine, auth=service, store_settings=settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = await _login(c)
        up = await c.post("/uploads", files={"file": ("m.hl7", body, "text/plain")}, headers=h)
        assert up.status_code == 200, up.text
        fid = up.json()["file_id"]
        return await c.post(f"/uploads/{fid}/resend", json={"index": 0, "to": "in1"}, headers=h)


# --- /uploads/{file_id}/resend ----------------------------------------------------------------------


async def test_upload_resend_over_the_engine_ceiling_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    # The headline case: [store].max_upload_bytes defaults to 25 MiB, above the 16 MiB ingress ceiling,
    # so one upload could carry a single message no listener would take.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path)))
    big = f"MSH|^~\\&|S|F|R|RF|20260101||ORU^R01|BIG|P|2.5.1\rOBX|1|TX|||{'A' * DEFAULT_MAX_MESSAGE_BYTES}\r"
    r = await _upload_then_resend(engine, tmp_path, big, max_upload_bytes=20 * 1024 * 1024)
    assert r.status_code == 413, r.text
    assert await _message_count(engine, "in1") == 0  # nothing committed
    rejected = await _actions(engine, "upload.resend_reject")
    assert len(rejected) == 1 and "exceeds max size" in str(rejected[0]["detail"])
    assert not await _actions(engine, "upload.resend")


async def test_upload_resend_over_the_inbounds_own_ceiling_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    # An inbound configured BELOW the default must hold that line too.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, max_message_bytes=len(ADT) - 1)))
    r = await _upload_then_resend(engine, tmp_path, ADT)
    assert r.status_code == 413, r.text
    assert await _message_count(engine, "in1") == 0


async def test_upload_resend_to_an_inbound_of_another_declared_type_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    # An HL7 message injected into a JSON inbound: the listener's sniff would dead-letter it.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, content_type=ContentType.JSON)))
    r = await _upload_then_resend(engine, tmp_path, ADT)
    assert r.status_code == 415, r.text
    assert "'json'" in r.json()["detail"]
    assert await _message_count(engine, "in1") == 0
    assert len(await _actions(engine, "upload.resend_reject")) == 1


async def test_upload_resend_that_fits_is_still_injected(engine: Engine, tmp_path: Path) -> None:
    # The control: the same route and inbound shape admit a body that fits, so a red above is the guard.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, max_message_bytes=len(ADT))))
    r = await _upload_then_resend(engine, tmp_path, ADT)
    assert r.status_code == 200, r.text
    assert await _message_count(engine, "in1") == 1


# --- /messages/{id}/edit-resend ---------------------------------------------------------------------


async def _edit_resend(
    engine: Engine, payload: dict[str, object], *, origin_channel: str = "in1"
) -> tuple[str, httpx.Response]:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    await engine.start()
    mid = await engine.store.enqueue_message(
        channel_id=origin_channel, raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
    )
    app = create_app(engine, allow_no_auth=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return mid, await c.post(f"/messages/{mid}/edit-resend", json=payload)


async def _assert_nothing_committed(engine: Engine, mid: str, r: httpx.Response) -> None:
    assert PHI_MARKER not in r.text
    assert await _message_count(engine, "in1") == 1  # only the origin; no correlated child
    orig = await engine.store.get_message(mid)
    assert orig is not None and orig["raw"] == ADT
    assert not await _actions(engine, "message_edit_resend")
    rejected = await _actions(engine, "message_edit_resend_reject")
    assert len(rejected) == 1
    assert PHI_MARKER not in str(rejected[0]["detail"])


async def test_edit_resend_reroute_of_a_mistyped_body_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path)))
    mid, r = await _edit_resend(
        engine, {"raw": f"not an HL7 message {PHI_MARKER}", "idempotency_key": "k1"}
    )
    # Peek.parse is the HL7 inbound's type check, as it is the listener's, so this is a parse refusal.
    assert r.status_code == 422, r.text
    await _assert_nothing_committed(engine, mid, r)


async def test_edit_resend_reroute_with_no_inbound_to_guard_with_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    # An origin inbound this engine does not hold (removed, or owned by another engine shard) has no
    # declared type or ceiling to check against, so the re-route fails closed instead of open.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path)))
    mid, r = await _edit_resend(
        engine,
        {"raw": f"not an HL7 message {PHI_MARKER}", "idempotency_key": "k1"},
        origin_channel="IB_ELSEWHERE",
    )
    assert r.status_code == 409, r.text
    assert PHI_MARKER not in r.text
    assert await _message_count(engine, "IB_ELSEWHERE") == 1  # only the origin
    assert not await _actions(engine, "message_edit_resend")
    orig = await engine.store.get_message(mid)
    assert orig is not None and orig["raw"] == ADT


async def test_edit_resend_reroute_over_the_inbounds_ceiling_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, max_message_bytes=len(EDITED))))
    mid, r = await _edit_resend(
        engine, {"raw": EDITED + f"NTE|1||{PHI_MARKER}\r", "idempotency_key": "k1"}
    )
    assert r.status_code == 413, r.text
    await _assert_nothing_committed(engine, mid, r)


async def test_edit_resend_reroute_with_a_nul_is_refused(engine: Engine, tmp_path: Path) -> None:
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path)))
    mid, r = await _edit_resend(
        engine, {"raw": EDITED + f"NTE|1||{PHI_MARKER}\x00\r", "idempotency_key": "k1"}
    )
    assert r.status_code == 422, r.text
    await _assert_nothing_committed(engine, mid, r)


async def test_edit_resend_direct_with_a_nul_is_refused(engine: Engine, tmp_path: Path) -> None:
    # The direct path writes an OUTBOUND row, so there is no inbound type to sniff against; the
    # engine-wide guards (NUL, the 16 MiB default) still hold.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path)))
    mid, r = await _edit_resend(
        engine,
        {"raw": EDITED + f"NTE|1||{PHI_MARKER}\x00\r", "idempotency_key": "k1", "to": "OB2"},
    )
    assert r.status_code == 422, r.text
    await _assert_nothing_committed(engine, mid, r)
    # The direct path's own artifact is an outbound row to OB2; the in1 count cannot see it.
    async with engine.store._read() as db:
        cur = await db.execute(
            "SELECT COUNT(*) FROM queue WHERE stage=? AND destination_name=?",
            (Stage.OUTBOUND.value, "OB2"),
        )
        row = await cur.fetchone()
    assert row is not None and row[0] == 0


async def test_upload_resend_into_a_binary_inbound_commits_carriage(
    engine: Engine, tmp_path: Path
) -> None:
    # The listener commits a binary inbound's body as mfb64:v1: carriage; so must the resend.
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, content_type=ContentType.BINARY)))
    r = await _upload_then_resend(engine, tmp_path, ADT)
    assert r.status_code == 200, r.text
    row = await engine.store.get_message(r.json()["message_id"])
    assert row is not None and row["raw"].startswith("mfb64:v1:")


async def test_edit_resend_reroute_that_fits_is_still_resubmitted(
    engine: Engine, tmp_path: Path
) -> None:
    engine.add_registry(_registry(tmp_path, _inbound(tmp_path, max_message_bytes=len(EDITED))))
    _mid, r = await _edit_resend(engine, {"raw": EDITED, "idempotency_key": "k1"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "resubmitted"


# --- the pure guard ---------------------------------------------------------------------------------


def _ic(content_type: ContentType, max_message_bytes: int | None = None) -> InboundConnection:
    return InboundConnection(
        "in1",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
        router="r",
        content_type=content_type,
        max_message_bytes=max_message_bytes,
    )


def test_guard_applies_the_hl7_ceiling_per_connection() -> None:
    admit_resubmitted_body(ADT, _ic(ContentType.HL7V2, max_message_bytes=len(ADT)))
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(ADT, _ic(ContentType.HL7V2, max_message_bytes=len(ADT) - 1))
    assert exc.value.phase == "size"


def test_guard_sniffs_the_declared_type() -> None:
    admit_resubmitted_body('{"a": 1}', _ic(ContentType.JSON))
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(ADT, _ic(ContentType.JSON))
    assert exc.value.phase == "type"
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body('{"a": 1}', _ic(ContentType.HL7V2))
    assert exc.value.phase == "parse"  # an HL7 inbound's type check is Peek.parse, not the sniff


def test_guard_sniffs_a_binary_inbound_on_its_bytes() -> None:
    dicom = b"\x00" * 128 + b"DICM" + b"\x02\x00"
    admit_resubmitted_body(carry(dicom), _ic(ContentType.DICOM))
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(ADT, _ic(ContentType.DICOM))
    assert exc.value.phase == "type"
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body("mfb64:v1:not base64!", _ic(ContentType.BINARY))
    assert exc.value.phase == "decode"


def test_guard_refuses_text_the_declared_charset_cannot_hold() -> None:
    ic = InboundConnection(
        "in1",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575, "encoding": "ascii"}),
        router="r",
    )
    admit_resubmitted_body(ADT, ic)
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(ADT.replace("JANE", "JOSÉ"), ic)
    assert exc.value.phase == "decode"
    # The reason names a position, never the character, because it is returned and audited.
    assert "É" not in exc.value.reason and "\\xc9" not in exc.value.reason


def test_guard_without_an_inbound_keeps_the_engine_wide_rules() -> None:
    admit_resubmitted_body("anything at all", None)
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body("a\x00b", None)
    assert exc.value.phase == "decode"
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body("A" * (DEFAULT_MAX_MESSAGE_BYTES + 1), None)
    assert exc.value.phase == "size"


def test_guard_applies_the_hl7_segment_cap_peek_parse_applies() -> None:
    from messagefoundry.parsing.peek import DEFAULT_MAX_SEGMENTS

    too_many = ADT + "NTE|1\r" * DEFAULT_MAX_SEGMENTS
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(too_many, _ic(ContentType.HL7V2))
    assert exc.value.phase == "size" and "max segments" in exc.value.reason


@pytest.mark.parametrize(
    "body",
    [
        "FHS|^~\\&|S\r" + ADT,  # a batch header the sniff admits and Peek.parse refuses
        "﻿" + ADT,  # a BOM the sniff strips and Peek.parse does not
        "MSH",  # a bare segment id
    ],
)
def test_guard_refuses_what_peek_parse_refuses_and_the_sniff_admits(body: str) -> None:
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(body, _ic(ContentType.HL7V2))
    assert exc.value.phase == "parse"


@pytest.mark.parametrize("lead", ["\xa0", "\x1c", "\x85"])
def test_guard_admits_what_peek_parse_admits_and_the_sniff_refuses(lead: str) -> None:
    # Peek.parse strips leading whitespace with str.lstrip(); the byte sniff does not. The listener
    # never applies the sniff to HL7, so a body it accepts must stay resendable.
    admit_resubmitted_body(lead + ADT, _ic(ContentType.HL7V2))


def test_guard_stores_canonical_carriage() -> None:
    broken = carry(b"ABCDEFGHIJ")[:15] + "\r\n" + carry(b"ABCDEFGHIJ")[15:]
    assert admit_resubmitted_body(broken, _ic(ContentType.BINARY)) == carry(b"ABCDEFGHIJ")


def test_guard_returns_the_form_the_listener_commits() -> None:
    # HL7 is committed \r-normalized, as the listener's normalize() leaves it.
    assert admit_resubmitted_body(ADT.replace("\r", "\r\n"), _ic(ContentType.HL7V2)) == ADT
    # Another text type is committed verbatim.
    assert admit_resubmitted_body('{"a":\r\n1}', _ic(ContentType.JSON)) == '{"a":\r\n1}'
    # A binary inbound's row is carriage: bare text is carried, carriage is kept as it is.
    assert admit_resubmitted_body("plain", _ic(ContentType.BINARY)) == carry(b"plain")
    assert admit_resubmitted_body(carry(b"x"), _ic(ContentType.BINARY)) == carry(b"x")


def test_guard_holds_a_streaming_inbound_to_the_engine_ceiling() -> None:
    # A streaming inbound raises max_message_bytes to pay for a detach the resend path does not do.
    big = ADT + "NTE|1||" + "A" * DEFAULT_MAX_MESSAGE_BYTES + "\r"
    with pytest.raises(IngressGuardError) as exc:
        admit_resubmitted_body(big, _ic(ContentType.HL7V2, max_message_bytes=64 * 1024 * 1024))
    assert exc.value.phase == "size"
