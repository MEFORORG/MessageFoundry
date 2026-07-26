# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SOAP body-secret substitution (ADR 0015 amendment, BACKLOG #236).

A partner whose operation carries credentials as **body elements** (a CDC-IIS ``submitSingleMessage``)
rather than a WS-Security header. The Handler emits an opaque placeholder token inside the ``<Body>``;
the transport substitutes the ``env()``-resolved secret in ``send()`` — after the payload leaves the
store, before the wire encode — so **the secret is never in the message**: not the outbound row, the
done row, a dead-letter row, a replayed body, or ``dryrun`` output. These tests hold that line, and
hold the fail-closed / escaping / no-leak-in-an-error behaviours around it.

Two build paths, deliberately: the **config** tests go through the real ``Soap()`` factory +
``resolve_env_settings`` (the author's path); the **transport** tests build the connector from
already-resolved flat settings (what the loader hands the connector post-resolution) so a real secret
string can be exercised without putting it in an ``env()``.
"""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import (
    Registry,
    Soap,
    WiringError,
    build_outbound_connection,
    display_settings,
    env,
    redacted_settings,
    resolve_env_settings,
)
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.soap import SoapDestination

URL = "https://api.example.com/svc"
TOKEN = "MF_IIS_PW_9f2c41ab3d7e"
TOKEN2 = "MF_IIS_USER_5b1d90ee0a11"
#: A secret containing every XML metacharacter, so the escaping is proven, not assumed.
SECRET = "s3cr3t-P@ss&<>\"'w0rd"
ESCAPED = "s3cr3t-P@ss&amp;&lt;&gt;&quot;&apos;w0rd"


# --- fakes -------------------------------------------------------------------


class _Resp:
    def __init__(self, status: int = 200, body: bytes = b"<ok/>") -> None:
        self.status = status
        self._body = body
        self.headers = email.message.Message()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _Opener:
    def __init__(self, resp: _Resp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp or _Resp()
        self._exc = exc
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _Resp:
        self.requests.append(req)
        if self._exc is not None:
            raise self._exc
        return self._resp


def _http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, status, "err", email.message.Message(), io.BytesIO(body))


def _dest(
    *, secret: str = SECRET, resp: _Resp | None = None, exc: Exception | None = None, **over: object
) -> tuple[SoapDestination, _Opener]:
    """A SoapDestination built from already-resolved flat settings (the loader's post-resolution shape),
    with its opener faked so nothing hits the network and the wire bytes are captured."""
    settings: dict[str, object] = {
        "url": URL,
        "soap_action": "urn:submit",
        "body_secret_tokens": [TOKEN],
        "body_secret_value_0": secret,
    }
    settings.update(over)
    d = build_destination(Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings))
    assert isinstance(d, SoapDestination)
    op = _Opener(resp=resp, exc=exc)
    d._opener = op  # type: ignore[assignment]
    return d, op


def _body(token: str = TOKEN) -> str:
    return f'<sub:submit xmlns:sub="urn:x"><sub:pw>{token}</sub:pw></sub:submit>'


# --- config layer: the factory + resolution + redaction ----------------------


def test_factory_hoists_to_flat_keys_and_env_resolves() -> None:
    spec = Soap(url=env("registry_url"), body_secrets={TOKEN: env("pw"), TOKEN2: env("usr")})
    s = spec.settings
    assert s["body_secret_tokens"] == sorted([TOKEN, TOKEN2])
    # each secret is a top-level EnvRef, so the existing resolver materializes it at connector build
    resolved = resolve_env_settings(s, {"registry_url": URL, "pw": SECRET, "usr": "acct"})
    idx = s["body_secret_tokens"].index(TOKEN)
    assert resolved[f"body_secret_value_{idx}"] == SECRET


def test_missing_env_value_fails_loud_at_resolution() -> None:
    spec = Soap(url=URL, body_secrets={TOKEN: env("pw")})
    with pytest.raises(WiringError, match="pw"):
        resolve_env_settings(spec.settings, {})  # the ADR 0050 missing-value gate arms


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({TOKEN: "literal-secret"}, "must be an env"),  # inline literal refused
        ({TOKEN: env("pw", default="fallback")}, "default="),  # fallback secret refused
        ({TOKEN: env("pw", cast="int")}, "cast="),  # cast refused
        ({"short": env("pw")}, "must match"),  # low-entropy token refused
        ({TOKEN: env("a"), TOKEN + "XX": env("b")}, "substring"),  # overlapping tokens refused
    ],
)
def test_factory_rejects_bad_body_secrets(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(WiringError, match=match):
        Soap(url=URL, body_secrets=kwargs)  # type: ignore[arg-type]


def test_connections_toml_nested_form_is_refused_code_first() -> None:
    # A connections.toml [settings.body_secrets] table arrives as raw {"env": ...} dicts (parse_env_setting
    # is top-level only), so the factory's EnvRef check refuses it pointing back to code-first — there is
    # deliberately no TOML/GUI round-trip that could persist a plaintext secret or corrupt on save.
    with pytest.raises(WiringError, match="code-first only"):
        Soap(url=URL, body_secrets={TOKEN: {"env": "pw"}})  # type: ignore[dict-item]


def test_body_secret_value_is_never_served_by_a_settings_serializer() -> None:
    spec = Soap(url=URL, body_secrets={TOKEN: env("pw")})
    for view in (redacted_settings(spec.settings), display_settings(spec.settings)):
        blob = json.dumps(view)
        assert "pw" in blob  # the env KEY is shown (a name, useful + safe)
        assert view["body_secret_value_0"] == {"env": "pw"}  # key only — no value, no default
    # the token itself is NOT a secret (it is public in the committed Handler source)
    assert redacted_settings(spec.settings)["body_secret_tokens"] == [TOKEN]


def test_wiring_refuses_body_secrets_with_reingress() -> None:
    spec = Soap(url=URL, body_secrets={TOKEN: env("pw")}, reingress_to="IB_LOOP")
    with pytest.raises(WiringError, match="reingress_to"):
        build_outbound_connection("OB_SOAP", spec)


# --- transport layer: substitution, escaping, fail-closed --------------------


async def test_wire_carries_the_secret_and_never_the_token() -> None:
    d, op = _dest()
    await d.send(_body())
    wire = op.requests[0].data.decode()  # type: ignore[union-attr]
    assert ESCAPED in wire  # the real (XML-escaped) secret is on the wire
    assert TOKEN not in wire  # the placeholder is gone


async def test_secret_is_quoteattr_escaped_in_attribute_position() -> None:
    # The well-formedness gate accepts a token in an attribute (`pw="TOKEN"`), so a secret with a quote
    # must be escaped to all five metacharacters or it breaks out of the attribute. saxutils.escape
    # alone (& < >) would leave the quotes and FAIL this.
    d, op = _dest()
    await d.send(f'<sub:submit xmlns:sub="urn:x"><c pw="{TOKEN}"/></sub:submit>')
    wire = op.requests[0].data.decode()  # type: ignore[union-attr]
    assert ESCAPED in wire
    # the envelope must still parse — the quotes did not escape the attribute
    import defusedxml.ElementTree as ET

    ET.fromstring(wire)


async def test_missing_token_fails_closed_without_leaking() -> None:
    d, op = _dest()
    with pytest.raises(NegativeAckError) as ei:
        await d.send(_body(token="NO_SUCH_TOKEN_PRESENT"))
    exc = ei.value
    assert exc.permanent is True  # a body that never carries the token will never succeed
    assert op.requests == []  # NOTHING was POSTed
    assert TOKEN in str(exc) and "0" in str(exc)  # names the token + count
    assert SECRET not in str(exc) and "NO_SUCH_TOKEN" not in str(
        exc
    )  # not the secret, not the payload


async def test_duplicate_token_fails_closed() -> None:
    d, op = _dest()
    dup = f'<sub:submit xmlns:sub="urn:x"><a>{TOKEN}</a><b>{TOKEN}</b></sub:submit>'
    with pytest.raises(NegativeAckError) as ei:
        await d.send(dup)
    assert ei.value.permanent is True
    assert op.requests == []
    assert SECRET not in str(ei.value)


async def test_literal_braces_round_trip() -> None:
    # str.replace, not str.format — a body with literal { } is untouched (the reason the envelope
    # skeleton is concatenated, not formatted).
    d, op = _dest()
    await d.send(
        f'<sub:submit xmlns:sub="urn:x"><n>{{0}} and {{x}}</n><pw>{TOKEN}</pw></sub:submit>'
    )
    wire = op.requests[0].data.decode()  # type: ignore[union-attr]
    assert "{0} and {x}" in wire and ESCAPED in wire


async def test_no_body_secrets_is_byte_identical() -> None:
    # A SOAP dest with no body_secrets sends the payload verbatim (the whole feature is inert).
    plain = build_destination(
        Destination(name="OB", type=ConnectorType.SOAP, settings={"url": URL, "soap_action": "u"})
    )
    op = _Opener()
    plain._opener = op  # type: ignore[assignment]
    await plain.send("<env>unchanged</env>")
    assert op.requests[0].data == b"<env>unchanged</env>"  # type: ignore[union-attr]


# --- construction-time credential validation, no value in the error ----------


@pytest.mark.parametrize("bad", ["", "has\x01control"])
def test_construction_rejects_empty_or_control_char_secret_without_leaking(bad: str) -> None:
    with pytest.raises(ValueError) as ei:  # noqa: PT011 - message asserted below
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings={"url": URL, "body_secret_tokens": [TOKEN], "body_secret_value_0": bad},
            )
        )
    msg = str(ei.value)
    assert TOKEN in msg  # names the placeholder
    assert bad not in msg or bad == ""  # never the value (empty string is vacuous)


def test_construction_rejects_secret_not_encodable_in_the_connection_encoding() -> None:
    # A secret with a non-ASCII char under encoding="ascii" would UnicodeEncodeError at the send-time
    # wire encode, and str(UnicodeEncodeError) names the offending character — which would land in
    # queue.last_error. Reject it at BUILD instead, naming the token + codec, never the character.
    non_ascii = "s3cr3tépw"  # the 'é' cannot be encoded as ASCII
    with pytest.raises(ValueError) as ei:  # noqa: PT011 - message asserted below
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings={
                    "url": URL,
                    "encoding": "ascii",
                    "body_secret_tokens": [TOKEN],
                    "body_secret_value_0": non_ascii,
                },
            )
        )
    msg = str(ei.value)
    assert TOKEN in msg and "ascii" in msg  # names the token + the codec
    assert "é" not in msg and non_ascii not in msg  # never the character or the value
    # utf-8 (the default encoding) encodes it fine — no false positive.
    _dest(secret=non_ascii)  # builds without raising


async def test_cleartext_http_hop_with_body_secret_is_refused() -> None:
    with pytest.raises(Exception) as ei:  # noqa: PT011,B017 - egress/credential-hop refusal at build
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings={
                    "url": "http://registry.example.com/svc",  # cleartext, non-loopback
                    "body_secret_tokens": [TOKEN],
                    "body_secret_value_0": SECRET,
                },
            )
        )
    assert SECRET not in str(ei.value)  # the refusal names no credential


# --- captured response scrub (best-effort, documented) -----------------------


async def test_captured_fault_echoing_the_secret_is_scrubbed() -> None:
    fault = f"<soap:Fault><faultstring>rejected credential {SECRET}</faultstring></soap:Fault>"
    d, _ = _dest(capture_response=True, resp=_Resp(200, fault.encode()))
    resp = await d.send(_body())
    assert resp is not None and resp.outcome == "rejected"
    assert SECRET not in resp.body and ESCAPED not in resp.body
    assert "***" in resp.body


async def test_low_entropy_secret_is_not_scrubbed_from_the_reply() -> None:
    # A 5-char facility code a CDC-IIS ACK legitimately echoes must survive — a content-blind replace
    # would shred the operator's reconciliation key.
    fac = "FAC42"
    ack = f"<ok><facility>{fac}</facility></ok>"
    d, _ = _dest(secret=fac, capture_response=True, resp=_Resp(200, ack.encode()))
    resp = await d.send(_body())
    assert resp is not None and fac in resp.body  # not masked (below the scrub floor)


# --- THE headline: the store holds only the token ----------------------------

RAW = "MSH|^~\\&|S|F|R|RF|20260101||VXU^V04|MSG1|P|2.5.1\r"
CHANNEL = "IB_IMM"
DEST = "OB_REGISTRY"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "bs.db")
    yield s
    await s.close()


async def _seed_outbound(store: MessageStore, body: str) -> str:
    """Drive one message ingress→routed→outbound with ``body`` as the delivered payload."""
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
        deliveries=[(DEST, body)],
        now=0.0,
    )
    return mid


async def _stored_payloads(store: MessageStore, mid: str) -> str:
    """Every at-rest rendering of the outbound payload for ``mid``, concatenated for a substring scan:
    the live queue row and the decrypted operator/parity read path."""
    cur = await store._db.execute(
        "SELECT COALESCE(payload,'') FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.OUTBOUND.value),
    )
    rows = await cur.fetchall()
    parts = [str(r[0]) for r in rows]
    parts += [str(p.get("payload", "")) for p in await store.outbox_payloads_for(mid)]
    return "\n".join(parts)


def _runner(store: MessageStore) -> RegistryRunner:
    return RegistryRunner(Registry(), store, poll_interval=0.02, alert_sink=LoggingAlertSink())


async def test_stored_rows_hold_only_the_token_while_the_wire_gets_the_secret(
    store: MessageStore,
) -> None:
    body = _body()
    mid = await _seed_outbound(store, body)
    # sanity: the token-bearing body really is what got stored (so the assertions below can't pass vacuously)
    assert TOKEN in await _stored_payloads(store, mid)

    d, op = _dest()
    runner = _runner(store)
    runner._destinations[DEST] = d  # type: ignore[assignment]
    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    await runner._process_delivery_item(DEST, item)

    # the WIRE carried the real secret...
    wire = op.requests[0].data.decode()  # type: ignore[union-attr]
    assert ESCAPED in wire and TOKEN not in wire
    # ...while EVERY at-rest rendering holds only the token, never the secret
    stored = await _stored_payloads(store, mid)
    assert TOKEN in stored
    assert SECRET not in stored and ESCAPED not in stored


async def test_forced_dead_letter_never_persists_the_secret(store: MessageStore) -> None:
    body = _body()
    mid = await _seed_outbound(store, body)
    # a permanent HTTP 4xx dead-letters the row (NOT a credential rejection — that would be captured)
    d, _ = _dest(exc=_http_error(400, b"bad request"))
    runner = _runner(store)
    runner._destinations[DEST] = d  # type: ignore[assignment]
    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    await runner._process_delivery_item(DEST, item)

    cur = await store._db.execute(
        "SELECT status, COALESCE(last_error,'') FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.OUTBOUND.value),
    )
    row = await cur.fetchone()
    assert row is not None and row[0] == OutboxStatus.DEAD.value
    assert SECRET not in row[1] and ESCAPED not in row[1]  # not in last_error
    assert SECRET not in await _stored_payloads(store, mid)  # not in the retained payload


async def test_replay_re_substitutes(store: MessageStore) -> None:
    body = _body()
    mid = await _seed_outbound(store, body)
    # first attempt dead-letters
    d1, _ = _dest(exc=_http_error(400, b"bad"))
    runner = _runner(store)
    runner._destinations[DEST] = d1  # type: ignore[assignment]
    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    await runner._process_delivery_item(DEST, item)

    # replay re-pends the SAME stored (token-only) payload (explicit now: the claim below must be later)
    assert await store.replay(mid, now=2.0) == 1
    d2, op2 = _dest()  # a fresh, healthy connector
    runner._destinations[DEST] = d2  # type: ignore[assignment]
    item2 = await store.claim_next_fifo(DEST, now=3.0)
    assert item2 is not None
    await runner._process_delivery_item(DEST, item2)

    # the wire carries the secret again (re-substituted from config); the store still holds only the token
    assert ESCAPED in op2.requests[0].data.decode()  # type: ignore[union-attr]
    assert SECRET not in await _stored_payloads(store, mid)
