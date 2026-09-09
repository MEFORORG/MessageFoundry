# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""End-to-end pin for every field-level redaction site (ASVS 8.1.2).

``docs/SECURITY.md`` states that the same disposition text gates on ``messages:view_summary`` on
**every** surface that returns it, and names six. The map-level guards
(``tests/test_field_authz.py``, ``tests/test_security_doc_drift.py``) prove the POLICY is complete and
documented; they cannot prove it is APPLIED — a future PHI-bearing route that forgets the
``redact_unauthorized`` call passes all of them, because ``redact_unauthorized`` fails **open**.

So this hits each of the six surfaces over HTTP with a caller who lacks the unlocking permission and
asserts every documented gated property comes back ``null``. Two callers are needed, which is itself
the point:

* **Viewer** (``monitoring:read`` + ``messages:read``) covers the five ``messages:read`` surfaces;
* a **custom role** holding ``messages:view_raw`` *without* ``messages:view_summary`` covers
  ``GET /messages/{id}`` — and demonstrates that the doc's "the split is reachable" claim is real,
  not theoretical (``view_raw`` is not a superset of ``view_summary``).

Synthetic HL7 only — the MRN and name below are invented.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.field_authz import PHI_FIELDS
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import Permission
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus

PW = "a-strong-test-passphrase"  # >= 15 chars, satisfies the ASVS password policy

#: Synthetic ADT — invented MRN/name, never real PHI.
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSGSEED|P|2.5.1\rPID|1||MRN9001^^^H^MR||DOE^JANE\r"

#: The six surfaces the doc names, each with the caller that can reach it. ``{mid}`` is the seeded
#: message id and ``{preset}`` that caller's own saved preset (layered search is owner-scoped).
_SURFACES: tuple[tuple[str, str], ...] = (
    ("/dead-letters", "viewer"),
    ("/messages", "viewer"),
    ("/messages/search?field_path=PID-3", "viewer"),
    ("/messages/{mid}", "rawonly"),
    ("/messages/{eid}", "rawonly"),  # the ERROR-disposition row carries MessageDetail.error
    # The DEAD-lettered message. Its detail is the ONLY surface on which OutboxInfo.last_error is
    # non-null, so without this row that (model, property) pair had ZERO coverage: neutering
    # redact_unauthorized for OutboxInfo alone left the whole suite green while a view_raw-without-
    # view_summary caller received outbox[].last_error in full.
    ("/messages/{did}", "rawonly"),
    ("/messages/{mid}/responses", "viewer"),
    ("/search/layered?presets={preset}", "viewer"),
)

#: Every property the doc's read table gates, flattened — what must be null for a caller without
#: ``messages:view_summary``. Derived from the map so a new gated property is checked automatically.
_GATED_PROPERTIES = {prop for props in PHI_FIELDS.values() for prop in props}

#: The same map keyed on ``(model, property)`` PAIRS. The flattened name set above cannot express
#: coverage: ``last_error`` is "covered" by ``DeadLetterRow.last_error`` on ``/dead-letters`` while
#: ``OutboxInfo.last_error`` is never exercised, which is exactly how the anti-vacuity guard passed
#: over an uncovered row.
_GATED_PAIRS = frozenset(
    (cls.__name__, prop) for cls, props in PHI_FIELDS.items() for prop in props
)

#: ``{frozenset(field names): model name}`` — every mapped model's field set is distinct, so a JSON
#: object can be attributed to its model by signature. Asserted, not assumed.
_MODEL_SIGNATURES: dict[frozenset[str], str] = {
    frozenset(cls.model_fields): cls.__name__ for cls in PHI_FIELDS
}


def _attributed_pairs(node: object) -> set[tuple[str, str]]:
    """``{(model, property)}`` for every gated property that came back NON-null in ``node``."""
    found: set[tuple[str, str]] = set()
    for obj in _objects(node):
        model = _MODEL_SIGNATURES.get(frozenset(obj))
        if model is None:
            continue
        for _cls_name, prop in _GATED_PAIRS:
            if _cls_name == model and obj.get(prop) is not None:
                found.add((model, prop))
    return found


@dataclass(frozen=True)
class _Seed:
    engine: Engine
    service: AuthService
    message_id: str
    error_message_id: str
    dead_message_id: str
    presets: dict[str, str]


def _objects(node: object) -> list[dict[str, object]]:
    """Every JSON object nested anywhere in a decoded response body."""
    found: list[dict[str, object]] = []
    if isinstance(node, dict):
        found.append(node)
        for value in node.values():
            found.extend(_objects(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_objects(value))
    return found


@pytest.fixture
async def seeded(tmp_path: Path) -> AsyncIterator[_Seed]:
    """An engine holding one message with a summary, an error, metadata, a captured reply and a
    dead-lettered delivery — so every gated property has a non-null value to withhold."""
    engine = await Engine.create(tmp_path / "field_authz_sites.db", poll_interval=0.02)
    try:
        # require_mfa=False: this is a redaction test, not an MFA test — the step-up surfaces
        # (/messages/search, /search/layered) must not be blocked by the secure-by-default MFA gate.
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()

        custom = await service.create_custom_role(
            display_name="Raw only",
            description="messages:view_raw WITHOUT messages:view_summary (ADR 0045)",
            permissions=[Permission.MESSAGES_READ.value, Permission.MESSAGES_VIEW_RAW.value],
            actor="test",
        )
        for username, roles in (
            ("viewer", [Role.VIEWER.value]),
            ("rawonly", [custom.id]),
            ("boss", [Role.ADMINISTRATOR.value]),
        ):
            uid = await service.create_local_user(
                username=username,
                password=PW,
                display_name=None,
                email=None,
                roles=roles,
                actor="test",
            )
            # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
            # fixture still stands for an operator who has been provisioned; the channel axis itself
            # is exercised in tests/test_channel_rbac.py.
            await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
            user = await service.store.get_user(uid)
            assert user is not None and user.password_hash is not None
            # Admin-created accounts force first-login rotation (WP-L3-12); clear it, keep the hash.
            await service.store.set_password(
                uid, password_hash=user.password_hash, must_change_password=False
            )

        mid = await engine.store.enqueue_message(
            channel_id="IB_SEED",
            raw=ADT,
            deliveries=[("OB_Q", ADT)],
            message_type="ADT^A01",
            control_id="MSGSEED",
            summary="MRN9001 DOE^JANE",
            metadata=json.dumps({"user": {"note": "attached by a handler"}}),
        )
        # Resolve the delivery with a captured reply, then dead-letter it so /dead-letters has a row.
        items = await engine.store.claim_ready(destination_name="OB_Q")
        await engine.store.complete_with_response(
            items[0].id, body="MSA|AA", outcome="accepted", detail="MSA-1=AA for MRN9001"
        )
        second = await engine.store.enqueue_message(
            channel_id="IB_SEED",
            raw=ADT,
            deliveries=[("OB_DEAD", ADT)],
            message_type="ADT^A01",
            control_id="MSGDEAD",
            summary="MRN9002 ROE^RICHARD",
        )
        assert second
        # A third row whose disposition is ERROR, so MessageSummary/MessageDetail.error is non-null.
        eid = await engine.store.record_received(
            channel_id="IB_SEED",
            raw=ADT,
            status=MessageStatus.ERROR,
            error="strict validation failed on segment PID",
            message_type="ADT^A01",
            control_id="MSGERR",
            summary="MRN9003 POE^PAT",
            metadata=json.dumps({"user": {"note": "attached by a handler"}}),
        )
        dead = await engine.store.claim_ready(destination_name="OB_DEAD")
        assert dead, "the dead-letter seed did not claim its outbox row"
        await engine.store.dead_letter_now(dead[0].id, error="handler blew up on MRN9002")

        # Layered search is OWNER-scoped, so every caller needs a preset of their own. The owner key
        # is the immutable Identity.user_id, never the reassignable username (BACKLOG #1225), so the
        # seed has to resolve the id -- seeding by name writes a row no route can reach.
        presets: dict[str, str] = {}
        for username in ("viewer", "rawonly", "boss"):
            seeded_user = await engine.store.get_user_by_username(username)
            assert seeded_user is not None, f"seed user {username!r} was not created"
            preset_id, _replaced = await engine.store.upsert_search_preset(
                preset_id=f"preset-{username}",
                owner_user_id=seeded_user.id,
                name="jane",
                criteria=json.dumps({"content": "JANE", "target": "both", "limit": 50}),
            )
            presets[username] = preset_id
        yield _Seed(
            engine=engine,
            service=service,
            message_id=mid,
            error_message_id=eid,
            dead_message_id=second,
            presets=presets,
        )
    finally:
        await engine.stop()


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(client: httpx.AsyncClient, username: str) -> dict[str, str]:
    response = await client.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


async def test_view_summary_is_withheld_on_every_documented_surface(seeded: _Seed) -> None:
    """No caller lacking ``messages:view_summary`` receives ANY gated property, on ANY of the six
    surfaces docs/SECURITY.md names.

    RULE: ``redact_unauthorized`` fails OPEN, so a PHI-bearing route that forgets to call it is
    invisible to every map-level test. This is the assertion that catches it.
    """
    async with _client(seeded.engine, seeded.service) as client:
        tokens = {
            "viewer": await _login(client, "viewer"),
            "rawonly": await _login(client, "rawonly"),
        }
        for template, who in _SURFACES:
            path = template.format(
                mid=seeded.message_id,
                eid=seeded.error_message_id,
                did=seeded.dead_message_id,
                preset=seeded.presets[who],
            )
            response = await client.get(path, headers=tokens[who])
            assert response.status_code == 200, (
                f"{path} as {who}: {response.status_code} {response.text}"
            )
            leaked = [
                (prop, obj[prop])
                for obj in _objects(response.json())
                for prop in _GATED_PROPERTIES
                if obj.get(prop) is not None
            ]
            assert not leaked, (
                f"{path} returned gated propert(ies) {leaked} to a caller without "
                "messages:view_summary — the route is missing its redact_unauthorized call "
                "(ASVS 8.1.2)."
            )


def test_every_mapped_model_has_a_distinct_field_signature() -> None:
    """The attribution below is sound only while the six signatures are unique — assert it."""
    assert len(_MODEL_SIGNATURES) == len(PHI_FIELDS), (
        "two PHI_FIELDS models now share a field-name signature, so a JSON object cannot be "
        "attributed to its model. Re-key _attributed_pairs before trusting it."
    )


async def test_the_seed_actually_carries_every_gated_model_property_pair(seeded: _Seed) -> None:
    """Guard against a vacuous pass, keyed on ``(model, property)`` PAIRS, not property names.

    RULE: the withholding assertion above is meaningful only for a row the seed actually exercises.
    Keyed on names, ``last_error`` looked covered (via ``DeadLetterRow`` on ``/dead-letters``) while
    ``OutboxInfo.last_error`` had ZERO coverage — so neutering redaction for ``OutboxInfo`` alone
    left the whole suite green next to a real leak. Attributing each JSON object to its model by
    field signature closes that.
    """
    async with _client(seeded.engine, seeded.service) as client:
        boss = await _login(client, "boss")
        exposed: set[tuple[str, str]] = set()
        for template, _who in _SURFACES:
            path = template.format(
                mid=seeded.message_id,
                eid=seeded.error_message_id,
                did=seeded.dead_message_id,
                preset=seeded.presets["boss"],
            )
            response = await client.get(path, headers=boss)
            assert response.status_code == 200, response.text
            exposed |= _attributed_pairs(response.json())
        assert exposed == set(_GATED_PAIRS), (
            "the seed does not exercise every (model, property) row, so the withholding assertions "
            f"would pass vacuously for: {sorted(set(_GATED_PAIRS) - exposed)}"
        )


async def test_view_raw_without_view_summary_is_reachable(seeded: _Seed) -> None:
    """The doc claims a custom role may hold ``view_raw`` without ``view_summary``. Pin it, since the
    whole reason the disposition fields sit on the view_summary tier rests on that being possible."""
    async with _client(seeded.engine, seeded.service) as client:
        headers = await _login(client, "rawonly")
        response = await client.get(f"/messages/{seeded.message_id}", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["raw"], "the custom role holds messages:view_raw, so the body must be returned"
        assert body["summary"] is None and body["error"] is None and body["metadata"] is None
