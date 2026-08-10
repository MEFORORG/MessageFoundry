# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The PHI property gate is fail-CLOSED at the model, not fail-open at the call site (BACKLOG #1045).

``redact_unauthorized`` used to be the *only* thing that masked a PHI property, so masking happened
exactly where the call was made and nowhere else. Coverage was pinned by an enumerated test
(``tests/test_field_authz_enforcement_sites.py``), which can only pin the routes someone remembered
to add: a new PHI-returning route that forgot the call would have serialized every gated property in
full, with the whole suite green.

The default now denies. A PHI-bearing response model withholds each of its declared gated properties
from JSON serialization until something explicitly releases it, and ``redact_unauthorized`` is what
releases the ones the caller's permissions actually unlock. A forgotten call is therefore a route
that returns ``null`` — a functional bug, visible to whoever wrote it — rather than a PHI leak.

Every assertion below carries its positive control: proving a property comes back ``null`` is
worthless unless the same shape demonstrably returns the value once released.

Synthetic HL7 only — the MRN and name below are invented.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.field_authz import PHI_FIELDS, redact_unauthorized
from messagefoundry.api.models import MessageDetail, MessageSummary
from messagefoundry.api.phi_gate import GATEABLE_PROPERTIES, PhiGatedModel
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.pipeline import Engine

#: Invented MRN/name, never real PHI.
_SUMMARY = "MRN9001 DOE^JANE"
_ERROR = "strict validation failed on segment PID"
_METADATA = json.dumps({"user": {"note": "attached by a handler"}})


def _identity(*perms: Permission) -> Identity:
    return Identity(
        user_id="1",
        username="u",
        auth_provider=AuthProvider.LOCAL,
        roles=frozenset(),
        permissions=frozenset(perms),
    )


def _summary(**over: Any) -> MessageSummary:
    base: dict[str, Any] = dict(  # noqa: C408
        id="m1",
        channel_id="IB",
        received_at=0.0,
        source_type="mllp",
        control_id="c1",
        message_type="ADT^A01",
        status="ERROR",
        error=_ERROR,
        summary=_SUMMARY,
        metadata=_METADATA,
    )
    base.update(over)
    return MessageSummary(**base)


def _detail() -> MessageDetail:
    return MessageDetail(**_summary().model_dump(), raw="MSH|^~\\&|S|F", outbox=[], events=[])


# --- the default: constructed but not released -> serialized as null ----------------------------


def test_a_freshly_built_phi_model_serializes_its_gated_properties_as_null() -> None:
    """The fail-closed default itself. A model nobody released withholds every gated property.

    RULE: this is what a route that forgets ``redact_unauthorized`` now produces.
    """
    dumped = _summary().model_dump(mode="json")
    withheld = {prop: dumped[prop] for prop in ("summary", "error", "metadata")}
    assert withheld == {"summary": None, "error": None, "metadata": None}, (
        f"an unreleased MessageSummary serialized PHI: {withheld}"
    )
    # Positive control: the SAME model, released, emits the values — so the assertion above is about
    # the gate, not about a seed that never carried PHI or a dump that drops every field.
    released = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_VIEW_SUMMARY))
    emitted = released.model_dump(mode="json")
    assert emitted["summary"] == _SUMMARY
    assert emitted["error"] == _ERROR
    assert emitted["metadata"] == _METADATA


def test_the_attribute_still_carries_the_value_so_server_side_code_is_unaffected() -> None:
    """The gate is on SERIALIZATION, not on the attribute: the engine still composes with the value.

    ``api/app.py`` builds ``MessageDetail`` from ``_summary(row).model_dump()`` before any redaction
    decision exists, so a gate that emptied the python-mode dump would silently blank the detail
    route for an authorized caller.
    """
    row = _summary()
    assert row.summary == _SUMMARY
    assert row.model_dump()["summary"] == _SUMMARY  # python mode: the internal composition path
    assert _detail().summary == _SUMMARY


def test_redaction_releases_only_what_the_caller_holds() -> None:
    """A caller without the permission gets null; a holder gets the value. Both in one place."""
    nonholder = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_READ))
    assert nonholder.model_dump(mode="json")["summary"] is None
    holder = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_VIEW_SUMMARY))
    assert holder.model_dump(mode="json")["summary"] == _SUMMARY


# --- end to end: a route that forgets the call -------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "phi_gate.db", poll_interval=0.05)
    try:
        yield eng
    finally:
        await eng.stop()


async def test_a_route_that_forgets_redact_unauthorized_denies_rather_than_exposes(
    engine: Engine,
) -> None:
    """THE item. A PHI-returning route with no ``redact_unauthorized`` call returns nulls.

    The route is mounted on a throwaway app here rather than shipped, because the point is what
    happens to a route nobody has written yet. ``allow_no_auth=True`` keeps the test about
    serialization: an authenticated caller holding every permission would still get nulls, because
    nothing released the model.
    """
    app = create_app(engine, allow_no_auth=True)

    @app.get("/test-forgot-the-call", response_model=MessageDetail)
    async def forgot() -> MessageDetail:
        return _detail()

    @app.get("/test-made-the-call", response_model=MessageDetail)
    async def remembered() -> MessageDetail:
        return redact_unauthorized(_detail(), _identity(Permission.MESSAGES_VIEW_SUMMARY))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        forgotten = (await client.get("/test-forgot-the-call")).json()
        assert forgotten["raw"], "the non-PHI half of the model must still be returned"
        leaked = {p: forgotten[p] for p in ("summary", "error", "metadata") if forgotten[p]}
        assert not leaked, f"a route with no redact_unauthorized call returned PHI: {leaked}"
        # Positive control on the SAME app and the SAME model: with the call, the holder sees it.
        served = (await client.get("/test-made-the-call")).json()
        assert served["summary"] == _SUMMARY
        assert served["error"] == _ERROR
        assert served["metadata"] == _METADATA


# --- the declaration cannot drift ---------------------------------------------------------------


def test_every_mapped_model_declares_the_same_gate_on_itself() -> None:
    """``PHI_FIELDS`` (which permission unlocks a property) and the model (which properties are
    gated) are two statements about one policy; they must agree exactly, in both directions."""
    for model_cls, props in PHI_FIELDS.items():
        assert issubclass(model_cls, PhiGatedModel), (
            f"{model_cls.__name__} is in PHI_FIELDS but is not a PhiGatedModel, so its properties "
            "would serialize UNGATED whenever a route forgot to redact it"
        )
        assert set(props) == set(model_cls.phi_gated_properties), (
            f"{model_cls.__name__}: PHI_FIELDS gates {sorted(props)} but the model declares "
            f"{sorted(model_cls.phi_gated_properties)}"
        )


def test_the_gate_does_not_untype_the_published_response_schema() -> None:
    """The gate must not be paid for with the API contract.

    A model-level wrap serializer collapses the whole model's serialization schema to
    ``{"type": "object", "additionalProperties": true}`` (measured 2026-08-10 against pydantic
    2.13.4 / fastapi 0.141.1), and a field serializer returning ``Any`` untypes its own property —
    both would publish a vaguer OpenAPI than the code actually returns.
    """
    for model_cls in PHI_FIELDS:
        schema = model_cls.model_json_schema(mode="serialization")
        assert schema.get("properties"), f"{model_cls.__name__} lost its serialization properties"
        for prop in model_cls.phi_gated_properties:
            declared = schema["properties"][prop]
            assert declared.get("anyOf") == [{"type": "string"}, {"type": "null"}], (
                f"{model_cls.__name__}.{prop} is published as {declared} — the gate untyped it"
            )


def test_declaring_a_property_the_serializer_does_not_cover_is_refused() -> None:
    """The one way this gate could go quietly inert: a gated property outside the set the base
    class's field serializer is declared over would never reach the serializer at all.

    So class creation refuses it. Proven by construction, not by review.
    """
    with pytest.raises(TypeError, match="phi_gated_properties"):

        class Ungateable(PhiGatedModel):
            phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"not_a_gateable_name"})

            not_a_gateable_name: str | None = None

    with pytest.raises(TypeError, match="phi_gated_properties"):

        class NotAField(PhiGatedModel):
            # A name the serializer covers, but the model has no such field — the declaration is
            # a typo that would silently gate nothing.
            phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"summary"})

    # Positive control: the same shape, declared correctly, builds and gates.
    class Fine(PhiGatedModel):
        phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"summary"})

        summary: str | None = None

    assert Fine(summary=_SUMMARY).model_dump(mode="json")["summary"] is None
    assert "summary" in GATEABLE_PROPERTIES
