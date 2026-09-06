# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An API request body refuses an unknown key; an API response body still tolerates one.

BACKLOG #1109, the API limb of ASVS 2.2.1. Pydantic's default is ``extra="ignore"``, so every API
request body used to accept a misspelled key, drop it, and answer 200. The worst instance is
``PUT /users/{id}/channel-scope``: ``channels`` is optional and ``None`` means *all channels*, so
``{"chanels": ["IB_ACME_ADT"]}`` asked for one connection and granted every one of them.

The posture is deliberately DIRECTIONAL, and these tests pin both halves of it, because a blanket
``extra="forbid"`` across the module would be a different and worse defect:
:mod:`messagefoundry.apiclient.client` validates engine RESPONSES into these same classes and the
web console ships as a separately-versioned wheel, so a strict response model would make an older
client raise on a newer engine that merely grew a field.

Every assertion carries its positive control. "The request was refused" proves nothing on its own --
a route that rejects every body would satisfy it -- so each refusal is paired with the same body,
minus the unknown key, going through.

The membership tests read FastAPI's own ``route.body_field``, which is the decision the framework
actually makes at request time. Re-deriving that from the source with a regex would be a second,
silently different definition of "request model" -- the failure CLAUDE.md section 11 records for the
backlog glyph parser.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError

from messagefoundry.api import auth_models as auth_models_mod
from messagefoundry.api import create_app
from messagefoundry.api import models as models_mod
from messagefoundry.api.auth_models import ChannelScope, UserCreateRequest
from messagefoundry.api.models import StatsResponse
from messagefoundry.api.request_model import RequestModel
from messagefoundry.pipeline import Engine

#: The five shapes the API parses from a request body AND returns in a response. They carry the
#: request rule, so adding a field to one of them is a client-visible wire change that needs the
#: client bump in the same release. Pinned here so growing this set is a decision, not a drift --
#: the reasoning lives in :mod:`messagefoundry.api.request_model`.
DUAL_USE = frozenset(
    {"AdGroupMap", "AdGroupMapEntry", "AdGroupScopeEntry", "AdGroupScopeMap", "ChannelScope"}
)


def _declared(mod: ModuleType) -> dict[str, type[BaseModel]]:
    """The Pydantic models this module DEFINES (not the ones it imports)."""
    return {
        name: obj
        for name, obj in vars(mod).items()
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj.__module__ == mod.__name__
    }


def _reachable(annotation: object, out: set[str]) -> None:
    """Every model name reachable from ``annotation``, following nested model fields."""
    seen: set[int] = set()
    stack: list[Any] = [annotation]
    while stack:
        cur = stack.pop()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        if inspect.isclass(cur) and issubclass(cur, BaseModel):
            out.add(cur.__name__)
            stack.extend(f.annotation for f in cur.model_fields.values())
            continue
        stack.extend(getattr(cur, "__args__", ()))


def _partition() -> tuple[dict[str, type[BaseModel]], set[str], set[str]]:
    """(every declared model, the request-body set, the response set) as FastAPI sees them."""
    declared = {**_declared(models_mod), **_declared(auth_models_mod)}
    app = create_app(engine=None, allow_no_auth=True)  # type: ignore[arg-type]
    body: set[str] = set()
    resp: set[str] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.body_field is not None:
            _reachable(route.body_field.field_info.annotation, body)
        if route.response_model is not None:
            _reachable(route.response_model, resp)
    return declared, body & set(declared), resp & set(declared)


def _forbids(model: type[BaseModel]) -> bool:
    return model.model_config.get("extra") == "forbid"


def test_every_request_body_model_forbids_unknown_keys() -> None:
    declared, body, _ = _partition()
    assert body, "instrument check: FastAPI reported no request-body models at all"
    tolerant = sorted(n for n in body if not _forbids(declared[n]))
    assert not tolerant, (
        f"these models are parsed from a request body and still silently drop unknown keys:"
        f" {tolerant} -- subclass messagefoundry.api.request_model.RequestModel"
    )


def test_response_only_models_stay_tolerant() -> None:
    """The positive control for the test above: the split is directional, not a blanket flip.

    A pass on ``test_every_request_body_model_forbids_unknown_keys`` alone is also what a blanket
    ``extra="forbid"`` on all 125 models would produce -- and that would break every client reading
    a newer engine. This is the half that tells the two apart.
    """
    declared, body, _ = _partition()
    response_only = set(declared) - body
    assert response_only, "instrument check: no response-only models found"
    strict = sorted(n for n in response_only if _forbids(declared[n]))
    assert not strict, (
        f"these models are never parsed from a request body and must stay tolerant, so an older"
        f" client does not raise on a newer engine that grew a field: {strict}"
    )


def test_dual_use_models_are_exactly_the_recorded_set() -> None:
    _, body, resp = _partition()
    assert set(body & resp) == set(DUAL_USE), (
        "the set of shapes used in BOTH directions moved. Each one is strict, so adding a field to"
        " it is a client-visible wire change -- update DUAL_USE and the note in"
        " messagefoundry/api/request_model.py together, on purpose."
    )


def test_request_model_base_is_what_carries_the_rule() -> None:
    """The rule lives on one base class, so it cannot be half-applied by copy-paste."""
    assert _forbids(RequestModel)
    assert not _forbids(StatsResponse), "positive control: a response model is not strict"


def test_unknown_key_is_refused_at_the_model_with_a_control() -> None:
    good = {"username": "op", "password": "pw", "roles": ["viewer"]}
    assert UserCreateRequest.model_validate(good).username == "op"
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        UserCreateRequest.model_validate({**good, "rolez": ["admin"]})


def test_the_channel_scope_typo_no_longer_widens_the_grant() -> None:
    """The concrete defect: ``channels=None`` means ALL channels, so a dropped key over-granted."""
    assert ChannelScope.model_validate({"channels": ["IB_ACME_ADT"]}).channels == ["IB_ACME_ADT"]
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        ChannelScope.model_validate({"chanels": ["IB_ACME_ADT"]})


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "extra.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


@pytest.mark.asyncio
async def test_over_the_wire_an_unknown_body_key_is_a_422(client: httpx.AsyncClient) -> None:
    """End to end, with the accepted body as the control: the refusal is the extra key, not the route."""
    good = await client.post("/messages/search", json={"content": "MRN", "limit": 5})
    assert good.status_code != 422, good.text

    bad = await client.post("/messages/search", json={"content": "MRN", "limit": 5, "limt": 9})
    assert bad.status_code == 422, bad.text
    assert "limt" in bad.text
