# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine client answers a dual-control hold as a hold (ASVS 2.3.5, BACKLOG #1113).

Three approval-gated operations reach the engine through
:class:`~messagefoundry.apiclient.EngineClient`: ``purge_connection``, ``replay_dead_letters`` and
``reload_config``. When ``[approvals]`` gates one, the engine answers **202 with a
``PendingApprovalResponse``** instead of running it -- the operation has NOT happened, and a
distinct second approver must release it.

Before this file, the client answered that 202 three different ways, which was the defect: two
methods validated the hold body against a result model whose every field is required and let
pydantic's ``ValidationError`` escape (breaking the contract ``_decode``'s own docstring states),
and the third reported the hold as an engine version-skew ``ApiError``. A deploying site that
turned the gate on would have seen all three.

The negative control is the load-bearing half: without it, a client that reported EVERY response as
held would pass the hold assertions.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import Callable

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from messagefoundry.api.models import (
    DeadLetterReplayResult,
    PendingApprovalResponse,
    PurgeResult,
    ReloadResult,
)
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.apiclient.client import _HTTP_PENDING_APPROVAL

# One row per approval-gated client method: (label, call, the engine's operation key, the result
# model instance a COMPLETED call returns). The success bodies are real model instances, not hand
# typed dicts, so a field added to one of these models reaches this test rather than drifting past it.
_GATED_CALLS: list[tuple[str, Callable[[EngineClient], object], str, BaseModel]] = [
    (
        "purge_connection",
        lambda c: c.purge_connection("OB_ACME_ADT"),
        "connection_purge",
        PurgeResult(cancelled=3),
    ),
    (
        "replay_dead_letters",
        lambda c: c.replay_dead_letters(),
        "dead_letter_replay",
        DeadLetterReplayResult(requeued=7),
    ),
    (
        "reload_config",
        lambda c: c.reload_config(),
        "config_reload",
        ReloadResult(inbound=1, outbound=2, routers=3, handlers=4, running=True),
    ),
]

# The routes those three methods POST to, each declared on the engine as
# ``response_model=<result> | PendingApprovalResponse``.
_GATED_ROUTES = ("/connections/{name}/purge", "/dead-letters/replay", "/config/reload")


def _hold_body(operation: str) -> object:
    """The 202 body, serialized from the ENGINE's own :class:`PendingApprovalResponse`.

    Built from the model rather than typed out here so the test cannot drift away from the wire
    shape: a renamed or added field changes this body automatically, and a field the client stops
    reading is caught by the assertions below rather than by a stale literal that still matches."""
    return PendingApprovalResponse(
        approval_id="0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        operation=operation,
        detail="held for a second approver (dual-control)",
    ).model_dump(mode="json")


def _client_answering(status: int, body: object) -> EngineClient:
    """An ``EngineClient`` whose transport answers every request with ``status`` and ``body``.

    ``_request`` builds the request then dispatches it through ``self._http.send``, so ``send`` is
    the seam a stub replaces (the same seam ``tests/test_apiclient.py`` uses)."""
    client = EngineClient("http://127.0.0.1:8765")

    def _send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        return httpx.Response(status, json=body, request=request)

    client._http.send = _send  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize(
    ("label", "call", "operation", "_completed"),
    _GATED_CALLS,
    ids=[row[0] for row in _GATED_CALLS],
)
def test_a_held_operation_returns_the_hold_and_never_a_bare_validation_error(
    label: str,
    call: Callable[[EngineClient], object],
    operation: str,
    _completed: BaseModel,
) -> None:
    """A 202 + ``PendingApprovalResponse`` decodes to the hold on all three methods, identically."""
    client = _client_answering(_HTTP_PENDING_APPROVAL, _hold_body(operation))
    try:
        result = call(client)
    except ValidationError as exc:  # the shipped defect on replay_dead_letters / reload_config
        pytest.fail(f"{label} leaked a bare pydantic ValidationError on a hold: {exc}")
    except ApiError as exc:  # the shipped defect on purge_connection (a hold read as version skew)
        pytest.fail(f"{label} reported a hold as an API error: {exc}")
    finally:
        client.close()
    assert isinstance(result, PendingApprovalResponse), (
        f"{label} decoded a 202 hold as {type(result).__name__}, so a caller cannot tell a held "
        "operation from a completed one"
    )
    assert result.operation == operation
    assert result.approval_id == "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    assert result.status == "pending_approval"


@pytest.mark.parametrize(
    ("label", "call", "_operation", "completed"),
    _GATED_CALLS,
    ids=[row[0] for row in _GATED_CALLS],
)
def test_a_completed_operation_still_returns_its_own_result_unchanged(
    label: str,
    call: Callable[[EngineClient], object],
    _operation: str,
    completed: BaseModel,
) -> None:
    """NEGATIVE CONTROL. Without this, a client that reported everything as held would pass the
    test above. A 200 + the real result body must still decode to that result, untouched."""
    client = _client_answering(200, completed.model_dump(mode="json"))
    try:
        result = call(client)
    finally:
        client.close()
    assert not isinstance(result, PendingApprovalResponse), (
        f"{label} reported a COMPLETED operation as held for approval"
    )
    assert result == completed


@pytest.mark.parametrize(
    ("label", "call", "operation", "_completed"),
    _GATED_CALLS,
    ids=[row[0] for row in _GATED_CALLS],
)
def test_a_malformed_hold_body_is_still_an_apierror(
    label: str,
    call: Callable[[EngineClient], object],
    operation: str,
    _completed: BaseModel,
) -> None:
    """The hold path keeps the module's decoder contract: a 202 whose body does not match the model
    (an engine skew) raises ``ApiError``, never a bare ``ValidationError`` out of the client."""
    client = _client_answering(_HTTP_PENDING_APPROVAL, {"unexpected": "shape"})
    try:
        with pytest.raises(ApiError, match="invalid response from engine"):
            call(client)
    finally:
        client.close()


def test_the_hold_body_carries_the_fields_the_client_reads() -> None:
    """Pin the wire shape against the engine's own model, not a literal.

    ``_hold_body`` serializes :class:`PendingApprovalResponse`; this asserts the three fields a
    caller acts on survive that serialization, so dropping or renaming one reds here."""
    body = _hold_body("config_reload")
    assert isinstance(body, dict)
    assert set(body) >= {"approval_id", "operation", "status", "detail"}
    assert body["status"] == "pending_approval", (
        "the engine's own default; a caller keying on it would silently stop matching"
    )


def test_the_engine_answers_a_hold_with_the_status_the_client_discriminates_on() -> None:
    """``_HTTP_PENDING_APPROVAL`` is a claim about the ENGINE, so read it back from the engine.

    The client picks the hold branch on the status code. Scanning ``api/app.py`` for every
    ``response.status_code = N`` immediately preceding a ``return PendingApprovalResponse(...)``
    answers the question the client asks -- what does the engine actually set -- rather than
    re-asserting 202 against itself.

    The route list is the positive control: a scan that found nothing would otherwise be
    indistinguishable from an engine that never holds anything."""
    from messagefoundry.api import app as app_module

    source = pathlib.Path(app_module.__file__).read_text(encoding="utf-8")
    holds = re.findall(
        r"response\.status_code = (\d+)\s*\r?\n\s*return PendingApprovalResponse\(", source
    )
    assert len(holds) == len(_GATED_ROUTES), (
        f"expected one hold site per gated route ({len(_GATED_ROUTES)}), found {len(holds)}: "
        "either a gated route was added/removed, or the scan stopped matching the code"
    )
    assert set(holds) == {str(_HTTP_PENDING_APPROVAL)}, (
        f"the engine holds with {sorted(set(holds))} but the client discriminates on "
        f"{_HTTP_PENDING_APPROVAL}"
    )
    for route in _GATED_ROUTES:
        declaration = re.search(
            rf'"{re.escape(route)}",\s*response_model=[^)]*PendingApprovalResponse', source
        )
        assert declaration is not None, (
            f"{route} no longer declares PendingApprovalResponse in its response_model, so the "
            "engine's own signature has stopped saying it can hold"
        )


def test_every_gated_client_method_routes_through_the_shared_hold_decoder() -> None:
    """The three methods must answer a hold the SAME way -- three behaviours was the defect.

    Reads each method's own source (via ``inspect``, so it cannot drift onto the wrong lines) and
    requires it to decode through ``_decode_approvable``. A revert to a bare ``model_validate``
    reds here instead of quietly reintroducing a third behaviour."""
    import inspect

    for label, _call, _operation, _completed in _GATED_CALLS:
        body = inspect.getsource(getattr(EngineClient, label))
        assert "_decode_approvable(" in body, (
            f"{label} does not decode through _decode_approvable, so it answers a dual-control "
            "hold differently from its two siblings"
        )
        assert "model_validate(" not in body, (
            f"{label} validates a response body directly, bypassing the module's decoder contract"
        )
