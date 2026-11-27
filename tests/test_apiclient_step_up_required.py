# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An unanswered step-up refusal is a typed error, and a declined one leaves no stale purpose
(BACKLOG #5945).

A polling client has no step-up handler, so the harness messages panel could see a step-up refusal
only as a bare 403, which a role or scope refusal shares. ``StepUpRequired`` names it. And a step-up
the handler declined used to leave its ``X-Step-Up-Action`` stashed, so the next ``reauth()`` made
for another reason posted that action as its purpose.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from messagefoundry.apiclient import ApiError, EngineClient, IdpStepUpRequired, StepUpRequired


def _client_answering(answer: Callable[[httpx.Request], httpx.Response]) -> EngineClient:
    client = EngineClient("http://127.0.0.1:8765")

    def _send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        return answer(request)

    client._http.send = _send  # type: ignore[method-assign]
    return client


def _refusing(headers: dict[str, str], bodies: list[dict[str, object]]) -> EngineClient:
    def _answer(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me/reauth":
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"token": "rotated"}, request=request)
        return httpx.Response(403, json={"detail": "refused"}, headers=headers, request=request)

    return _client_answering(_answer)


def test_a_step_up_refusal_with_no_handler_raises_step_up_required() -> None:
    client = _refusing({"X-Step-Up-Required": "1"}, [])
    try:
        with pytest.raises(StepUpRequired) as raised:
            client.search_messages(content="x")
    finally:
        client.close()
    assert isinstance(raised.value, ApiError)
    assert raised.value.status == 403


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-MFA-Required": "1"}],
    ids=["role-or-scope", "second-factor"],
)
def test_another_403_stays_a_plain_api_error(headers: dict[str, str]) -> None:
    client = _refusing(headers, [])
    try:
        with pytest.raises(ApiError) as raised:
            client.search_messages(content="x")
    finally:
        client.close()
    assert not isinstance(raised.value, StepUpRequired)


def test_an_idp_step_up_is_not_step_up_required() -> None:
    client = _refusing({"X-Step-Up-Required": "1", "X-Step-Up-Via": "idp"}, [])
    try:
        with pytest.raises(IdpStepUpRequired) as raised:
            client.search_messages(content="x")
    finally:
        client.close()
    assert not isinstance(raised.value, StepUpRequired)


def test_a_declined_step_up_leaves_no_purpose_for_the_next_reauth() -> None:
    bodies: list[dict[str, object]] = []
    client = _refusing({"X-Step-Up-Required": "1", "X-Step-Up-Action": "purge"}, bodies)
    client.set_step_up_handler(lambda: False)  # the operator cancels the prompt
    try:
        with pytest.raises(StepUpRequired):
            client.search_messages(content="x")
        client.reauth("pw")  # a re-proof made later, for something else
    finally:
        client.close()
    assert bodies == [{"password": "pw"}], "the declined action rode along as the purpose"


@pytest.mark.parametrize(
    ("headers", "action"),
    [
        ({"X-Step-Up-Required": "1", "X-Step-Up-Action": "purge"}, "purge"),
        ({"X-Step-Up-Required": "1"}, None),
        ({"X-Step-Up-Required": "1", "X-Step-Up-Action": ""}, None),
    ],
    ids=["per-action", "session-window", "empty-action"],
)
def test_step_up_required_names_the_action_the_refusal_named(
    headers: dict[str, str], action: str | None
) -> None:
    """A per-action gate (ADR 0077) mints its grant only for a re-proof that names the action, and
    a handler-less client stashes nothing, so the refusal itself must carry it."""
    client = _refusing(headers, [])
    try:
        with pytest.raises(StepUpRequired) as raised:
            client.search_messages(content="x")
    finally:
        client.close()
    assert raised.value.action == action


def test_an_empty_action_posts_no_purpose_through_the_handler() -> None:
    """The handler path normalizes an empty X-Step-Up-Action the same way: as a purpose an empty
    string would win over none and be refused."""
    bodies: list[dict[str, object]] = []
    client = _refusing({"X-Step-Up-Required": "1", "X-Step-Up-Action": ""}, bodies)

    def prove() -> bool:
        client.reauth("pw")
        return True

    client.set_step_up_handler(prove)
    try:
        with pytest.raises(StepUpRequired):  # the fake refuses the retry too
            client.search_messages(content="x")
    finally:
        client.set_step_up_handler(None)
        client.close()
    assert bodies == [{"password": "pw"}]


def test_a_declined_handler_still_names_the_action() -> None:
    """The handler declined, so the caller sees the refusal and may re-prove for it later."""
    client = _refusing({"X-Step-Up-Required": "1", "X-Step-Up-Action": "purge"}, [])
    client.set_step_up_handler(lambda: False)
    try:
        with pytest.raises(StepUpRequired) as raised:
            client.search_messages(content="x")
    finally:
        client.close()
    assert raised.value.action == "purge"
