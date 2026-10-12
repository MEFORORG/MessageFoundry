# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Answer an action-bound step-up refusal the way a first-party JSON client does (vault BACKLOG #3241).

Vault BACKLOG #2625 bound resend, edit-resend, upload resend, export, purge and reload to a
single-use proof minted for their own action (ADR 0077). The suites whose subject is what those
routes DO then switched ``[auth].require_action_step_up`` off, so they ran in a posture the engine
does not ship. This transport lets them run with it on.

On a 403 that names an action in ``X-Step-Up-Action`` it re-proves the password for that action
through ``POST /me/reauth``, as the IDE, the harness and the DAST sweep do, and sends the request
once more. ``/me/reauth`` re-keys the session, so the transport also rewrites any later request
that still carries a re-keyed bearer: a test keeps using the header it built at sign-in.

It changes nothing a test asserts about the gate itself. A request that needs no proof goes
through untouched, and a refusal it cannot answer (a wrong password, a second refusal) is
returned as the engine sent it. ``tests/test_bound_step_up_injection.py`` pins the gate.
"""

from __future__ import annotations

import json

import httpx

__all__ = ["ReprovingTransport", "reproving_client"]

_ACTION_HEADER = "X-Step-Up-Action"


class ReprovingTransport(httpx.AsyncBaseTransport):
    """Wraps ``inner``; re-proves ``password`` for an action-bound refusal and retries once."""

    def __init__(self, inner: httpx.AsyncBaseTransport, password: str) -> None:
        self._inner = inner
        self._password = password
        #: Authorization header a test sent -> the header of the session it was re-keyed to.
        self._rekeyed: dict[str, str] = {}
        #: How many re-proofs this transport made, so a suite can show it exercised the proof.
        self.reproofs = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        sent = request.headers.get("Authorization")
        if sent is not None and sent in self._rekeyed:
            sent = self._rekeyed[sent]
            request.headers["Authorization"] = sent
        content = await request.aread()
        response = await self._inner.handle_async_request(request)
        action = response.headers.get(_ACTION_HEADER)
        if response.status_code != 403 or not action or sent is None:
            return response
        reauth = await self._inner.handle_async_request(
            httpx.Request(
                "POST",
                request.url.copy_with(path="/me/reauth", query=None),
                headers={"Authorization": sent, "Content-Type": "application/json"},
                content=json.dumps({"password": self._password, "purpose": action}).encode(),
            )
        )
        body = await reauth.aread()
        if reauth.status_code != 200:
            return response
        await response.aread()
        self.reproofs += 1
        fresh = f"Bearer {json.loads(body)['token']}"
        for original, current in list(self._rekeyed.items()):
            if current == sent:
                self._rekeyed[original] = fresh
        self._rekeyed[sent] = fresh
        headers = [(k, v) for k, v in request.headers.items() if k.lower() != "authorization"]
        retry = httpx.Request(
            request.method,
            request.url,
            headers=[*headers, ("Authorization", fresh)],
            content=content,
        )
        return await self._inner.handle_async_request(retry)

    async def aclose(self) -> None:
        await self._inner.aclose()


def reproving_client(
    app: object, password: str, *, base_url: str = "http://t"
) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` over the ASGI ``app`` that re-proves as :class:`ReprovingTransport`."""
    inner = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=ReprovingTransport(inner, password), base_url=base_url)
