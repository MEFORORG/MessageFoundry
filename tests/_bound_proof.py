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

A request that needs no proof goes through untouched, and a refusal it cannot answer (a wrong
password, a second refusal) is returned as the engine sent it. ``tests/test_bound_step_up_injection.py``
pins the gate itself.

THE REFUSED FIRST TRY IS A REAL REQUEST. It passed the permission check, so it wrote its grant
audit row and, for a write, charged the admin-write gap. A test that counts those rows or budgets,
reads the re-keyed session afterwards, or runs under a deadline a password hash outlasts should
prove up front with :func:`prove` instead, and a suite whose retry would be paced turns
``admin_write_min_interval_seconds`` off.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

__all__ = ["ReprovingTransport", "prove", "reproving_transport"]

_ACTION_HEADER = "X-Step-Up-Action"


class ReprovingTransport(httpx.AsyncBaseTransport):
    """Wraps ``inner``; re-proves ``password`` for an action-bound refusal and retries once."""

    def __init__(self, inner: httpx.AsyncBaseTransport, password: str) -> None:
        self._inner = inner
        self._password = password
        #: Authorization header a test sent -> the header of the session it was re-keyed to.
        self._rekeyed: dict[str, str] = {}

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


def reproving_transport(password: str, **asgi_kwargs: Any) -> ReprovingTransport:
    """An ``httpx.ASGITransport(**asgi_kwargs)`` wrapped in a :class:`ReprovingTransport`."""
    return ReprovingTransport(httpx.ASGITransport(**asgi_kwargs), password)


async def prove(client: httpx.AsyncClient, token: str, password: str, action: str) -> str:
    """Mint a proof bound to ``action`` up front, as ``POST /me/reauth`` does; the re-keyed token."""
    r = await client.post(
        "/me/reauth",
        json={"password": password, "purpose": action},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])
