#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bring up the DAST scan target in ONE process and hand back a frozen handle.

THE DEFECT THIS EXISTS FOR. The cheap way to scan a FastAPI app is ``httpx.ASGITransport``, which
calls the ASGI application directly. That target is a DIFFERENT application from the one operators
run, in ways that matter to exactly the controls a security scan is there to exercise: it bypasses
uvicorn's HTTP parser entirely (so the Content-Length + Transfer-Encoding, chunked and oversize
framings the app guards can never be produced — a real loopback socket answers 400 where
ASGITransport cannot), and it leaves ``request.client`` as ``None``, so every IP-keyed control
degenerates to a single anonymous bucket. A scan run over that transport would report those controls
as untested-but-green. The target here is therefore a REAL uvicorn listener on a loopback ephemeral
port, which costs about a second and recovers all of it.

WHAT IT IS STILL NOT. This is plain HTTP on loopback, so the https-gated controls remain structurally
unobservable: the ``__Host-`` cookie prefix, the ``Secure`` flag, HSTS, the effective-https CSP
bundle and the TLS version floor. The sweep's receipt prints the posture it scanned for exactly this
reason — a reader must never mistake it for the shipped default.

NO CONFIG DIR IS PASSED ANYWHERE. An empty ``Registry`` means the engine binds only the API port, so a
run can never collide with another engine's MLLP / TCP / DICOM listeners on the same box, and the scan
has no inbound connection to accidentally feed.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

from messagefoundry.api.app import create_app
from messagefoundry.auth.permissions import BUILTIN_ROLE_PERMISSIONS, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

#: Environment variable holding the password for the two throwaway scan identities. It is OPTIONAL and
#: exists only as an escape hatch (e.g. reproducing a run by hand): the accounts are created by this
#: module, in a store this module creates empty in a temporary directory, and are destroyed with it. No
#: credential is hardcoded — when the variable is absent a fresh cryptographically random password is
#: generated per run, which is strictly stronger than a checked-in constant and cannot go stale.
SCAN_PASSWORD_ENV = "MEFOR_DAST_SCAN_PASSWORD"  # nosec B105 — the env-var NAME, not a password value

ADMIN_USERNAME = "dast-admin"
VIEWER_USERNAME = "dast-viewer"

#: Deep authenticated route used as the bring-up preflight. It must answer 200 for the administrator
#: identity: a session that cannot reach a deep route makes every later 403 meaningless, so the sweep
#: must fail closed rather than report a clean wall of refusals.
PREFLIGHT_PATH = "/connections"

#: Stand-in recorded as the token under ``canary="open-auth"``. Authentication is DISABLED at that
#: target, so ``POST /auth/login`` answers 503 ("authentication is not enabled") and there is no
#: session to mint — which is the whole point of that canary. Nothing authenticates with this value.
_NO_SESSION_SENTINEL = "dast-canary-no-session"

CANARIES = ("open-auth", "bfla")


class DastTargetUnusable(RuntimeError):
    """The target came up but cannot be scanned meaningfully (the preflight failed, or an identity
    could not be minted). The runner turns this into exit 2 — could not measure — never a clean pass."""


@dataclass(frozen=True)
class DastTarget:
    """A live, authenticated scan target."""

    base_url: str
    admin_token: str
    viewer_token: str
    app: FastAPI
    posture: dict[str, str]
    identities: dict[str, tuple[str, ...]]


def _scan_password() -> str:
    """The throwaway password for both scan identities. See :data:`SCAN_PASSWORD_ENV`."""
    from_env = os.environ.get(SCAN_PASSWORD_ENV)
    if from_env:
        return from_env
    # ~32 chars of URL-safe entropy: comfortably over the 15-character floor and containing no
    # application, vendor or username substring by construction.
    return secrets.token_urlsafe(24)


def _auth_settings(*, enabled: bool = True) -> AuthSettings:
    """The scan posture. Every relaxation here is PRINTED in the receipt, because a reader must be able
    to tell what was and was not exercised.

    ``lockout_threshold`` must never be 0: the check is ``attempts >= threshold``, so 0 would lock the
    account on its FIRST failed attempt — and the negative pass makes a great many of those.
    """
    return AuthSettings(
        enabled=enabled,
        require_mfa=False,
        login_rate_limit_enabled=False,
        phi_read_rate_limit_enabled=False,
        admin_write_rate_limit_enabled=False,
        lockout_threshold=1_000_000,
        step_up_max_age_seconds=86400,
    )


def _posture(*, canary: str | None) -> dict[str, str]:
    return {
        "auth": "DISABLED (canary open-auth)" if canary == "open-auth" else "ENABLED",
        "require_mfa": "OFF",
        "login_rate_limit": "OFF",
        "phi_read_rate_limit": "OFF",
        "admin_write_rate_limit": "OFF",
        "lockout_threshold": "1000000",
        "step_up_max_age": "86400s",
        "serve_ui": "OFF",
        "expose_docs": "OFF",
        "transport": "uvicorn/loopback/http",
        "canary": canary or "none",
    }


async def _provision(service: AuthService, username: str, role: Role, password: str) -> None:
    """Create a local user and make its session immediately usable.

    Admin-created accounts force a first-login rotation (WP-L3-12), which would make every probe
    answer 403 "password change required" instead of exercising the gate under test. Re-set the SAME
    hash with the flag cleared — the tests/test_api_auth.py pattern — rather than weakening the policy.
    """
    user_id = await service.create_local_user(
        username=username,
        password=password,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="dast",
    )
    user = await service.store.get_user(user_id)
    if user is None or user.password_hash is None:
        raise DastTargetUnusable(f"provisioning {username} produced no usable credential")
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
    response = await client.post(
        "/auth/login", json={"username": username, "password": password, "provider": "local"}
    )
    if response.status_code != 200:
        # Deliberately does NOT echo the response body: it can carry a reason string, and this message
        # travels to CI logs.
        raise DastTargetUnusable(
            f"could not mint a session for {username}: POST /auth/login answered "
            f"{response.status_code}. Without a real identity every later refusal is meaningless."
        )
    token = response.json().get("token")
    if not isinstance(token, str) or not token:
        raise DastTargetUnusable(f"POST /auth/login returned no token for {username}")
    return token


async def _await_started(server: uvicorn.Server) -> None:
    """Poll the ACTUAL condition (never a fixed sleep, which is a race dressed up as a wait)."""
    for _ in range(600):  # 30 s ceiling; a listener that slow is a failure, not a slow start
        if server.started:
            return
        await asyncio.sleep(0.05)
    raise DastTargetUnusable("the uvicorn target never reported started")


@asynccontextmanager
async def dast_target(
    *, canary: str | None = None, db_dir: Path | None = None
) -> AsyncIterator[DastTarget]:
    """Bring up engine + auth + a loopback uvicorn listener, yield the handle, tear it all down.

    ``canary`` injects a REAL defect through supported configuration and provisioning only — nothing
    under ``messagefoundry/`` is patched, so the injection survives any refactor of ``require()``:

    * ``"open-auth"`` — authentication bypass. CRITICAL AND COUNTERINTUITIVE: ``allow_no_auth`` is
      honoured only when ``auth is None or not auth.enabled`` (messagefoundry/api/security.py), so
      passing ``allow_no_auth=True`` alongside an ENABLED AuthService is SILENTLY IGNORED and the
      canary reports zero findings — indistinguishable from a blind scanner. The app must therefore be
      built against a second, DISABLED service. Users are still created against the enabled service so
      the store is byte-identical to a real run.
    * ``"bfla"`` — broken function-level authorization, injected by provisioning the low-privilege
      identity with the ADMINISTRATOR role while the sweep's expectation set stays the VIEWER
      permission set. Authentication is untouched, which is precisely why this cannot be caught by the
      ``open-auth`` canary and must be a separate one.
    """
    if canary is not None and canary not in CANARIES:
        raise ValueError(f"unknown canary {canary!r}; expected one of {CANARIES}")

    tmp = tempfile.TemporaryDirectory(prefix="mefor-dast-", ignore_cleanup_errors=True)
    root = db_dir if db_dir is not None else Path(tmp.name)
    password = _scan_password()

    engine = await Engine.create(root / "dast.db", poll_interval=0.02)
    server: uvicorn.Server | None = None
    task: asyncio.Task[None] | None = None
    try:
        service = AuthService(engine.store, _auth_settings())
        await service.initialize()

        viewer_role = Role.ADMINISTRATOR if canary == "bfla" else Role.VIEWER
        await _provision(service, ADMIN_USERNAME, Role.ADMINISTRATOR, password)
        await _provision(service, VIEWER_USERNAME, viewer_role, password)

        # expose_docs=False (the shipped default). Nothing in the sweep reads the OpenAPI document, and
        # turning it on would publish four anonymous 200 endpoints — /openapi.json, /docs,
        # /docs/oauth2-redirect, /redoc — that exist ONLY because the scan asked for them. Scanning a
        # surface the scan itself created, and reporting it beside the real anonymous set, is noise at
        # best and a fabricated finding at worst.
        if canary == "open-auth":
            open_service = AuthService(engine.store, _auth_settings(enabled=False))
            await open_service.initialize()
            app = create_app(
                engine, auth=open_service, expose_docs=False, serve_ui=False, allow_no_auth=True
            )
        else:
            app = create_app(engine, auth=service, expose_docs=False, serve_ui=False)

        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", lifespan="on")
        )
        task = asyncio.create_task(server.serve())
        await _await_started(server)
        port = int(server.servers[0].sockets[0].getsockname()[1])
        base_url = f"http://127.0.0.1:{port}"

        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            if canary == "open-auth":
                # Authentication is disabled at this target, so there is no session to mint; every
                # route answers to a tokenless caller, which is the defect being injected.
                admin_token = viewer_token = _NO_SESSION_SENTINEL
            else:
                admin_token = await _login(client, ADMIN_USERNAME, password)
                viewer_token = await _login(client, VIEWER_USERNAME, password)

            preflight = await client.get(
                PREFLIGHT_PATH, headers={"Authorization": f"Bearer {admin_token}"}
            )
            if preflight.status_code != 200:
                blockers = [
                    h for h in ("X-MFA-Required", "X-Step-Up-Required") if h in preflight.headers
                ]
                raise DastTargetUnusable(
                    f"preflight GET {PREFLIGHT_PATH} answered {preflight.status_code}"
                    + (f" ({', '.join(blockers)})" if blockers else "")
                    + " for the administrator identity. A session that cannot reach a deep route "
                    "makes every later 403 meaningless, so this run measured nothing."
                )

        yield DastTarget(
            base_url=base_url,
            admin_token=admin_token,
            viewer_token=viewer_token,
            app=app,
            posture=_posture(canary=canary),
            identities={
                ADMIN_USERNAME: tuple(
                    sorted(p.value for p in BUILTIN_ROLE_PERMISSIONS[Role.ADMINISTRATOR])
                ),
                VIEWER_USERNAME: tuple(
                    sorted(p.value for p in BUILTIN_ROLE_PERMISSIONS[viewer_role])
                ),
            },
        )
    finally:
        # The suite shares ONE session-scoped event loop, so a leaked server task poisons every later
        # test. Every wait is bounded for the same reason.
        if server is not None:
            server.should_exit = True
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=10)
            except TimeoutError:
                task.cancel()
        await engine.stop()
        tmp.cleanup()
