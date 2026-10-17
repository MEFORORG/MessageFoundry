# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Helpers shared by the ``test_webui_*.py`` files.

They were one file, ``test_webui.py``, until BACKLOG #2509 split it so ``--dist loadfile`` can
spread it across workers. A helper used by one file only stays in that file.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode

import httpx
from _ui_clients import create_local_user_chosen, issue_continuation

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
# An HL7 field carrying HTML metacharacters — the XSS payload the browser must never execute.
XSS_RAW = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|X1|P|2.5.1\rPID|1||1||<script>alert(1)</script>\r"

# The shared ``engine`` fixture lives in the package ``conftest.py`` (so the golden-surface tests can
# build an app too); everything below is /ui-suite-local.


async def _service(engine: Engine) -> AuthService:
    # BACKLOG #187 flipped [auth].require_mfa to default-ON (secure-by-default). This /ui suite
    # exercises routing / RBAC / user-management, not MFA enrollment, and its fixtures never enroll
    # an authenticator — so under the new default every unenrolled session diverts to
    # /ui/account?m=enroll_first. Pin require_mfa=False here (the pre-#187 assumption); the handful
    # of tests that DO exercise the require_mfa gate construct their own AuthSettings(require_mfa=True).
    # The suite also drives writes and second factors at machine speed, so the two human-timing
    # floors those would trip are off here (BACKLOG #2301).
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            require_mfa=False,
        ),
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, *, serve_ui: bool = True) -> httpx.AsyncClient:
    # The suite models a browser connected directly to http://t, so the request Host is its origin.
    # create_app no longer assumes that when told nothing (BACKLOG #2219), so the suite says it.
    app = create_app(engine, auth=service, serve_ui=serve_ui, webauthn_rp_from_request=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _cookie_login(c: httpx.AsyncClient, username: str) -> httpx.Response:
    """Sign in via the browser cookie flow (urlencoded form; the client keeps the Set-Cookie)."""
    return await c.post("/ui/login", data={"username": username, "password": PW})


async def _mint_action(
    c: httpx.AsyncClient, next_path: str, *, code: str | None = None
) -> httpx.Response:
    """7.5.1 (ADR 0077): POST /ui/reauth to mint the single-use ACTION grant bound to ``next_path``;
    the caller then re-POSTs the action to consume it. The login window no longer unlocks a /ui factor
    bind, so every factor lane needs its own fresh grant. Pass ``code`` for a full-step-up (enrolled)
    reauth (e.g. disable-MFA on an enrolled session).

    The continuation is issued first, as the step-up gate's refusal would issue it (vault BACKLOG
    #2764): /ui/reauth mints the grant only for a continuation the console issued to this session."""
    issue_continuation(c, next_path)
    data = {"next": next_path, "password": PW}
    if code is not None:
        data["code"] = code
    return await c.post("/ui/reauth", data=data, headers={"Sec-Fetch-Site": "same-origin"})


async def _seed(engine: Engine, raw: str = ADT, control_id: str = "MSG1") -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=raw,
        deliveries=[("archive", raw)],
        control_id=control_id,
        message_type="ADT^A01",
        source_type="file",
    )


# An EDITED body distinct from ADT (a different MRN/name) — stands in for the operator's client-side
# edit. Never real PHI (synthetic HL7 only).
EDITED = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"


_GIB = 1024**3


def _sysinfo(
    disk_free: int | None,
    *,
    logs_free: int | None | Literal["unmeasured"] = None,
    pool_idle: int | None = None,
    channels: int = 2,
    channels_running: int | None = None,
    failed_names: list[str] | None = None,
    failed_count: int | None = None,
    uptime: float = 1.0,
    journal_mode: str = "wal",
):
    """A minimal SystemStatus for _derive_health tests — only the fields the rollup reads matter.

    ``channels`` defaults to a NONZERO deployed-inbound count on purpose (BACKLOG #1741): zero
    deployed inbounds on a started engine is now itself a warn, so a zero default would make every
    test below assert against an incidentally-warning engine. The zero case gets its own tests.

    ``failed_count`` defaults to ``len(failed_names)`` and is passed separately only to build the
    channel-scoped shape, where the caller sees the COUNT of failed inbounds but not every name.

    A caller passing failures usually raises ``channels`` to cover them. That keeps the fixture
    self-consistent (channels_failed is a SUBSET of channels_stopped, never a fourth bucket) — it
    changes no assertion, because the rollup reads only total, failed, the names, and uptime.

    ``logs_free`` carries all three log states in ONE argument (BACKLOG #1563), so the fixture
    cannot express a contradiction: ``None`` = no log section at all (stdout-only), ``"unmeasured"``
    = configured but the probe failed, an int = a measured figure. ``disk_free=None`` is the DB
    drive's unmeasurable case. A ``0`` anywhere here is a real measured zero that must still alarm.

    ``journal_mode`` is the BACKEND, because what ``disk_free=None`` means depends on it: it
    defaults to SQLite's ``"wal"``, where a null can only be a failed local probe, and callers pass
    ``"postgres"`` or a SQL Server recovery model for the disk the engine cannot see at all.
    """
    from messagefoundry.api.models import (
        DbInfo,
        EngineInfo,
        LogInfo,
        PoolInfo,
        PoolWaitInfo,
        SystemStatus,
    )

    names = list(failed_names or [])
    failed = failed_count if failed_count is not None else len(names)
    running = channels_running if channels_running is not None else max(0, channels - failed)
    if logs_free is None:
        logs = None  # stdout-only: no log directory configured, so no section at all
    elif logs_free == "unmeasured":
        logs = LogInfo(path="l", size_bytes=None, disk_free_bytes=None)
    else:
        logs = LogInfo(path="l", size_bytes=1, disk_free_bytes=logs_free)
    return SystemStatus(
        engine=EngineInfo(
            version="0",
            uptime_seconds=uptime,
            pid=1,
            channels_total=channels,
            channels_running=running,
            channels_stopped=channels - running,
            outbox_by_status={},
            channels_failed=failed,
            channels_failed_names=names,
        ),
        db=DbInfo(
            path="db",
            size_bytes=1,
            disk_free_bytes=disk_free,
            journal_mode=journal_mode,
            messages=0,
            events=0,
            audit=0,
        ),
        logs=logs,
        pool=None
        if pool_idle is None
        else PoolInfo(
            backend="postgres",
            max_size=10,
            size=10,
            idle=pool_idle,
            acquire_wait=PoolWaitInfo(
                count=0, p50_ms=0.0, mean_ms=0.0, p95_ms=0.0, p99_ms=0.0, max_ms=0.0
            ),
        ),
    )


@asynccontextmanager
async def _boss_client(engine: Engine, service: AuthService) -> AsyncIterator[httpx.AsyncClient]:
    """An admin ('boss') signed in via the cookie flow."""
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        yield c


async def _uid(service: AuthService, username: str) -> str:
    user = await service.store.get_user_by_username(username)
    assert user is not None
    return user.id


async def _post_pairs(
    c: httpx.AsyncClient, url: str, pairs: list[tuple[str, str]]
) -> httpx.Response:
    """Same-origin urlencoded form POST with REPEATED fields (checkboxes/map rows) — httpx's dict
    ``data=`` collapses duplicate keys, so encode the pair list explicitly."""
    return await c.post(
        url,
        content=urlencode(pairs),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
        },
    )


async def _add_with_role_ids(service: AuthService, username: str, role_ids: list[str]) -> None:
    """Like _add, but with raw role ids (so a CUSTOM role can be assigned)."""
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=role_ids,
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _start_two_out(engine: Engine, tmp_path: Path) -> None:
    """Attach two inbounds (in1/in2) both feeding two outbounds (out1/out2) and start the runner, so the
    pooled delivery dispatcher exists and outbound pause/quiesce is live. No traffic is sent — the bulk
    endpoints resolve control targets from the submitted row keys, not from dashboard edges."""
    reg = Registry()
    for name in ("in1", "in2", "out1", "out2"):
        (tmp_path / name).mkdir(exist_ok=True)
    for ib in ("in1", "in2"):
        reg.add_inbound(
            InboundConnection(
                ib,
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(tmp_path / ib), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router=f"r_{ib}",
            )
        )
    for ob in ("out1", "out2"):
        reg.add_outbound(
            OutboundConnection(
                ob, ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / ob)})
            )
        )
    reg.add_router("r_in1", lambda m: ["h"])
    reg.add_router("r_in2", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("out1", m), Send("out2", m)])
    engine.add_registry(reg)
    await engine.start()


async def _wait_quiesced(engine: Engine, name: str) -> None:
    rr = engine.registry_runner
    assert rr is not None
    for _ in range(200):
        if rr.outbound_quiesced(name):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{name} never quiesced")
