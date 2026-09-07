# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The /ui MFA gate must audit its refusals, as the JSON plane's gate already does.

BACKLOG #1197, ASVS 16.3.2. ``AuthService.audit_mfa_denied`` states the reason in its own docstring:
the MFA gate sits ABOVE the permission loop, so ``audit_permission_denied`` never fires for a refusal
there. Without a row of its own, a stolen password-only cookie could walk the whole authenticated
``/ui`` surface and leave the trail completely silent.

The engine's HTTP and WebSocket gates both call it. ``require_ui`` did not, so on a first deployment
the silence would sit on the plane a human actually uses.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)

#: The audit action the engine's own gates write. The console must write the SAME one: a
#: console-specific action name would satisfy a "something was logged" test while leaving any query
#: written against the engine's vocabulary blind to the console's refusals.
_ACTION = "auth.mfa_denied"


async def _service(engine: Engine, **kw: object) -> AuthService:
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False, **kw))  # type: ignore[arg-type]
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return user_id


async def _login(c: httpx.AsyncClient, username: str = "op") -> httpx.Response:
    return await c.post("/ui/login", data={"username": username, "password": PW})


async def _mfa_denials(engine: Engine) -> list[dict[str, object]]:
    return [r for r in await engine.store.list_audit(limit=200) if r["action"] == _ACTION]


async def test_a_confined_navigation_writes_an_mfa_denial_row(engine: Engine) -> None:
    """RED when: the audit_mfa_denied call is removed from require_ui.

    THE CONTROL IS THE FIRST ASSERTION, and it is not decoration. This suite's other MFA tests would
    all still pass against a console that logged nothing, so a bare "there is a row" check here could
    only fail for reasons unrelated to the gate. Asserting the trail is EMPTY before the navigation
    means the row that appears afterwards was written by the refusal and not by the login that
    preceded it.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303

        assert await _mfa_denials(engine) == [], (
            "the login itself wrote an mfa_denied row, so a row found after the navigation below "
            "would prove nothing about the gate"
        )

        r = await c.get("/ui/messages")
        assert r.status_code == 303 and r.headers["location"] == "/ui/mfa"

    rows = await _mfa_denials(engine)
    assert len(rows) == 1, f"expected exactly one {_ACTION} row for one refusal, got {len(rows)}"
    assert rows[0]["actor"] == "op"
    assert "/ui/messages" in str(rows[0]["detail"]), (
        "the row must name the path that was refused, or it cannot tell an investigator what a "
        f"stolen cookie reached. detail={rows[0]['detail']!r}"
    )


async def test_each_refused_navigation_is_recorded_separately(engine: Engine) -> None:
    """RED when: the audit is hoisted somewhere it fires once per session.

    An enumeration attempt is a SEQUENCE of refusals. One row for the first and silence after it
    would hide exactly the walk this audit exists to make visible.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        await _login(c)
        for path in ("/ui/messages", "/ui/connections", "/ui/audit"):
            assert (await c.get(path)).status_code == 303

    paths = [str(r["detail"]) for r in await _mfa_denials(engine)]
    assert len(paths) == 3, f"expected one row per refused navigation, got {len(paths)}: {paths}"
    assert any("/ui/connections" in p for p in paths)


async def test_the_confinement_page_itself_is_not_audited_as_a_denial(engine: Engine) -> None:
    """RED when: the audit is moved above the allow_mfa_pending check.

    ``/ui/mfa`` is where a pending session is SUPPOSED to go. Recording its own arrival as a refusal
    would bury the real denials under a row per page load, which is the flood cost this cell's
    all-decisions clause is traded against -- and it would be a false positive besides.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        await _login(c)
        before = len(await _mfa_denials(engine))
        await c.get("/ui/mfa")

    assert len(await _mfa_denials(engine)) == before, (
        "the confinement page audited itself as a denial; a pending session reaching /ui/mfa is the "
        "intended outcome, not a refusal"
    )


async def test_a_satisfied_session_writes_no_denial(engine: Engine) -> None:
    """RED when: the gate audits unconditionally rather than on the refusal branch.

    A control on the predicate, not on the plumbing: an audit call placed outside the ``if`` would
    satisfy every test above while recording a denial for every request the console ever serves.
    """
    # require_mfa defaults to True, so this must be set explicitly -- an omitted kwarg leaves
    # the session PENDING and the test passes for the wrong reason.
    service = await _service(engine, require_mfa=False)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        await c.get("/ui/messages")

    assert await _mfa_denials(engine) == [], (
        "a session with no MFA requirement was recorded as MFA-denied"
    )


@pytest.mark.parametrize("path", ["/ui/messages", "/ui/audit"])
async def test_the_console_uses_the_engines_own_action_name(engine: Engine, path: str) -> None:
    """RED when: the console writes a console-specific action name.

    A distinct name passes a "was anything logged" test and is invisible to every query written
    against the engine's vocabulary, which is the vocabulary an investigator would use.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        await _login(c)
        await c.get(path)

    actions = {str(r["action"]) for r in await engine.store.list_audit(limit=200)}
    assert _ACTION in actions, f"no {_ACTION} row; the console wrote {sorted(actions)}"
