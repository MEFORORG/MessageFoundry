# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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


# --- the step-up factories --------------------------------------------------------------------------
#
# Every test above drives a plain require_ui route. require_ui_step_up and require_ui_step_up_action
# built their base with allow_mfa_pending=True, which switched the audited gate OFF and refused with a
# bare redirect of their own, so none of the tests above could see the silence on those routes.

#: Sent on every request so assert_same_origin passes. A cross-site 403 would land before the gate
#: this file is about, and prove nothing about it.
_SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


@pytest.mark.parametrize(
    ("method", "path", "role", "location"),
    [
        pytest.param(
            "GET",
            "/ui/messages/search",
            Role.OPERATOR,
            "/ui/reauth?next=/ui/messages/search",
            id="step_up-get",
        ),
        pytest.param(
            "POST",
            "/ui/cluster/stepdown",
            Role.ADMINISTRATOR,
            "/ui/reauth?next=/ui/cluster/stepdown-confirm",
            id="step_up-post-with-reauth_next",
        ),
        pytest.param(
            "POST",
            "/ui/account/mfa/disable",
            Role.OPERATOR,
            "/ui/reauth?next=/ui/account/mfa/disable",
            id="step_up_action",
        ),
    ],
)
async def test_a_step_up_route_refusal_writes_an_mfa_denial_row(
    engine: Engine, method: str, path: str, role: Role, location: str
) -> None:
    """RED when: a step-up factory refuses a pending session without the audited gate.

    BOTH halves are asserted, because each guards a different mistake. The row is the defect. The
    Location is what ``allow_mfa_pending`` was added to protect: a fix that restored the row by
    sending the browser to ``/ui/mfa``, or by answering a bare 403, would pass a row-only test while
    losing the continuation the operator clicked. One case per factory shape: a step-up GET, a step-up
    POST whose continuation ``reauth_next`` remaps, and the action-bound factory.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", role)

    async with _client(engine, service) as c:
        assert (await _login(c)).status_code == 303
        assert await _mfa_denials(engine) == [], (
            "the login itself wrote an mfa_denied row, so a row found below would prove nothing"
        )

        r = await c.request(method, path, headers=_SAME_ORIGIN)
        assert r.status_code == 303, f"expected the reauth redirect, got {r.status_code}"
        assert r.headers["location"] == location, (
            "the refusal lost its continuation, which is the behaviour allow_mfa_pending existed for"
        )

    rows = await _mfa_denials(engine)
    assert len(rows) == 1, f"expected exactly one {_ACTION} row for one refusal, got {len(rows)}"
    assert rows[0]["actor"] == "op"
    assert path in str(rows[0]["detail"]), f"the row must name the refused path: {rows[0]!r}"


async def test_a_pending_session_cannot_learn_which_step_up_permissions_it_holds(
    engine: Engine,
) -> None:
    """RED when: a step-up factory checks permissions before the MFA gate.

    ``require_ui`` states the rule in its own comment: a pending session must not learn whether it
    holds a permission. With the gate switched off in the base, a password-only cookie got a 403 from
    an admin form its user lacks and a redirect from one it holds, which is a free map of the victim's
    authority. The JSON twin refuses both the same way, before its permission loop runs.
    """
    service = await _service(engine, require_mfa=True)
    await _add(service, "op", Role.OPERATOR)  # holds no users:manage

    async with _client(engine, service) as c:
        await _login(c)
        r = await c.get("/ui/users/new")
        assert r.status_code == 303, f"a pending session saw {r.status_code}, not the MFA refusal"
        assert r.headers["location"] == "/ui/reauth?next=/ui/users/new"

    actions = [str(row["action"]) for row in await engine.store.list_audit(limit=200)]
    assert actions.count(_ACTION) == 1, f"expected one {_ACTION} row, the store holds {actions}"
    assert "auth.permission_denied" not in actions, (
        "the permission loop ran for a pending session, so its result reached the caller"
    )


@pytest.mark.parametrize(
    ("require_mfa", "charged"),
    [pytest.param(True, False, id="pending"), pytest.param(False, True, id="control-satisfied")],
)
async def test_a_pending_session_spends_no_admin_write_budget_on_a_step_up_route(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, require_mfa: bool, charged: bool
) -> None:
    """RED when: the admin-write charge runs before the MFA gate on a step-up route.

    The budget is per actor. A password-only cookie that could spend it could throttle the real
    operator's writes without ever passing the second factor; the JSON twin charges only after its
    MFA gate. The satisfied case is the control: it proves the spy is wired, so the pending case's
    empty list means "not charged" and not "not observed".
    """
    service = await _service(engine, require_mfa=require_mfa)
    await _add(service, "op", Role.OPERATOR)
    calls: list[str] = []
    real = service.allow_admin_write

    def spy(user_id: str) -> bool:
        calls.append(user_id)
        return real(user_id)

    async with _client(engine, service) as c:
        await _login(c)
        monkeypatch.setattr(
            service, "allow_admin_write", spy
        )  # after login, so only the route counts
        r = await c.post("/ui/account/mfa/disable", headers=_SAME_ORIGIN)
        assert r.status_code == 303

    assert bool(calls) is charged, f"allow_admin_write calls: {calls}"


async def test_a_stale_step_up_proof_is_not_recorded_as_an_mfa_denial(engine: Engine) -> None:
    """RED when: the audit is placed on a step-up factory's freshness branch.

    A satisfied session with no fresh action-bound proof is refused too, and to the same page. That
    refusal is an ordinary step-up, not a second-factor denial, and recording it as one would put a
    false MFA row on every sensitive action an operator takes.
    """
    service = await _service(engine, require_mfa=False)
    await _add(service, "op", Role.OPERATOR)

    async with _client(engine, service) as c:
        await _login(c)
        r = await c.post("/ui/account/mfa/disable", headers=_SAME_ORIGIN)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/disable"

    assert await _mfa_denials(engine) == [], "a step-up refusal was recorded as an MFA denial"
