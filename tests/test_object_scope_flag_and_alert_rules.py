# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two connection-bearing routes answer a channel-scoped caller by its scope (BACKLOG #1152, ASVS 8.2.2).

* ``POST /connections/{name}/flag`` writes into ``connections.toml``. Before this, its only gate was
  ``config:deploy``, so a DEPLOYMENT account scoped to one channel could flag any TOML-managed
  connection, and a 200 against a 409 told it which names were TOML-managed. It now gives the one
  refusal the per-name routes give (BACKLOG #2551, #2640) to every target outside the caller's scope.
* ``GET /alerts/rules`` returned every rule's ``connection`` and ``control_target``. It now withholds
  any rule that names a connection outside the caller's scope.

NOT-DEPLOYED beta: each gap was one a first deployment would have carried, not a live exposure.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AlertRule, AlertsSettings
from messagefoundry.pipeline import Engine
from tests.test_channel_rbac import _add, _login, _probe, _service, engine  # noqa: F401
from tests.test_connection_audit_writes import toml_engine  # noqa: F401

_DENIED = {"detail": "not authorized for this connection"}


async def _user(service: AuthService, username: str, role: Role, scope: list[str]) -> None:
    await service.set_channel_scope(await _add(service, username, role), scope, actor="test")


async def _flag(
    c: httpx.AsyncClient, eng: Engine, h: dict[str, str], name: str, direction: str
) -> tuple[int, object, list[tuple[str, str | None]]]:
    return await _probe(
        c,
        eng,
        h,
        "POST",
        f"/connections/{name}/flag",
        json={"direction": direction, "flagged": True},
    )


async def test_flag_refuses_every_target_outside_the_callers_scope(
    toml_engine: Engine,  # noqa: F811
) -> None:
    """A scoped caller gets one answer, one body and one audit kind for every target it may not
    reach: a TOML-managed inbound outside its scope, the outbound its scope lists, either name on
    the other side, a name that exists nowhere, and one its scope lists that exists nowhere. None
    writes the file or a ``connection_flag_set`` row."""
    service = await _service(toml_engine, admin_write_rate_limit=False)
    await _user(service, "scoped", Role.DEPLOYMENT, ["IB_GONE", "OB_TOML"])
    await _user(service, "own", Role.DEPLOYMENT, ["IB_TOML"])
    await _user(service, "wide", Role.DEPLOYMENT, [ALL_CHANNELS])
    config_dir = toml_engine.running_config_dir
    assert config_dir is not None
    toml: Path = config_dir / "connections.toml"
    before = toml.read_bytes()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(toml_engine, auth=service)),
        base_url="http://t",
    ) as c:
        h = await _login(c, "scoped")
        targets = [
            ("IB_TOML", "inbound"),  # exists and is TOML-managed: a 200 before the fix
            ("OB_TOML", "outbound"),  # listed in the scope, but an outbound spans channels
            ("OB_TOML", "inbound"),
            ("IB_TOML", "outbound"),
            ("IB_NOPE", "inbound"),  # exists nowhere
            ("IB_GONE", "inbound"),  # listed in the scope, exists nowhere
        ]
        answers = set()
        for name, direction in targets:
            status, body, audit = await _flag(c, toml_engine, h, name, direction)
            assert (status, body) == (403, _DENIED), (name, direction, status, body)
            # The denial row names the probed name, so compare the actions across targets.
            assert ("auth.channel_denied", name) in audit, (name, direction, audit)
            answers.add(tuple(sorted(action for action, _ in audit)))
        assert len(answers) == 1, answers
        assert toml.read_bytes() == before, "a refused flag must not touch connections.toml"
        assert await toml_engine.store.list_audit(action="connection_flag_set") == []

        # The control: a caller scoped to the inbound flags it, and the write lands.
        status, body, audit = await _flag(
            c, toml_engine, await _login(c, "own"), "IB_TOML", "inbound"
        )
        assert status == 200, body
        assert ("connection_flag_set", None) in audit
        assert toml.read_bytes() != before

        # An all-channels caller is unchanged: 409 for a name with no TOML home, no denial row.
        hw = await _login(c, "wide")
        status, _, audit = await _flag(c, toml_engine, hw, "IB_NOPE", "inbound")
        assert status == 409
        assert not [a for a in audit if a[0] == "auth.channel_denied"], audit
        assert (await _flag(c, toml_engine, hw, "OB_TOML", "outbound"))[0] == 200


async def test_flag_with_no_graph_checks_the_scope_first(engine: Engine) -> None:  # noqa: F811
    """With no registry runner the scope still decides first: a name outside it gets the audited
    403, and a name inside it reaches the engine, which refuses it 409 for its own reason."""
    assert engine.registry_runner is None
    service = await _service(engine)
    await _user(service, "scoped", Role.DEPLOYMENT, ["IB_A"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(engine, auth=service)),
        base_url="http://t",
    ) as c:
        h = await _login(c, "scoped")
        status, body, audit = await _flag(c, engine, h, "IB_B", "inbound")
        assert (status, body) == (403, _DENIED)
        assert ("auth.channel_denied", "IB_B") in audit
        status, _, audit = await _flag(c, engine, h, "IB_A", "inbound")
        assert status == 409
        assert not [a for a in audit if a[0] == "auth.channel_denied"], audit


_RULES = AlertsSettings(
    rules=[
        AlertRule(id="all", connection="*"),
        AlertRule(id="mine", connection="IB_A"),
        AlertRule(id="theirs", connection="IB_B"),
        AlertRule(id="glob", connection="IB_*"),
        AlertRule(id="question", connection="IB_?"),
        AlertRule(
            id="mine-targets-out",
            event_type="connection_stopped",
            connection="IB_A",
            control_action="restart_outbound",
            control_target="OB_X",
        ),
        AlertRule(
            id="mine-targets-mine",
            event_type="connection_stopped",
            connection="IB_A",
            control_action="restart_inbound",
            control_target="IB_A",
        ),
    ]
)


async def test_alert_rules_withhold_any_rule_naming_the_estate_outside_the_scope(
    engine: Engine,  # noqa: F811
) -> None:
    """A scoped caller sees a rule only when its ``connection`` is ``*`` or a name in its scope and
    its ``control_target`` is unset or in its scope. An all-channels caller sees every rule."""
    service = await _service(engine)
    await _user(service, "scoped", Role.OPERATOR, ["IB_A"])
    await _user(service, "empty", Role.OPERATOR, [])
    await _user(service, "wide", Role.OPERATOR, [ALL_CHANNELS])
    app = create_app(engine, auth=service, alerts_settings=_RULES)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def ids(username: str) -> list[str]:
            r = await c.get("/alerts/rules", headers=await _login(c, username))
            assert r.status_code == 200, r.text
            return [rule["id"] for rule in r.json()["rules"]]

        assert await ids("wide") == [r.id for r in _RULES.rules]
        assert await ids("scoped") == ["all", "mine", "mine-targets-mine"]
        # An unprovisioned operator still sees the rule that names nobody.
        assert await ids("empty") == ["all"]
