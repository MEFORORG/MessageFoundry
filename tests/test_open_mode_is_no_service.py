# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The open mode is an app with NO auth service, and nothing else (vault BACKLOG #3062).

Engine PR 2051 (vault BACKLOG #2825) made a built service always require sign-in, and left
``AuthService.enabled`` as a property that returned True. About twenty guards still read it as
``auth is None or not auth.enabled``. This file pins what replaced them: no engine or console code
reads an ``enabled`` switch on an auth service, the class has none, and the open mode is
reachable, and reported, only with no service attached.
"""

from __future__ import annotations

import ast
import functools
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient, WebSocketDenialResponse

from messagefoundry.api import create_app, create_managed_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    _REMOVED_KEYS,
    AuthSettings,
    EgressSettings,
    ServiceSettings,
    _section_models,
)
from messagefoundry.pipeline import Engine
from tests._ast_sites import callee_name
from tests.test_api_auth import PW, _add, _auth, _login, _service
from tests.test_managed_app_no_auth_default import _client

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED = ("messagefoundry", "messagefoundry_webconsole")
_EGRESS = EgressSettings(deny_by_default=False)


# --- item 1: no code reads an `enabled` switch on an auth service --------------------------------


def _is_auth_source(value: ast.expr | None) -> bool:
    """Whether an assigned value is one of the ways engine and console code reach the service."""
    if isinstance(value, ast.Attribute):
        return value.attr == "auth"  # request.app.state.auth
    if not isinstance(value, ast.Call):
        return False
    name = callee_name(value)
    if name == "get_auth":
        return True
    return (
        name == "getattr"
        and len(value.args) >= 2
        and isinstance(value.args[1], ast.Constant)
        and value.args[1].value == "auth"
    )


def _names_auth(annotation: ast.expr | None) -> bool:
    return annotation is not None and "AuthService" in ast.unparse(annotation)


def _auth_bound_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names a function binds to an auth service, by annotation or by how it fetched the value."""
    args = func.args
    every_arg = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    bound = {a.arg for a in every_arg if _names_auth(a.annotation)}
    for node in ast.walk(func):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if _names_auth(node.annotation) or _is_auth_source(node.value):
                bound.add(node.target.id)
        elif isinstance(node, ast.Assign) and _is_auth_source(node.value):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return bound


def _reads_on_auth(source: str, attrs: frozenset[str]) -> Iterator[tuple[str, int, str]]:
    """``(attr, line, name)`` for each read of ``<name>.<attr>`` where ``name`` holds an auth
    service and ``attr`` is one of ``attrs``."""
    for func in ast.walk(ast.parse(source)):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        bound = _auth_bound_names(func)
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in attrs
                and isinstance(node.value, ast.Name)
                and node.value.id in bound
            ):
                yield node.attr, node.lineno, node.value.id


#: The read under test, and the control read through the same bindings.
_SCANNED_ATTRS = frozenset({"enabled", "identity_for_token"})


@functools.cache
def _scan() -> dict[str, set[tuple[str, int, str]]]:
    """Every scanned read, by attribute, with each file parsed once."""
    found: dict[str, set[tuple[str, int, str]]] = {attr: set() for attr in _SCANNED_ATTRS}
    for package in _SCANNED:
        for path in sorted((_ROOT / package).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for attr, line, name in _reads_on_auth(source, _SCANNED_ATTRS):
                found[attr].add((path.relative_to(_ROOT).as_posix(), line, name))
    return found


_EVERY_BINDING_FORM = """
async def a(request):
    auth = get_auth(request)
    if auth is None or not auth.enabled:
        return
async def b(websocket):
    svc = getattr(websocket.app.state, "auth", None)
    return svc.enabled
def c(service: AuthService):
    return service.enabled
def d(request):
    current: AuthService | None = request.app.state.auth
    def inner():
        return current.enabled
    return inner
def control(dr, service):
    return dr.enabled and service.enabled
"""


def test_the_scanner_finds_every_binding_form() -> None:
    """Positive control: each way the tree binds a service is recognised, and a same-named read on
    something else is not. A scanner that recognised nothing would report the clean zero below."""
    reads = _reads_on_auth(_EVERY_BINDING_FORM, frozenset({"enabled"}))
    assert sorted(name for _, _, name in reads) == [
        "auth",
        "current",
        "service",
        "svc",
    ]


def test_no_engine_or_console_code_reads_enabled_on_an_auth_service() -> None:
    """The guards mean ``auth is None``, so they say it, and a stand-in reporting false changes nothing.

    The control on the same walk: the service's own methods are read through these bindings in the
    real tree, so the walk reached the files and recognised the bindings in them."""
    assert _scan()["enabled"] == set()
    assert len(_scan()["identity_for_token"]) >= 5, "control: the walk sees real auth bindings"


def test_the_service_has_no_enabled_switch() -> None:
    assert not hasattr(AuthService, "enabled")


# --- item 2: a removed key is refused by the model, not only by the loader -----------------------


@pytest.mark.parametrize(("section", "key"), sorted(_REMOVED_KEYS))
def test_every_removed_key_is_refused_by_the_section_built_in_code(section: str, key: str) -> None:
    """``SecuritySettings(require_sign_in=False)`` used to drop the key and keep sign-in on silently.

    Built from a mapping, which the validator reads either way: a literal unknown keyword in a test
    is refused by ``tests/test_settings_unknown_kwargs.py``."""
    model = _section_models()[section]
    model()  # control: the same section builds without the key
    with pytest.raises(ValueError, match=key):
        model.model_validate({key: False})
    with pytest.raises(ValueError, match=key):
        ServiceSettings.model_validate({section: {key: False}})


# --- item 3: GET /security/posture reports the open mode ----------------------------------------


def _switches(posture: httpx.Response) -> list[str]:
    assert posture.status_code == 200, posture.text
    return [entry["switch"] for entry in posture.json()["loosenings"]]


async def test_the_posture_names_the_open_mode_and_only_the_open_mode(tmp_path: Path) -> None:
    engine = await Engine.create(
        tmp_path / "posture.db", poll_interval=0.05, egress_settings=_EGRESS
    )
    try:
        async with _client(create_app(engine, allow_no_auth=True)) as c:
            assert "allow_no_auth" in _switches(await c.get("/security/posture"))
        # A service beside the flag still requires sign-in, so there is no open mode to name.
        service = await _service(engine)
        flagged = create_app(engine, auth=service)
        flagged.state.allow_no_auth = True
        await _add(service, "root", Role.ADMINISTRATOR)
        async with _client(flagged) as c:
            signed_in = await _login(c, "root")
            assert signed_in.status_code == 200, signed_in.text
            token = signed_in.json()["token"]
            assert "allow_no_auth" not in _switches(
                await c.get("/security/posture", headers=_auth(token))
            )
    finally:
        await engine.stop()


# --- item 9: the stats socket ignores the flag beside a service ---------------------------------


def test_the_stats_socket_ignores_the_flag_beside_a_service(tmp_path: Path) -> None:
    """``authorize_ws`` answers a tokenless socket with no identity once a service is attached, even
    with the flag set after the build and a stand-in ``enabled = False`` on the service.

    The refusal is read at the HANDSHAKE (a 403 denial, never accepted). After accept the route
    re-checks the session and closes, so a test that only waited for a disconnect stayed green when
    ``authorize_ws`` let the flag win."""
    app = create_managed_app(
        db_path=tmp_path / "ws-flagged.db",
        poll_interval=0.05,
        auth_settings=AuthSettings(require_mfa=False, notify_security_events=False),
        egress_settings=_EGRESS,
    )
    with TestClient(app) as tc:
        app.state.allow_no_auth = True
        app.state.auth.enabled = False
        with pytest.raises(WebSocketDenialResponse) as denied, tc.websocket_connect("/ws/stats"):
            pass
        assert denied.value.status_code == 403
        # The control on the same app: a signed-in socket opens.
        assert tc.portal is not None
        tc.portal.call(functools.partial(_add, app.state.auth, "root", Role.ADMINISTRATOR))
        login = tc.post(
            "/auth/login", json={"username": "root", "password": PW, "provider": "local"}
        )
        assert login.status_code == 200, login.text
        headers = _auth(login.json()["token"])
        with tc.websocket_connect("/ws/stats", headers=headers) as ws:
            assert "outbox_by_status" in ws.receive_json()


# --- item 10: console pages never take the open mode --------------------------------------------


@pytest.mark.parametrize("page", ["/ui", "/ui/connections"])
async def test_console_pages_ask_for_a_session_in_the_open_mode(tmp_path: Path, page: str) -> None:
    """The open mode opens the API, never the console: a page still redirects to sign-in."""
    app = create_managed_app(
        db_path=tmp_path / "ui-open.db",
        poll_interval=0.05,
        serve_ui=True,
        allow_no_auth=True,
        egress_settings=_EGRESS,
    )
    async with app.router.lifespan_context(app), _client(app) as c:
        assert (await c.get("/stats")).status_code == 200, "control: the open mode is on"
        answer = await c.get(page)
    assert answer.status_code == 303
    assert answer.headers["location"].startswith("/ui/login")
