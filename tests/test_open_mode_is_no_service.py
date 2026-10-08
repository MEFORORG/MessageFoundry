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
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from starlette.datastructures import State
from starlette.testclient import TestClient, WebSocketDenialResponse

from messagefoundry.api import create_app, create_managed_app
from messagefoundry.api.security import AUTH_NOT_CONFIGURED, open_mode
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    _REMOVED_KEYS,
    AuthSettings,
    EgressSettings,
    SecuritySettings,
    ServiceSettings,
    _removed_key_message,
    _section_models,
    load_settings,
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
        # request.app.state.auth, self._auth, deps.auth_service
        return value.attr in {"auth", "_auth", "auth_service"}
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
    """Names a function binds to an auth service, by annotation or by how it fetched the value.

    ``auth`` itself always counts, whatever bound it: the tree uses that name for the service, and
    a tuple unpack such as ``auth, identity = await _session_caller(request)`` names no source."""
    args = func.args
    every_arg = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    bound = {"auth"} | {a.arg for a in every_arg if _names_auth(a.annotation)}
    for node in ast.walk(func):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if _names_auth(node.annotation) or _is_auth_source(node.value):
                bound.add(node.target.id)
        elif isinstance(node, ast.Assign) and _is_auth_source(node.value):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.NamedExpr) and _is_auth_source(node.value):
            bound.add(node.target.id)
    return bound


def _holds_auth(value: ast.expr, bound: set[str]) -> str | None:
    """The source text of ``value`` when it holds an auth service, else ``None``."""
    if (isinstance(value, ast.Name) and value.id in bound) or _is_auth_source(value):
        return ast.unparse(value)
    return None


def _reads_on_auth(source: str, attrs: frozenset[str]) -> Iterator[tuple[str, int, str]]:
    """``(attr, line, holder)`` for each read of ``attr`` (one of ``attrs``) on an auth service.

    A read is ``holder.attr`` or ``getattr(holder, "attr", ...)``, where ``holder`` is a bound name
    or the fetch itself (``get_auth(request).attr``, ``request.app.state.auth.attr``)."""
    for func in ast.walk(ast.parse(source)):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        bound = _auth_bound_names(func)
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and node.attr in attrs:
                holder = _holds_auth(node.value, bound)
                attr = node.attr
            elif (
                isinstance(node, ast.Call)
                and callee_name(node, bare_only=True) == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in attrs
            ):
                holder = _holds_auth(node.args[0], bound)
                attr = str(node.args[1].value)
            else:
                continue
            if holder is not None:
                yield attr, node.lineno, holder


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
async def e(request):
    if (found := get_auth(request)) is None or not getattr(found, "enabled", True):
        return
    auth, identity = await _session_caller(request)
    return auth.enabled or get_auth(request).enabled or self.auth.enabled or self._auth.enabled
def f(deps):
    held = deps.auth_service
    return held.enabled or deps.auth_service.enabled
def control(dr, service):
    return dr.enabled and service.enabled and getattr(dr, "enabled", False)
"""


def test_the_scanner_finds_every_binding_form() -> None:
    """Positive control: each way the tree binds or reaches a service is recognised, and a
    same-named read on something else is not. A scanner that recognised nothing would report the
    clean zero below."""
    reads = _reads_on_auth(_EVERY_BINDING_FORM, frozenset({"enabled"}))
    assert sorted(holder for _, _, holder in reads) == [
        "auth",
        "auth",
        "current",
        "deps.auth_service",
        "found",
        "get_auth(request)",
        "held",
        "self._auth",
        "self.auth",
        "service",
        "svc",
    ]


def test_no_engine_or_console_code_reads_enabled_on_an_auth_service() -> None:
    """The guards mean ``auth is None``, so they say it, and a stand-in reporting false changes nothing.

    The control on the same walk: the service's own methods are read through these bindings in the
    real tree, so the walk reached the files and recognised the bindings in them. The walk covers
    function bodies and the holders the positive control lists, not module or class level."""
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
    # One refusal for every key, `[auth].enabled` included (vault BACKLOG #3216): AuthSettings no
    # longer carries a second validator of its own.
    reason = _REMOVED_KEYS[section, key]
    message = re.escape(_removed_key_message(section, key, reason, built_directly=True))
    with pytest.raises(ValueError, match=message):
        model.model_validate({key: False})
    with pytest.raises(ValueError, match=message):
        ServiceSettings.model_validate({section: {key: False}})


@pytest.mark.parametrize(("section", "key"), sorted(_REMOVED_KEYS))
def test_each_refusal_names_only_the_places_the_key_could_be(section: str, key: str) -> None:
    """The removal step fits the surface that refused (vault BACKLOG #3216).

    The loader reads the file and the environment, so its message names the variable. A section
    built directly reads no environment, so its message names none: four of the six reasons used
    to carry the loader's "unset MEFOR_..." step into a refusal an environment variable cannot
    cause."""
    variable = f"MEFOR_{section.upper()}_{key.upper()}"
    reason = _REMOVED_KEYS[section, key]
    assert "MEFOR_" + section.upper() not in reason, "the reason carries the decision only"
    assert variable in _removed_key_message(section, key, reason), "control: the loader names it"
    with pytest.raises(ValueError) as built:
        _section_models()[section].model_validate({key: False})
    assert variable not in str(built.value)
    assert "built directly" in str(built.value)
    assert f"Remove `{key}`" in str(built.value)
    # The loader's own refusal, from the environment: it names the variable that set the key.
    with pytest.raises(ValueError, match=variable):
        load_settings(environ={variable: "false"}, default_file=False)


def test_only_the_auth_switch_in_code_is_pointed_at_the_open_mode() -> None:
    """``AuthSettings(enabled=False)`` in code most likely wanted no sign-in, so the refusal says how.

    The loader's refusal of the same key does not: ``serve`` never reaches the open mode."""
    with pytest.raises(ValueError, match="allow_no_auth=True and no auth settings"):
        AuthSettings.model_validate({"enabled": False})
    with pytest.raises(ValueError) as loaded:
        load_settings(environ={"MEFOR_AUTH_ENABLED": "false"}, default_file=False)
    assert "allow_no_auth" not in str(loaded.value)
    with pytest.raises(ValueError) as security:
        SecuritySettings.model_validate({"require_sign_in": False})
    assert "allow_no_auth" not in str(security.value)


def test_a_subclass_of_a_section_inherits_its_refusals() -> None:
    class _Embedded(SecuritySettings):
        pass

    with pytest.raises(ValueError, match="require_sign_in"):
        _Embedded.model_validate({"require_sign_in": False})


def test_the_refusal_names_the_first_removed_key_in_order() -> None:
    """Two removed keys in one section: the model names the one the loader names, every run."""
    with pytest.raises(ValueError, match="handles_real_patient_data"):
        SecuritySettings.model_validate({"require_sign_in": False, "handles_real_patient_data": 1})


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


# --- vault BACKLOG #3216: every open-mode check, in every state ----------------------------------


@pytest.mark.parametrize(
    ("service", "flag", "protected", "is_open"),
    [
        pytest.param(False, False, 503, False, id="no-service"),
        pytest.param(False, True, 200, True, id="no-service-flag"),
        pytest.param(True, False, 401, False, id="service"),
        pytest.param(True, True, 401, False, id="service-flag"),
    ],
)
def test_every_open_mode_check_agrees_in_every_state(
    tmp_path: Path, service: bool, flag: bool, protected: int, is_open: bool
) -> None:
    """The open mode is no service AND the flag, at every place that asks.

    Four places ask: the ``require`` gate, ``optional_identity``, ``authorize_ws`` and the posture.
    Each is read here in all four states, so a check that drifts from the others turns one row red.
    The flag is set on ``app.state`` after the build, because both factories refuse it beside a
    service."""
    app = create_managed_app(
        db_path=tmp_path / "matrix.db",
        poll_interval=0.05,
        auth_settings=(
            AuthSettings(require_mfa=False, notify_security_events=False) if service else None
        ),
        egress_settings=_EGRESS,
    )
    with TestClient(app) as tc:
        app.state.allow_no_auth = flag
        assert tc.get("/stats").status_code == protected  # the `require` gate
        # optional_identity: the build version goes only to an identified caller.
        assert (tc.get("/health").json()["version"] is not None) is is_open
        if is_open:  # authorize_ws
            with tc.websocket_connect("/ws/stats") as ws:
                assert "outbox_by_status" in ws.receive_json()
        else:
            with (
                pytest.raises(WebSocketDenialResponse) as denied,
                tc.websocket_connect("/ws/stats"),
            ):
                pass
            assert denied.value.status_code == 403
        # The posture: a signed-in read where a service is attached, so the row is read, not refused.
        headers: dict[str, str] = {}
        if service:
            assert tc.portal is not None
            tc.portal.call(functools.partial(_add, app.state.auth, "root", Role.ADMINISTRATOR))
            login = tc.post(
                "/auth/login", json={"username": "root", "password": PW, "provider": "local"}
            )
            assert login.status_code == 200, login.text
            headers = _auth(login.json()["token"])
        posture = tc.get("/security/posture", headers=headers)
        if service or is_open:
            assert ("allow_no_auth" in _switches(posture)) is is_open
        else:
            assert posture.status_code == 503, "fail closed: no service and no opt-in"


@pytest.mark.parametrize(
    ("auth", "flag", "expected"),
    [
        pytest.param(None, False, False, id="no-service"),
        pytest.param(None, True, True, id="no-service-flag"),
        pytest.param(object(), False, False, id="service"),
        pytest.param(object(), True, False, id="service-flag"),
        pytest.param(None, "yes", True, id="truthy-flag"),
    ],
)
def test_the_helper_reads_both_halves(auth: object, flag: object, expected: bool) -> None:
    """``open_mode`` is no service AND the flag. A state that never set either is closed."""
    assert open_mode(State({"auth": auth, "allow_no_auth": flag})) is expected
    assert open_mode(State()) is False, "fail closed: an app that set neither"
    assert open_mode(State({"allow_no_auth": True})) is True, "an unset service is no service"


def test_no_service_answers_one_503_text_on_every_surface(tmp_path: Path) -> None:
    """With no service and no opt-in, each provider gives the same 503 detail.

    The sign-in routes and the console's account pages used to say "authentication is not enabled",
    which named a switch that vault BACKLOG #2825 removed. The gate already said "not configured"."""
    assert AUTH_NOT_CONFIGURED == "authentication is not configured"
    app = create_managed_app(
        db_path=tmp_path / "text.db", poll_interval=0.05, serve_ui=True, egress_settings=_EGRESS
    )
    with TestClient(app) as tc:
        assert tc.get("/health").status_code == 200, "control: the app is serving"
        gate = tc.get("/stats")  # api.security._session_caller
        sign_in = tc.post(  # api.auth_routes._service
            "/auth/login", json={"username": "root", "password": PW, "provider": "local"}
        )
        console = tc.get("/ui/account", follow_redirects=False)  # the console's own _service
    for answer in (gate, sign_in):
        assert (answer.status_code, answer.json()["detail"]) == (503, AUTH_NOT_CONFIGURED)
    assert console.status_code == 503
    assert AUTH_NOT_CONFIGURED in console.text
    assert "not enabled" not in console.text
